import ctypes
import glob
import os
import pathlib
import sys

import grpc
import numpy as np
import yaml
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hadoop.io import (  # pylint: disable=no-name-in-module
    BytesWritable,
    IntWritable,
    SequenceFile,
)
from numproto import ndarray_to_proto, proto_to_ndarray
from OpenSSL import crypto
from paramiko import AutoAddPolicy, SSHClient
from scp import SCPClient

from .exceptions import (
    AttestationError,
    CryptoError,
    MC2ClientComputeError,
    MC2ClientConfigError,
)
from .rpc import (  # pylint: disable=no-name-in-module
    remote_pb2,
    remote_pb2_grpc,
)

# Load in C++ library
curr_path = os.path.dirname(os.path.abspath(os.path.expanduser(__file__)))
dll_path = [
    curr_path,
    os.path.join(curr_path, "../../src/build/"),
    os.path.join(curr_path, "./build/"),
    os.path.join(sys.prefix, "mc2client"),
    pathlib.Path(__file__).parent.absolute(),
]

dll_path = [os.path.join(p, "libmc2client.so") for p in dll_path]
lib_path = [p for p in dll_path if os.path.exists(p) and os.path.isfile(p)]
lib_path = [os.path.relpath(p) for p in lib_path]

if len(lib_path) == 0:
    raise Exception("Cannot find libmc2client.so")
else:
    lib_path = lib_path[0]

_LIB = ctypes.CDLL(lib_path)

_LIB.api_free_ptr.argtypes = (ctypes.c_void_p,)

_LIB.api_free_double_ptr.argtypes = (ctypes.POINTER(ctypes.c_void_p), ctypes.c_int)


# _CONF is a cache of data retrieved throughout processing
_CONF = {}


def _check_call(ret):
    """Check the return value of C API call

    This function will raise exception when error occurs.
    Wrap every API call with this function

    Parameters
    ----------
    ret : int
        return value from API calls
    """
    if ret != 0:
        raise MC2ClientComputeError()


def _check_remote_call(ret):
    """check the return value of c api call

    this function will raise exception when error occurs.
    wrap every api call with this function

    parameters
    ----------
    ret : proto
        return value from remote api calls
    """
    channel_addr = _CONF["remote_addr"]
    if channel_addr:
        if ret.status.status != 0:
            raise MC2ClientComputeError(ret.status.exception)
        else:
            return ret


def c_array(ctype, values):
    """Convert a python list to c array."""
    return (ctype * len(values))(*values)


def c_arr_to_list(cptr, length, dtype=np.uint8):
    """Convert a ctypes pointer array to a Python list."""
    NUMPY_TO_CTYPES_MAPPING = {
        np.float32: ctypes.c_float,
        np.uint32: ctypes.c_uint,
        np.uint8: ctypes.c_uint8,
        np.intc: ctypes.c_int,
    }
    if dtype not in NUMPY_TO_CTYPES_MAPPING:
        raise RuntimeError("Supported types: {}".format(NUMPY_TO_CTYPES_MAPPING.keys()))
    ctype = NUMPY_TO_CTYPES_MAPPING[dtype]
    if not isinstance(cptr, ctypes.POINTER(ctype)):
        raise RuntimeError("expected {} pointer, got {}".format(ctype, type(cptr)))
    res = np.zeros(length, dtype=dtype)
    if not ctypes.memmove(
        res.ctypes.data,
        cptr,
        length * res.strides[0],  # pylint: disable=unsubscriptable-object
    ):
        raise RuntimeError("memmove failed")
    return res


def from_pystr_to_cstr(data):
    """Convert a list of Python str to C pointer
    Parameters
    ----------
    data : list
        list of str
    """

    if not isinstance(data, list):
        raise NotImplementedError
    pointers = (ctypes.c_char_p * len(data))()
    data = [bytes(d, "utf-8") for d in data]
    pointers[:] = data
    return pointers


def c_str(py_str):
    """Convert a Python string to a C char*

    Parameters
    ----------
    py_str : str
        string to be converted to char*
    """
    return ctypes.c_char_p(py_str.encode("utf-8"))


def from_cstr_to_pystr(data, length):
    """Revert C pointer to list of Python str
    Parameters
    ----------
    data : ctypes pointer
        pointer to data
    length : ctypes pointer
        pointer to length of data
    """
    res = []
    for i in range(length.value):
        res.append(str(data[i].decode("utf-8")))
    return res


def py_str(c_char):
    """
    Convert a C char* to a Python string

    Parameters
    ----------
    c_char : ctypes pointer
        C char* to be converted to Python string
    """
    return str(c_char.decode("utf-8"))


def from_pyfloat_to_cfloat(data):
    """
    Convert a list of lists of Python floats to C float double pointer

    Parameters
    ----------
    data : list
        list of list of floats
    """

    if not isinstance(data, list):
        raise NotImplementedError

    pointers = (ctypes.POINTER(ctypes.c_float) * len(data))()
    num_floats_per_pointer = (ctypes.c_int * len(data))()
    for i in range(len(data)):
        float_lst = data[i]
        pointers[i] = c_array(ctypes.c_float, float_lst)
        num_floats_per_pointer[i] = ctypes.c_int(len(float_lst))

    return pointers, num_floats_per_pointer


def from_cfloat_to_pyfloat(data, num_floats, length):
    """
    Convert a C float double pointer to a list of lists of Python floats

    Parameters
    ----------
    data : list
        C float double pointer
    num_floats : list
        Num floats per list in data
    """
    num_floats_per_list = c_arr_to_list(num_floats, length.value, np.intc)
    res = []
    for i in range(length.value):
        float_lst = c_arr_to_list(data[i], num_floats_per_list[i], np.float32)
        res.append(float_lst)

    return res


def ctypes2numpy(cptr, length, dtype):
    """
    Convert a ctypes pointer array to a numpy array.
    """
    NUMPY_TO_CTYPES_MAPPING = {
        np.float32: ctypes.c_float,
        np.uint32: ctypes.c_uint,
        np.uint8: ctypes.c_uint8,
    }
    if dtype not in NUMPY_TO_CTYPES_MAPPING:
        raise RuntimeError("Supported types: {}".format(NUMPY_TO_CTYPES_MAPPING.keys()))
    ctype = NUMPY_TO_CTYPES_MAPPING[dtype]
    if not isinstance(cptr, ctypes.POINTER(ctype)):
        raise RuntimeError("expected {} pointer".format(ctype))
    res = np.zeros(length, dtype=dtype)
    if not ctypes.memmove(
        res.ctypes.data,
        cptr,
        length * res.strides[0],  # pylint: disable=unsubscriptable-object
    ):
        raise RuntimeError("memmove failed")
    return res


def ctypes2buffer(cptr, length):
    """
    Convert ctypes pointer to buffer type.
    """
    if not isinstance(cptr, ctypes.POINTER(ctypes.c_char)):
        raise RuntimeError("expected char pointer")
    res = bytearray(length)
    rptr = (ctypes.c_char * length).from_buffer(res)
    if not ctypes.memmove(rptr, cptr, length):
        raise RuntimeError("memmove failed")
    return res


def pointer_to_proto(pointer, pointer_len, nptype=np.uint8):
    """
    Convert C u_int or float pointer to proto for RPC serialization

    Parameters
    ----------
    pointer : ctypes.POINTER
    pointer_len : length of pointer
    nptype : np type to cast to
        if pointer is of type ctypes.c_uint, nptype should be np.uint32
        if pointer is of type ctypes.c_float, nptype should be np.float32

    Returns:
        proto : proto.NDArray
    """
    ndarray = ctypes2numpy(pointer, pointer_len, nptype)
    proto = ndarray_to_proto(ndarray)
    return proto


def proto_to_pointer(proto, ctype=ctypes.c_uint8):
    """
    Convert a serialized NDArray to a C pointer

    Parameters
    ----------
    proto : proto.NDArray

    Returns:
        pointer :  ctypes.POINTER(ctypes.u_int)
    """

    ndarray = proto_to_ndarray(proto)
    # FIXME make the ctype POINTER type configurable
    pointer = ndarray.ctypes.data_as(ctypes.POINTER(ctype))
    return pointer


def encrypt_data_with_pk(data, data_len, pem_key, key_size):
    """
    Parameters
    ----------
    data : byte array
    data_len : int
    pem_key : proto
    key_size : int

    Returns
    -------
    encrypted_data : proto.NDArray
    encrypted_data_size_as_int : int
    """
    # Cast data to char*
    data = ctypes.c_char_p(data)
    data_len = ctypes.c_size_t(data_len)

    # Cast proto to pointer to pass into C++ encrypt_data_with_pk()
    pem_key = proto_to_pointer(pem_key)

    # Allocate memory that will be used to store the encrypted_data and encrypted_data_size
    encrypted_data = np.zeros(1024).ctypes.data_as(ctypes.POINTER(ctypes.c_uint8))
    encrypted_data_size = ctypes.c_size_t(1024)

    # Encrypt the data with pk pem_key
    _LIB.encrypt_data_with_pk(
        data,
        data_len,
        pem_key,
        key_size,
        encrypted_data,
        ctypes.byref(encrypted_data_size),
    )

    # Cast the encrypted data back to a proto.NDArray (for RPC purposes) and return it
    encrypted_data_size_as_int = encrypted_data_size.value
    encrypted_data = pointer_to_proto(encrypted_data, encrypted_data_size_as_int)

    return encrypted_data, encrypted_data_size_as_int


def sign_data(key, data, data_size):
    """
    Parameters
    ----------
    keyfile : str
    data : proto.NDArray or str
    data_size : int

    Returns
    -------
    signature : proto.NDArray
    sig_len_as_int : int
    """
    if not os.path.exists(key):
        raise FileNotFoundError("Cannot find private key: {}".format(key))

    # Cast the keyfile to a char*
    keyfile = ctypes.c_char_p(str.encode(key))

    # Cast data : proto.NDArray to pointer to pass into C++ sign_data() function
    if isinstance(data, str):
        data = c_str(data)
    elif isinstance(data, ctypes.Array) and (data._type_ is ctypes.c_char):
        pass
    else:
        # FIXME error handling for other types
        data = proto_to_pointer(data)

    data_size = ctypes.c_size_t(data_size)

    # Allocate memory to store the signature and sig_len
    signature = np.zeros(1024).ctypes.data_as(ctypes.POINTER(ctypes.c_uint8))
    sig_len = ctypes.c_size_t(1024)

    # Sign data with key keyfile
    _LIB.sign_data_with_keyfile(
        keyfile, data, data_size, signature, ctypes.byref(sig_len)
    )

    # Cast the signature and sig_len back to a gRPC serializable format
    sig_len_as_int = sig_len.value
    signature = pointer_to_proto(signature, sig_len_as_int, nptype=np.uint8)

    return signature, sig_len_as_int


def convert_to_sequencefiles(cpp_encrypted_data):
    # Get all data files outputted by C++
    partition_pattern = os.path.join(cpp_encrypted_data, "data/cpp-part*")
    partition_files = glob.glob(partition_pattern)

    # Convert each partition to SequenceFile format
    for partition_file in partition_files:
        # FIXME: should we stream this so we dont load entire 1 GB into memory?
        with open(partition_file, "rb") as partition:
            partition_data = partition.read()

        # FIXME: better way of generating new file name
        # This way has the limitation of original path cannot contain `cpp-`
        output_partition_file = partition_file.replace("cpp-", "")
        sequence_file_writer = SequenceFile.createWriter(
            output_partition_file, IntWritable, BytesWritable
        )

        key = IntWritable()
        value = BytesWritable()

        key.set(0)
        value.set(partition_data)

        sequence_file_writer.append(key, value)
        sequence_file_writer.close()

        # Remove temporary file generated by C++
        os.remove(partition_file)


def convert_from_sequencefiles(encrypted_data):
    partition_pattern = os.path.join(encrypted_data, "data/part-*")
    partition_files = glob.glob(partition_pattern)

    output_partition_files = []

    # Convert each partition from SequenceFile format to bytes
    for partition_file in partition_files:
        # Example taken from
        # https://github.com/matteobertozzi/Hadoop/blob/master/python-hadoop/examples/SequenceFileReader.py
        sequence_file_reader = SequenceFile.Reader(partition_file)
        key_class = sequence_file_reader.getKeyClass()
        value_class = sequence_file_reader.getValueClass()

        key = key_class()
        value = value_class()

        # FIXME: better way of generating intermediate file name
        output_partition_file = partition_file.replace("part-", "cpp-part-")

        # FIXME: Unclear if we need the below line
        #  position = sequence_file_reader.getPosition()
        with open(output_partition_file, "wb") as partition:
            while sequence_file_reader.next(key, value):
                partition.write(value.toBytes())
                #  position = sequence_file_reader.getPosition()

        sequence_file_reader.close()

        output_partition_files.append(output_partition_file)

    return output_partition_files


def _createSSHClient(server, port=22, user=None, password=None):
    client = SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, port, user, password)
    return client


####################
# Exposed APIs below
####################


def set_config(general_config):
    """
    Set the path to the config file. This function must be run before running anything else.

    Parameters
    ----------
    path : str
        Path to config file
    """
    _CONF["general_config"] = general_config
    config = yaml.safe_load(open(_CONF["general_config"]).read())
    _CONF["current_user"] = config["user"]["username"]

    # Set optionally included configs
    _CONF["remote_addr"] = config["cloud"].get("orchestrator")


def generate_keypair(expiration=10 * 365 * 24 * 60 * 60):
    """
    Generate a new private key and certificate and save it to path
    specified by user in config YAML passed to `set_config()`

    Parameters
    ----------
    expiration : int
        Number of seconds from now after which the generated certificate should expire
    """
    if _CONF.get("general_config") is None:
        raise MC2ClientConfigError("Configuration not set")

    user_config = yaml.safe_load(open(_CONF["general_config"]).read())["user"]

    username = user_config["username"]
    private_key_path = user_config["private_key"]
    cert_path = user_config["certificate"]
    print(cert_path)

    root_cert_path = user_config["root_certificate"]
    root_private_key_path = user_config["root_private_key"]

    if os.path.exists(private_key_path):
        print(
            "Skipping keypair generation - private key already exists at {}".format(
                private_key_path
            )
        )
        return

    if os.path.exists(cert_path):
        print(
            "Skipping keypair generation - certificate already exists at {}".format(
                cert_path
            )
        )
        return

    # Generate the key
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 3072)

    with open(private_key_path, "wb") as priv_key_file:
        priv_key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    # Generate the certificate signing request
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(root_cert_path).read())
    ca_key = crypto.load_privatekey(
        crypto.FILETYPE_PEM, open(root_private_key_path).read()
    )

    req = crypto.X509Req()
    req.get_subject().CN = username
    req.set_pubkey(key)
    req.sign(ca_key, "sha256")

    # Generate the certificate
    cert = crypto.X509()
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(expiration)  # Certificate expiration
    cert.set_issuer(ca_cert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(ca_key, "sha256")

    with open(cert_path, "wb") as cert_file:
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))


def generate_symmetric_key(num_bytes=32):
    """
    Generate a new symmetric key and save it path specified by user in config YAML passed to `set_config()`

    Parameters
    ----------
    num_bytes : int
        Number of bytes for key
    """
    if _CONF.get("general_config") is None:
        raise MC2ClientConfigError("Configuration not set")

    symmetric_key_path = yaml.safe_load(open(_CONF["general_config"]).read())["user"][
        "symmetric_key"
    ]
    if os.path.exists(symmetric_key_path):
        print(
            "Skipping symmetric key generation - key already exists at {}".format(
                symmetric_key_path
            )
        )
        return

    key = AESGCM.generate_key(bit_length=num_bytes * 8)
    with open(symmetric_key_path, "wb") as symm_key:
        symm_key.write(key)


def encrypt_data(
    plaintext_file, encrypted_file, schema_file=None, enc_format="securexgboost"
):
    """
    Encrypt a file in a certain format

    Parameters
    ----------
    plaintext_file : str
        Path to data to be encrypted
    encrypted_file : str
        Destination path of encrypted data
    schema_file : str
        Path to schema of data. Represented as comma separated column types.
        Necessary for Opaque encryption format.
    enc_format : str
        The format (i.e. Opaque or Secure XGBoost) to use for encryption
    """
    if _CONF.get("general_config") is None:
        raise MC2ClientConfigError("Configuration not set")

    if not os.path.exists(plaintext_file):
        raise FileNotFoundError(
            "Cannot find file to encrypt: {}".format(plaintext_file)
        )

    cleaned_format = "".join(enc_format.split()).lower()

    symmetric_key_path = yaml.safe_load(open(_CONF["general_config"]).read())["user"][
        "symmetric_key"
    ]

    if not os.path.exists(symmetric_key_path):
        raise CryptoError("Symmetric key not found at {}".format(symmetric_key_path))

    result = ctypes.c_int()
    if cleaned_format == "securexgboost":
        _LIB.sxgb_encrypt_data(
            c_str(plaintext_file),
            c_str(encrypted_file),
            c_str(symmetric_key_path),
            ctypes.byref(result),
        )
    elif cleaned_format == "opaque":
        _LIB.opaque_encrypt_data(
            c_str(plaintext_file),
            c_str(schema_file),
            c_str(encrypted_file),
            c_str(symmetric_key_path),
            ctypes.byref(result),
        )
        convert_to_sequencefiles(encrypted_file)
    else:
        raise CryptoError("Encryption format not currently supported")

    if result.value != 0:
        raise CryptoError("Encryption failed")


def decrypt_data(encrypted_file, plaintext_file, enc_format):
    """
    Encrypt a file in a certain format

    Parameters
    ----------
    encrypted_file : str
        Path to encrypted data to decrypt
    plaintext_file : str
        Path to decrypted data
    enc_format : str
        The encryption format (i.e. Opaque or Secure XGBoost)
    """
    if _CONF.get("general_config") is None:
        raise MC2ClientConfigError("Configuration not set")

    if not os.path.exists(encrypted_file):
        raise FileNotFoundError(
            "Cannot find file to decrypt: {}".format(encrypted_file)
        )

    cleaned_format = "".join(enc_format.split()).lower()

    symmetric_key_path = yaml.safe_load(open(_CONF["general_config"]).read())["user"][
        "symmetric_key"
    ]

    if not os.path.exists(symmetric_key_path):
        raise FileNotFoundError(
            "Symmetric key not found at {}".format(symmetric_key_path)
        )

    result = ctypes.c_int()
    if cleaned_format == "securexgboost":
        _LIB.sxgb_decrypt_data(
            c_str(encrypted_file),
            c_str(plaintext_file),
            c_str(symmetric_key_path),
            ctypes.byref(result),
        )
    elif cleaned_format == "opaque":
        # Convert from SequenceFile format to Flatbuffers bytes
        data_files = sorted(convert_from_sequencefiles(encrypted_file))

        # Decrypt serialized encrypted data
        _LIB.opaque_decrypt_data(
            from_pystr_to_cstr(data_files),
            ctypes.c_size_t(len(data_files)),
            c_str(plaintext_file),
            c_str(symmetric_key_path),
            ctypes.byref(result),
        )

        # Remove intermediate Flatbuffers bytes files
        for tmp_file in data_files:
            os.remove(tmp_file)
    else:
        raise CryptoError("Encryption format not currently supported")

    if result.value != 0:
        raise CryptoError("Decryption failed")




def upload_file(input_path, output_path):
    """
    Upload file to Azure storage

    Parameters
    ----------
    input_path : str
        Path to input file
    output_path : str
        Path to output file
    """
    cloud_config = yaml.safe_load(open(_CONF["general_config"]).read())["cloud"]
    remote_username = cloud_config.get("remote_username")

    worker_ips = cloud_config.get("nodes")

    ips = worker_ips

    for ip in ips:
        ssh = _createSSHClient(ip, 22, remote_username)
        scp = SCPClient(ssh.get_transport())
        scp.put(input_path, output_path, recursive=True)


def download_file(input_path, output_path):
    """
    Download file from Azure storage

    Parameters
    ----------
    input_path : str
        Path to input file
    output_path : str
        Path to output file
    """
    cloud_config = yaml.safe_load(open(_CONF["general_config"]).read())["cloud"]
    remote_username = cloud_config.get("remote_username")

    head_ip = cloud_config.get("orchestrator")

    if not head_ip:
        raise MC2ClientConfigError(
            "Remote orchestrator IP not set. Run oc.create_cluster() \
            to launch VMs and configure IPs automatically or explicitly set it in the user YAML."
        )

    ssh = _createSSHClient(head_ip, 22, remote_username)
    scp = SCPClient(ssh.get_transport())
    scp.get(input_path, output_path)


def attest():
    """
    Verify remote attestation report of enclave and extract its public key.
    The report and public key are saved as instance attributes.
    Parameters for attestation, e.g. whether to verify report,
    whether to check client list, whether to check MRSIGNER/MRENCLAVE, can be specified in config YAML.

    """
    pem_key = ctypes.POINTER(ctypes.c_uint8)()
    pem_key_size = ctypes.c_size_t()
    nonce = ctypes.POINTER(ctypes.c_uint8)()
    nonce_size = ctypes.c_size_t()
    client_list = ctypes.POINTER(ctypes.c_char_p)()
    client_list_size = ctypes.c_size_t()
    remote_report = ctypes.POINTER(ctypes.c_uint8)()
    remote_report_size = ctypes.c_size_t()

    channel_addr = _CONF["remote_addr"]

    if channel_addr is None:
        raise MC2ClientConfigError(
            "Remote orchestrator IP not set. Run oc.create_cluster() \
            to launch VMs and configure IPs automatically or explicitly set it in the user YAML."
        )

    with grpc.insecure_channel(channel_addr) as channel:
        stub = remote_pb2_grpc.RemoteStub(channel)
        response = stub.rpc_get_remote_report_with_pubkey_and_nonce(
            remote_pb2.Status(status=1)
        )

    pem_key = proto_to_ndarray(response.pem_key).ctypes.data_as(
        ctypes.POINTER(ctypes.c_uint8)
    )
    pem_key_size = ctypes.c_size_t(response.pem_key_size)
    nonce = proto_to_ndarray(response.nonce).ctypes.data_as(
        ctypes.POINTER(ctypes.c_uint8)
    )
    nonce_size = ctypes.c_size_t(response.nonce_size)
    client_list = from_pystr_to_cstr(list(response.client_list))
    client_list_size = ctypes.c_size_t(response.client_list_size)

    remote_report = proto_to_ndarray(response.remote_report).ctypes.data_as(
        ctypes.POINTER(ctypes.c_uint8)
    )
    remote_report_size = ctypes.c_size_t(response.remote_report_size)

    if _CONF.get("general_config") is None:
        raise MC2ClientConfigError("Configuration not set")

    # Load config to see what parameters user has specified
    attestation_config = yaml.safe_load(open(_CONF["general_config"]).read())[
        "attestation"
    ]
    simulation_mode = attestation_config.get("simulation_mode")
    check_client_list = attestation_config.get("check_client_list")

    mrenclave_hash = attestation_config.get("mrenclave")
    if mrenclave_hash and mrenclave_hash != "NULL":
        check_mrenclave = 1
        expected_mrenclave = c_str(mrenclave_hash)
        # TODO: should this be incremented?
        expected_mrenclave_len = len(mrenclave_hash) + 1
    else:
        check_mrenclave = 0
        expected_mrenclave = c_str("NULL")
        expected_mrenclave_len = 0

    mrsigner_public_key = attestation_config.get("mrsigner")
    if mrsigner_public_key and mrsigner_public_key != "NULL":
        check_mrsigner = 1
        expected_mrsigner = c_str(mrsigner_public_key)
        expected_mrsigner_len = len(mrsigner_public_key) + 1
    else:
        check_mrsigner = 0
        expected_mrsigner = c_str("NULL")
        expected_mrsigner_len = 0

    verification_passes = ctypes.c_int()

    # Verify attestation report
    if not simulation_mode:
        # Check public key, nonce, client list is in report hash
        _LIB.attest(
            pem_key,
            pem_key_size,
            nonce,
            nonce_size,
            from_pystr_to_cstr(attestation_config.get("client_list")),
            ctypes.c_size_t(len(attestation_config.get("client_list"))),
            remote_report,
            remote_report_size,
            check_mrenclave,
            expected_mrenclave,
            ctypes.c_size_t(expected_mrenclave_len),
            check_mrsigner,
            expected_mrsigner,
            ctypes.c_size_t(expected_mrsigner_len),
            ctypes.byref(verification_passes),
        )

        if not verification_passes.value:
            raise AttestationError("Remote attestation report verification failed")

    # Verify client names match
    if simulation_mode and check_client_list:
        received_client_list = sorted(from_cstr_to_pystr(client_list, client_list_size))
        expected_client_list = sorted(attestation_config.get("client_list"))
        if received_client_list != expected_client_list:
            raise AttestationError(
                "Provided client list doesn't match that received from enclave"
            )

    # Set nonce, enclave public key, respective sizes
    _CONF["enclave_pk"] = pem_key
    _CONF["enclave_pk_size"] = pem_key_size
    _CONF["nonce"] = nonce
    _CONF["nonce_size"] = nonce_size
    _CONF["nonce_ctr"] = 0

    # Add client key to enclave
    # TODO: figure out how to do this for both Secure XGBoost and Opaque
    _add_client_key()
    _get_enclave_symm_key()


def _add_client_key():
    """
    Add private (symmetric) key to enclave.
    This function encrypts the user's symmetric key using the enclave's public key,
    and signs the ciphertext with the user's private key.
    The signed message is sent to the enclave.
    """
    # Convert key to serialized numpy array
    enclave_public_key_size = _CONF["enclave_pk_size"].value
    enclave_public_key = ctypes2numpy(
        _CONF["enclave_pk"], enclave_public_key_size, np.uint8
    )
    enclave_public_key = ndarray_to_proto(enclave_public_key)

    # Convert nonce to serialized numpy array
    nonce_size = _CONF["nonce_size"].value
    nonce = ctypes2numpy(_CONF["nonce"], nonce_size, np.uint8)
    nonce = ndarray_to_proto(nonce)

    if _CONF.get("general_config") is None:
        raise MC2ClientConfigError("Configuration not set")

    user_config = yaml.safe_load(open(_CONF["general_config"]).read())["user"]

    symm_key_path = user_config["symmetric_key"]
    if not os.path.exists(symm_key_path):
        raise FileNotFoundError("Symmetric key not found at {}".format(symm_key_path))
    else:
        _CONF["symm_key"] = symm_key_path

    priv_key_path = user_config["private_key"]
    if not os.path.exists(priv_key_path):
        raise FileNotFoundError("Private key not found at {}".format(priv_key_path))
    else:
        _CONF["private_key"] = priv_key_path

    cert_path = user_config["certificate"]
    if not os.path.exists(cert_path):
        raise FileNotFoundError("Certificate not found at {}".format(cert_path))

    with open(symm_key_path, "rb") as symm_keyfile:
        user_symm_key = symm_keyfile.read()

    with open(cert_path, "rb") as cert_file:
        cert = cert_file.read()

    enc_sym_key, enc_sym_key_size = encrypt_data_with_pk(
        user_symm_key, len(user_symm_key), enclave_public_key, enclave_public_key_size
    )

    # Sign the encrypted symmetric key
    sig, sig_size = sign_data(priv_key_path, enc_sym_key, enc_sym_key_size)

    # Send the encrypted key to the enclave
    channel_addr = _CONF["remote_addr"]
    if channel_addr is None:
        raise MC2ClientConfigError(
            "Remote orchestrator IP not set. Run oc.create_cluster() \
            to launch VMs and configure IPs automatically or explicitly set it in the user YAML."
        )

    if channel_addr:
        with grpc.insecure_channel(channel_addr) as channel:
            stub = remote_pb2_grpc.RemoteStub(channel)
            stub.rpc_add_client_key_with_certificate(
                remote_pb2.DataMetadata(
                    certificate=cert,
                    enc_sym_key=enc_sym_key,
                    key_size=enc_sym_key_size,
                    signature=sig,
                    sig_len=sig_size,
                )
            )


def _get_enclave_symm_key():
    """
    Get enclave's symmetric key used to encrypt output common to all clients
    """
    user_config = yaml.safe_load(open(_CONF["general_config"]).read())["user"]
    username = user_config["username"]

    symm_key_path = user_config["symmetric_key"]
    if not os.path.exists(symm_key_path):
        raise FileNotFoundError("Symmetric key not found at {}".format(symm_key_path))

    with open(symm_key_path, "rb") as symm_keyfile:
        user_symm_key = symm_keyfile.read()

    channel_addr = _CONF["remote_addr"]

    if channel_addr is None:
        raise MC2ClientConfigError(
            "Remote orchestrator IP not set. Run oc.create_cluster() \
            to launch VMs and configure IPs automatically or explicitly set it in the user YAML."
        )

    if channel_addr:
        with grpc.insecure_channel(channel_addr) as channel:
            stub = remote_pb2_grpc.RemoteStub(channel)
            response = stub.rpc_get_enclave_symm_key(remote_pb2.Name(username=username))

            enc_key_serialized = response.key
            enc_key_size = ctypes.c_size_t(response.size)
            enc_key = proto_to_pointer(enc_key_serialized)

    # Decrypt the key and save it
    c_char_p_key = ctypes.c_char_p(user_symm_key)
    enclave_symm_key = ctypes.POINTER(ctypes.c_uint8)()

    _LIB.decrypt_enclave_key(
        c_char_p_key, enc_key, enc_key_size, ctypes.byref(enclave_symm_key)
    )
    _CONF["enclave_sym_key"] = enclave_symm_key
