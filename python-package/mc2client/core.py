import base64
import ctypes
import glob
import math
import os
import logging
import pathlib
import secrets
import shutil
import signal
import sys
import subprocess

import flatbuffers
import grpc
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hadoop.io import (  # pylint: disable=no-name-in-module
    BytesWritable,
    IntWritable,
    SequenceFile,
)
from envyaml import EnvYAML
from numproto import ndarray_to_proto, proto_to_ndarray
from OpenSSL import crypto
from paramiko import AutoAddPolicy, SSHClient, SSHException
from scp import SCPClient

from .cache import add_cache_entry, get_cache_entry, remove_cache_entry
from .exceptions import (
    AttestationError,
    CryptoError,
    MC2ClientComputeError,
    MC2ClientConfigError,
)
from .rpc import (
    attest_pb2,
    attest_pb2_grpc,
)  # pylint: disable=no-name-in-module
from .toolchain.node_provider import get_node_provider
from .toolchain.updater import with_interactive
from .toolchain.toolchain import (
    cluster,
    container,
    download,
    get_head_node_ip,
    get_worker_node_ips,
    resource_group,
    run_remote_cmds_on_cluster,
    storage,
    upload,
)
from .toolchain.flatbuffers.tuix import SignedKey

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

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

# create formatter
formatter = logging.Formatter(
    "%(asctime)s - %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S"
)

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger.addHandler(ch)

# Ensure that each logging message is only logged once
logger.propagate = False

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
    if _CONF["use_azure"]:
        head_ip = get_head_node_ip(_CONF["azure_config"])
    else:
        head_ip = _CONF["head"]

    if head_ip:
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
        raise RuntimeError(
            "Supported types: {}".format(NUMPY_TO_CTYPES_MAPPING.keys())
        )
    ctype = NUMPY_TO_CTYPES_MAPPING[dtype]
    if not isinstance(cptr, ctypes.POINTER(ctype)):
        raise RuntimeError(
            "expected {} pointer, got {}".format(ctype, type(cptr))
        )
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
        raise RuntimeError(
            "Supported types: {}".format(NUMPY_TO_CTYPES_MAPPING.keys())
        )
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


def encrypt_data_with_sym_key(data, sym_key):
    """
    Parameters
    ----------
    data : bytes
    sym_key : bytes

    Returns
    -------
    encrypted_data : bytes
    """
    # Allocate memory that will be used to store the encrypted data
    encrypted_data_size = _LIB.sym_enc_size(len(data))
    encrypted_data = bytes(encrypted_data_size)

    # Encrypt the data with sym_key
    _LIB.sym_enc(
        ctypes.c_char_p(data),
        ctypes.c_size_t(len(data)),
        ctypes.c_char_p(sym_key),
        ctypes.c_size_t(len(sym_key)),
        ctypes.cast(encrypted_data, ctypes.POINTER(ctypes.c_uint8)),
    )
    return encrypted_data


def encrypt_data_with_pk(data, pem_key):
    """
    Parameters
    ----------
    data : bytes
    pem_key : bytes

    Returns
    -------
    encrypted_data : bytes
    """

    # Allocate memory that will be used to store the encrypted data
    encrypted_data_size = _LIB.asym_enc_size(len(data))
    encrypted_data = bytes(encrypted_data_size)

    # Encrypt the data with pk pem_key
    _LIB.asym_enc(
        ctypes.c_char_p(data),
        ctypes.c_size_t(len(data)),
        ctypes.cast(pem_key, ctypes.POINTER(ctypes.c_uint8)),
        ctypes.c_size_t(len(pem_key)),
        ctypes.cast(encrypted_data, ctypes.POINTER(ctypes.c_uint8)),
    )
    return encrypted_data


def sign_data(keyfile, data):
    """
    Parameters
    ----------
    keyfile : str
    data : bytes

    Returns
    -------
    signature : bytes
    """
    # Allocate memory to store the signature
    sig_len = _LIB.asym_sign_size()
    signature = bytes(sig_len)

    # Sign data with key keyfile
    _LIB.sign_using_keyfile(
        ctypes.c_char_p(str.encode(keyfile)),
        ctypes.cast(data, ctypes.POINTER(ctypes.c_uint8)),
        ctypes.c_size_t(len(data)),
        ctypes.cast(signature, ctypes.POINTER(ctypes.c_uint8)),
    )
    return signature


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
        has_next = sequence_file_reader.next(key, value)
        if has_next:
            with open(output_partition_file, "wb") as partition:
                while has_next:
                    partition.write(value.toBytes())
                    has_next = sequence_file_reader.next(key, value)
                    #  position = sequence_file_reader.getPosition()

            output_partition_files.append(output_partition_file)

        sequence_file_reader.close()

    return output_partition_files


def _createSSHClient(server, port=22, user=None, key_file=None):
    client = SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, port, user, key_file)
    return client


def _get_azure_ips():
    _CONF["head"]["ip"] = get_head_ip()
    for (worker, ip) in zip(_CONF["workers"], get_worker_ips()):
        worker["ip"] = ip


####################
# Exposed APIs below
####################


def set_config(general_config=None):
    """
    Set the path to the config file. This function must be run before running anything else.

    Parameters
    ----------
    path : str
        Path to config file

    Returns
    -------
    general_config : str
        The path to the config file. This return value is useful when we're calling `set_config()` without a parameter -- it enables the caller the retrieve the cached config_path
    """
    # If we're specifically configuring the config path
    if general_config is not None:
        add_cache_entry("config", general_config)
    else:
        general_config = get_cache_entry("config")

    if general_config is None:
        raise Exception("Please configure the path to your MC2 config")

    _CONF["general_config"] = general_config
    config = EnvYAML(_CONF["general_config"])
    _CONF["current_user"] = config["user"]["username"]

    # Networking configs
    manual_head_node = config["launch"].get("head")
    manual_worker_nodes = config["launch"].get("workers") or []
    _CONF["azure_config"] = config["launch"].get("azure_config")
    _CONF["use_azure"] = not (manual_head_node or manual_worker_nodes)

    # SSH information
    if _CONF["use_azure"]:
        azure_config = EnvYAML(_CONF["azure_config"], strict=False)
        remote_username = azure_config["auth"]["ssh_user"]
        ssh_key = azure_config["auth"]["ssh_private_key"]
        # Since `set_config` may be called before Azure VMs may have been
        # launched, we can't initialize the IPs of the nodes. This value will
        # be set later once we can guarantee the nodes are launched
        _CONF["head"] = {
            "username": remote_username,
            "ssh_key": ssh_key,
            "identity": "head node",
        }
        _CONF["workers"] = [
            {
                "username": remote_username,
                "ssh_key": ssh_key,
                "identity": "worker node",
            }
            for _ in range(azure_config["num_workers"])
        ]
    else:
        _CONF["head"] = manual_head_node
        _CONF["workers"] = manual_worker_nodes

    return general_config


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

    user_config = EnvYAML(_CONF["general_config"])["user"]

    username = user_config["username"]
    private_key_path = user_config["private_key"]
    public_key_path = user_config["public_key"]
    cert_path = user_config["certificate"]

    root_cert_path = user_config["root_certificate"]
    root_private_key_path = user_config["root_private_key"]

    if os.path.exists(private_key_path):
        logger.warning(
            "Skipping keypair generation - private key already exists at {}".format(
                private_key_path
            )
        )
        return

    if os.path.exists(public_key_path):
        logger.warning(
            "Skipping keypair generation - public key already exists at {}".format(
                public_key_path
            )
        )
        return

    if os.path.exists(cert_path):
        logger.warning(
            "Skipping keypair generation - certificate already exists at {}".format(
                cert_path
            )
        )
        return

    # Generate the key
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, _LIB.rsa_mod_size() * 8)

    with open(private_key_path, "wb") as priv_key_file:
        priv_key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    logger.info(
        "Generated private key and outputted to {}".format(private_key_path)
    )

    with open(public_key_path, "wb") as public_key_file:
        public_key_file.write(crypto.dump_publickey(crypto.FILETYPE_PEM, key))

    logger.info(
        "Generated public key and outputted to {}".format(public_key_path)
    )

    # Generate the certificate signing request
    ca_cert = crypto.load_certificate(
        crypto.FILETYPE_PEM, open(root_cert_path).read()
    )
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

    logger.info("Generated certificate and outputted to {}".format(cert_path))


def generate_symmetric_key():
    """
    Generate a new symmetric key and save it path specified by user in config YAML passed to `set_config()`

    Parameters
    ----------
    num_bytes : int
        Number of bytes for key
    """
    num_bytes = _LIB.cipher_key_size()

    if _CONF.get("general_config") is None:
        raise MC2ClientConfigError("Configuration not set")

    symmetric_key_path = EnvYAML(_CONF["general_config"])["user"][
        "symmetric_key"
    ]
    if os.path.exists(symmetric_key_path):
        logger.warning(
            "Skipping symmetric key generation - key already exists at {}".format(
                symmetric_key_path
            )
        )
        return

    key = AESGCM.generate_key(bit_length=num_bytes * 8)
    with open(symmetric_key_path, "wb") as symm_key:
        symm_key.write(key)

    logger.info(
        "Generated symmetric key and outputted to {}".format(
            symmetric_key_path
        )
    )


def clear_cache():
    """
    Clears all data located in the MC² cache
    """
    # Clear attestation data
    remove_cache_entry("attested_nodes")
    remove_cache_entry("public_keys")


def encrypt_data(
    plaintext_file, encrypted_file, schema_file=None, enc_format="xgb"
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
        Necessary for Opaque SQL encryption format.
    enc_format : str
        The format to use for encryption
        Input `sql` if running Opaque SQL or `xgb` if running Secure XGBoost
    """
    if _CONF.get("general_config") is None:
        raise MC2ClientConfigError("Configuration not set")

    if not os.path.exists(plaintext_file):
        raise FileNotFoundError(
            "Cannot find file to encrypt: {}".format(plaintext_file)
        )

    cleaned_format = "".join(enc_format.split()).lower()

    symmetric_key_path = EnvYAML(_CONF["general_config"])["user"][
        "symmetric_key"
    ]

    if not os.path.exists(plaintext_file):
        raise CryptoError(
            "File to encrypt not found at {}".format(plaintext_file)
        )

    if not os.path.exists(symmetric_key_path):
        raise CryptoError(
            "Symmetric key not found at {}".format(symmetric_key_path)
        )

    result = ctypes.c_int()
    if cleaned_format == "xgb":
        _LIB.sxgb_encrypt_data(
            c_str(plaintext_file),
            c_str(encrypted_file),
            c_str(symmetric_key_path),
            ctypes.byref(result),
        )
        logger.info(
            "Encrypted {} in xgb format and outputted to {}".format(
                plaintext_file, encrypted_file
            )
        )
    elif cleaned_format == "sql":
        if not os.path.exists(schema_file):
            raise CryptoError("Schema not found at {}".format(schema_file))

        _LIB.opaque_encrypt_data(
            c_str(plaintext_file),
            c_str(schema_file),
            c_str(encrypted_file),
            c_str(symmetric_key_path),
            ctypes.byref(result),
        )
        convert_to_sequencefiles(encrypted_file)
        logger.info(
            "Encrypted {} in sql format and outputted to {}".format(
                plaintext_file, encrypted_file
            )
        )
    else:
        raise CryptoError("Encryption format not currently supported")

    if result.value != 0:
        raise CryptoError("Encryption failed")


def decrypt_data(encrypted_file, plaintext_file, enc_format):
    """
    Decrypt a file in a certain format

    Parameters
    ----------
    encrypted_file : str
        Path to encrypted data to decrypt
    plaintext_file : str
        Path to decrypted data
    enc_format : str
        The encryption format (i.e. `sql` for Opaque SQL or `xgb` for Secure XGBoost)
    """
    if _CONF.get("general_config") is None:
        raise MC2ClientConfigError("Configuration not set")

    if not os.path.exists(encrypted_file):
        raise FileNotFoundError(
            "Cannot find file to decrypt: {}".format(encrypted_file)
        )

    cleaned_format = "".join(enc_format.split()).lower()

    symmetric_key_path = EnvYAML(_CONF["general_config"])["user"][
        "symmetric_key"
    ]

    if not os.path.exists(symmetric_key_path):
        raise FileNotFoundError(
            "Symmetric key not found at {}".format(symmetric_key_path)
        )

    result = ctypes.c_int()
    if cleaned_format == "xgb":
        _LIB.sxgb_decrypt_data(
            c_str(encrypted_file),
            c_str(plaintext_file),
            c_str(symmetric_key_path),
            ctypes.byref(result),
        )
        logger.info(
            "Decrypted {} in xgb format and outputted to {}".format(
                encrypted_file, plaintext_file
            )
        )
    elif cleaned_format == "sql":
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
        logger.info(
            "Decrypted {} in sql format and outputted to {}".format(
                encrypted_file, plaintext_file
            )
        )
    else:
        raise CryptoError("Encryption format not currently supported")

    if result.value != 0:
        raise CryptoError("Decryption failed")


def create_storage():
    """
    Create storage from configuration file
    """
    if _CONF.get("azure_config") is None:
        raise MC2ClientConfigError("Azure configuration not set")

    storage(_CONF["azure_config"], create=True)


def delete_storage():
    """
    Delete storage from configuration file
    """
    if _CONF.get("azure_config") is None:
        raise MC2ClientConfigError("Azure configuration not set")

    storage(_CONF["azure_config"], create=False)


def create_container():
    """
    Create container in storage from configuration file
    """
    if _CONF.get("azure_config") is None:
        raise MC2ClientConfigError("Azure configuration not set")

    container(_CONF["azure_config"], create=True)


def delete_container():
    """
    Delete container in storage from configuration file
    """
    if _CONF.get("azure_config") is None:
        raise MC2ClientConfigError("Azure configuration not set")

    container(_CONF["azure_config"], create=False)


def upload_file(input_path, output_path, use_azure=True):
    """
    Upload file to Azure storage or disk of all cluster VMs

    Parameters
    ----------
    input_path : str
        Path to input file
    output_path : str
        Path to output file
    """
    # Make sure all of the node information is up to date
    if _CONF["use_azure"]:
        _get_azure_ips()

    if not _CONF["use_azure"] and use_azure:
        raise MC2ClientConfigError(
            "Attempted to use Azure storage with"
            "node addresses manually configured"
        )

    if _CONF["use_azure"] and _CONF.get("azure_config") is None:
        raise MC2ClientConfigError("Azure configuration not set")

    if use_azure:
        logger.info("Uploading {} to Azure blob storage".format(input_path))
        upload(_CONF["azure_config"], input_path, output_path)
    else:
        nodes = [_CONF["head"]] + _CONF["workers"]
        for node in nodes:
            if node["ip"] == "0.0.0.0" or node["ip"] == "127.0.0.1":
                # Overwrite the destination path
                if os.path.exists(output_path):
                    if os.path.isdir(output_path):
                        shutil.rmtree(output_path)
                    else:
                        os.remove(output_path)

                # We're using a local deployment
                logger.info(
                    "Using local deployment. Copying {} to {}".format(
                        input_path, output_path
                    )
                )
                if os.path.isdir(input_path):
                    shutil.copytree(input_path, output_path)
                else:
                    shutil.copy2(input_path, output_path)
            else:
                # Use scp
                logger.info(
                    "Uploading {} to disk of {}".format(
                        input_path, node.get("identity", node["ip"])
                    )
                )
                ssh = _createSSHClient(
                    node["ip"], 22, node["username"], node["ssh_key"]
                )
                scp = SCPClient(ssh.get_transport())
                scp.put(input_path, output_path, recursive=True)
                ssh.close()


def download_file(input_path, output_path, use_azure=True):
    """
    Download file from Azure storage or head node disk

    Parameters
    ----------
    input_path : str
        Path to input file
    output_path : str
        Path to output file
    """
    # Make sure all of the node information is up to date
    if _CONF["use_azure"]:
        _get_azure_ips()

    if not _CONF["use_azure"] and use_azure:
        raise MC2ClientConfigError(
            "Attempted to use Azure storage with"
            "node addresses manually configured"
        )

    if _CONF["use_azure"] and _CONF.get("azure_config") is None:
        raise MC2ClientConfigError("Azure configuration not set")

    if use_azure:
        logger.info(
            "Downloading {} from Azure blob storage".format(input_path)
        )
        download(_CONF["azure_config"], input_path, output_path)
    else:  # use scp
        head = _CONF["head"]
        if head["ip"] == "0.0.0.0" or head["ip"] == "127.0.0.1":
            logger.info(
                "Using local deployment. Copying data from {}".format(
                    input_path
                )
            )
            if os.path.isdir(input_path):
                shutil.copytree(input_path, output_path)
            else:
                shutil.copy2(input_path, output_path)
        else:
            logger.info(
                "Downloading {} from disk of {}".format(
                    input_path, head.get("identity", head["ip"])
                )
            )
            ssh = _createSSHClient(
                head["ip"], 22, head["username"], head["ssh_key"]
            )
            scp = SCPClient(ssh.get_transport())
            scp.get(input_path, output_path, recursive=True)


def create_cluster():
    """
    Create a cluster
    """
    if _CONF.get("azure_config") is None:
        raise MC2ClientConfigError("Azure configuration not set")

    cluster(_CONF["azure_config"], create=True)


def delete_cluster():
    """
    Delete a cluster
    """
    if _CONF.get("azure_config") is None:
        raise MC2ClientConfigError("Azure configuration not set")

    cluster(_CONF["azure_config"], create=False)


def create_resource_group():
    """
    Create a resource group
    """
    if _CONF.get("azure_config") is None:
        raise MC2ClientConfigError("Azure configuration not set")

    resource_group(_CONF["azure_config"], create=True)


def delete_resource_group():
    """
    Delete a resource group
    """
    if _CONF.get("azure_config") is None:
        raise MC2ClientConfigError("Azure configuration not set")

    resource_group(_CONF["azure_config"], create=False)


def get_head_ip():
    """
    Get IP address of head node of created cluster
    """
    return get_head_node_ip(_CONF["azure_config"])


def get_worker_ips():
    """
    Get IP addresses of all worker nodes in created cluster
    """
    return get_worker_node_ips(_CONF["azure_config"])


def run_remote_cmds(head_cmds, worker_cmds):
    """
    Remotely run commands on head and worker nodes

    Parameters
    ----------
    head_cmds : list
        List of commands to run on the head node
    worker_cmds : list
        List of commands to run on the worker nodes
    """
    # Make sure all of the node information is up to date
    if _CONF["use_azure"]:
        _get_azure_ips()

    commands = [(_CONF["head"], head_cmds)] + [
        (worker, worker_cmds) for worker in _CONF["workers"]
    ]

    # Get the list of remote processes from the cache
    running_processes = get_cache_entry("processes") or dict()

    for (i, (node, cmds)) in enumerate(commands):
        if (node["ip"] == "0.0.0.0") or (node["ip"] == "127.0.0.1"):
            # We're using a local deployment.
            #
            # Launch the commands in a local shell subprocess. All
            # output from these commands is ignored.
            for cmd in cmds:
                # The `preexec_fn` argument ensures that the spawned
                # shell is a group leader, and thus sending a signal to
                # it will also send a signal to any subprocesses that it
                # spawns
                ps = subprocess.Popen(
                    cmd,
                    shell=True,
                    preexec_fn=os.setsid,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                logger.info(f"Running '{cmd}' locally")

                # Append the shell PID to the list associated with the node IP
                running_processes.setdefault(node["ip"], []).append(
                    (cmd, ps.pid)
                )
        else:
            # We're using a remote deployment - SSH into the node
            try:
                ssh = _createSSHClient(
                    node["ip"], 22, node["username"], node["ssh_key"]
                )
            except SSHException as e:
                raise Exception(
                    "Failed to SSH into {}: {}".format(
                        node.get("identity", node["ip"]), e
                    )
                ) from None

            # Launch the commands in a remote shell subprocess. All
            # output from these commands is ignored.
            for cmd in cmds:
                # TODO: Spawn a background process to log the
                #       stdout/stderr of the process to a file
                #
                # By default, the SSH client uses a non-login,
                # non-interactive shell and will not source any shell
                # configuration files. To combat this, we wrap all of our
                # commands in the `with_interactive` function to force an
                # interactive shell.
                #
                # We obtain the PID of the spawned shell via `echo $$` and
                # run the specified command in a background subshell so that
                # `start` doesn't block on the command finishing.  Note that
                # the SID (session ID) of all process spawned in the subshell
                # will be equal to the PID we obtained via `echo $$` - we will
                # use this to later terminate the process.
                shell_cmd = " ".join(
                    with_interactive("echo $$; {{ {}; }} &".format(cmd))
                )
                (_, stdout, stderr) = ssh.exec_command(shell_cmd, get_pty=True)

                # If the command is valid, then the first line of output
                # with be the PID. Otherwise an error has occured
                try:
                    output = stdout.readline()
                    pid = int(output.rstrip())
                except ValueError:
                    out = output + " ".join(stdout.readlines())
                    err = " ".join(stderr.readlines())
                    node_string = node.get("identity", node["ip"])
                    raise Exception(
                        f"Running '{cmd}' remotely on {node_string} "
                        + "failed with errors:\n"
                        + f"\nSTDOUT:\n{out}"
                        + f"\nSTDERR:\n{err}"
                    ) from None

                logger.info(
                    "Running '{}' remotely on {}".format(
                        cmd, node.get("identity", node["ip"])
                    )
                )
                # Append the shell PID to the list associated with the node IP
                running_processes.setdefault(node["ip"], []).append((cmd, pid))
            ssh.close()

    # Cache the lists of running processes
    add_cache_entry("processes", running_processes)


def stop_remote_cmds():
    """
    Stop commands running on head and worker nodes
    """
    # Make sure all of the node information is up to date
    if _CONF["use_azure"]:
        _get_azure_ips()

    # Get the list of remote processes from the cache
    running_processes = get_cache_entry("processes") or dict()

    # Send the SIGTERM signal to all processes spawned via run()
    for (ip, processes) in running_processes.items():
        # We're using a local deployment
        if (ip == "0.0.0.0") or (ip == "127.0.0.1"):
            for (cmd, pid) in processes:
                try:
                    # Send the signal to the group associated with the
                    # spawned shell subprocess
                    os.killpg(os.getpgid(pid), signal.SIGTERM)
                    logger.info(f"Stopping '{cmd}' locally")
                except ProcessLookupError:
                    logger.warning(f"Command '{cmd}' already stopped")
        else:
            # Get the node information corresponding to the cached IP
            nodes = [_CONF["head"]] + _CONF["workers"]
            node = [node for node in nodes if node["ip"] == ip]

            # Make sure there's a single YAML entry for the cached IP
            if not node or len(node) > 1:
                logging.warning(
                    "Invalid network configuration for {}.  Skipping...".format(
                        node.get("identity", node["ip"])
                    )
                )
                pass
            else:
                node = node[0]

            # SSH to the node
            ssh = _createSSHClient(
                node["ip"], 22, node["username"], node["ssh_key"]
            )
            for (cmd, pid) in processes:
                # This command sends the SIGTERM signal to all processes
                # whose SID matches the provided PID
                ssh.exec_command(f"ps -o pid -g {pid} | sed '1d' | xargs kill")
                logger.info(
                    "Stopping '{}' remotely on {}".format(
                        cmd, node.get("identity", node["ip"])
                    )
                )

            ssh.close()

        # Clear the cache entries
        remove_cache_entry("processes")


def configure_job(config):
    """
    Attest all of the worker enclaves and give them the shared symmetric key.
    """
    # Make sure all of the node information is up to date
    if _CONF["use_azure"]:
        _get_azure_ips()

    user_config = config["user"]
    attestation_config = config["run"]["attestation"]

    # Get the address of the head node's attestation gRPC listener
    head_address = _CONF["head"]["ip"] + ":50051"

    # If we are not in simulation mode, get the enclave signing key
    simulation_mode = attestation_config.get("simulation_mode")
    if not simulation_mode:
        mrsigner_path = attestation_config["mrsigner"]
        if not os.path.exists(mrsigner_path):
            raise FileNotFoundError(
                "Enclave signing key not found at:", mrsigner_path
            )
        else:
            enclave_signer_pem = open(mrsigner_path).read()
    else:
        enclave_signer_pem = ""

    # Attest the enclaves and obtain their public keys
    _attest(head_address, simulation_mode, enclave_signer_pem)

    # Get the user's symmetric key
    symm_key_path = user_config["symmetric_key"]
    if not os.path.exists(symm_key_path):
        raise FileNotFoundError(
            "Symmetric key not found at {}".format(symm_key_path)
        )
    else:
        user_symm_key = open(symm_key_path, "rb").read()

    # Get the user's private keyfile path
    priv_key_path = user_config["private_key"]
    if not os.path.exists(priv_key_path):
        raise FileNotFoundError(
            "Private key not found at {}".format(priv_key_path)
        )

    # Sign the client's symmetric key
    sig = sign_data(priv_key_path, user_symm_key)

    # Construct and encrypt the `SignedKey` flatbuffers object
    key_bytes = _construct_signed_key_fb(
        user_symm_key,
        sig,
    )

    # For each enclave public key, encrypt a signedkey object
    enc_keys = []
    for pk in _CONF["enclave_pks"]:
        enc_keys.append(encrypt_data_with_pk(key_bytes, pk))

    # Return encrypted keys to the head node
    logger.info("Sending client key to enclave")
    with grpc.insecure_channel(head_address) as channel:
        stub = attest_pb2_grpc.ClientToEnclaveStub(channel)
        stub.GetFinalAttestationResult(attest_pb2.EncryptedKeys(keys=enc_keys))


def _attest(head_address, simulation_mode, mrsigner):
    """
    Verify remote attestation report of enclaves and extract their public keys.
    The public keys are saved as instance attributes. Parameters for
    attestation, e.g. whether to verify report, whether to check
    MRSIGNER/MRENCLAVE, can be specified in config YAML.
    """
    node_ips = [node["ip"] for node in _CONF["workers"]]

    # Begin to attest compute service enclaves
    with grpc.insecure_channel(head_address) as channel:
        stub = attest_pb2_grpc.ClientToEnclaveStub(channel)
        response = stub.GetRemoteEvidence(
            attest_pb2.AttestationStatus(status=0)
        )

    # Extract evidence list from response
    evidence_list = response.evidences

    # Extract public keys from the evidence
    pk_list = []
    pk_size = _LIB.cipher_pk_size()
    for msg in evidence_list:
        # Allocate memory for enclave public key
        pk_bytes = bytes(pk_size)
        _LIB.get_public_key(
            ctypes.cast(msg, ctypes.POINTER(ctypes.c_uint8)),
            ctypes.cast(pk_bytes, ctypes.POINTER(ctypes.c_uint8)),
        )
        pk_list.append(pk_bytes)

    # Verify attestation report
    if not simulation_mode:
        for msg in evidence_list:
            if _LIB.attest_evidence(
                ctypes.c_char_p(mrsigner.encode("utf-8")),
                ctypes.c_size_t(len(mrsigner) + 1),
                ctypes.cast(msg, ctypes.POINTER(ctypes.c_uint8)),
                ctypes.c_size_t(len(msg)),
            ):
                raise AttestationError(
                    "Remote attestation report verification failed"
                )

    # Set enclave public keys in the config
    _CONF["enclave_pks"] = pk_list

    # Cache the attestation information
    add_cache_entry("attested_nodes", node_ips)
    add_cache_entry(
        "public_keys",
        [base64.b64encode(pk).decode("ascii") for pk in pk_list],
    )


def _construct_signed_key_fb(sym_key, sig):
    """
    Constructs the `SignedKey` flatbuffers object, and outputs it's byte
    representation

    Parameters
    ----------
    sym_key : bytes
        The client symmetric key
    sig : bytes
        Signature over `sym_key`

    Returns:
        root : bytearray
    """
    builder = flatbuffers.Builder(200)

    # Serialize vectors
    fb_sym_key = builder.CreateByteVector(sym_key)
    fb_sig = builder.CreateByteVector(sig)

    # Construct the `SignedKey` object
    SignedKey.SignedKeyStart(builder)
    SignedKey.SignedKeyAddKey(builder, fb_sym_key)
    SignedKey.SignedKeyAddSig(builder, fb_sig)
    signed_key = SignedKey.SignedKeyEnd(builder)
    builder.Finish(signed_key)

    # Output the resulting bytes
    return bytes(builder.Output())
