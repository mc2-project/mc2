Global Configuration
====================

Before using MC\ :sup:`2` Client, you'll need to perform some configuration by specifying parameters in a YAML file. An example YAML file can be found at ``demo/mc2.yaml``. We describe the various parameters below.

User Configuration
------------------
We'll need to perform some configuration for the user in the ``user`` section of the YAML file. Parameters are:

- ``username`` : your username. This username will be used for certificate generation and authentication purposes.

- ``symmetric_key`` : path to your symmetric key. If you don't yet have a symmetric key, you can ask MC\ :sup:`2` Client to generate a key for you (see :ref:`Generating Keys`). MC\ :sup:`2` Client will look to this path for your key when encrypting and decrypting your data.

- ``private_key`` : path to your private key. If you don't yet have a private key, you can ask MC\ :sup:`2` Client to generate a private key/certificate for you (see :ref:`Generating Keys`). MC\ :sup:`2` Client will use your private key to sign messages sent to the cloud.

- ``certificate`` : path to your certificate. if you don't yet have a certificate, you can ask MC\ :sup:`2` Client to generate a certificate/private key for you (see :ref:`Generating Keys`). MC\ :sup:`2` Client will use your certificate to authenticate you to the cloud.

- ``root_private_key`` : path to the Certificate Authority's private key. MC\ :sup:`2` Client uses the CA's private key to generate a certificate for you. The MC\ :sup:`2` compute service should also be aware of the CA private key.

- ``root_certificate`` : path to the Certificate Authority's certificate. MC\ :sup:`2` Client uses the CA's certificate to generate a certificate for you. The MC\ :sup:`2` compute service should also be aware of the CA certificate.

Cloud
-----
You'll need to configure some parameters for the cloud.

- ``remote_username`` : the username to be used when transferring data over ``scp``.
- ``orchestrator`` : the IP address of the compute orchestrator. MC\ :sup:`2` Client will send attestation requests to this IP address.
- ``nodes`` : the IP addresses of the cluster workers.
- ``data_dir`` : the directory to transfer data to.
- ``results`` : a list of paths, each of which is a result outputted during computation.


Local
-----
You'll also need to configure some parameters to tell MC\ :sup:`2` Client about what to run.

- ``data`` : a list of data files that will be used during computation. MC\ :sup:`2` Client will encrypt and upload this data.
- ``schemas`` : a list of files, each detailing the schema of the respective data file listed in ``data``. Note that schema ``i`` should reflect the schema of data file ``i`` above. The schemas are only needed if you're running Opaque SQL.
- ``script`` : a Python (if running Secure XGBoost) or Scala (if running Opaque SQL) script detailing your computation. MC\ :sup:`2` Client will run this code.
- ``results`` : a directory to download results. Once computation has finished, MC\ :sup:`2` Client will retrieve the results specified in ``cloud --> results`` in the :ref:`Cloud` section above and download them to this directory.


Attestation
-----------
Likewise, we'll need to perform some configuration for the ``attestation`` section of the YAML file. In particular, we'll need to specify what we want to check during attestation, and which clients should be allowed to use the same MC\ :sup:`2` compute service cluster.

- ``simulation_mode`` : this value should be either ``0`` or ``1``.

    ``0`` means false, or that we're not running in simulation mode, and that consequently we should verify the attestation report sent back to the client by the MC\ :sup:`2` compute service. 

    ``1`` means true, or that we're running in simulation mode, and to not check the attestation report. This should only be done for development purposes, as not attesting makes the MC\ :sup:`2` compute services insecure.

- ``mrenclave`` : the ``MRENCLAVE`` value of the enclave, or the hash of the enclave log logging every step of the enclave build and initialization process. Setting this to ``NULL`` will result in MC\ :sup:`2` Client not checking this value. However, doing this is insecure and should not be done in production environments. You can retrieve the ``MRENCLAVE`` value from MC\ :sup:`2` Systems for each compute service.

- ``mrsigner`` : the ``MRSIGNER`` value of the enclave, or the key of the authority that signed the enclaves' certificates. Setting this to ``NULL`` will result in MC\ :sup:`2` Client not checking this value. However, this is insecure and should not be done in production environments.

- ``check_client_list`` : this value should be either ``0`` or ``1``.

    If ``1``, MC\ :sup:`2` Client checks that a list of clients sent back to it during attestation by the MC\ :sup:`2` compute service is the correct list, i.e. the expected list of clients. This is particularly relevant in a collaboration, when multiple parties may be using the same compute cluster. You can list out the expected list of clients in the parameter ``client_list``.

    If ``0``, MC\ :sup:`2` Client will not check that the clients sent back to it during attestation by the MC\ :sup:`2` compute services are the expected clients.

- ``client_list`` : a list of client usernames with whom you've agreed to collaborate.

