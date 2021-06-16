Global Configuration
====================
.. _conf:

Before using MC\ :sup:`2` Client, you'll need to perform some configuration by specifying parameters in a YAML file. An example YAML file can be found `here <https://github.com/mc2-project/mc2/blob/master/demo/config.yaml>`_, and has also been copied at the bottom of this page. We describe the various parameters below.

User Configuration
------------------
We'll need to perform some configuration for the user in the ``user`` section of the YAML file. Parameters are:

- ``username`` : your username. This username will be used for certificate generation and authentication purposes.

- ``symmetric_key`` : path to your symmetric key. If you don't yet have a symmetric key, you can ask MC\ :sup:`2` Client to generate a key for you (see :ref:`Generating Keys`). MC\ :sup:`2` Client will look to this path for your key when encrypting and decrypting your data.

- ``private_key`` : path to your private key. If you don't yet have a private key, you can ask MC\ :sup:`2` Client to generate a private key/certificate for you (see :ref:`Generating Keys`). MC\ :sup:`2` Client will use your private key to sign messages sent to the cloud.

- ``certificate`` : path to your certificate. if you don't yet have a certificate, you can ask MC\ :sup:`2` Client to generate a certificate/private key for you (see :ref:`Generating Keys`). MC\ :sup:`2` Client will use your certificate to authenticate you to the cloud.

- ``root_private_key`` : path to the Certificate Authority's private key. MC\ :sup:`2` Client uses the CA's private key to generate a certificate for you. The MC\ :sup:`2` compute service should also be aware of the CA private key.

- ``root_certificate`` : path to the Certificate Authority's certificate. MC\ :sup:`2` Client uses the CA's certificate to generate a certificate for you. The MC\ :sup:`2` compute service should also be aware of the CA certificate.

Launch
------
Configuration for launching Azure resources. Parameters are:

- ``azure_config`` : the absolute path to your Azure configuration YAML. More on Azure configuration can be found :doc:`here <azure>`.

- ``head``: manually specify the IP address (``ip``), username (``username``), and absolute path to the SSH key (``ssh_key``) of the head node. If the node is being run locally, only the ``ip`` field needs to be populated.

.. note::
	This parameter is **optional** and will override ``azure_config`` - if specified, the user is in charge of launching and stopping their own machines. If left blank, Opaque Client will default to using Azure. **This parameter is for testing/development and should not be used in production.**

- ``workers``: manually specify a list of IP addresses (``ip``), usernames (``username``), and absolute paths to SSH keys (``ssh_key``) corresponding to the worker nodes. If the nodes are being run locally, only the ``ip`` field needs to be populated.  This field will override ``azure_config``. **This parameter is for testing/developement and should not be used in production.**

.. note::
	This parameter is **optional** and will override ``azure_config`` - if specified, the user is in charge of launching and stopping their own machines. If left blank, Opaque Client will default to using Azure. **This parameter is for testing/development and should not be used in production.**

- ``cluster`` : a boolean (``true`` or ``false``) - whether to launch a cluster of VMs

- ``storage`` : a boolean (``true`` or ``false``) - whether to launch a new Azure blob storage account

- ``container`` : a boolean (``true`` or ``false``) - whether to launch a storage container


Start
-----
In this section, you can specify what commands you want to run to start the compute services. Commands will run on the Azure VM cluster that you launch. You can specify different commands for the head node and the worker nodes.

- ``head`` : a list of commands to run on the cluster's head node

- ``workers`` : a list of commands to run on the workers nodes

Upload
------
In this section, you can specify what data you want to encrypt and upload, how you want to upload the data, and what encryption format you want to use.

- ``storage`` : options are ``blob`` or ``disk``. If ``blob``, MC\ :sup:`2` Client will upload your data to the Azure storage container you create. If ``disk``, MC\ :sup:`2` Client will ``scp`` your data to each launched VM.

- ``format`` : options are ``xgb`` and ``sql``. If ``xgb``, MC\ :sup:`2` Client will encrypt your data in a format compatible with Secure XGBoost. If ``sql``, MC\ :sup:`2` Client will encrypt your data in a format compatible with Opaque SQL.

- ``src`` : a list of files to encrypt and upload

- ``schemas`` : a list of schemas, one for each file you want to encrypt. This field is required if encrypting in ``sql`` format, and not required otherwise. More detail on the format used to specify the schema is :ref:`here <sqlformat>`.

- ``dst`` : the directory to upload the data to. For now, this should be ignored if using Azure blob storage, as blob storage doesn't support directories.

Run
---
In this section, you can specify the script you want to run during computation, as well as some parameters for attestation.

- ``script`` : the script to run

- ``compute`` : the compute service you're using. Options are ``xgb`` or ``sql``.

- ``attestation``:

  - ``simulation_mode`` : options are ``0`` or ``1``. If ``0``, we are not running in simulation mode, and consequently should verify the compute enclaves during attestation. If ``1``, we are running in simluation mode, and verification does not occur.

  - ``mrenclave`` : the hash of the enclave build log.

  - ``mrsigner`` : the path to the public key of the entity signing all compute enclaves and the TMS.

- ``consortium``: a list of elements in the following format, representing each member of the consortium

  .. code-block:: yaml

    - username:
        public_key: /path/to/user/public/key
        release_policy: {true,false}

Download
--------
In this section, you can specify what you want to download and decrypt, how you want to download the data, and what decryption format you want to use.


- ``storage`` : options are ``blob`` or ``disk``. If ``blob``, MC\ :sup:`2` Client will upload your data to the Azure storage container you create. If ``disk``, MC\ :sup:`2` Client will ``scp`` your data to each launched VM.

- ``format`` : options are ``xgb`` and ``sql``. If ``xgb``, MC\ :sup:`2` Client will decrypt your data in a format compatible with Secure XGBoost. If ``sql``, MC\ :sup:`2` Client will decrypt your data in a format compatible with Opaque SQL.

- ``src`` : a list of files to download.

- ``dst`` : the directory to download the data to. 

Stop
----
Not implemented

Teardown
--------
In this section, you can specify what Azure resources you want to terminate that you previously launched.


- ``cluster`` : a boolean (``true`` or ``false``) - whether to delete the cluster of VMs

- ``storage`` : a boolean (``true`` or ``false``) - whether to delete the new Azure blob storage account

- ``container`` : a boolean (``true`` or ``false``) - whether to delete the storage container

- ``resource_group`` : a boolean (``true`` or ``false``) - whether to delete the resource group


Example
-------
All together, the configuration file will look something like the following.

.. code-block:: yaml

    # User configuration
    user:
        # Your username - username should be specified in certificate
        username: user1

        # Path to your symmetric key - will be used for encryption/decryption
        # If you don't have a symmetric key, specify a path here 
        # and run `mc2 init` to generate a key
        #
        # `mc2 init` will not overwrite anything at this path
        symmetric_key: ${MC2_CLIENT_HOME}/demo/keys/user1_sym.key

        # Path to your private key and certificate
        # If you don't have a private key / certificate, specify paths here
        # and run `mc2 init` to generate a keypair
        #
        # `mc2 init` will not overwrite anything at this path
        private_key: ${MC2_CLIENT_HOME}/demo/keys/user1.pem
        certificate: ${MC2_CLIENT_HOME}/demo/keys/user1.crt

        # Path to CA certificate and private key
        # Needed if you want to generate a certificate signed by CA
        root_certificate: ${MC2_CLIENT_HOME}/demo/keys/root.crt
        root_private_key: ${MC2_CLIENT_HOME}/demo/keys/root.pem

    # Configuration for launching cloud resources
    launch:
        # The absolute path to your Azure configuraton
        # This needs to be an absolute path
        azure_config: ${MC2_CLIENT_HOME}/demo/azure.yaml

        # # Manually specify the IP/uname/ssh_key of the head node or workers.
        # # If these values exist, they will override any values in `azure_config`.
        # # Consequently, the `launch` and `stop` commands will do nothing.
        # head:
        #    ip:
        #    username:
        #    ssh_key:
        # workers:
        #  - ip:
        #    username:
        #    ssh_key:

        # Whether to launch a cluster of VMs
        cluster: true

        # Whether to launch Azure blob storage
        storage: true

        # Whether to launch a storage container
        container: true

    # Commands to start compute service
    start:
        # Commands to run on head node
        head:
          - echo "Hello from head"

        # Commands to run on worker nodes
        workers:
          - echo "Hello from worker"

    # Configuration for `mc2 upload`
    upload:
        # Whether to upload data to Azure blob storage or disk
        # Allowed values are `blob` or `disk`
        # If `blob`, Azure CLI will be called to upload data
        # Else, `scp` will be used
        storage: blob

        # Encryption format to use
        # Options are `sql` if you want to use Opaque SQL
        # or `xgb` if you want to use Secure XGBoost
        format: sql

        # Files to encrypt and upload
        src:
          - ${MC2_CLIENT_HOME}/demo/data/opaquesql.csv

        # If you want to run Opaque SQL, you must also specify a schema,
        # one for each file you want to encrypt and upload
        schemas:
          - ${MC2_CLIENT_HOME}/demo/data/opaquesql_schema.json

        # Directory to upload data to
        dst:


    # Computation configuration
    run:
        # Script to run
        script: ${MC2_CLIENT_HOME}/demo/opaque_sql_demo.scala

        # Compute service you're using
        # Choices are `xgb` or `sql`
        compute: sql

        # Attestation configuration
        attestation:
            # Whether we are running in simulation mode
            # If 0 (False), we are _not_ running in simulation mode,
            # and should verify the attestation evidence
            simulation_mode: 0

            # MRENCLAVE value to check
            # MRENCLAVE is a hash of the enclave build log
            mrenclave: NULL

            # Path to MRSIGNER value to check
            # MRSIGNER is the key used to sign the built enclave
            mrsigner: ${MC2_CLIENT_HOME}/python-package/tests/keys/mc2_test_key.pub

    # Configuration for downloading results
    download:
        # Whether to upload data to Azure blob storage or disk
        # Allowed values are `blob` or `disk`
        # If `blob`, Azure CLI will be called to upload data
        # Else, `scp` will be used
        storage: blob

        # Format this data is encrypted with
        format: sql

        # Directory/file to download
        src:
          - results/opaque_sql_result

        # Local directory to download data to
        dst: results/

    # Configuration for stopping services
    stop:

    # Configuration for deleting Azure resources
    teardown:

        # Whether to terminate launched VMs
        cluster: true

        # Whether to terminate created Azure blob storage
        storage: true

        # Whether to terminate created storage container
        container: true
        resource_group: true
