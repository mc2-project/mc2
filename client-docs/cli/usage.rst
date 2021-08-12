CLI Usage
=========

Below, you'll find guides on how to use the |platform| Client command line interface. The CLI is dependent on the :substitution-code:`|python-package|` Python package, so ensure that you've first installed the Python package by trying to import :substitution-code:`python-package`.

.. code-block:: python
   :substitutions:

    import |python-package| as |python-package-short|

The CLI relies heavily on a configuration file in which you can specify the parameters for each command as explained in the next section.

Configuring |platform| Client
-------------------------
Before running anything, you'll need to create a configuration YAML file specifying certain parameters. More on configuration is :doc:`here <../config/config>`.

Once you've populated a YAML file with your desired parameters, configure |platform| Client with the path to your configuration file.

.. code-block:: bash
   :substitutions:

    # An example config is at `demo/config.yaml`
    |cmd| configure /path/to/config/yaml

Generating Keys
---------------
If you don't already have a keypair and/or a symmetric key, you'll want to generate them so that you can interact with |platform| cloud compute services in a cryptographically secure manner. |platform| uses your keypair to authenticate you to |platform| compute services, and uses your symmetric key to encrypt your data to ensure that the cloud doesn't see it in plaintext..

You can generate a keypair, corresponding certificate, and a symmetric key through the CLI. You should have specified paths for your private key, public key, certificate, and symmetric key during configuration. If something already exists at either the private key, public key, or certificate path, |platform| Client will skip generating the keypair and corresponding certificate. If something already exists at the symmetric key path, |platform| Client will skip generating the symmetric key.

.. code-block:: bash
   :substitutions:

    # Generate a keypair, corresponding certificate, and symmetric key
    # If something exists at any paths specified in the config,
    # |platform| Client will skip generation.
    $ |cmd| init

*Note that, by default, |platform| Client uses a pre-generated RSA public key for enclave verification. This key should be not be used in a production environment.* 

Launching Cloud Resources
-------------------------
You can use |platform| Client to launch resources in Azure. In particular, you can create a cluster of VMs, Azure blob storage, and a storage container. This section in the configuration looks as follows.

.. code-block:: yaml

   launch:
      # The absolute path to your Azure configuraton
      # This needs to be an absolute path
      azure_config: /path/to/azure.yaml

      # Whether to launch a cluster of VMs
      cluster: {true, false}

      # Whether to launch Azure blob storage
      storage: {true, false}

      # Whether to launch a storage container
      container: {true, false}

You will also need to specify details for the Azure resources you want to launch in a separate configuration file. An example of the file can be found in ``demo/azure.yaml``.

In particular, note the following important sections in the Azure configuration that you will likely want to modify.

.. code-block:: yaml
   :substitutions:

   # An unique identifier for the head node and workers of this cluster.
   cluster_name: default

   # The total number of workers nodes to launch in addition to the head
   # node. This number should be >= 0.
   num_workers: 0

   # Cloud-provider specific configuration.
   provider:
      type: azure

      # Location of resources
      location: eastus

      # Name of resource group that will contain your launched resources
      resource_group: |cmd|-client-dev

      # Name of Azure blob storage you want to create
      storage_name: |cmd|storage

      # Name of storage container you want to create
      container_name: blob-container-1

      # If left blank, the default subscription ID from Azure CLI will be used
      subscription_id:

   # How MC2 will authenticate with newly launched nodes.
   auth:
      # The username used to SSH into created VMs
      ssh_user: mc2

      # you must specify paths to matching private and public key pair files
      # use `ssh-keygen -t rsa -b 4096` to generate a new ssh key pair
      ssh_private_key: ~/.ssh/id_rsa
      ssh_public_key: ~/.ssh/id_rsa.pub


To launch the resources, run the following command:

.. code-block:: bash
   :substitutions:
   
   |cmd| launch

.. note::
	If nodes have been manually configured (via the ``head`` or ``workers`` fields in the ``launch`` section), this command will not do anything.


Starting Compute Services Remotely
----------------------------------
To run computation, you'll need to remotely start the compute services. You can specify commands to start the compute services using |platform| Client through configuration. |platform| Client will remotely run these commands on each VM in the Azure cluster.

.. code-block:: yaml

   start:
      # Commands to run on head node
      head:
      - echo "Hello from head"

      # Commands to run on worker nodes
      workers:
      - echo "Hello from worker"


To start the services, run the following command:

.. code-block:: bash
   :substitutions:

   |cmd| start

.. note::
	If nodes have been manually configured (via the ``head`` or ``workers`` fields in the ``launch`` section) and are locally hosted (i.e. ``ip`` is ``0.0.0.0`` or ``127.0.0.1``) then the commands will be run in a local subprocess.


Encrypting and Uploading Data
-----------------------------
|platform| Client will use the symmetric key you specified during configuration to encrypt your sensitive data. If you don't yet have a symmetric key, see the above section on :ref:`Generating Keys`.

.. code-block:: yaml

   upload:
      # Whether to upload data to Azure blob storage or disk
      # Allowed values are `blob` or `disk`
      # If `blob`, Azure CLI will be called to upload data
      # Else, `scp` will be used
      storage: {blob, disk}

      # Encryption format to use
      # Options are `sql` if you want to use Opaque SQL
      # or `xgb` if you want to use Secure XGBoost
      format: {sql, xgb}

      # Files to encrypt and upload
      src:
        - /path/to/your/data.csv

      # If you want to run Opaque SQL, you must also specify a schema,
      # one for each file you want to encrypt and upload
      schemas:
      - /path/to/opaquesql_schema.json

      # Directory to upload data to
      dst: dst_dir


To encrypt and upload your data, run the following command:

.. code-block:: bash
   :substitutions:

   |cmd| upload

.. note::
	If nodes have been manually configured (via the ``head`` or ``workers`` fields in the ``launch`` section) and are locally hosted (i.e. ``ip`` is ``0.0.0.0`` or ``127.0.0.1``) then the file will be copied to ``dst`` on the local machine.


.. _sqlformat:

Note on ``sql`` Format
~~~~~~~~~~~~~~~~~~~~~~

If you plan on using the |platform| compute service, you'll want to encrypt your data in ``sql`` format. For this format, you'll first need to create a file specifying the schema of the data.

The schema must be written in the following format:

.. code-block:: bash

    col_1_name:col_1_type,col_2_name:col_2_type,col_3_name:col_3_type

For example, if your data has 3 columns, named ``age`` of type ``integer``, ``rank`` of type ``float``, and ``animal`` of type ``string``, the schema would look like the following:

.. code-block:: bash

    age:integer,rank:float,animal:string


Currently, |platform| supports the following types:

- ``integer``
- ``long``
- ``float``
- ``double``
- ``string``

If the data in your column is not of any of these types, |platform| Client will by default encrypt it as a string type. 


Running Computation
-------------------
To run computation, you should specify a script to run in the configuration. In addition, when you initiate computation, |platform| Client will under the hood attest the enclave deployment before actually running the computation. Attestation ensures that all enclaves were built and loaded with the proper code and that they were properly initialized. You will also need to specify some configuration values for attestation.

.. code-block:: yaml
   :substitutions:

   # Computation configuration
   run:
      # Script to run
      script: opaque_sql_demo.scala

      # Compute service you're using
      # Choices are `xgb` or `sql`
      compute: {xgb, sql}

      # Attestation configuration
      attestation:
         # Whether we are running in simulation mode
         # If 0 (False), we are _not_ running in simulation mode,
         # and should verify the attestation evidence
         simulation_mode: {0, 1}

         # Path to MRENCLAVE value to check
         # MRENCLAVE is a hash of the enclave build log
         mrenclave: NULL

         # Path to MRSIGNER value to check
         # MRSIGNER is the key used to sign the built enclave
        mrsigner: ${|platform_uppercase|_CLIENT_HOME}/python-package/tests/keys/mc2_test_key.pub

      # The client consortium. Each username is mapped to a public key and
      # release policy
      consortium:
       - username:
           public_key: /path/to/user/public/key
           release_policy: {true,false}

Begin computation by running the following command:

.. code-block:: bash 
   :substitutions:
   
   |cmd| run

Downloading and Decrypting Data
-------------------------------
|platform| Client will use the symmetric key you specified during configuration to decrypt computation results. If you don't yet have a symmetric key, see the above section on :ref:`Generating Keys`. You should download results from where the compute services saved the results.

.. code-block:: yaml

   # Configuration for downloading results
   download:
       # Whether to upload data to Azure blob storage or disk
       # Allowed values are `blob` or `disk`
       # If `blob`, Azure CLI will be called to upload data
       # Else, `scp` will be used
       storage: {blob, disk}

       # Format this data is encrypted with
       format: {xgb, sql}

       # Directory/file to download
       src:
         - securexgb_train.csv.enc

       # Local directory to download data to
       dst: results/


To encrypt and upload your data, run the following command:

.. code-block:: bash
   :substitutions:

   |cmd| download

.. note::
	If nodes have been manually configured (via the ``head`` or ``workers`` fields in the ``launch`` section) and are locally hosted (i.e. ``ip`` is ``0.0.0.0`` or ``127.0.0.1``) then the file will be copied from ``src`` to ``dst`` on the local machine.

Stopping Compute Services
-------------------------
Not implemented

Terminating Azure Resources
---------------------------
You can use |platform| Client to terminate your launched Azure resources. Specify which resources you want to terminate in the configuration.

.. code-block:: yaml
   :substitutions:

   teardown:
      # Whether to terminate launched VMs
      cluster: {true, false}

      # Whether to terminate created Azure blob storage
      storage: {true, false}

      # Whether to terminate created storage container
      container: {true, false}

To terminate desired resources, run the following command:

.. code-block:: bash
   :substitutions:
   
   |cmd| teardown
