Usage with Opaque SQL
=====================
|platform| offers `Opaque SQL <https://mc2-project.github.io/opaque-sql/>`_, a secure analytics engine built on top of Apache Spark SQL, as a compute service that users can run. Opaque SQL provides a SQL and Scala interface for users to express their desired SQL-like computation. |platform| Client integrates directly with Opaque SQL, and enables users to start the Opaque SQL service as well as encrypt and decrypt data in a format readable by Opaque SQL.

First, install Opaque SQL by following `this guide <https://mc2-project.github.io/opaque-sql/install/install.html>`_. 

Next, to use |platform| Client for Opaque SQL, you'll need to specifically modify several sections of the :doc:`configuration <config/config>`: the ``start``, ``upload``, ``run``, and ``download`` sections. Once you've finished configuration, look at the :doc:`quickstart` guide on how to securely run a query.

Start
-----
In the ``start`` section, you must specify the command to launch the Opaque SQL service: ``build/sbt run``. The section should look something like this:

.. code-block:: yaml

   start:
      # Commands to run on head node
      head:
      # To run Opaque SQL locally
      - cd /path/to/opaque-sql; build/sbt run

      # Or to run a standalone Spark cluster
      - cd /path/to/opaque-sql; build/sbt assembly
      - cd /path/to/opaque-sql; spark-submit --class edu.berkeley.cs.rise.opaque.rpc.Listener <Spark configuration parameters> --deploy-mode client ${|platform_uppercase|_HOME}/target/scala-2.12/opaque-assembly-0.1.jar

      # Commands to run on worker nodes
      workers: []

Upload
------
In the ``upload`` section, you should tell |platform| Client that you want to encrypt data in ``sql`` format, the format readable by Opaque SQL. Along with the data, you should specify the path to the data schema. More on the schema format can be found :ref:`here <sqlformat>`.

The section should look something like this:

.. code-block:: yaml
   :substitutions:

   upload:
      # Whether to upload data to Azure blob storage or disk
      # Allowed values are `blob` or `disk`
      # If `blob`, Azure CLI will be called to upload data
      # Else, `scp` will be used
      storage: disk

      # Encryption format to use
      # Options are `sql` if you want to use Opaque SQL
      # or `xgb` if you want to use Secure XGBoost
      format: sql

      # Files to encrypt and upload
      src:
        - ${|platform_uppercase|_CLIENT_HOME}/quickstart/data/opaquesql.csv

      # If you want to run Opaque SQL, you must also specify a schema,
      # one for each file you want to encrypt and upload
      schemas:
        - ${|platform_uppercase|_CLIENT_HOME}/quickstart/data/opaquesql_schema.json

      # Directory to upload data to
      dst: /mc2/data

Run
---
In the ``run`` section, you should tell |platform| Client that you're running Opaque SQL, and specify an Opaque SQL script written in Scala. This section should look something like this:

.. code-block:: yaml
   :substitutions:

   run:
      # Script to run
      script: opaque_sql_demo.scala

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
         mrsigner: ${|platform_uppercase|_CLIENT_HOME}/python-package/tests/keys/mc2_test_key.pub

      # The client consortium. Each username is mapped to a public key and
      # release policy
      consortium:
        - username: user1
          public_key: keys/user1.pub
          result_release: true


Download
--------
In the download section, you should tell |platform| Client that the results you are retrieving are encrypted by Opaque SQL. This section should look something like this:

.. code-block:: yaml

   download:
      # Whether to download data from Azure blob storage or disk
      # Allowed values are `blob` or `disk`
      # If `blob`, Azure CLI will be called to download data
      # Else, `scp` will be used
      storage: disk

      # Format this data is encrypted with
      format: sql

      # Directory/file to download
      src:
      - /mc2/opaque_sql_result

      # Local directory to download data to
      dst: results/


Example
-------
All together, the configuration file should look something like the following when running Opaque SQL.

.. code-block:: yaml
   :substitutions:

   # User configuration
   user:
      # Your username - username should be specified in certificate
      username: user1

      # Path to your symmetric key - will be used for encryption/decryption
      # If you don't have a symmetric key, specify a path here 
      # and run `|platform| init` to generate a key
      #
      # `|platform| init` will not overwrite anything at this path
      symmetric_key: ${|platform_uppercase|_CLIENT_HOME}/quickstart/keys/user1_sym.key

      # Path to your keypair and certificate
      # If you don't have a keypair / certificate, specify paths here
      # and run `|platform| init` to generate a keypair
      #
      # `|platform| init` will not overwrite anything at this path
      private_key: ${|platform_uppercase|_CLIENT_HOME}/quickstart/keys/user1.pem
      public_key: ${|platform_uppercase|_CLIENT_HOME}/quickstart/keys/user1.pub
      certificate: ${|platform_uppercase|_CLIENT_HOME}/quickstart/keys/user1.crt

      # Path to CA certificate and private key
      # Needed if you want to generate a certificate signed by CA
      root_certificate: ${|platform_uppercase|_CLIENT_HOME}/quickstart/keys/root.crt
      root_private_key: ${|platform_uppercase|_CLIENT_HOME}/quickstart/keys/root.pem

   # Configuration for launching cloud resources
   launch:
      # The absolute path to your Azure configuraton
      # This needs to be an absolute path
      azure_config: ${|platform_uppercase|_CLIENT_HOME}/quickstart/azure.yaml

      # Whether to launch a cluster of VMs
      cluster: true

      # Whether to launch Azure blob storage
      storage: true

      # Whether to launch a storage container
      container: true

   # Commands to start compute service
   start:
      # Commands to run on head node
      # This command is used to start the Opaque SQL service
      head:
      - cd /mc2/opaque-sql; build/sbt run

      # Commands to run on worker nodes
      # For this quickstart there is only one node - no worker nodes
      workers: []

   # Configuration for `|platform| upload`
   upload:
      # Whether to upload data to Azure blob storage or disk
      # Allowed values are `blob` or `disk`
      # If `blob`, Azure CLI will be called to upload data
      # Else, `scp` will be used
      storage: disk

      # Encryption format to use
      # Options are `sql` if you want to use Opaque SQL
      # or `xgb` if you want to use Secure XGBoost
      format: sql

      # Files to encrypt and upload
      src:
      - ${|platform_uppercase|_CLIENT_HOME}/quickstart/data/opaquesql.csv

      # If you want to run Opaque SQL, you must also specify a schema,
      # one for each file you want to encrypt and upload
      schemas:
      - ${|platform_uppercase|_CLIENT_HOME}/quickstart/data/opaquesql_schema.json

      # Directory to upload data to
      dst: /mc2/data


   # Computation configuration
   run:
      # Script to run
      script: opaque_sql_demo.scala

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
         # This key should be used for testing purposes only,
         # and is not secure for production purpose.
         mrsigner: ${|platform_uppercase|_CLIENT_HOME}/python-package/tests/keys/mc2_test_key.pub

      # The client consortium. Each username is mapped to a public key and
      # release policy
      consortium:
        - username: user1
          public_key: keys/user1.pub
          result_release: true

     # Configuration for downloading results
     download:
        # Whether to download data from Azure blob storage or disk
        # Allowed values are `blob` or `disk`
        # If `blob`, Azure CLI will be called to download data
        # Else, `scp` will be used
        storage: disk

        # Format this data is encrypted with
        format: sql

        # Directory/file to download
        # FIXME: If storage is `blob` this value must be a file
        # Need to investigate whether we can use directories in Azure blob storage
        src:
          - /mc2/opaque_sql_result

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

        # Whether to terminate specified resource group
        resource_group: true
