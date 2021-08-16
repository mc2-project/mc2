Python Package Usage
====================

Below, you'll find guides on how to use the |platform| Client Python package. Ensure that you've first installed the Python package.

.. code-block:: bash
   :substitutions:

    $ python3
    Python 3.6.9 (default, Dec 30 2020, 10:13:08)
    [Clang 12.0.0 (clang-1200.0.32.28)] on darwin
    Type "help", "copyright", "credits" or "license" for more information.

    >>> import |python-package| as |python-package-short|


Configuring |platform| Client
-----------------------------
Before running anything, you'll need to create a YAML file specifying certain parameters, e.g. the paths to your keys, what to check during remote attestation, and the path to your Azure configuration. Exact instructions on configuration are :doc:`here <../config/config>`.

Once you've populated a YAML file with your desired parameters, set the path to your configuration file.

.. code-block:: python
   :substitutions:

    # An example config is at `demo/config.yaml`
    |python-package-short|.set_config("/path/to/config.yaml")

Key Generation
--------------
If you don't already have a keypair and/or a symmetric key, you'll want to generate them so that you can interact with |platform| cloud compute services in a cryptographically secure manner. |platform| uses your keypair and certificate to authenticate you to |platform| compute services, and uses your symmetric key to encrypt your data to ensure that the cloud doesn't see it in plaintext..

|platform| Client provides a function to generate a keypair and corresponding certificate as well as a function to generate a symmetric key. You should have specified paths for your private key, public key, certificate, and symmetric key during configuration. These functions will output the private key, public key, certificate, and symmetric key to these paths.

.. code-block:: python
   :substitutions:

    # Generate a keypair and corresponding certificate
    |python-package-short|.generate_keypair()

    # Generate a symmetric key
    |python-package-short|.generate_symmetric_key()

Encrypting and Decrypting Files
-------------------------------
|platform| Client will use the symmetric key you specified during configuration to encrypt your sensitive data and decrypt sensitive results outputted by the |platform| compute services. If you don't yet have a symmetric key, see the above section on :ref:`Generating Keys`.

.. |platform| Client encrypts your data into two different formats, depending on which compute service you plan to use: ``sql`` or ``xgb``. ``sql`` format is for the |platform| compute service, while ``xgb`` is for Secure XGBoost.

.. ``xgb`` Format
.. ~~~~~~~~~~~~~~~~~~~~~~~~~
.. If you plan on using the Secure XGBoost compute service, you'll want to encrypt your data in ``xgb`` format. For this format, you'll need to specify the path to the plaintext data and a path for |platform| Client to output the encrypted data, as well as the encryption format.
.. 
.. .. note::
..     Data to be encrypted in ``xgb`` format should not contain a header row.
.. 
.. .. code-block:: python
..    :substitutions:
.. 
..     # Encrypt data in `xgb` format
..     |python-package-short|.encrypt_data(
..         "/path/to/plaintext/data",
..         "/path/to/output/encrypted/data",
..         enc_format="xgb",
..     )
.. 
.. To decrypt data encrypted in ``xgb`` format, you'll need to specify the path to the encrypted data, a path for |platform| Client to output the decrypted data, and the encryption format.
.. 
.. .. code-block:: python
..    :substitutions:
..    
..     # Decrypt data encrypted in `xgb` format
..     |python-package-short|.decrypt_data(
..         "/path/to/encrypted/data",
..         "/path/to/decrypted/data",
..         enc_format="xgb",
..     )
.. 

``sql`` Format
~~~~~~~~~~~~~~~~~
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

.. note::
    Data to be encrypted in ``xgb`` format should contain a header row, i.e., the first row should be a comma-separated list of column names.

To encrypt the data, you'll need to specify the path to the plaintext data, a path for |platform| Client to output the encrypted data, the path to the schema of the data, and the encryption format.

.. code-block:: python
   :substitutions:

    # Encrypt data in `sql` format
    |python-package-short|.encrypt_data(
        "/path/to/plaintext/data",
        "/path/to/output/encrypted/data",
        schema_file="/path/to/schema",
        enc_format="sql",
    )

To decrypt data encrypted in ``sql`` format, you'll need to specify the path to the encrypted data, a path for |platform| Client to output the decrypted data, and the encryption format.

.. code-block:: python
   :substitutions:
   
    # Decrypt data encrypted in `sql` format
    |python-package-short|.decrypt_data(
        "/path/to/encrypted/data",
        "/path/to/decrypted/data",
        enc_format="sql",
    )

Azure Resource Management
-------------------------
Before you can work with Azure through |platform| Client, you must first login to Azure through the command line. See how to do so :ref:`here <Azure Login>`.

You can spin up and delete resources using |platform| Client. For example, before running anything on an |platform| compute service, you'll need to create file storage. You'll also need to create an enclave-enabled cluster. When launching these resources using |platform| Client, you must first specify Azure-specific configuration parameters in a YAML file. An example can be found in ``demo/azure.yaml``. 

In particular, note the following important fields:

- ``cluster_name`` : name of the cluster to use

- ``num_workers`` : the total number of workers to launch

- ``provider.resource_group`` : the name of an existing resource group that you want to launch the resources in

- ``provider.storage_name`` : name of the Azure storage you want to use

- ``provider.container_name`` : name of the container you want to transfer data to or from

- ``auth`` : the username and SSH keys to use when spinning up VMs

-  ``*node*.azure_arm_parameters.vmSize`` : size of the VM you want to launch as the head node. See `here <https://docs.microsoft.com/en-us/azure/virtual-machines/dcv2-series>`_ for all options for SGX-enabled VMs.


If you haven't already launched resources for |platform| compute to use, you can do so with |platform| Client.

.. code-block:: python
   :substitutions:
  
    # Create resource group with name specified in Azure config YAML
    |python-package-short|.create_resource_group()

    # Create Azure file storage with name specified in Azure config YAML
    |python-package-short|.create_storage()

    # Create container with name specified in Azure config YAML
    # You can only create the container after you create storage
    |python-package-short|.create_container()

    # Create a cluster with parameters specified in Azure config YAML
    |python-package-short|.create_cluster()

Once you've finished using |platform| compute services, you can also delete your resources using |platform| Client.

.. code-block:: python
   :substitutions:
  
    # Delete container with name specified in Azure config YAML
    |python-package-short|.delete_container()

    # Delete Azure file storage with name specified 
    # in Azure config YAML
    |python-package-short|.delete_storage()

    # Delete the cluster specified by `cluster_name` 
    # in Azure config YAML
    |python-package-short|.delete_cluster()

    # Delete resource group specified in Azure config YAML
    |python-package-short|.delete_resource_group()

Remote Attestation
------------------
Before using |platform| compute services, you'll want to attest the |platform| cluster in the cloud to authenticate all the enclaves and to ensure that the expected code has been properly loaded into each enclave. Attestation parameters, e.g. what values to check, are specified during :doc:`configuration <../config/config>`. |platform| Client will retrieve these parameters under the hood and attest accordingly.


.. code-block:: python
   :substitutions:

    # Remotely attest the |platform| cluster
    |python-package-short|.configure_job()

Azure File Transfer
-------------------
Once you've encrypted your data and set up your Azure storage, you can upload your encrypted data to the Azure storage specified in your Azure config YAML. For more details about this configuration, see :ref:`Azure Resource Management`.

.. code-block:: python
   :substitutions:
    
    # Upload your data to Azure
    # |platform| Client will transfer your data to the Azure container
    # specified in Azure config YAML
    |python-package-short|.upload_file(
        "/local/path/to/encrypted/data",
        "/name/of/file/in/Azure/container"
    )

Similarly, you can download any data outputted by |platform| compute services to your Azure containers. |platform| compute services will, before outputting data, encrypt the data with your symmetric key (as specified during configuration), so any data outputted to the Azure containers will be encrypted.

.. code-block:: python
   :substitutions:
    
    # Download encrypted data from Azure
    # |platform| Client will look for the data from the Azure container
    # specified in Azure config YAML
    |python-package-short|.download_file(
        "/file/to/fetch/in/Azure/container",
        "/local/path/to/download/data/to"
    )

.. note::

	If nodes have been manually configured (via the ``head`` or ``workers`` fields in the ``launch`` section) and are locally hosted (i.e. ``ip`` is ``0.0.0.0`` or ``127.0.0.1``) then these commands will simply copy the file on the local machine.
