CLI Usage
=========

Below, you'll find guides on how to use the MC\ :sup:`2` Client command line interface. The CLI is dependent on the ``mc2client`` Python package, so ensure that you've first installed the Python package by trying to import ``mc2client``.

.. code-block:: python

    import mc2client as oc

Configuring MC\ :sup:`2` Client
-------------------------
Before running anything, you'll need to create a YAML file specifying certain parameters, e.g. the paths to your keys, what to check during remote attestation, and the path to your Azure configuration. Exact instructions on configuration are :doc:`here <../config>`.

Once you've populated a YAML file with your desired parameters, set the ``MC2_CONFIG`` environment variable to the path to your configuration file.

.. code-block:: bash

    export MC2_CONFIG=/path/to/config/yaml

Generating Keys
---------------
If you don't already have a keypair and/or a symmetric key, you'll want to generate them so that you can interact with MC\ :sup:`2` cloud compute services in a cryptographically secure manner. MC\ :sup:`2` uses your certificate and private key to authenticate you to MC\ :sup:`2` compute services, and uses your symmetric key to encrypt your data to ensure that the cloud doesn't see it in plaintext..

You can generate a certificate and corresponding private key, and a symmetric key, through the CLI. You should have specified paths for your certificate, private key, and symmetric key during configuration. These functions will output the certificate, private key, and symmetric key to these paths.

.. code-block:: bash

    # Generate a certificate and corresponding private key
    python3 cli.py crypto --gen-keypair

    # Generate a symmetric key
    python3 cli.py crypto --gen-symm-key


Encrypting and Uploading Data
-----------------------------
MC\ :sup:`2` Client will use the symmetric key you specified during configuration to encrypt your sensitive data and decrypt sensitive results outputted by the MC\ :sup:`2` compute services. If you don't yet have a symmetric key, see the above section on :ref:`Generating Keys`.

MC\ :sup:`2` Client encrypts your data into two different formats, depending on which compute service you plan to use: ``opaque`` or ``securexgboost``. ``opaque`` format is for the Opaque SQL compute service, while ``securexgboost`` is for Secure XGBoost. You should specify the data you will use during computation (and hence should encrypt and upload) and the nodes you're using for computation, i.e., where you want to upload your data during the :doc:`configuration step <../config>`.

MC\ :sup:`2` Client will encrypt and upload your data in one step through the command line.

Secure XGBoost Format
~~~~~~~~~~~~~~~~~~~~~
If you plan on using the Secure XGBoost compute service, you'll want to encrypt your data in ``securexgboost`` format. To do so, specify the ``--xgb`` option.

.. code-block:: bash

    # Encrypt data in `securexgboost` format and upload it 
    # to a location readable by the Secure XGBoost compute service.
    mc2 upload --xgb


Opaque SQL Format
~~~~~~~~~~~~~~~~~
If you plan on using the Opaque SQL compute service, you'll want to encrypt your data in ``opaque`` format -- specify the ``--sql`` option. For this format, you'll first need to create a file specifying the schema of the data.

The schema must be written in the following format:

.. code-block:: bash

    col_1_name:col_1_type,col_2_name:col_2_type,col_3_name:col_3_type

For example, if your data has 3 columns, named ``age`` of type ``integer``, ``rank`` of type ``float``, and ``animal`` of type ``string``, the schema would look like the following:

.. code-block:: bash

    age:integer,rank:float,animal:string


Currently, MC\ :sup:`2` Client supports the following types with Opaque SQL:

- ``integer``
- ``long``
- ``float``
- ``double``
- ``string``

If the data in your column is not of any of these types, MC\ :sup:`2` Client will by default encrypt it as a string type. 

**Note**: Currently, you must include a header with all data you'll use with Opaque SQL. The header should be a comma-separated list of column names.

.. code-block:: bash

    # Encrypt data in `opaque` format
    mc2 upload --sql


Running Computation
-------------------
To perform computation, first write a script that contains the Python (in the case of Secure XGBoost) or the Scala (in the case of Opaque SQL) code that you want to run. Example scripts can be found in ``demo/``. Specify this script in the :doc:`configuration YAML <../config>`. You can then remotely run this script using MC\ :sup:`2` Client.

.. code-block:: bash

    # Run your Secure XGBoost or Opaque SQL computation
    mc2 run --xgb/--sql

As part of this step, MC\ :sup:`2` Client will perform remote attestation to authenticate all enclaves and ensure that the expected code has been properly loaded into each enclave. Attestation parameters, e.g. what values to check, are also specified during :doc:`configuration <../config>`. MC\ :sup:`2` Client will retrieve these parameters under the hood and attest accordingly.

Decrypting and Downloading Results
----------------------------------
Once your computation has finished, you can download and, optionally, decrypt the results. All compute services included with MC\ :sup:`2` will only save encrypted results to disk, i.e. it will not expose any results in plaintext. You should specify the source of the transfer, i.e. the paths of the results on the cloud, and the destination of the transfer, i.e. the local directory to which you want to save results, during :doc:`configuration <../config>`.


.. code-block:: bash

    # Retrieve results from the first worker node,
    # as specified during configuration.
    mc2 download

    # Optionally, if you want to also decrypt results
    # encrypted during Secure XGBoost computation,
    # specify the --xgb flag.
    mc2 download --xgb

    # Optionally, if you want to also decrypt results
    # encrypted during Opaque SQL computation,
    # specify the --sql flag.
    mc2 download --sql
