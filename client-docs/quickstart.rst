Quickstart
==========
This quickstart will give you a flavor of using MC\ :sup:`2` with Opaque SQL, and can be entirely done locally with Docker if desired. You will use MC\ :sup:`2` Client to encrypt some data, transfer the encrypted data to a remote machine, run an Opaque SQL job on the encrypted data on the remote machine, and retrieve and decrypt the job's encrypted results. To run everything securely, you can choose to spin up Opaque SQL on Azure VMs with SGX-support. Alternatively, to get a flavor of MC\ :sup:`2` without having to use Azure, you can use the deployment of Opaque SQL in the Docker container.

MC\ :sup:`2` Client provides a command line interface that enables you to remotely interact with MC\ :sup:`2` compute services. The CLI relies on a :doc:`configuration file <config/config>` that you should modify before each step in this quickstart to tell MC\ :sup:`2` Client what exactly you want to do.

Docker Quickstart
-----------------
If you'd like to try everything out locally, you can do so within the Docker container you built in the :doc:`installation <install>` section.

1. Copy the contents of the ``quickstart`` directory to your mounted "playground" directory to ensure that your changes inside the container get reflected on your host. Then, set the ``MC2_CONFIG`` environment variable to the path of your configuration file.

.. code-block:: bash

    # From the /mc2/client directory
    cp -r quickstart/* playground
    export MC2_CONFIG=</path/to/playground/config.yaml>

2. Optionally, generate a keypair and a symmetric key that MC\ :sup:`2` Client will use to encrypt your data. Specify your username and output paths in the ``user`` section of the configuration file. Then, generate the keys.

.. code-block:: bash

    mc2 init

3. Start the Opaque SQL compute service.
    
.. code-block:: bash

    mc2 start

4. Prepare your data for computation by encrypting and uploading it. Note that "uploading" here means copying because we have a local deployment.

.. code-block:: bash

    mc2 upload

5. Run the provided Opaque SQL quickstart script, to be executed by MC\ :sup:`2`. The script can be found [here](quickstart/opaque_sql_demo.scala). 

.. code-block:: bash

    mc2 run

6. Once computation has finished, you can retrieve your encrypted results and decrypt them. Specify the results' path and their encryption format in the ``download`` section of configuration. The decrypted results will be in the same directory.

.. code-block:: bash

    mc2 download

Azure Quickstart
----------------
You can also choose to run this quickstart with enclave-enabled VMs on the cloud with Azure Confidential Computing. This guide will take you through launching such VMs and using them with MC\ :sup:`2`.

1. In the container, copy the contents of the ``quickstart`` directory to your mounted "playground" directory to ensure that your changes inside the container get reflected on your host. Otherwise, no need to do anything. Then, set the ``MC2_CONFIG`` environment variable to the path of your configuration file.

.. code-block:: bash

    # From the /mc2/client directory
    cp -r quickstart/* playground
    export MC2_CONFIG=</path/to/playground/config.yaml>

2. Optionally, generate a keypair and a symmetric key that MC\ :sup:`2` Client will use to encrypt your data. Specify your username and output paths in the ``user`` section of the configuration file. Then, generate the keys.

.. code-block:: bash

    mc2 init

3. Next, launch the machines and resources you'll be using for computation. MC\ :sup:`2` Client provides an interface to launch resources on Azure (and sets up the machines with necessary dependencies). Take a look at the ``launch`` section of the configuration file -- you'll need to specify the path to your :doc:`Azure configuration file <config/azure>`, which is a YAML file that details the names and types of various resources you will launch. 

Next, log in to Azure through the command line and set your subscription ID. `Here <https://docs.microsoft.com/en-us/azure/media-services/latest/setup-azure-subscription-how-to?tabs=portal>`_ are instructions on how to find your subscription ID.

.. code-block:: bash

    az login
    az account set -s <YOUR_SUBSCRIPTION_ID>

Once you've done that, launch the resources.

.. code-block:: bash

    mc2 launch

4. Start the Opaque SQL compute service. 
    
.. code-block:: bash

    mc2 start

5. Prepare your data for computation by encrypting and uploading it.

.. code-block:: bash

    mc2 upload

6. Run the provided Opaque SQL demo script, to be executed by MC\ :sup:`2`. The script can be found [here](quickstart/opaque_sql_demo.scala). All paths in the script are remote paths, since the script will be executing on the remote Opaque SQL service. Then, go to the ``run`` section of the configuration and specify the path to your script, as well as parameters for remote attestation. Run the following command to remotely start computation.  

.. code-block:: bash

    mc2 run

7. Once computation has finished, you can retrieve your encrypted results and decrypt them.

.. code-block:: bash

    mc2 download

8. Once you've finished using your Azure resources, you can use MC\ :sup:`2` Client to terminate them. You can specify which resources to terminate in the ``teardown`` section of the configuration.
    
.. code-block:: bash

    mc2 teardown
