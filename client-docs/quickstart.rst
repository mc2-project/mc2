Quickstart
==========
This quickstart will give you a flavor of using |platform| with Opaque SQL, and can be entirely done locally with Docker if desired. You will use |platform| Client to encrypt some data, transfer the encrypted data to a remote machine, run an Opaque SQL job on the encrypted data on the remote machine, and retrieve and decrypt the job's encrypted results. To run everything securely, you can choose to spin up Opaque SQL on Azure VMs with SGX-support. Alternatively, to get a flavor of |platform| without having to use Azure, you can use the deployment of Opaque SQL in the Docker container.

|platform| Client provides a command line interface that enables you to remotely interact with |platform| compute services. The CLI relies on a :doc:`configuration file <config/config>` that you should modify before each step in this quickstart to tell |platform| Client what exactly you want to do.

Docker Quickstart
-----------------
If you'd like to try everything out locally, you can do so within the Docker container you built in the :doc:`installation <install>` section.

1. Decide whether you want to run Spark (Scala) or PySpark (Python). The former is the default, while the latter will require two modifications to ``/mc2/client/quickstart/config.yaml``:

Change ``run --> script`` to point to the Python file.
    
.. code-block:: yaml
    :substitutions:

    run:
        script: ${|platform_uppercase|_CLIENT_HOME}/demo/single-party/opaquesql/opaque_sql_demo.py

Change ``start --> head`` to include instructions on starting the PySpark listener. For a local listener, this will be 

.. code-block:: yaml
    :substitutions:

    start:
        head:
          - cd /home/mc2/opaque-sql; build/sbt assembly
          - cd /home/mc2/opaque-sql; spark-submit --master local[1] --jars ${|platform_uppercase|_HOME}/target/scala-2.12/opaque-assembly-0.1.jar --py-files ${|platform_uppercase|_HOME}/target/python.zip ${|platform_uppercase|_HOME}/target/python/listener.py


2. In the container, copy the contents of the ``quickstart`` directory to your mounted ``playground`` directory to ensure that your changes inside the container get reflected on your host. Then, specify the path to your configuration file.

.. code-block:: bash
    :substitutions:

    # From the /mc2/client directory
    cp -r quickstart/* playground
    |cmd| configure $(pwd)/playground/config.yaml

3. Generate a keypair and a symmetric key that |platform| Client will use to encrypt your data. Specify your username and output paths in the ``user`` section of the configuration file. Then, generate the keys.

.. code-block:: bash
    :substitutions:

    |cmd| init

4. Start the Opaque SQL compute service.
    
.. code-block:: bash
    :substitutions:

    |cmd| start

5. Prepare your data for computation by encrypting and uploading it. Note that "uploading" here means copying because we have a local deployment.

.. code-block:: bash
    :substitutions:

    |cmd| upload

5. Run the provided Opaque SQL quickstart script, to be executed by |platform|. The Scala script can be found `here <https://github.com/opaque-systems/opaque-client/blob/master/quickstart/opaque_sql_demo.scala>`_, while Python is found `here <https://github.com/opaque-systems/opaque-client/blob/master/quickstart/opaque_sql_demo.py>`_.

.. code-block:: bash
    :substitutions:

    |cmd| run

6. Once computation has finished, you can retrieve your encrypted results and decrypt them. Specify the results' path and their encryption format in the ``download`` section of configuration. The decrypted results will be in the same directory.

.. code-block:: bash
    :substitutions:

    |cmd| download

Azure Quickstart
----------------
You can also choose to run this quickstart with enclave-enabled VMs on the cloud with Azure Confidential Computing. This guide will take you through launching such VMs and using them with |platform|.

1. Decide whether you want to run Spark (Scala) or PySpark (Python). The former is the default, while the latter will require two modifications to ``/mc2/client/quickstart/config.yaml``:

Change ``run --> script`` to point to the Python file.
    
.. code-block:: yaml
    :substitutions:

    run:
        script: ${|platform_uppercase|_CLIENT_HOME}/quickstart/opaque_sql_demo.py

Change ``start --> head`` to include instructions on starting the PySpark listener. For a local listener, this will be 

.. code-block:: yaml
    :substitutions:

    start:
        head:
          - cd /home/mc2/opaque-sql; build/sbt assembly
          - cd /home/mc2/opaque-sql; spark-submit --master local[1] --jars ${|platform_uppercase|_HOME}/target/scala-2.12/opaque-assembly-0.1.jar --py-files ${|platform_uppercase|_HOME}/target/python.zip ${|platform_uppercase|_HOME}/target/python/listener.py


2. In the container, copy the contents of the ``quickstart`` directory to your mounted ``playground`` directory to ensure that your changes inside the container get reflected on your host. Then, set the path to your configuration file.

.. code-block:: bash
    :substitutions:

    # From the /mc2/client directory
    cp -r quickstart/* playground
    |cmd| configure $(pwd)/playground/config.yaml

3. Generate a keypair and a symmetric key that |platform| Client will use to encrypt your data. Specify your username and output paths in the ``user`` section of the configuration file. Then, generate the keys.

.. code-block:: bash
    :substitutions:

    |cmd| init

4. Next, launch the machines and resources you'll be using for computation. |platform| Client provides an interface to launch resources on Azure (and sets up the machines with necessary dependencies). Take a look at the ``launch`` section of the configuration file -- you'll need to specify the path to your :doc:`Azure configuration file <config/azure>`, which is a YAML file that details the names and types of various resources you will launch. 

Next, log in to Azure through the command line and set your subscription ID. `Here <https://docs.microsoft.com/en-us/azure/media-services/latest/setup-azure-subscription-how-to?tabs=portal>`_ are instructions on how to find your subscription ID.

.. code-block:: bash

    az login
    az account set -s <YOUR_SUBSCRIPTION_ID>

Once you've done that, launch the resources.

.. code-block:: bash
    :substitutions:

    |cmd| launch

5. Start the Opaque SQL compute service. 
    
.. code-block:: bash
    :substitutions:

    |cmd| start

6. Prepare your data for computation by encrypting and uploading it.

.. code-block:: bash
    :substitutions:

    |cmd| upload

7. Run the provided Opaque SQL demo script, to be executed by |platform|. The Scala script can be found `here <https://github.com/opaque-systems/opaque-client/blob/master/quickstart/opaque_sql_demo.scala>`_, while Python is found `here <https://github.com/opaque-systems/opaque-client/blob/master/quickstart/opaque_sql_demo.py>`_. Both perform a filter operation over our data -- the results will contain records of all patients who are younger than 30 years old. Results are encrypted by |platform| before being saved, and can only be decrypted with the key you used to encrypt your data in the previous step.

.. code-block:: bash
    :substitutions:

    |cmd| run

8. Once computation has finished, you can retrieve your encrypted results and decrypt them.

.. code-block:: bash
    :substitutions:

    |cmd| download

9. Once you've finished using your Azure resources, you can use |platform| Client to terminate them. You can specify which resources to terminate in the ``teardown`` section of the configuration.
    
.. code-block:: bash
    :substitutions:

    |cmd| teardown
