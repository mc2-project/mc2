# MC<sup>2</sup>: A Platform for Secure Analytics and Machine Learning
Born out of research in the [UC Berkeley RISE Lab](https://rise.cs.berkeley.edu/), MC<sup>2</sup> is a platform for running secure analytics and machine learning on encrypted data.
With MC<sup>2</sup>, users can outsource their confidential data workloads to the cloud, while ensuring that the data is never exposed unencrypted to the cloud provider. 
MC<sup>2</sup> also enables secure collaboration, i.e., multiple data owners can use the platform to jointly analyze their collective data, without revealing their individual data to each other.

MC<sup>2</sup> provides the following (actively maintained) secure computation services:
* [Opaque SQL](https://github.com/mc2-project/opaque): Encrypted data analytics on Spark SQL using hardware enclaves
* [Secure XGBoost](https://github.com/mc2-project/secure-xgboost): Collaborative XGBoost training and inference on encrypted data using hardware enclaves
* [Federated XGBoost](https://github.com/mc2-project/federated-xgboost): Collaborative XGBoost in the federated setting

The MC<sup>2</sup> project also includes research prototypes that develop new cryptographic techniques for secure computation. Please visit the individual project pages for more information:
* [Cerebro](https://github.com/mc2-project/cerebro): A general purpose Python DSL for learning with secure multiparty computation.
* [Delphi](https://github.com/mc2-project/delphi): Secure inference for deep neural networks.

This repository contains the source code for the **MC<sup>2</sup> client**, which enables users to easily interface with MC<sup>2</sup> services deployed remotely in the cloud. Currently, the client supports remote deployments of Secure XGBoost and Opaque SQL only. 
To run an end-to-end MC<sup>2</sup> workflow:
1. Launch Opaque SQL or Secure XGBoost in the cloud (instructions to do so can be found in the respective repositories) 
2. Use the MC<sup>2</sup> client to encrypt data locally, transfer it to the cloud VMs, run scripts specifying the desired computation, and retrieve and view encrypted results.

Alternatively, to use the individual services without the MC<sup>2</sup> client, please visit the respective project pages linked above.

## Table of Contents
* [Quickstart](#quickstart)
* [Documentation](#documentation)
* [Contact](#contact)

## Quickstart
To quickly get a flavor of MC<sup>2</sup>, you can work in a Docker image that comes with pre-built versions of MC<sup>2</sup> Client, Opaque SQL, and Secure XGBoost, and all dependencies. This quickstart is completely self-contained within a container.

1. You must have [Docker](https://docs.docker.com/get-docker/) installed. We recommend giving Docker at least 2 CPUs, 6 GB of memory, and 2 GB of swap space (instructions for [Mac](https://docs.docker.com/docker-for-mac/#resources), [Windows](https://docs.docker.com/docker-for-windows/#resources)). Without sufficient resources, the quickstart may not work.

    Once that is done, pull the Docker image and launch a container.
    ```sh
    docker pull mc2project/mc2
    docker run -it -p 22:22 -p 50051-50055:50051-50055 -w /root mc2project/mc2
    ```
    Start an SSH server inside the container. (Note that you only need to start the SSH server if running in a Docker container -- most cloud VMs automatically start an SSH server on boot.)

    ```
    service ssh start
    ```

1. Navigate to the `mc2-client/demo` directory. The configuration for this quickstart has been pre-populated in `demo/mc2.yaml`. More on the configuration can be found [here](https://mc2-project.github.io/mc2/config.html). By default, the configuration has been set assuming you want to run Secure XGBoost. If you want to run Opaque SQL instead, comment out the Secure XGBoost section in the `local` part of the YAML configuration and comment in the Opaque SQL section.

    ```yaml
    # Configuration for local data
    local:
        # If you want to run Secure XGBoost
        # Your data to compute on
        data:
            - data/securexgb_train.csv
            - data/securexgb_test.csv

        # Secure XGBoost script to run
        script: secure_xgboost_demo.py
        # ----------------------------------


        # # If you want to run Opaque SQL
        # # Your data to compute on
        # data:
        #     - data/opaquesql.csv
        # 
        # schemas:
        #     - data/opaquesql_schema.json
        # 
        # # Opaque SQL script to run
        # script: opaque_sql_demo.scala
        # # ------------------------------
    ```
    Included in the repo are a [sample Secure XGBoost script](demo/secure_xgboost_demo.py) and a [sample Opaque SQL script](demo/opaque_sql_demo.scala).

1. Start the desired compute service within the container (Secure XGBoost or Opaque SQL). In a production environment, these compute services would be started in the cloud. Starting a compute service will start a listener that listens on port 50052.

    ```sh
    # Start the Secure XGBoost service. Replace `--xgb` with `--sql` for Opaque SQL instead.
    mc2 launch --xgb
    ```

    The Secure XGBoost service will take a few seconds to start, while the Opaque SQL service will take anywhere between 20-30 seconds to start. You can check whether the service is ready:

    ```sh
    mc2 check
    ```

1. Next, encrypt and transfer the encrypted data. Data to be encrypted/transferred is in `mc2.yaml` (this is pre-populated with the sample data). In this quickstart, the "transfer" is just a `scp` to another directory in the same container. In practice, the transfer is an upload to a remote machine in the cloud. The destination path for the data can also be specified in the configuration YAML under `cloud/data_dir`. In the `demo` directory, run the following command depending on which compute service you've started.

    ```sh
    cd mc2/demo

    # Specify the `--xgb` flag if running Secure XGBoost. Specify `--sql` for Opaque SQL instead.
    mc2 upload --xgb
    ```

1. Now, you're ready to run computation. Start computation through MC<sup>2</sup> according to the compute service.

    ```sh
    # Specify the `--xgb` flag if running Secure XGBoost. Specify `--sql` for Opaque SQL instead.
    mc2 run --xgb
    ```

1. Once computation has finished, download results. The source and destination of downloaded results can be specified in the configuration YAML under `cloud/results` and `local/results`, respectively. To also decrypt results, specify either `--xgb` or `--sql` to decrypt results outputted by Secure XGBoost or Opaque SQL, respectively.

    For this quickstart, the predictions outputted by Secure XGBoost are sent over the network and automatically decrypted client-side instead of saved to a file, so you will not need to decrypt results if running Secure XGBoost.

    ```sh
    # Download results
    mc2 download

    # If running Opaque SQL, download results and decrypt them
    # mc2 download --sql
    ```

## Documentation
For more thorough documentation on installation and usage, please visit:

* [MC<sup>2</sup> Client](https://mc2-project.github.io/mc2/)
* [Opaque SQL](https://mc2-project.github.io/opaque/)
* [Secure XGBoost](https://secure-xgboost.readthedocs.io/en/latest/)


## Contact
For questions and general discussion, please reach out to mc2-dev@googlegroups.com.
