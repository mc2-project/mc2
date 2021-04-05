# MC<sup>2</sup>: A Platform for Secure Analytics and Machine Learning
Born out of research in the [UC Berkeley RISE Lab](https://rise.cs.berkeley.edu/), MC<sup>2</sup> is a platform for running secure analytics and machine learning on confidential data in an untrusted environment, like the cloud. MC<sup>2</sup> provides compute services that can be cryptographically trusted to correctly and securely perform computation on the data, without compromising data confidentiality.

This repo contains the source code for the MC<sup>2</sup> client, which enables a user to interface with MC<sup>2</sup>'s cloud compute services. Actively maintained compute services include:

* [Federated XGBoost](https://github.com/mc2-project/federated-xgboost): Collaborative XGBoost in the federated setting.
* [Opaque SQL](https://github.com/mc2-project/opaque): Encrypted data analytics on Spark SQL using hardware enclaves.
* [Secure XGBoost](https://github.com/mc2-project/secure-xgboost): Collaborative XGBoost training and inference on encrypted data using hardware enclaves.

MC<sup>2</sup> also contains some research prototypes:

* [Cerebro](https://github.com/mc2-project/cerebro): A general purpose Python DSL for learning with secure multiparty computation.
* [Delphi](https://github.com/mc2-project/delphi): Secure inference for deep neural networks.

## Table of Contents
* [MC<sup>2</sup> Client](#mc2-client)
* [Quickstart](#quickstart)
* [Documentation](#documentation)
* [Contact](#contact)

## MC<sup>2</sup> Client
The Opaque SQL and Secure XGBoost compute services require a client to run an end-to-end workflow. In particular, once a user has launched VMs running Opaque SQL or Secure XGBoost (instructions to do so can be found in each repository), the user can encrypt their data and transfer it to such VMs, submit queries to specify the exact computation they want to run, and retrieve and view encrypted results.

## Quickstart
To quickly get a flavor of MC<sup>2</sup>, you can work in a Docker image that comes with pre-built versions of MC<sup>2</sup> Client, Opaque SQL, and Secure XGBoost, and all dependencies. This quickstart is completely self-contained within a container.

1. You must have [Docker](https://docs.docker.com/get-docker/) installed. Once that is done, pull the Docker image and launch a container.

    ```sh
    docker pull mc2project/mc2
    docker run -it -p 22:22 -p 50051-50055:50051-50055 -w /root mc2project/mc2
    ```

1. Navigate to the `mc2-client/demo` directory. The configuration for this quickstart has been pre-populated in `demo/mc2.yaml`. More on the configuration can be found [here](). By default, the configuration has been set assuming you want to run Secure XGBoost. If you want to run Opaque SQL instead, comment out the Secure XGBoost section in the `local` part of the YAML configuration and comment in the Opaque SQL section.

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

    * To start Secure XGBoost, navigate to `/root/secure-xgboost/demo/python/remote-control/server` and start the (simulated) enclave, then navigate to `/root/secure-xgboost/demo/python/remote-control/orchestrator` and start the orchestrator.

    ```sh
    cd /root/secure-xgboost/demo/python/remote-control/server/
    python3 enclave_serve.py

    cd ../orchestrator
    python3 start_orchestrator.py
    ```

    * To start Opaque SQL, navigate to `/root/opaque/` and start everything at once.

    ```sh
    cd /root/opaque/
    build/sbt run
    ```

1. Once you've started the compute service, encrypt and transfer the encrypted data. Data to be encrypted/transferred is in `mc2.yaml` (this is pre-populated with the sample data). In this quickstart, the "transfer" is just a `scp` to another directory in the same container. In practice, the transfer is an upload to a remote machine in the cloud. The destination path for the data can also be specified in the configuration YAML under `cloud/data_dir`. In the `demo` directory, run the following command depending on which compute service you've started.

    ```sh
    # Specify the --xgb flag if running Secure XGBoost
    mc2 upload --xgb

    # Specify the --sql flag if running Opaque SQL
    # mc2 upload --sql
    ```

1. Now, you're ready to run computation. Start computation through MC<sup>2</sup> according to the compute service.

    ```sh
    # Specify the --xgb flag if running Secure XGBoost
    mc2 run --xgb

    # Specify the --sql flag if running Opaque SQL
    # mc2 run --sql
    ```

1. Once computation has finished, download results. The source and destination of downloaded results can be specified in the configuration YAML under `cloud/results` and `local/results`, respectively. To also decrypt results, specify either `--xgb` or `--sql` to decrypt results outputted by Secure XGBoost and Opaque SQL, respectively.

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
