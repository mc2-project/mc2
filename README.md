# federated-xgboost
Federated learning allows multiple parties to collaboratively learn a shared model while keeping each party's data at its respective site. It allows for collaborative learning with lower latencies while ensuring data privacy.

This project extends the existing XGBoost gradient boosting machine learning framework to enable training models in the federated setting. This work is being actively contributed to and is still under development.

### Quickstart
1. Clone the federated-xgboost codebase and initialize the submodule.

    ```sh
    git clone https://github.com/mc2-project/federated-xgboost.git
    git submodule init 
    git submodule update
    ```

2. Ensure that the Python3 version of XGBoost has been installed on every machine that will be performing training.

    ```sh
    pip3 install xgboost
    ```

3. Ensure that SSH keys have been properly set up between the tracker and other parties. 
    * If the machine running the tracker doesn't yet have SSH keys set up (most likely at `~/.ssh/`), generate a 4096 bit RSA key. There should now be keys at `~/.ssh/`
        ```sh
        ssh-keygen -t rsa -b 4096
        ```
    * Otherwise, if the tracker has already set up SSH keys, ensure that the private key is in a file named `~/.ssh/id_rsa`.
    * Set up communication between the tracker and the worker nodes by appending the driver's public key to the `~/.ssh/authorized_keys` file of all nodes. The public key should be in `~/.ssh/id_rsa.pub`. You can manually copy and paste the public key over to each party's node.
    * Make sure that you also add the public key to the tracker's own `~/.ssh/authorized_keys` file.

4. Modify the `hosts.config` file in `federated-xgboost/sample/` to reflect the IPs of the parties. 

5. Place the training and test data .csv files at each party **at the same location**. Replace the paths passed into `fxgb.load_training_data()` and `fxgb.load_test_data()` with your respective paths.

6. Ensure that the `sample.py` file is at the same place on the machine of each party. For example, if on the tracker machine the `sample.py` file is at `/home/ubuntu/federated-xgboost/sample/sample.py`, ensure that the same path exists on machines of all parties.  

7. Run the following command to start the `sample.py` training and evaluation script.
    ```sh
    ./start_job.sh -w 3 -d /home/ubuntu/federated-xgboost/sample/ -j /home/ubuntu/federated-xgboost/sample/sample.py -w 3g
    ``` 

### Usage
The following flags must be specified when running the `start_job.sh`
``` sh
./start_job.sh
``` 
* `-m | --worker-memory` string, specified as "<memory>g", e.g. 3g
    * Amount of memory on workers allocated to job
* `-p | --num-parties` integer
    * Number of parties in the federation
* `-d | --dir` string
    * Path to created subdirectory containing job script, e.g. `/home/ubuntu/federated-xgboost/sample`
* `-j | --job` string
    * Path to job script. This should be the parameter passed into the `--dir` option concatenated with the job script file name, e.g. `/home/ubuntu/federated-xgboost/sample/sample.py`
    


### Notes
* This has only been tested with Python 3
* The recommended (required) way of running distributed training is by creating a subdirectory in the `federated-xgboost/` directory that contains `hosts.config`, the training script, `start_job.sh`, and `FederatedXGBoost.py`. Run the `start_job.sh` from the subdirectory.
* `FederatedXGBoost.py` is a wrapper that simplifies the data loading, training, and evaluation process. 
* The `--sync-dst-dir` option in the `dmlc-submit` command copies everything in the passed in directory to all worker machines.This means that the training script can initially only be on the tracker machine, and will be automatically copied over to all parties once the job is submitted. 
