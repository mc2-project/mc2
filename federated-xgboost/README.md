# federated-xgboost
Federated learning allows multiple parties to collaboratively learn a shared model while keeping each party's data at its respective site. It allows for collaborative learning with lower latencies without a central data storage, thereby improving the privacy of individual parties' data.

In the federated setting, a central party has a basic model that is initially broadcast to all parties. Each party locally trains the model with its own data, then sends a summary of the updates to the model back to the central party. In the decision tree case, parties would be sending the best local feature splits back to the central party. The central party then aggregates all updates, updates its own model with the aggregated update, and broadcasts the newly updated model to all parties. This process is then repeated over and over.

![federated diagram](./images/federated-xgboost-diagram.png)

This project extends the existing XGBoost gradient boosting machine learning framework to enable training models in the federated setting. This work is being actively contributed to and is still under development.

### Quickstart
1. Clone the federated-xgboost codebase and initialize the submodule.

    ```sh
    git clone https://github.com/mc2-project/mc2.git
    git submodule init 
    git submodule update
    ```

2. Ensure that the necessary packages have been installed on every machine that will be performing training.

    ```sh
    pip3 install -r requirements.txt
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

6. The recommended (required) way of running distributed training is by creating a subdirectory in the `federated-xgboost/` directory that contains `hosts.config`, the training script, `start_job.sh`, and `FederatedXGBoost.py`. No modifications are needed to `start_job.sh` and `FederatedXGBoost.py`. You can just copy them over to the new subdirectory.

7. Ensure that there is a directory named `federated-xgboost/` at the same place on each party's machine. The directory doesn't have to contain anything on any of the non-tracker machines, but must exist. For example, if on the tracker machine the `federated-xgboost/` file is at `/home/ubuntu//mc2/federated-xgboost/`, ensure that the same path exists on machines of all parties.  

8. Run the following command to start the `sample.py` job script.
    ```sh
    ./start_job.sh -p 3 -m 3g -d /home/ubuntu/mc2/federated-xgboost/sample/ -j /home/ubuntu/mc2/federated-xgboost/sample/sample.py 
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
    * Path to created subdirectory containing job script, e.g. `/home/ubuntu/mc2/federated-xgboost/sample`
* `-j | --job` string
    * Path to job script. This should be the parameter passed into the `--dir` option concatenated with the job script file name, e.g. `/home/ubuntu/mc2/federated-xgboost/sample/sample.py`
    
### Notes
* This has only been tested with Python 3
* `FederatedXGBoost.py` is a wrapper that simplifies the data loading, training, and evaluation process. 
* The `--sync-dst-dir` option in the `dmlc-submit` command copies everything in the passed in directory to all worker machines.This means that the training script can initially only be on the tracker machine, and will be automatically copied over to all parties once the job is submitted. 
