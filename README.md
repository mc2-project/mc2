# federated-xgboost
This project modifies the tracker in the existing dmlc-core library to enable training XGBoost models in the federated setting. The project is still under development.

### Quickstart
1. Clone the federated-xgboost codebase.

  ```sh
  git clone https://github.com/mc2-project/federated-xgboost.git
  ```

2. Ensure that the Python3 version of XGBoost has been installed on every machine that will be performing training.

  ```sh
  pip3 install xgboost
  ```

3. Ensure that SSH keys have been properly set up between the tracker (driver) and the worker nodes by adding the driver's public key to the `authorized_keys` file of all worker nodes.  

4. Modify the `hosts.config` file in `federated-xgboost/sample/` to reflect the IPs of the parties. 

5. Place the training and test data .csv files at each party **at the same location**. Replace the paths passed into `fxgb.load_training_data()` and `fxgb.load_test_data()` with your respective paths.

6. Ensure that the `sample.py` file is at the same place on the machine of each party. For example, if on the tracker machine the `sample.py` file is at `/home/ubuntu/federated-xgboost/sample/sample.py`, ensure that the same path exists on machines of all parties.  

7. Run the following command to start the `sample.py` training and evaluation script.
  ```sh
  ../dmlc-core/tracker/dmlc-submit --cluster ssh --num-workers 3  --host-file hosts.config --worker-memory 3g --sync-dst-dir <path to federated-xgboost/sample on each machine> python3 <path to federated-xgboost/sample/sample.py on each machine>
  ``` 


### Notes
* This has only been tested with Python 3
* The recommended way of running distributed training is by creating a subdirectory in the `federated-xgboost/` directory that contains `hosts.config`, the training script, and `FederatedXGBoost.py`. `FederatedXGBoost.py` is a wrapper that simplifies the data loading, training, and evaluation process. 
* The `--sync-dst-dir` option in the `dmlc-submit` command copies everything in the passed in directory to all worker machines.This means that the training script can initially only be on the tracker machine, and will be automatically copied over to all parties once the job is submitted. 
