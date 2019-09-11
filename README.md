# federated-xgboost
This project modifies the tracker in the existing dmlc-core library to enable training XGBoost models in the federated setting. The project is still under development.

### Setup
1. Clone the federated-xgboost codebase.
`git clone https://github.com/mc2-project/federated-xgboost.git` 
<br>
2. Ensure that the Python3 version of XGBoost has been installed on every machine that will be performing training.
`pip3 install xgboost`

3. Configure the tracker by adding all parties' IPs to the `hosts.config` file. The tracker will be connecting to the workers via SSH, so ensure that port 22 is open. A sample config file is available at federated-xgboost/hosts.config.sample.

