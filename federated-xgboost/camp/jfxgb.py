import subprocess

class JFedX:
    def __init__(self):
        self.model_path = "jn_model.model"
        self.training_data_path = None
        self.training_file = "xgb_train.py"

    def load_training_data(self, training_data_path):
        self.training_data_path = training_data_path
    
    def train(self, params, num_rounds):
        print("Beginning training...")
        with open(self.training_file, "w") as train_file:
            train_file.write("from FederatedXGBoost import FederatedXGBoost")
            train_file.write("\n\nfxgb = FederatedXGBoost()")
            train_file.write("\nfxgb.load_training_data('{}')".format(self.training_data_path))
            train_file.write("\nfxgb.train({}, {})".format(params, num_rounds))
            train_file.write("\nfxgb.save_model('{}')".format(self.model_path))
            train_file.write("\nfxgb.shutdown()")

        output = subprocess.check_output(["./start_job.sh", "-p", "3" ,"-m", "3g", "-d", "/home/ubuntu/mc2/federated-xgboost/camp/", "-j", "/home/ubuntu/mc2/federated-xgboost/camp/xgb_train.py"])
        print(output)
