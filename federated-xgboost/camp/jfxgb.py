import subprocess

class JFedX:
    def __init__(self):
        self.model_path = "jn_model.model"
        self.num_parties = 3
        self.training_data_path = None
        self.training_file = "xgb_train.py"
        self.test_data_path = None
        self.test_file = "xgb_test.py"

    def set_num_parties(self, num_parties):
        self.num_parties = num_parties
    
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

        # output = subprocess.run(["./start_job.sh", "-p", str(self.num_parties),"-m", "3g", "-d", "/home/ubuntu/mc2/federated-xgboost/camp/", "-j", "/home/ubuntu/mc2/federated-xgboost/camp/xgb_train.py"], stdout=subprocess.PIPE)
        # print(output.stdout.decode('utf-8'))

    def load_test_data(self, test_data_path):
        self.test_data_path = test_data_path

    def eval(self):
        with open(self.test_file, "w") as test_file:
            test_file.write("from FederatedXGBoost import FederatedXGBoost")
            test_file.write("\n\nfxgb = FederatedXGBoost()")
            test_file.write("\nfxgb.load_test_data('{}')".format(self.test_data_path))
            test_file.write("\nfxgb.load_model('{}')".format(self.test_data_path))
            test_file.write("\nfxgb.eval()")
            test_file.write("\nfxgb.shutdown()")

        # output = subprocess.run(["./start_job.sh", "-p", str(self.num_parties),"-m", "3g", "-d", "/home/ubuntu/mc2/federated-xgboost/camp/", "-j", "/home/ubuntu/mc2/federated-xgboost/camp/xgb_test.py"], stdout=subprocess.PIPE)
        # print(output.stdout.decode('utf-8'))



