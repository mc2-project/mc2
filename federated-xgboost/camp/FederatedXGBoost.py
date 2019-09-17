import xgboost as xgb
from numpy import genfromtxt
import logging

class FederatedXGBoost:
    def __init__(self):
        xgb.rabit.init()
        self.dtrain = None
        self.dtest = None
        self.model = None

    def load_training_data(self, training_data_path):
        training_data = genfromtxt(training_data_path, delimiter=',')
        self.dtrain = xgb.DMatrix(training_data[:, 1:], label=training_data[:, 0])

    def load_test_data(self, test_data_path):
        test_data = genfromtxt(test_data_path, delimiter=',')
        self.dtest = xgb.DMatrix(test_data[:, 1:], label=test_data[:, 0])
    
    def train(self, params, num_rounds):
        if self.dtrain == None:
            logging.error("Training data not yet loaded")
        self.model = xgb.train(params, self.dtrain, num_rounds)

    def predict(self):
        if self.dtest == None:
            logging.error("Test data not yet loaded")
        return self.model.predict(self.dtest)

    def eval(self):
        if self.dtest == None:
            logging.error("Test data not yet loaded")
        return self.model.eval(self.dtest)

    def get_num_parties(self):
        return xgb.rabit.get_world_size()

    def load_model(self, model_path):
        self.model = xgb.Booster()
        self.model.load_model(model_path)

    def save_model(self, model_name):
        self.model.save_model(model_name)
        logging.info("Saved model to {}".format(model_name))

    def shutdown(self):
        logging.info("Shutting down tracker")
        xgb.rabit.finalize()
