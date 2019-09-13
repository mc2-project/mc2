#!/usr/bin/python3

import numpy as np
from FederatedXGBoost import FederatedXGBoost

# Instantiate FederatedXGBoost
fxgb = FederatedXGBoost()

# Get number of federating parties
print(fxgb.get_num_parties())

# Load training data
# Ensure that each party's data is in the same location with the same name
fxgb.load_training_data('/home/ubuntu/mc2/data/msd_training_data_split.csv')

# Train a model
params = {'max_depth': 3, 'min_child_weight': 1.0, 'lambda': 1.0}
num_rounds = 40
fxgb.train(params, num_rounds)

# Load the test data
fxgb.load_test_data('/home/ubuntu/mc2/data/msd_test_data_split.csv')

# Evaluate the model
print(fxgb.eval())

# Get predictions
ypred = fxgb.predict()

# Save the model
fxgb.save_model("sample_model.model")

# Shutdown
fxgb.shutdown()


