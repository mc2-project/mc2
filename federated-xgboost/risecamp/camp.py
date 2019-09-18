import numpy as np
from FederatedXGBoost import FederatedXGBoost

# Instantiate FederatedXGBoost
fxgb = FederatedXGBoost()

fxgb.load_model("sample_model.model")

# Load the test data
fxgb.load_test_data('/home/ubuntu/data/msd_test_data_split.csv')

# Evaluate the model
print(fxgb.eval())

# Get predictions
ypred = fxgb.predict()

# Shutdown
fxgb.shutdown()


