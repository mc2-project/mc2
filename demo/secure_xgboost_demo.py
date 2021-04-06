import mc2client.xgb as xgb

# Load training data
# TODO: fill in the path to your training data
dtrain = xgb.DMatrix({"user1": "/root/data/securexgb_train.csv.enc?format=csv&label_column=9"})

# Get number of columns in training data
training_num_cols = dtrain.num_col()

# Load test data
# TODO: fill in the path to your test data
dtest = xgb.DMatrix({"user1": "/root/data/securexgb_test.csv.enc?format=csv&label_column=9"})

# Get number of columns in test data
test_num_col = dtest.num_col()

# Train a model
params = {
    "tree_method": "hist",
    "n_gpus": "0",
    "objective": "binary:logistic",
    "min_child_weight": "1",
    "gamma": "0.1",
    "max_depth": "120",
    "verbosity": "0",
    "max_bin": "256",
}

bst = xgb.Booster(params, [dtrain])

num_rounds = 10
for i in range(num_rounds):
    bst.update(dtrain, i, None)

# Save model
bst.save_model("/root/results/xgb.model")

# Get fscores of model
feature_map = bst.get_fscore()

# Get features
sorted_features = {feature: importance for feature, importance in sorted(feature_map.items(), key=lambda item: item[1], reverse=True)}

# Get encrypted predictions
predictions = bst.predict(dtest)[0]

# Print first 10 predictions
print("Probability of breast cancer of first 10 patients:")
for i in range(10):
    print(predictions[i], end=" ")
print("\n\n")

print("Probability of breast cancer of last 10 patients:")
for i in range(10):
    print(predictions[-i], end=" ")
print("")
