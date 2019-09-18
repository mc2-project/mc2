from FederatedXGBoost import FederatedXGBoost

fxgb = FederatedXGBoost()
fxgb.load_training_data('/home/ubuntu/data/training_data_split.csv')
fxgb.train({'max_depth': 3, 'min_child_weight': 1.0, 'lambda': 1.0}, 40)
fxgb.save_model('jn_model.model')
fxgb.shutdown()