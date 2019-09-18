from FederatedXGBoost import FederatedXGBoost

fxgb = FederatedXGBoost()
fxgb.load_test_data('/home/ubuntu/data/msd_test_data_split.csv')
fxgb.load_model(/home/ubuntu/data/msd_test_data_split.csv)
fxgb.eval()
fxgb.shutdown()