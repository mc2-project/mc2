import filecmp
import os
import pathlib
import shutil
import yaml

import numpy as np
import mc2client as mc2
import pytest

from envyaml import EnvYAML

# Note: to run this test, you'll need to start a gRPC orchestrator and an enclave running Secure XGBoost
# Follow the demo here to do so: https://secure-xgboost.readthedocs.io/en/latest/tutorials/outsourced.html
# Then, in the test config.yaml, modify the `orchestrator` variable to hold the IP address of the remote VM
# Lastly, run `pytest -s to_test_securexgboost.py` to run this test.
# You'll need to restart the enclave every time you run this test, otherwise you'll get an issue with the nonce
# counter not resetting.


@pytest.fixture(autouse=True)
def config(tmp_path):
    tests_dir = pathlib.Path(__file__).parent.absolute()
    original_config_path = os.path.join(tests_dir, "config.yaml")

    tmp_keys_dir = os.path.join(tmp_path, "keys")
    shutil.copytree(os.path.join(tests_dir, "keys"), tmp_keys_dir)

    test_cert = os.path.join(tmp_path, "keys", "user1.crt")
    test_priv_key = os.path.join(tmp_path, "keys", "user1.pem")
    test_symm_key = os.path.join(tmp_path, "keys", "user1_sym.key")

    # Rewrite config YAML with test paths
    config = EnvYAML(original_config_path)
    config["user"]["certificate"] = test_cert
    config["user"]["private_key"] = test_priv_key
    config["user"]["symmetric_key"] = test_symm_key

    # Point to root certificate
    config["user"]["root_private_key"] = os.path.join(
        tmp_path, "keys/root.pem"
    )
    config["user"]["root_certificate"] = os.path.join(
        tmp_path, "keys/root.crt"
    )

    test_config_path = os.path.join(tmp_path, "config.yaml")

    with open(test_config_path, "w") as out:
        yaml.dump(dict(config), out, default_flow_style=False)

    mc2.set_config(test_config_path)
    return tests_dir


@pytest.fixture()
def attest(config):
    mc2.attest()


# TODO: Ideally, we'd separate all the function calls in `test_securexgboost` into
# their own individual tests, but some functions rely on the results of previous functions
# Additionally, we would ideally attest only once at the beginning of the test suite.
def test_securexgboost(attest, tmp_path):
    # Load our training data
    dtrain = create_dtrain()

    # Load our test data
    dtest = create_dtest()

    # Train a model for 5 rounds
    booster = learn(dtrain)

    # Check if the trained model produces the expected predictions
    predict(booster, dtest)

    # Save original model, load it, and test to see
    # if it produces the same predictions
    save_and_load_model(booster, dtest)

    # Get feature importance
    get_feature_importance_by_weight(booster)
    get_feature_importance_by_gain(booster)
    get_feature_importance_by_cover(booster)
    get_feature_importance_by_total_gain(booster)
    get_feature_importance_by_total_cover(booster)

    # Get model dump
    get_dump(tmp_path, booster)


def create_dtrain():
    dtrain = mc2.xgb.DMatrix({"user1": "/home/chester/agaricus_train.enc"})

    num_col = dtrain.num_col()
    assert num_col == 127

    return dtrain


def create_dtest():
    dtest = mc2.xgb.DMatrix({"user1": "/home/chester/agaricus_test.enc"})

    num_col = dtest.num_col()
    assert num_col == 127

    return dtest


def learn(dtrain):
    params = {
        "tree_method": "hist",
        "n_gpus": "0",
        "objective": "binary:logistic",
        "min_child_weight": "1",
        "gamma": "0.1",
        "max_depth": "3",
        "verbosity": "0",
    }

    bst = mc2.xgb.Booster(params, [dtrain])

    for i in range(5):
        bst.update(dtrain, i, None)

    return bst


def predict(bst, dtest):
    predictions = bst.predict(dtest)[0]
    predictions = [float(i) for i in predictions[:10]]
    predictions = np.round(predictions, 7).tolist()

    expected_predictions = [
        0.1045543,
        0.8036663,
        0.1045543,
        0.1045543,
        0.1366708,
        0.3470695,
        0.8036663,
        0.1176554,
        0.8036663,
        0.1060325,
    ]

    # Check that predictions are as expected for this model and test data
    assert predictions == expected_predictions


def save_and_load_model(bst, dtest):
    bst.save_model("/home/chester/test_model.model")

    new_booster = mc2.xgb.Booster()
    new_booster.load_model("/home/chester/test_model.model")

    predict(new_booster, dtest)


def get_feature_importance_by_weight(bst):
    features = bst.get_fscore()

    # Check that feature importance is as expected
    assert features == {
        "f29": 5,
        "f109": 5,
        "f67": 3,
        "f56": 2,
        "f21": 3,
        "f60": 2,
        "f27": 1,
        "f87": 1,
        "f23": 2,
        "f36": 2,
        "f24": 2,
        "f39": 1,
    }


def get_feature_importance_by_gain(bst):
    features = bst.get_score(importance_type="gain")

    # Check that feature importance is as expected
    assert features == {
        "f29": 1802.9560316,
        "f109": 92.41320182000001,
        "f67": 55.9419556,
        "f56": 806.4257524999999,
        "f21": 276.0743410333333,
        "f60": 396.88085950000004,
        "f27": 258.393555,
        "f87": 33.4832764,
        "f23": 273.617882,
        "f36": 7.1899185345,
        "f24": 324.178024,
        "f39": 26.8505859,
    }


def get_feature_importance_by_cover(bst):
    features = bst.get_score(importance_type="cover")

    # Check that feature importance is as expected
    assert features == {
        "f29": 1253.9055662,
        "f109": 534.3081298,
        "f67": 584.0368756666667,
        "f56": 830.696289,
        "f21": 352.7288766333333,
        "f60": 727.8263855,
        "f27": 248.831985,
        "f87": 530.806152,
        "f23": 542.0738525,
        "f36": 53.75369265,
        "f24": 488.320175,
        "f39": 337.194916,
    }


def get_feature_importance_by_total_gain(bst):
    features = bst.get_score(importance_type="total_gain")

    # Check that feature importance is as expected
    assert features == {
        "f29": 9014.780158,
        "f109": 462.06600910000003,
        "f67": 167.8258668,
        "f56": 1612.8515049999999,
        "f21": 828.2230231,
        "f60": 793.7617190000001,
        "f27": 258.393555,
        "f87": 33.4832764,
        "f23": 547.235764,
        "f36": 14.379837069,
        "f24": 648.356048,
        "f39": 26.8505859,
    }


def get_feature_importance_by_total_cover(bst):
    features = bst.get_score(importance_type="total_cover")

    # Check that feature importance is as expected
    assert features == {
        "f29": 6269.527831,
        "f109": 2671.5406489999996,
        "f67": 1752.110627,
        "f56": 1661.392578,
        "f21": 1058.1866298999998,
        "f60": 1455.652771,
        "f27": 248.831985,
        "f87": 530.806152,
        "f23": 1084.147705,
        "f36": 107.5073853,
        "f24": 976.64035,
        "f39": 337.194916,
    }


def get_dump(tmp_path, bst):
    tests_dir = pathlib.Path(__file__).parent.absolute()
    expected_output = os.path.join(tests_dir, "data/expected_booster.dump")

    output = os.path.join(tmp_path, "booster.dump")
    bst.dump_model(output)

    # Check that dumped model is the same as expected
    assert filecmp.cmp(expected_output, output)
