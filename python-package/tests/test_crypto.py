import filecmp
import os
import pathlib

import mc2client as mc2
import pytest
import yaml


@pytest.fixture(autouse=True)
def config(tmp_path):
    tests_dir = pathlib.Path(__file__).parent.absolute()
    original_config_path = os.path.join(tests_dir, "config.yaml")

    test_cert = os.path.join(tmp_path, "test.crt")
    test_priv_key = os.path.join(tmp_path, "test.pem")
    test_symm_key = os.path.join(tmp_path, "test_sym.key")

    # Rewrite config YAML with test paths
    config = yaml.safe_load(open(original_config_path).read())
    config["user"]["certificate"] = test_cert
    config["user"]["private_key"] = test_priv_key
    config["user"]["symmetric_key"] = test_symm_key

    # Point to root certificate
    config["user"]["root_private_key"] = os.path.join(tests_dir, "keys/root.pem")
    config["user"]["root_certificate"] = os.path.join(tests_dir, "keys/root.crt")

    test_config_path = os.path.join(tmp_path, "config.yaml")

    with open(test_config_path, "w") as out:
        yaml.dump(config, out, default_flow_style=False)

    mc2.set_config(test_config_path)
    return tests_dir


@pytest.fixture()
def keys(config, tmp_path):
    mc2.generate_symmetric_key()
    mc2.generate_keypair()


@pytest.fixture
def data_paths(config, tmp_path):
    plaintext = os.path.join(config, "data/test_data.csv")
    encrypted = os.path.join(tmp_path, "enc_data")
    decrypted = os.path.join(tmp_path, "test_data.csv.copy")
    return plaintext, encrypted, decrypted


@pytest.fixture
def schema(config):
    return os.path.join(config, "data/test_data.schema")


def test_key_generation(keys, tmp_path):
    test_cert = os.path.join(tmp_path, "test.crt")
    test_priv_key = os.path.join(tmp_path, "test.pem")
    test_symm_key = os.path.join(tmp_path, "test_sym.key")

    assert os.path.exists(test_cert)
    assert os.path.exists(test_priv_key)
    assert os.path.exists(test_symm_key)


def test_opaque_encryption(keys, data_paths, schema):
    plaintext, encrypted, decrypted = data_paths

    mc2.encrypt_data(
        plaintext, encrypted, schema_file=schema, enc_format="opaque",
    )

    mc2.decrypt_data(encrypted, decrypted, enc_format="opaque")

    # Remove first line (header) from original file,
    # as the decrypted copy doesn't have it
    with open(plaintext, "r") as f:
        original = f.readlines()[1:]

    with open(decrypted, "r") as f:
        copy = f.readlines()

    assert original == copy


def test_securexgboost_encryption(keys, data_paths):
    plaintext, encrypted, decrypted = data_paths

    mc2.encrypt_data(
        plaintext, encrypted, enc_format="securexgboost",
    )

    mc2.decrypt_data(encrypted, decrypted, enc_format="securexgboost")

    assert filecmp.cmp(plaintext, decrypted)
