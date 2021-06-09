# Import the needed management objects from the libraries. The azure.common library
# is installed automatically with the other libraries.
import os

from azure.common.client_factory import get_client_from_cli_profile
from azure.mgmt.storage import StorageManagementClient
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceExistsError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

container_client = None


class CryptoUtil(object):
    KEY_SIZE = 16
    NONCE_SIZE = 12
    backend = default_backend()

    # Generate a private key given a password
    @classmethod
    def generate_priv_key(cls, priv_key_path):
        # 128 bit security, like in Secure XGBoost
        key = AESGCM.generate_key(bit_length=cls.KEY_SIZE * 8)
        with open(priv_key_path, "wb") as priv_key:
            priv_key.write(key)

    @classmethod
    def encrypt_data(cls, priv_key_path, input_filename):
        # FIXME: if file is larger than memory, we should read in chunks
        with open(priv_key_path, "rb") as priv_key, open(
            input_filename, "rb"
        ) as input_file:

            key = priv_key.read()
            data = input_file.read()
            cipher = AESGCM(key)

            nonce = os.urandom(cls.NONCE_SIZE)
            enc_data = cipher.encrypt(nonce, data, b"")

            data = nonce + enc_data

            return data

    @classmethod
    def decrypt_data(cls, priv_key_filename, enc_data, output_filename):
        with open(priv_key_filename, "rb") as priv_key, open(
            output_filename, "wb"
        ) as output_file:

            key = priv_key.read()
            cipher = AESGCM(key)

            nonce = enc_data[: cls.NONCE_SIZE]
            data = enc_data[cls.NONCE_SIZE :]  # noqa: E203

            aad = b""
            dec_data = cipher.decrypt(nonce, data, aad)
            output_file.write(dec_data)


def create_storage(config):
    rg_name = config["resource_group"]
    location = config["location"]
    storage_name = config["storage_name"]

    storage_client = get_client_from_cli_profile(StorageManagementClient)
    availability_result = storage_client.storage_accounts.check_name_availability(
        storage_name
    )

    if not availability_result.name_available:
        # TODO: add logging warning
        print("Storage account {} already exists, skipping storage account creation".format(storage_name))
        return

    # The name is available, so provision the account
    poller = storage_client.storage_accounts.create(
        rg_name,
        storage_name,
        {"location": location, "kind": "StorageV2", "sku": {"name": "Standard_ZRS"}},
    )

    # Long-running operations return a poller object; calling poller.result()
    # waits for completion.
    account_result = poller.result()
    print(f"Provisioned storage account {account_result.name}")


def terminate_storage(config):
    rg_name = config["resource_group"]
    location = config["location"]
    storage_name = config["storage_name"]

    storage_client = get_client_from_cli_profile(StorageManagementClient)
    storage_client.storage_accounts.delete(
        rg_name, storage_name, {"location": location, "kind": "StorageV2"}
    )


def create_container(config):
    container_name = ""
    try:
        blob_service_client = get_blob_service_client(config)
        container_name = config["container_name"]
        blob_service_client.create_container(container_name)
    except ResourceExistsError as e:
        # TODO: add logging warning
        print("The specified container {} already exists".format(container_name))

def terminate_container(config):
    blob_service_client = get_blob_service_client(config)
    container_name = config["container_name"]
    container_client = blob_service_client.get_container_client(container_name)
    container_client.delete_container()


# Obtain the management object for resources, using the credentials from the CLI login.
def get_blob_service_client(config):
    storage_client = get_client_from_cli_profile(StorageManagementClient)
    rg_name = config["resource_group"]
    storage_name = config["storage_name"]
    keys = storage_client.storage_accounts.list_keys(rg_name, storage_name)
    conn_string = (
        "DefaultEndpointsProtocol=https;AccountName={};"
        "AccountKey={};EndpointSuffix=core.windows.net".format(
            storage_name, keys.keys[0].value
        )
    )
    blob_service_client = BlobServiceClient.from_connection_string(conn_str=conn_string)
    return blob_service_client


# `blob_name` is the blob that we want to write to/read from
def get_blob_client(config, blob_name):
    blob_service_client = get_blob_service_client(config)
    blob_client = blob_service_client.get_blob_client(
        container=config["container_name"], blob=blob_name
    )
    return blob_client


def upload_data(config, data, blob_name, overwrite=True):
    blob_client = get_blob_client(config, blob_name)
    blob_client.upload_blob(data, overwrite=overwrite)


def upload_data_from_file(config, input_filename, blob_name, overwrite=True):
    with open(input_filename, "rb") as input_file:
        data = input_file.read()
        upload_data(config, data, blob_name, overwrite=overwrite)


def download_data(config, blob_name, output_filename=None):
    blob_client = get_blob_client(config, blob_name)
    data = blob_client.download_blob().readall()

    if output_filename:
        with open(output_filename, "wb") as output_file:
            output_file.write(data)
    else:
        return data


# The below two functions are currently not used and do not work
def encrypt_and_upload_data(config, input_file_path, blob_name):
    priv_key_path = ["priv_key_path"]
    enc_data = CryptoUtil.encrypt_data(priv_key_path, input_file_path)
    upload_data(config, enc_data, blob_name)


def download_and_decrypt_data(config, blob_name, output_file_path):
    priv_key_path = config["priv_key_path"]
    enc_data = download_data(config, blob_name)
    CryptoUtil.decrypt_data(priv_key_path, enc_data, output_file_path)
