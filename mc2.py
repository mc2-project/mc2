import argparse
import os
import pathlib
import shutil
import subprocess

import mc2client as mc2
import mc2client.xgb as xgb
import yaml


parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(help="Command to run.", dest="command")
parser_upload = subparsers.add_parser(
    "upload", help="Encrypt and upload data."
)
parser_upload.add_argument("--sql", help="Encrypt data in Opaque SQL format", action="store_true")
parser_upload.add_argument("--xgb", help="Encrypt data in Opaque XGBoost format", action="store_true")

parser_run = subparsers.add_parser(
    "run", help="Attest the MC\ :sup:`2` deployment and run your script."
)
parser_run.add_argument("--sql", help="Run the Opaque SQL code specified in the config", action="store_true")
parser_run.add_argument("--xgb", help="Run the Opaque XGBoost code specified in the config", action="store_true")

parser_download = subparsers.add_parser(
    "download", help="Download and decrypt results from your computation."
)
parser_download.add_argument("--sql", help="Decrypt data in Opaque SQL format", action="store_true")
parser_download.add_argument("--xgb", help="Decrypt data in Opaque XGBoost format", action="store_true")

if __name__ == "__main__":
    mc2_config = os.environ.get("MC2_CONFIG")
    if not mc2_config:
        raise Exception("Please set the environment variable `MC2_CONFIG` to the path of your config file")

    mc2.set_config(mc2_config)
    args = parser.parse_args()
    config = yaml.safe_load(open(mc2_config).read())

    # All data that will be used during computation
    data = config["local"]["data"]

    # Path to schemas for Opaque SQL execution
    schemas = config["local"].get("schemas")

    # Username to use to scp data to cloud
    remote_username = config["cloud"]["remote_username"]

    # Remote data path
    remote_data = config["cloud"]["data_dir"]

    # List of IPs to upload data to 
    ips = config["cloud"]["nodes"]

    # Script to run
    script = config["local"]["script"]

    # Remote path to results (a list)
    remote_results = config["cloud"]["results"]

    # Path to local results
    local_results_dir = config["local"]["results"]

    # TODO: upload data to multiple machines
    if args.command == "upload":
        encrypted_data = [d + ".enc" for d in data]
        print("Encrypting and uploading data...")

        for i in range(len(data)):
            # Encrypt data
            if args.xgb:
                mc2.encrypt_data(data[i], encrypted_data[i], None, "securexgboost")
            elif args.sql:
                mc2.encrypt_data(data[i], encrypted_data[i], schemas[i], "opaque")
            else:
                raise Exception("Specified format not supported")

            # Transfer data
            filename = os.path.basename(encrypted_data[i])
            remote_path = os.path.join(remote_data, filename)
            mc2.upload_file(encrypted_data[i], remote_path)

    elif args.command == "run":
        if args.xgb:
            # TODO: comment in rabit functionality if you want to run in distributed manner
            # mc2.xgb.rabit.init()
            mc2.attest()
            print("Remote attestation succeeded")
            print("Running script...")
            exec(open(script).read())
            # mc2.xgb.rabit.finalize()
        elif args.sql:
            mc2.opaquesql.run(script)
        else:
            raise Exception("Only XGBoost and SQL are currently supported")

    elif args.command == "download":
        print("Downloading and decrypting data")

        # Create the local results directory if it doesn't exist
        if not os.path.exists(local_results_dir):
            pathlib.Path(local_results_dir).mkdir(parents=True, exist_ok=True)

        for remote_result in remote_results:
            filename = os.path.basename(remote_result)
            local_result = os.path.join(local_results_dir, filename)

            # Fetch file
            mc2.download_file(remote_result, local_result)

            # Decrypt data
            if args.xgb:
                mc2.decrypt_data(local_result, os.path.join(local_result, ".dec"), "securexgboost")
            elif args.sql:
                mc2.decrypt_data(local_result, os.path.join(local_result, ".dec"), "opaque")
            else:
                raise Exception("Specified format not supported")

