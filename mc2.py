import argparse
import logging
import os
import pathlib
import shutil
import subprocess
import time

import mc2client as mc2
import mc2client.xgb as xgb

from envyaml import EnvYAML

# Configure logging
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
)
logging.Formatter.converter = time.gmtime

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(help="Command to run.", dest="command")

# -------------Init--------------------
parser_init = subparsers.add_parser(
    "init", help="Optionally generate a symmetric key and keypair"
)

# -------------Launch------------------
parser_launch = subparsers.add_parser("launch", help="Launch Azure resources")

# -------------Start-------------------
parser_start = subparsers.add_parser(
    "start", help="Start services using specificed start up commands"
)

# -------------Upload----------------
parser_upload = subparsers.add_parser("upload", help="Encrypt and upload data.")

# -------------Run--------------------
parser_run = subparsers.add_parser(
    "run", help="Attest the MC\ :sup:`2` deployment and run your script."
)

# -------------Download---------------
parser_download = subparsers.add_parser(
    "download", help="Download and decrypt results from your computation."
)

# -------------Stop-------------------
parser_stop = subparsers.add_parser("stop", help="Stop previously started service")

# -------------Teardown---------------
parser_teardown = subparsers.add_parser("teardown", help="Teardown Azure resources")

if __name__ == "__main__":
    oc_config = os.environ.get("MC2_CONFIG")
    if not oc_config:
        raise Exception(
            "Please set the environment variable `MC2_CONFIG` to the path of your config file"
        )

    mc2.set_config(oc_config)
    args = parser.parse_args()
    config = EnvYAML(oc_config)

    if args.command == "init":
        # Generate a private key and certificate
        mc2.generate_keypair()

        # Generate a CIPHER_KEY_SIZE byte symmetric key
        mc2.generate_symmetric_key()

    elif args.command == "launch":
        config_launch = config["launch"]

        # If the nodes have been manually specified, don't do anything
        if config_launch.get("head") or config_launch.get("workers"):
            logging.warning(
                "Node addresses have been manually specified in the config "
                "... doing nothing"
            )
            quit()

        # Create resource group
        # Will do nothing if already exists
        mc2.create_resource_group()

        # Launch storage if desired
        create_storage = config_launch.get("storage")
        if create_storage:
            mc2.create_storage()

        # Launch container if desired
        create_container = config_launch.get("container")
        if create_container:
            mc2.create_container()

        # Launch cluster if desired
        create_cluster = config_launch.get("cluster")
        if create_cluster:
            mc2.create_cluster()

    elif args.command == "start":
        config_start = config["start"]

        # Get commands to run on head node
        head_cmds = config_start.get("head", [])

        # Get commands to run on worker nodes
        worker_cmds = config_start.get("workers", [])

        # Run commands
        mc2.run_remote_cmds(head_cmds, worker_cmds)

    elif args.command == "upload":
        config_upload = config["upload"]
        enc_format = config_upload.get("format")
        data = config_upload.get("src", [])
        schemas = config_upload.get("schemas", [])

        if config_upload.get("storage") == "blob":
            use_azure = True
        else:
            use_azure = False

        encrypted_data = [d + ".enc" for d in data]

        dst_dir = config_upload.get("dst", "")
        for i in range(len(data)):
            # Encrypt data
            if enc_format == "xgb":
                mc2.encrypt_data(data[i], encrypted_data[i], None, "xgb")
            elif enc_format == "sql":
                if schemas is None:
                    raise Exception(
                        "Please specify a schema when uploading data for Opaque SQL"
                    )
                # Remove temporary files from a previous run
                if os.path.exists(encrypted_data[i]):
                    if os.path.isdir(encrypted_data[i]):
                        shutil.rmtree(encrypted_data[i])
                    else:
                        os.remove(encrypted_data[i])

                mc2.encrypt_data(data[i], encrypted_data[i], schemas[i], "sql")
            else:
                raise Exception("Specified format {} not supported".format(enc_format))

            # Transfer data
            filename = os.path.basename(encrypted_data[i])
            remote_path = filename
            if dst_dir:
                remote_path = os.path.join(dst_dir, filename)
            mc2.upload_file(encrypted_data[i], remote_path, use_azure)

            # Remove temporary directory
            if os.path.isdir(encrypted_data[i]):
                shutil.rmtree(encrypted_data[i])
            else:
                os.remove(encrypted_data[i])

    elif args.command == "run":
        config_run = config["run"]
        script = config_run["script"]

        if config_run["compute"] == "xgb":
            logging.error("run() unimplemented for secure-xgboost")
            quit()
        elif config_run["compute"] == "sql":
            mc2.configure_job(config)
            mc2.opaquesql.run(script)
        else:
            raise Exception("Only XGBoost and SQL are currently supported")

    elif args.command == "download":
        config_download = config["download"]
        enc_format = config_download.get("format")

        if config_download.get("storage") == "blob":
            use_azure = True
        else:
            use_azure = False

        remote_results = config_download.get("src", [])
        local_results_dir = config_download["dst"]

        # Create the local results directory if it doesn't exist
        if not os.path.exists(local_results_dir):
            pathlib.Path(local_results_dir).mkdir(parents=True, exist_ok=True)

        for remote_result in remote_results:
            filename = os.path.basename(remote_result)
            local_result = os.path.join(local_results_dir, filename)

            # Fetch file
            mc2.download_file(remote_result, local_result, use_azure)

            # Decrypt data
            if enc_format == "xgb":
                mc2.decrypt_data(local_result, local_result + ".dec", "xgb")
            elif enc_format == "sql":
                mc2.decrypt_data(local_result, local_result + ".dec", "sql")
            else:
                raise Exception("Specified format {} not supported".format(enc_format))

            if os.path.isdir(local_result):
                shutil.rmtree(local_result)
            else:
                os.remove(local_result)

    elif args.command == "stop":
        logging.error("`opaque stop` is currently unsupported")
        pass

    elif args.command == "teardown":
        config_teardown = config["teardown"]

        # If the nodes have been manually specified, don't do anything
        if config["launch"].get("head") or config["launch"].get("workers"):
            logging.warning(
                "Node addresses have been manually specified in the config "
                "... doing nothing"
            )
            quit()

        delete_container = config_teardown.get("container")
        if delete_container:
            mc2.delete_container()

        delete_storage = config_teardown.get("storage")
        if delete_storage:
            mc2.delete_storage()

        delete_cluster = config_teardown.get("cluster")
        if delete_cluster:
            mc2.delete_cluster()

        delete_resource_group = config_teardown.get("resource_group")
        if delete_resource_group:
            mc2.delete_resource_group()

    else:
        logging.error(
            "Unsupported command specified. Please type `opaque -h` for a list of supported commands."
        )
