import os
import pathlib

import mc2client as mc2
from . import test_logger as logger


logger.info("Setting config file path")
tests_dir = pathlib.Path(__file__).parent.absolute()
config = os.path.join(tests_dir, "../test.yaml")
mc2.set_config(config)

download_path = os.path.join(tests_dir, "dummy_downloaded.txt")

logger.info("Downloading file")
mc2.download_file("dummy.txt", download_path)

if not os.path.isfile(download_path):
    logger.info("Error: Couldn't download file from Azure")
else:
    os.remove(download_path)

logger.info("Deleting container")
mc2.delete_container()

logger.info("Deleting storage")
mc2.delete_storage()

logger.info("Deleting cluster")
mc2.delete_cluster()

logger.info("Deleting resource group")
mc2.delete_resource_group()
