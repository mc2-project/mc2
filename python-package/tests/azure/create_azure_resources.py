import os
import pathlib

import mc2client as mc2
from . import test_logger as logger

tests_dir = pathlib.Path(__file__).parent.absolute()
config = os.path.join(tests_dir, "../test.yaml")
mc2.set_config(config)

dummy_file = os.path.join(tests_dir, "dummy.txt")

logger.info("Creating resource group")
mc2.create_resource_group()

logger.info("Creating storage")
mc2.create_storage()

logger.info("Creating container")
mc2.create_container()

logger.info("Uploading file")
mc2.upload_file(dummy_file, "dummy.txt")

logger.info("Creating cluster")
mc2.create_cluster()
