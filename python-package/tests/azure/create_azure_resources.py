import os
import pathlib

import mc2client as mc2

tests_dir = pathlib.Path(__file__).parent.absolute()
config = os.path.join(tests_dir, "../test.yaml")
mc2.set_config(config)

dummy_file = os.path.join(tests_dir, "dummy.txt")

print("Creating resource group")
mc2.create_resource_group()

print("Creating storage")
mc2.create_storage()

print("Creating container")
mc2.create_container()

print("Uploading file")
mc2.upload_file(dummy_file, "dummy.txt")

print("Creating cluster")
mc2.create_cluster()
