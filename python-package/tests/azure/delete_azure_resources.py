import os
import pathlib

import mc2client as mc2

print("Setting config file path")
tests_dir = pathlib.Path(__file__).parent.absolute()
config = os.path.join(tests_dir, "../test.yaml")
mc2.set_config(config)

download_path = os.path.join(tests_dir, "dummy_downloaded.txt")

print("Downloading file")
mc2.download_file("dummy.txt", download_path)

if not os.path.isfile(download_path):
    print("Error: Couldn't download file from Azure")
else:
    os.remove(download_path)

print("Deleting container")
mc2.delete_container()

print("Deleting storage")
mc2.delete_storage()
  
print("Deleting cluster")
mc2.delete_cluster()

print("Deleting resource group")
mc2.delete_resource_group()
