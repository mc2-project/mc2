import os
import shlex
import subprocess
import sys

from setuptools import find_packages, setup

sys.path.insert(0, ".")

subprocess.Popen(
    [
        "python3",
        "-m",
        "grpc_tools.protoc",
        "-I",
        "mc2client/rpc/protos",
        "--python_out=mc2client/rpc",
        "--grpc_python_out=mc2client/rpc",
        "mc2client/rpc/protos/remote.proto",
        "mc2client/rpc/protos/attest.proto",
        "mc2client/rpc/protos/ndarray.proto",
        "mc2client/rpc/protos/opaquesql.proto",
    ]
)

# Get path of built mc2client binary
curr_path = os.path.dirname(os.path.abspath(os.path.expanduser(__file__)))

config_fb_path = os.path.join(curr_path, "mc2client/toolchain/flatbuffers")
# Generate Python flatbuffers files
flatc_path = os.path.join(curr_path, "../src/build/_deps/mc2_serialization-build/flatbuffers/bin/flatc")
schemas_path = os.path.join(curr_path, "../src/build/_deps/mc2_serialization-src/src/flatbuffers/")
schemas = [
   "SignedKey.fbs",
   "sql/EncryptedBlock.fbs",
   "sql/Rows.fbs",
]

for schema in schemas:
    schema_path = schemas_path + schema
    subprocess.Popen(
        [
            flatc_path,
            "--python",
            "-o",
            config_fb_path,
            schema_path
        ]
    )

subprocess.Popen(["chmod", "a+rx", config_fb_path + "/tuix"])

# make pythonpack hack: copy this directory one level upper for setup.py
dll_path = [
    curr_path,
    os.path.join(curr_path, "../src/build/"),
    os.path.join(curr_path, "./build/"),
    os.path.join(sys.prefix, "mc2client"),
]

dll_path = [os.path.join(p, "libmc2client.so") for p in dll_path]
lib_path = [p for p in dll_path if os.path.exists(p) and os.path.isfile(p)]
lib_path = [os.path.relpath(p) for p in lib_path]

setup(
    name="mc2client",
    version="0.0.1",
    description="MC2 Client Python Package",
    #  install_requires=["numpy"],
    zip_safe=False,
    packages=find_packages(),
    package_data={
        "mc2client": [
            "toolchain/scripts/*.sh",
            "toolchain/mc2-schema.json",
            "toolchain/mc2_azure/*.json",
            "toolchain/mc2_azure/*.yaml",
        ]
    },
    data_files=[("mc2client", lib_path)],
    include_package_data=True,
    python_requires=">=3.6",
)

# Configure the shell to set the environment variable MC2_CLIENT_HOME equal
# to the root directory of the mc2 repository for easier paths in
# the configuration yamls.
print("\n####################\n")
print("Configuring shell for MC2 Client...\n")

home_path = os.path.abspath(os.path.join(curr_path, "../"))
# Terminal shell initialization scripts to support
shell_paths = [
    os.path.expanduser("~/.profile"),
    os.path.expanduser("~/.bashrc")
]

def set_path(path):
    try:
        with open(path, "r+") as f:
            # Only write to the file if the environment variable isn't
            # already present
            if 'export MC2_CLIENT_HOME' not in f.read():
                # At this point the file pointer is at the end of the file
                # so writing will append
                f.write(f"export MC2_CLIENT_HOME={home_path}\n")
            return True
    except FileNotFoundError:
        return False

# Attempt to set the environment variable for each shell script
shell_paths_set = [set_path(path) for path in shell_paths]

if not any(shell_paths_set):
    print(f"ERROR: Failed to write to any of the following:\n")
    for path in shell_paths:
        print(f"\t{path}")
    print("\nPlease add the following line to your shell initialization\n"\
          "file to ensure that MC2 Client is configured automatically:\n\n"\
          f"\texport MC2_CLIENT_HOME={home_path}")
else:
    print("Successfully modified:\n")
    for (success, path) in zip(shell_paths_set, shell_paths):
        if success:
            print(f"\t{path}")
    print("\nTo run MC2 Client you may need to restart your current shell.")

env_path = os.path.join(home_path, "mc2_client_env")
print(f"\nTo configure your current shell, run:\n\n\tsource {env_path}\n")
