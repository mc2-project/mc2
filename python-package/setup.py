import multiprocessing
import os
import shutil
import subprocess
import sys

from setuptools import find_packages, setup

# Get the absolute path of setup.py
setup_path = os.path.dirname(os.path.abspath(os.path.expanduser(__file__)))

# ---- Generate gRPC files ----
rpc_path = os.path.join(setup_path, "mc2client/rpc")
subprocess.Popen(
    [
        "python3",
        "-m",
        "grpc_tools.protoc",
        "-I",
        os.path.join(rpc_path, "protos"),
        f"--python_out={rpc_path}",
        f"--grpc_python_out={rpc_path}",
        os.path.join(rpc_path, "protos/ndarray.proto"),
        os.path.join(rpc_path, "protos/opaquesql.proto"),
        os.path.join(rpc_path, "protos/remote.proto"),
        os.path.join(rpc_path, "protos/attest.proto"),
    ]
)

# ---- Run CMake build ----

# Create the build directory
build_path = os.path.join(setup_path, "../src/build")
if not os.path.exists(build_path):
    os.makedirs(build_path)

# Call CMake and then Make (number of threads is equal to the number of
# physical CPU cores)
subprocess.check_call(
    ["cmake", os.path.join(build_path, "../")], cwd=build_path
)
subprocess.check_call(
    ["make", "-j", str(multiprocessing.cpu_count())], cwd=build_path
)

# ---- Generate flatbuffers files ----

config_fb_path = os.path.join(setup_path, "mc2client/toolchain/flatbuffers")
flatc_path = os.path.join(
    setup_path,
    "../src/build/_deps/mc2_serialization-build/flatbuffers/bin/flatc",
)
schemas_path = os.path.join(
    setup_path, "../src/build/_deps/mc2_serialization-src/src/flatbuffers/"
)
schemas = [
    "SignedKey.fbs",
    "sql/EncryptedBlock.fbs",
    "sql/Rows.fbs",
]
for schema in schemas:
    schema_path = schemas_path + schema
    subprocess.Popen(
        [flatc_path, "--python", "-o", config_fb_path, schema_path]
    )
subprocess.Popen(["chmod", "a+rx", config_fb_path + "/tuix"])

# ---- Install Opaque Client----

lib_path = [
    os.path.relpath(os.path.join(setup_path, "../src/build/libmc2client.so"))
]

setup(
    name="mc2client",
    version="0.0.1",
    description="MC2 Client Python Package",
    #  install_requires=["numpy"],
    zip_safe=False,
    packages=find_packages(),
    package_data={
        "mc2client": [
            os.path.join(setup_path, "mc2client/toolchain/scripts/*.sh"),
            os.path.join(setup_path, "mc2client/toolchain/mc2-schema.json"),
            os.path.join(setup_path, "mc2client/toolchain/mc2_azure/*.json"),
            os.path.join(setup_path, "mc2client/toolchain/mc2_azure/*.yaml"),
        ]
    },
    data_files=[("mc2client", lib_path)],
    include_package_data=True,
    python_requires=">=3.6",
)

# ---- Configure environment variables ----
# Configure the shell to set the environment variable MC2_CLIENT_HOME equal
# to the root directory of the mc2 repository for easier paths in
# the configuration yamls.

print("\n####################\n")
print("Configuring shell for MC2 Client...\n")

home_path = os.path.abspath(os.path.join(setup_path, "../"))
# Terminal shell initialization scripts to support
shell_paths = [
    os.path.expanduser("~/.profile"),
    os.path.expanduser("~/.bashrc"),
]


def set_path(path):
    try:
        with open(path, "r+") as f:
            # Only write to the file if the environment variable isn't
            # already present
            if "export MC2_CLIENT_HOME" not in f.read():
                # At this point the file pointer is at the end of the file
                # so writing will append
                f.write(f"export MC2_CLIENT_HOME={home_path}\n")

            # Reset the file pointer
            f.seek(0)

            # Add an alias to a bashrc or bash_profile if it exists
            if (
                "bashrc" in path or "bash_profile" in path
            ) and "alias mc2" not in f.read():
                # At this point the file pointer is at the end of the file
                # so writing will append
                alias_str = f'alias mc2="python3 {home_path}/mc2.py"'
                f.write(alias_str + "\n")
                subprocess.check_call([alias_str])
            return True
    except FileNotFoundError:
        return False


# Attempt to set the environment variable for each shell script
shell_paths_set = [set_path(path) for path in shell_paths]

if not any(shell_paths_set):
    print("ERROR: Failed to write to any of the following:\n")
    for path in shell_paths:
        print(f"\t{path}")
    print(
        "\nPlease add the following line to your shell initialization\n"
        "file to ensure that MC2 Client is configured automatically:\n\n"
        f"\texport MC2_CLIENT_HOME={home_path}"
    )
else:
    print("Successfully modified:\n")
    for (success, path) in zip(shell_paths_set, shell_paths):
        if success:
            print(f"\t{path}")
    print("\nTo run MC2 Client you may need to restart your current shell.")

env_path = os.path.join(home_path, "mc2_client_env")
print(f"\nTo configure your current shell, run:\n\n\tsource {env_path}\n")
