import os
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
        "mc2client/rpc/protos/ndarray.proto",
        "mc2client/rpc/protos/opaquesql.proto",
    ]
)

# Get path of built mc2client binary
curr_path = os.path.dirname(os.path.abspath(os.path.expanduser(__file__)))
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
