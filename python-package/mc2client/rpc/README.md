# Building RPC

If making changes to any of the files, rebuild using the following command within the rpc/ directory

python3 -m grpc_tools.protoc -Iprotos --python_out=. --grpc_python_out=. protos/remote.proto protos/ndarray.proto
