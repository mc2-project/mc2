import grpc

from ..core import _CONF, _check_remote_call
from ..rpc import (  # pylint: disable=no-name-in-module
    opaquesql_pb2,
    opaquesql_pb2_grpc,
)


def run(script):
    """
    Run a Opaque SQL Scala script

    Parameters
    ----------
    script : str
        path to script
    """
    with open(script, "r") as f:
        code = f.read()

    channel_addr = _CONF["remote_addr"]
    with grpc.insecure_channel(channel_addr) as channel:
        stub = opaquesql_pb2_grpc.ListenerStub(channel)
        response = _check_remote_call(
            stub.ReceiveQuery(opaquesql_pb2.QueryRequest(request=code))
        )
        return response.result
