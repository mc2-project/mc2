import grpc

from ..core import _CONF, _check_remote_call, get_head_ip
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

    # Job requires a TMS
    if _CONF["use_azure"]:
        head_address = get_head_ip() + ":50052"
    else:
        head_address = _CONF["head"]["ip"] + ":50052"
    with grpc.insecure_channel(head_address) as channel:
        stub = opaquesql_pb2_grpc.ListenerStub(channel)
        response = _check_remote_call(
            stub.ReceiveQuery(opaquesql_pb2.QueryRequest(request=code))
        )
        return response.result
