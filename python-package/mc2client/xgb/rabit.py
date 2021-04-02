import grpc

from ..core import _CONF
from ..rpc import (  # pylint: disable=no-name-in-module
    remote_pb2,
    remote_pb2_grpc,
)
from .securexgboost import _check_remote_call


def init(args=None):
    """Initialize the rabit library with arguments"""

    channel_addr = _CONF.get("remote_addr")
    current_user = _CONF.get("current_user")

    if channel_addr is None:
        raise OpaqueClientConfigError(
            "Remote orchestrator IP not set. Run oc.create_cluster() \
            to launch VMs and configure IPs automatically or explicitly set it in the user YAML."
        )

    if current_user is None:
        raise OpaqueClientConfigError("Username not set")

    # FIXME: add signature to rabit init
    with grpc.insecure_channel(channel_addr) as channel:
        stub = remote_pb2_grpc.RemoteStub(channel)
        response = _check_remote_call(
            stub.rpc_RabitInit(
                remote_pb2.RabitParams(
                    params=remote_pb2.Status(status=1),
                    username=current_user
                )
            )
        )


def finalize():
    """Finalize the process, notify tracker everything is done."""
    channel_addr = _CONF.get("remote_addr")
    current_user = _CONF.get("current_user")

    if channel_addr is None:
        raise OpaqueClientConfigError(
            "Remote orchestrator IP not set. Run oc.create_cluster() \
            to launch VMs and configure IPs automatically or explicitly set it in the user YAML."
        )

    if current_user is None:
        raise OpaqueClientConfigError("Username not set")

    # FIXME: add signature to rabit finalize
    with grpc.insecure_channel(channel_addr) as channel:
        stub = remote_pb2_grpc.RemoteStub(channel)
        response = _check_remote_call(
            stub.rpc_RabitFinalize(
                remote_pb2.RabitParams(
                    params=remote_pb2.Status(status=1),
                    username=current_user
                )
            )
        )
