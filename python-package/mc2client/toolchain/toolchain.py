import copy
import hashlib
import json
import logging
import os
import sys
import tempfile
import time
import yaml

from .encrypt_and_upload import (
    create_container,
    create_storage,
    download_data,
    terminate_container,
    terminate_storage,
    upload_data_from_file,
)
from .log_timer import LogTimer
from .mc2_azure.config import create_or_delete_resource_group
from .node_provider import NODE_PROVIDERS, get_node_provider
from .tags import (
    NODE_TYPE_HEAD,
    NODE_TYPE_WORKER,
    TAG_MC2_LAUNCH_CONFIG,
    TAG_MC2_NODE_NAME,
    TAG_MC2_NODE_TYPE,
)
from .updater import NodeUpdaterThread
from .util import (
    hash_launch_conf,
    hash_runtime_conf,
    prepare_config,
    validate_config,
)

logger = logging.getLogger(__name__)


def create_or_update_cluster(config):
    """Create or updates an MC2 cluster from a config json."""
    config = _bootstrap_config(config)
    logger.info("Creating head node")
    get_or_create_head_node(copy.deepcopy(config))
    logger.info("Creating worker nodes")
    get_or_create_worker_nodes(config)
    logger.info("Cluster creation complete")


def get_or_create_worker_nodes(config):
    """Create the workers."""
    provider = get_node_provider(config["provider"], config["cluster_name"])
    try:
        worker_filter = {TAG_MC2_NODE_TYPE: NODE_TYPE_WORKER}
        nodes = provider.non_terminated_nodes(worker_filter)
        launch_hash = hash_launch_conf(config["worker_nodes"], config["auth"])
        node_config = config["worker_nodes"]
        node_tags = {
            TAG_MC2_NODE_NAME: "mc2-{}-worker".format(config["cluster_name"]),
            TAG_MC2_NODE_TYPE: NODE_TYPE_WORKER,
            # TAG_MC2_NODE_STATUS: STATUS_UNINITIALIZED,
            TAG_MC2_LAUNCH_CONFIG: launch_hash,
        }
        count = config["num_workers"] - len(nodes)
        if count > 0:
            provider.create_node(node_config, node_tags, count)

        while True:
            nodes = provider.non_terminated_nodes(node_tags)
            if len(nodes) == config["num_workers"]:
                break
            time.sleep(1)

        # TODO: right now we always update the nodes even if the hash
        # matches. We could prompt the user for what they want to do here.
        runtime_hash = hash_runtime_conf(config["file_mounts"], config)
        logger.info("get_or_create_worker_nodes: Updating files on worker nodes...")

        init_commands = config["worker_setup_commands"]

        def _with_head_node_ip(cmds):
            head_node = _get_head_node(config, False)
            head_ip = provider.internal_ip(head_node)
            out = []
            for cmd in cmds:
                out.append("export MC2_HEAD_IP={}; {}".format(head_ip, cmd))
            return out

        mc2_start_commands = _with_head_node_ip(config["worker_start_mc2_commands"])

        updaters = []
        for node in nodes:
            updater = NodeUpdaterThread(
                node_id=node,
                provider_config=config["provider"],
                provider=provider,
                auth_config=config["auth"],
                cluster_name=config["cluster_name"],
                file_mounts=config["file_mounts"],
                initialization_commands=config["initialization_commands"],
                setup_commands=init_commands,
                mc2_start_commands=mc2_start_commands,
                runtime_hash=runtime_hash,
                docker_config=config.get("docker"),
            )
            updaters.append(updater)
            updater.start()
        for updater in updaters:
            updater.join()

    finally:
        provider.cleanup()


def _bootstrap_config(config):
    config = prepare_config(config)

    hasher = hashlib.sha1()
    hasher.update(json.dumps([config], sort_keys=True).encode("utf-8"))
    cache_key = os.path.join(
        tempfile.gettempdir(), "mc2-config-{}".format(hasher.hexdigest())
    )
    if os.path.exists(cache_key):
        logger.info("Using cached config at {}".format(cache_key))
        return json.loads(open(cache_key).read())
    validate_config(config)

    importer = NODE_PROVIDERS.get(config["provider"]["type"])
    if not importer:
        raise NotImplementedError("Unsupported provider {}".format(config["provider"]))

    bootstrap_config, _ = importer()
    resolved_config = bootstrap_config(config)
    with open(cache_key, "w") as f:
        f.write(json.dumps(resolved_config))
    return resolved_config


def teardown_cluster(config_file):
    """Destroys all nodes of an MC2 cluster described by a config json."""

    config = yaml.safe_load(open(config_file).read())
    config = prepare_config(config)
    validate_config(config)

    provider = get_node_provider(config["provider"], config["cluster_name"])
    try:

        def remaining_nodes():

            workers = provider.non_terminated_nodes(
                {TAG_MC2_NODE_TYPE: NODE_TYPE_WORKER}
            )

            head = provider.non_terminated_nodes({TAG_MC2_NODE_TYPE: NODE_TYPE_HEAD})

            return head + workers

        # Loop here to check that both the head and worker nodes are actually
        #   really gone
        A = remaining_nodes()
        with LogTimer("teardown_cluster: done."):
            while A:
                logger.info(
                    "teardown_cluster: Shutting down {} nodes...".format(len(A))
                )
                provider.terminate_nodes(A)
                time.sleep(1)
                A = remaining_nodes()
    finally:
        provider.cleanup()


def get_or_create_head_node(config):
    """Create the cluster head node, which in turn creates the workers."""
    provider = get_node_provider(config["provider"], config["cluster_name"])
    try:
        head_node_tags = {
            TAG_MC2_NODE_TYPE: NODE_TYPE_HEAD,
        }
        nodes = provider.non_terminated_nodes(head_node_tags)
        if len(nodes) > 0:
            head_node = nodes[0]
        else:
            head_node = None

        # Hash the head node config to see if it needs to be updated
        launch_hash = hash_launch_conf(config["head_node"], config["auth"])

        # If there's no existing head node or the existing head node's config
        # is out of date
        if (
            head_node is None
            or provider.node_tags(head_node).get(TAG_MC2_LAUNCH_CONFIG) != launch_hash
        ):
            # Shut down the head node if it is out of date
            if head_node is not None:
                logger.info(
                    "get_or_create_head_node: "
                    "Shutting down outdated head node {}".format(head_node)
                )
                provider.terminate_node(head_node)

            # Launch a new head node with udpated config
            logger.info("get_or_create_head_node: Launching new head node...")
            head_node_tags[TAG_MC2_LAUNCH_CONFIG] = launch_hash
            head_node_tags[TAG_MC2_NODE_NAME] = "mc2-{}-head".format(
                config["cluster_name"]
            )
            provider.create_node(config["head_node"], head_node_tags, 1)

        start = time.time()
        head_node = None
        while True:
            if time.time() - start > 50:
                raise RuntimeError("Failed to create head node.")
            nodes = provider.non_terminated_nodes(head_node_tags)
            if len(nodes) == 1:
                head_node = nodes[0]
                break
            time.sleep(1)

        # TODO: right now we always update the head node even if the hash
        # matches. We could prompt the user for what they want to do here.
        runtime_hash = hash_runtime_conf(config["file_mounts"], config)
        logger.info("get_or_create_head_node: Updating files on head node...")

        # Rewrite the auth config so that the head node can update the workers
        remote_config = copy.deepcopy(config)
        remote_key_path = "~/mc2_bootstrap_key.pem"
        remote_config["auth"]["ssh_private_key"] = remote_key_path

        # Adjust for new file locations
        new_mounts = {}
        for remote_path in config["file_mounts"]:
            new_mounts[remote_path] = remote_path
        remote_config["file_mounts"] = new_mounts

        # Now inject the rewritten config and SSH key into the head node
        remote_config_file = tempfile.NamedTemporaryFile("w", prefix="mc2-bootstrap-")
        remote_config_file.write(json.dumps(remote_config))
        remote_config_file.flush()
        config["file_mounts"].update(
            {"~/mc2_bootstrap_config.yaml": remote_config_file.name}
        )
        config["file_mounts"].update(
            {remote_key_path: config["auth"]["ssh_private_key"]}
        )

        # Run setup commands
        init_commands = config["head_setup_commands"]
        mc2_start_commands = config["head_start_mc2_commands"]

        updater = NodeUpdaterThread(
            node_id=head_node,
            provider_config=config["provider"],
            provider=provider,
            auth_config=config["auth"],
            cluster_name=config["cluster_name"],
            file_mounts=config["file_mounts"],
            initialization_commands=config["initialization_commands"],
            setup_commands=init_commands,
            mc2_start_commands=mc2_start_commands,
            runtime_hash=runtime_hash,
            docker_config=config.get("docker"),
        )
        updater.start()
        updater.join()

        # Refresh the node cache so we see the external ip if available
        provider.non_terminated_nodes(head_node_tags)

        if config.get("provider", {}).get("use_internal_ips", False) is True:
            head_node_ip = provider.internal_ip(head_node)
        else:
            head_node_ip = provider.external_ip(head_node)

        if updater.exitcode != 0:
            logger.error(
                "get_or_create_head_node: Updating {} failed".format(head_node_ip)
            )
            sys.exit(1)
        logger.info(
            "get_or_create_head_node: "
            "Head node up-to-date, IP address is: {}".format(head_node_ip)
        )

        #  monitor_str = "tail -n 100 -f /tmp/mc2/session_*/logs/monitor*"

        print(
            "To get a remote shell to the cluster manually, run:\n\n  {}\n".format(
                updater.cmd_runner.remote_shell_command_str()
            )
        )
    finally:
        provider.cleanup()


def get_head_node_ip(config_file):
    """Returns head node IP for given configuration file if exists."""

    config = yaml.safe_load(open(config_file).read())

    provider = get_node_provider(config["provider"], config["cluster_name"])
    try:
        head_node = _get_head_node(config)
        if config.get("provider", {}).get("use_internal_ips", False) is True:
            head_node_ip = provider.internal_ip(head_node)
        else:
            head_node_ip = provider.external_ip(head_node)
    finally:
        provider.cleanup()

    return head_node_ip


def get_worker_node_ips(config_file):
    """Returns worker node IPs for given configuration file."""

    config = yaml.safe_load(open(config_file).read())

    provider = get_node_provider(config["provider"], config["cluster_name"])
    try:
        nodes = provider.non_terminated_nodes({TAG_MC2_NODE_TYPE: NODE_TYPE_WORKER})

        if config.get("provider", {}).get("use_internal_ips", False) is True:
            return [provider.internal_ip(node) for node in nodes]
        else:
            return [provider.external_ip(node) for node in nodes]
    finally:
        provider.cleanup()


def _get_head_node(config, create_if_needed=False):
    provider = get_node_provider(config["provider"], config["cluster_name"])
    try:
        head_node_tags = {
            TAG_MC2_NODE_TYPE: NODE_TYPE_HEAD,
        }
        nodes = provider.non_terminated_nodes(head_node_tags)
    finally:
        provider.cleanup()

    if len(nodes) > 0:
        head_node = nodes[0]
        return head_node
    elif create_if_needed:
        get_or_create_head_node(config)
        return _get_head_node(config, create_if_needed=False)
    else:
        raise RuntimeError(
            "Head node of cluster ({}) not found!".format(config["cluster_name"])
        )


def storage(config_path, create):
    config = yaml.safe_load(open(config_path).read())["provider"]
    if create:
        create_storage(config)
    else:
        terminate_storage(config)


def container(config_path, create):
    config = yaml.safe_load(open(config_path).read())["provider"]
    if create:
        create_container(config)
    else:
        terminate_container(config)


def upload(config_path, input_file, output_blob):
    config = yaml.safe_load(open(config_path).read())["provider"]
    upload_data_from_file(config, input_file, output_blob)


def download(config_path, input_blob, output_file):
    config = yaml.safe_load(open(config_path).read())["provider"]
    download_data(config, input_blob, output_filename=output_file)


def cluster(config_path, create):
    if create:
        config = yaml.safe_load(open(config_path).read())
        create_or_update_cluster(config)
    else:
        teardown_cluster(config_path)


def resource_group(config_path, create):
    config = yaml.safe_load(open(config_path).read())
    create_or_delete_resource_group(config, create)


def run_remote_cmds_on_cluster(config_path, head_cmds=[], worker_cmds=[]):
    config = yaml.safe_load(open(config_path).read())

    # Replace config start cmds with new cmds
    config["head_start_mc2_commands"] = head_cmds
    config["worker_start_mc2_commands"] = worker_cmds

    # Delete all other cmds so they aren't unnecessarily rerun
    config["initialization_commands"] = []
    config["setup_commands"] = []
    config["head_setup_commands"] = []
    config["worker_setup_commands"] = []
    config["file_mounts"] = {}

    create_or_update_cluster(config)
