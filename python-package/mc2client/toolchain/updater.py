try:  # py3
    from shlex import quote
except ImportError:  # py2
    from pipes import quote

import hashlib
import logging
import os
import subprocess
import time
from getpass import getuser
from threading import Thread

from .log_timer import LogTimer
from .tags import (
    STATUS_SETTING_UP,
    STATUS_SYNCING_FILES,
    STATUS_UP_TO_DATE,
    STATUS_UPDATE_FAILED,
    STATUS_WAITING_FOR_SSH,
    TAG_MC2_NODE_STATUS,
    TAG_MC2_RUNTIME_CONFIG,
)

logger = logging.getLogger(__name__)

# How long to wait for a node to start, in seconds
NODE_START_WAIT_S = 300
READY_CHECK_INTERVAL = 5
HASH_MAX_LENGTH = 10


def with_interactive(cmd):
    force_interactive = (
        "true && source ~/.bashrc && "
        "export OMP_NUM_THREADS=1 PYTHONWARNINGS=ignore && "
    )
    return ["bash", "--login", "-c", "-i", quote(force_interactive + cmd)]


class SSHCommandRunner:
    def __init__(
        self,
        log_prefix,
        node_id,
        provider,
        auth_config,
        cluster_name,
        process_runner,
        use_internal_ip,
    ):

        ssh_control_hash = hashlib.md5(cluster_name.encode()).hexdigest()
        ssh_user_hash = hashlib.md5(getuser().encode()).hexdigest()
        ssh_control_path = "/tmp/mc2_ssh_{}/{}".format(
            ssh_user_hash[:HASH_MAX_LENGTH], ssh_control_hash[:HASH_MAX_LENGTH]
        )

        self.log_prefix = log_prefix
        self.process_runner = process_runner
        self.node_id = node_id
        self.use_internal_ip = use_internal_ip
        self.provider = provider
        self.ssh_private_key = auth_config["ssh_private_key"]
        self.ssh_user = auth_config["ssh_user"]
        self.ssh_control_path = ssh_control_path
        self.ssh_ip = None

    def get_default_ssh_options(self, connect_timeout):
        OPTS = [
            ("ConnectTimeout", "{}s".format(connect_timeout)),
            # Supresses initial fingerprint verification.
            ("StrictHostKeyChecking", "no"),
            # SSH IP and fingerprint pairs no longer added to known_hosts.
            # This is to remove a "REMOTE HOST IDENTIFICATION HAS CHANGED"
            # warning if a new node has the same IP as a previously
            # deleted node, because the fingerprints will not match in
            # that case.
            ("UserKnownHostsFile", os.devnull),
            ("ControlMaster", "auto"),
            ("ControlPath", "{}/%C".format(self.ssh_control_path)),
            ("ControlPersist", "10s"),
            # Try fewer extraneous key pairs.
            ("IdentitiesOnly", "yes"),
            # Abort if port forwarding fails (instead of just printing to
            # stderr).
            ("ExitOnForwardFailure", "yes"),
            # Quickly kill the connection if network connection breaks (as
            # opposed to hanging/blocking).
            ("ServerAliveInterval", 5),
            ("ServerAliveCountMax", 3),
        ]

        return ["-i", self.ssh_private_key] + [
            x for y in (["-o", "{}={}".format(k, v)] for k, v in OPTS) for x in y
        ]

    def get_node_ip(self):
        if self.use_internal_ip:
            return self.provider.internal_ip(self.node_id)
        else:
            return self.provider.external_ip(self.node_id)

    def wait_for_ip(self, deadline):
        while time.time() < deadline and not self.provider.is_terminated(self.node_id):
            logger.info(self.log_prefix + "Waiting for IP...")
            ip = self.get_node_ip()
            if ip is not None:
                return ip
            time.sleep(10)

        return None

    def set_ssh_ip_if_required(self):
        if self.ssh_ip is not None:
            return

        # We assume that this never changes.
        #   I think that's reasonable.
        deadline = time.time() + NODE_START_WAIT_S
        with LogTimer(self.log_prefix + "Got IP"):
            ip = self.wait_for_ip(deadline)
            assert ip is not None, "Unable to find IP of node"

        self.ssh_ip = ip

        # This should run before any SSH commands and therefore ensure that
        #   the ControlPath directory exists, allowing SSH to maintain
        #   persistent sessions later on.
        try:
            os.makedirs(self.ssh_control_path, mode=0o700, exist_ok=True)
        except OSError as e:
            logger.warning(e)

    def run(
        self,
        cmd,
        timeout=120,
        exit_on_fail=False,
        port_forward=None,
        with_output=False,
        **kwargs
    ):

        self.set_ssh_ip_if_required()

        ssh = ["ssh", "-tt"]

        if port_forward:
            if not isinstance(port_forward, list):
                port_forward = [port_forward]
            for local, remote in port_forward:
                logger.info(
                    self.log_prefix
                    + "Forwarding "
                    + "{} -> localhost:{}".format(local, remote)
                )
                ssh += ["-L", "{}:localhost:{}".format(remote, local)]

        final_cmd = (
            ssh
            + self.get_default_ssh_options(timeout)
            + ["{}@{}".format(self.ssh_user, self.ssh_ip)]
        )
        if cmd:
            logger.info(self.log_prefix + "Running {}".format(" ".join(final_cmd)))
            final_cmd += with_interactive(cmd)
        else:
            # We do this because `-o ControlMaster` causes the `-N` flag to
            # still create an interactive shell in some ssh versions.
            final_cmd.append(quote("while true; do sleep 86400; done"))

        num_tries = 0
        for i in range(3):
            try:
                if with_output:
                    return self.process_runner.check_output(final_cmd)
                else:
                    self.process_runner.check_call(final_cmd)
                    break
            except subprocess.CalledProcessError:
                num_tries += 1
                time.sleep(10)
                if num_tries > 3:
                    if exit_on_fail:
                        quoted_cmd = " ".join(final_cmd[:-1] + [quote(final_cmd[-1])])
                        # raise click.ClickException(
                        #     "Command failed: \n\n  {}\n".format(quoted_cmd)) from None
                        raise Exception("Command failed: \n\n  {}\n".format(quoted_cmd))
                    else:
                        # raise click.ClickException(
                        #     "SSH command Failed. See above for the output from the"
                        #     " failure.") from None
                        raise Exception(
                            "SSH command Failed. See above for the output from the failure."
                        )

    def run_rsync_up(self, source, target):
        self.set_ssh_ip_if_required()
        self.process_runner.check_call(
            [
                "rsync",
                "--rsh",
                " ".join(["ssh"] + self.get_default_ssh_options(120)),
                "-avz",
                source,
                "{}@{}:{}".format(self.ssh_user, self.ssh_ip, target),
            ]
        )

    def run_rsync_down(self, source, target):
        self.set_ssh_ip_if_required()
        self.process_runner.check_call(
            [
                "rsync",
                "--rsh",
                " ".join(["ssh"] + self.get_default_ssh_options(120)),
                "-avz",
                "{}@{}:{}".format(self.ssh_user, self.ssh_ip, source),
                target,
            ]
        )

    def remote_shell_command_str(self):
        return "ssh -o IdentitiesOnly=yes -i {} {}@{}\n".format(
            self.ssh_private_key, self.ssh_user, self.ssh_ip
        )


class NodeUpdater:
    """A process for syncing files and running init commands on a node."""

    def __init__(
        self,
        node_id,
        provider_config,
        provider,
        auth_config,
        cluster_name,
        file_mounts,
        initialization_commands,
        setup_commands,
        mc2_start_commands,
        runtime_hash,
        process_runner=subprocess,
        use_internal_ip=False,
        docker_config=None,
    ):

        print("Nodeupdater constructor")
        self.log_prefix = "NodeUpdater: {}: ".format(node_id)
        use_internal_ip = use_internal_ip or provider_config.get(
            "use_internal_ips", False
        )
        self.cmd_runner = provider.get_command_runner(
            self.log_prefix,
            node_id,
            auth_config,
            cluster_name,
            process_runner,
            use_internal_ip,
            docker_config,
        )

        self.daemon = True
        self.process_runner = process_runner
        self.node_id = node_id
        self.provider = provider
        self.file_mounts = {
            remote: os.path.join(os.path.dirname(__file__), os.path.expanduser(local))
            for remote, local in file_mounts.items()
        }
        self.initialization_commands = initialization_commands
        self.setup_commands = setup_commands
        self.mc2_start_commands = mc2_start_commands
        self.runtime_hash = runtime_hash

    def run(self):
        logger.info(self.log_prefix + "Updating to {}".format(self.runtime_hash))
        try:
            with LogTimer(
                self.log_prefix + "Applied config {}".format(self.runtime_hash)
            ):
                self.do_update()
        except Exception as e:
            error_str = str(e)
            #  if hasattr(e, "cmd"):
            #      error_str = "(Exit Status {}) {}".format(e.returncode, " ".join(e.cmd))
            self.provider.set_node_tags(
                self.node_id, {TAG_MC2_NODE_STATUS: STATUS_UPDATE_FAILED}
            )
            logger.error(
                self.log_prefix + "Error executing: {}".format(error_str) + "\n"
            )
            # if isinstance(e, click.ClickException):
            #     return
            raise

        self.provider.set_node_tags(
            self.node_id,
            {
                TAG_MC2_NODE_STATUS: STATUS_UP_TO_DATE,
                TAG_MC2_RUNTIME_CONFIG: self.runtime_hash,
            },
        )

        self.exitcode = 0

    def sync_file_mounts(self, sync_cmd):
        # Rsync file mounts
        for remote_path, local_path in self.file_mounts.items():
            assert os.path.exists(local_path), local_path
            if os.path.isdir(local_path):
                if not local_path.endswith("/"):
                    local_path += "/"
                if not remote_path.endswith("/"):
                    remote_path += "/"

            with LogTimer(
                self.log_prefix + "Synced {} to {}".format(local_path, remote_path)
            ):
                self.cmd_runner.run("mkdir -p {}".format(os.path.dirname(remote_path)))
                sync_cmd(local_path, remote_path)

    def wait_ready(self, deadline):
        with LogTimer(self.log_prefix + "Got remote shell"):
            logger.info(self.log_prefix + "Waiting for remote shell...")

            while time.time() < deadline and not self.provider.is_terminated(
                self.node_id
            ):
                try:
                    logger.debug(self.log_prefix + "Waiting for remote shell...")

                    self.cmd_runner.run("uptime", timeout=5)
                    logger.debug("Uptime succeeded.")
                    return True

                except Exception as e:
                    retry_str = str(e)
                    #  if hasattr(e, "cmd"):
                    #      retry_str = "(Exit Status {}): {}".format(
                    #          e.returncode, " ".join(e.cmd)
                    #      )
                    logger.debug(
                        self.log_prefix + "Node not up, retrying: {}".format(retry_str)
                    )
                    time.sleep(READY_CHECK_INTERVAL)
                    return

        assert False, "Unable to connect to node"

    def do_update(self):
        self.provider.set_node_tags(
            self.node_id, {TAG_MC2_NODE_STATUS: STATUS_WAITING_FOR_SSH}
        )
        deadline = time.time() + NODE_START_WAIT_S
        self.wait_ready(deadline)

        node_tags = self.provider.node_tags(self.node_id)
        logger.debug("Node tags: {}".format(str(node_tags)))
        if node_tags.get(TAG_MC2_RUNTIME_CONFIG) == self.runtime_hash:
            logger.info(
                self.log_prefix
                + "{} already up-to-date, skip to mc2 start".format(self.node_id)
            )
        else:
            self.provider.set_node_tags(
                self.node_id, {TAG_MC2_NODE_STATUS: STATUS_SYNCING_FILES}
            )
            self.sync_file_mounts(self.rsync_up)

            # Run init commands
            self.provider.set_node_tags(
                self.node_id, {TAG_MC2_NODE_STATUS: STATUS_SETTING_UP}
            )
            with LogTimer(
                self.log_prefix + "Initialization commands", show_status=True
            ):
                for cmd in self.initialization_commands:
                    self.cmd_runner.run(cmd)

            with LogTimer(self.log_prefix + "Setup commands", show_status=True):
                for cmd in self.setup_commands:
                    self.cmd_runner.run(cmd)

        with LogTimer(self.log_prefix + "MC2 start commands", show_status=True):
            for cmd in self.mc2_start_commands:
                self.cmd_runner.run(cmd)

    def rsync_up(self, source, target):
        logger.info(self.log_prefix + "Syncing {} to {}...".format(source, target))
        self.cmd_runner.run_rsync_up(source, target)

    def rsync_down(self, source, target):
        logger.info(self.log_prefix + "Syncing {} from {}...".format(source, target))
        self.cmd_runner.run_rsync_down(source, target)


class NodeUpdaterThread(NodeUpdater, Thread):
    def __init__(self, *args, **kwargs):
        Thread.__init__(self)
        NodeUpdater.__init__(self, *args, **kwargs)
        self.exitcode = -1
