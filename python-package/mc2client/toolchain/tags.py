"""Tags/labels are used to associate metadata with instances."""

# Tag for the name of the node
TAG_MC2_NODE_NAME = "mc2-node-name"

# Tag for the type of node (e.g. Head, Worker)
TAG_MC2_NODE_TYPE = "mc2-node-type"
NODE_TYPE_HEAD = "head"
NODE_TYPE_WORKER = "worker"

# Tag for the provider-specific instance type (e.g., m4.4xlarge). This is used
# for automatic worker instance type selection.
TAG_MC2_INSTANCE_TYPE = "mc2-instance-type"

# Tag that reports the current state of the node (e.g. Updating, Up-to-date)
TAG_MC2_NODE_STATUS = "mc2-node-status"
STATUS_UNINITIALIZED = "uninitialized"
STATUS_WAITING_FOR_SSH = "waiting-for-ssh"
STATUS_SYNCING_FILES = "syncing-files"
STATUS_SETTING_UP = "setting-up"
STATUS_UPDATE_FAILED = "update-failed"
STATUS_UP_TO_DATE = "up-to-date"

# Tag uniquely identifying all nodes of a cluster
TAG_MC2_CLUSTER_NAME = "mc2-cluster-name"

# Hash of the node launch config, used to identify out-of-date nodes
TAG_MC2_LAUNCH_CONFIG = "mc2-launch-config"

# Hash of the node runtime config, used to determine if updates are needed
TAG_MC2_RUNTIME_CONFIG = "mc2-runtime-config"
