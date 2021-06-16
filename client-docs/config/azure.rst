Azure Configuration
====================

MC\ :sup:`2` Client provides an interface to directly launch Azure resources -- you can launch VMs, blob storage accounts, or storage containers. To do so, you'll need to configure some parameters that will tell MC\ :sup:`2` Client how to set up your Azure resources. You should specify the path to this configuration in the ``["launch"]["azure_config"]`` section of your :doc:`Global Configuration <config>`.

Below is an example of the Azure configuration with comments about each field.

.. code-block:: yaml


   # An unique identifier for the head node and workers of this cluster.
   cluster_name: default

   # The total number of workers nodes to launch in addition to the head
   # node. This number should be >= 0.
   num_workers: 0

   # Cloud-provider specific configuration.
   provider:
      type: azure
      # https://docs.microsoft.com/en-us/azure/confidential-computing/virtual-machine-solutions

      # Location of resources
      # For a full list of regions that have VMs with enclave support,
      # go to the following link and look for DCs-v2 series VMs
      # https://azure.microsoft.com/en-us/global-infrastructure/services/?products=virtual-machines&regions=all
      location: eastus

      # The name of the resource group that will contain all resources
      resource_group: mc2-client-dev

      # The name of the storage account to create
      storage_name: mc2storage

      # The name of the storage container to create
      container_name: blob-container-1

      # If left blank or commented out, the default subscription ID
      # from the Azure CLI will be used
      # subscription_id:

   # How MC2 will authenticate with newly launched nodes.
   auth:
      # The username to use to SSH to launched nodes
      ssh_user: mc2

      # You must specify paths to matching private and public key pair files
      # Use `ssh-keygen -t rsa -b 4096` to generate a new SSH key pair
      ssh_private_key: ~/.ssh/id_rsa
      ssh_public_key: ~/.ssh/id_rsa.pub

   # Provider-specific config for the head node, e.g. instance type.
   head_node:
      azure_arm_parameters:
         # https://docs.microsoft.com/en-us/azure/confidential-computing/virtual-machine-solutions
         # The DCs_v2 VMs support Intel SGX
         vmSize: Standard_DC2s_v2

         # If launching a minimal Ubuntu machine
         # (and manually installing using setup commands)
         imagePublisher: Canonical
         imageOffer: UbuntuServer
         imageSku: 18_04-lts-gen2
         imageVersion: latest

   # Provider-specific config for worker nodes, e.g. instance type.
   worker_nodes:
      azure_arm_parameters:
         # https://docs.microsoft.com/en-us/azure/confidential-computing/virtual-machine-solutions
         # The DCs_v2 VMs support Intel SGX
         vmSize: Standard_DC2s_v2

         # If launching a minimal Ubuntu machine
         # (and manually installing using setup commands)
         imagePublisher: Canonical
         imageOffer: UbuntuServer
         imageSku: 18_04-lts-gen2
         imageVersion: latest

   ##############################################################################
   #       Everything below this can be ignored - you likely won't have to      #
   #       modify it.                                                           #
   ##############################################################################

   # Files or directories to copy to the head and worker nodes. The format is a
   # dictionary from REMOTE_PATH: LOCAL_PATH, e.g.
   file_mounts: {
      # This script installs Open Enclave
      "~/install_oe.sh" : "scripts/install_oe.sh",

      # This script builds Spark 3.1.1 from source
      "~/build_spark.sh" : "scripts/build_spark.sh",

      # This script downloads a pre-built Spark 3.1.1 binary
      "~/install_spark.sh" : "scripts/install_spark.sh",

      # This script builds Opaque SQL from source
      "~/build_opaque.sh" : "scripts/build_opaque.sh",

      # This script installs Secure XGBoost from source
      "~/install_secure_xgboost.sh" : "scripts/install_secure_xgboost.sh"
   }

   # List of commands that will be run before `setup_commands`. If docker is
   # enabled, these commands will run outside the container and before docker
   # is setup.
   initialization_commands:
      # Get rid of annoying Ubuntu message
      - touch ~/.sudo_as_admin_successful

   # List of shell commands to run to set up nodes.
   # Note: Use empty list if using image
   setup_commands:
      # This script installs Open Enclave on the node
      - chmod +x ~/install_oe.sh
      - source ~/install_oe.sh
      # This script installs Apache Spark on the node
      - chmod +x ~/install_spark.sh
      - source ~/install_spark.sh
      # This script installs Opaque SQL on the node
      - chmod +x ~/build_opaque.sh
      - source ~/build_opaque.sh
      # This script installs Secure XGBoost on the node
      - chmod +x ~/install_secure_xgboost.sh
      - source ~/install_secure_xgboost.sh

   # Custom commands that will be run on the head node after common setup.
   # Set to empty list if using image
   head_setup_commands: []

   # Custom commands that will be run on worker nodes after common setup.
   # Set to empty list if using image
   worker_setup_commands: []

   # Command to start MC2 on the head node.
   # Set to empty list if using image
   head_start_mc2_commands:
   - cd $SPARK_HOME; ./sbin/start-master.sh

   # Command to start MC2 on worker nodes.
   # Set to empty list if using image
   worker_start_mc2_commands:
   - cd $SPARK_HOME; ./sbin/start-slave.sh $MC2_HEAD_IP:7077
