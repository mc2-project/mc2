#!/bin/bash

set -e

if [[ $(lsb_release -is) != "Ubuntu" ]]; then 
	echo "Not installing Open Enclave: unsupported OS distribution."
	exit 1

elif [[ $(lsb_release -rs) == "18.04" ]]; then 
	# Install Open Enclave on Ubuntu 18.04

	# Configure the Intel and Microsoft APT Repositories
	echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
	wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -

	echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-7 main" | sudo tee /etc/apt/sources.list.d/llvm-toolchain-bionic-7.list
	wget -qO - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -

	echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" | sudo tee /etc/apt/sources.list.d/msprod.list
	wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

	# Install the Intel SGX DCAP Driver
	sudo apt update
	sudo apt -y install dkms
    wget https://download.01.org/intel-sgx/sgx-dcap/1.9/linux/distro/ubuntu18.04-server/sgx_linux_x64_driver_1.36.2.bin
    chmod +x sgx_linux_x64_driver_1.36.2.bin
    sudo ./sgx_linux_x64_driver_1.36.2.bin

	# Install the Intel and Open Enclave packages and dependencies
    sudo apt -y install clang-8 libssl-dev gdb libsgx-enclave-common libsgx-quote-ex libprotobuf10 libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client open-enclave=0.17.1

	# Configure OE environment variables
	echo "source /opt/openenclave/share/openenclave/openenclaverc" >> ~/.bashrc
	source /opt/openenclave/share/openenclave/openenclaverc

elif [[ $(lsb_release -rs) == "16.04" ]]; then 
	# Install Open Enclave on Ubuntu 16.04

	# Configure the Intel and Microsoft APT Repositories
	echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu xenial main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
	wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -

	echo "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-7 main" | sudo tee /etc/apt/sources.list.d/llvm-toolchain-xenial-7.list
	wget -qO - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -

	echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/16.04/prod xenial main" | sudo tee /etc/apt/sources.list.d/msprod.list
	wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

	# Install the Intel SGX DCAP Driver
	sudo apt update
	sudo apt -y install dkms
    wget https://download.01.org/intel-sgx/sgx-dcap/1.9/linux/distro/ubuntu16.04-server/sgx_linux_x64_driver_1.36.2.bin
    chmod +x sgx_linux_x64_driver_1.36.2.bin
    sudo ./sgx_linux_x64_driver_1.36.2.bin

	# Install the Intel and Open Enclave packages and dependencies
    sudo apt -y install clang-8 libssl-dev gdb libsgx-enclave-common libsgx-quote-ex libprotobuf10 libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client open-enclave=0.17.1

	# Configure OE environment variables
	echo "source /opt/openenclave/share/openenclave/openenclaverc" >> ~/.bashrc
	source /opt/openenclave/share/openenclave/openenclaverc

else
	echo "Not installing Open Enclave: unsupported Ubuntu version."
	exit 1
fi

# CMake
wget https://github.com/Kitware/CMake/releases/download/v3.15.6/cmake-3.15.6-Linux-x86_64.sh
sudo bash cmake-3.15.6-Linux-x86_64.sh --skip-license --prefix=/usr/local

# Make
sudo apt-get install make

# Mbed TLS
sudo apt-get install -y libmbedtls-dev
