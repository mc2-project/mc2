#!/bin/bash

sudo apt-get install -y libmbedtls-dev python3-pip
pip3 install numpy pandas sklearn numproto grpcio grpcio-tools

git clone https://github.com/mc2-project/secure-xgboost.git

cd secure-xgboost
mkdir build

cd build
cmake ..
make -j4

cd ../python-package
sudo python3 setup.py install
