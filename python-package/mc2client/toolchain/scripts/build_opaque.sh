#!/bin/bash

# Clone and build Opaque
git clone https://github.com/mc2-project/opaque-sql.git 

# Set environment variables
export OPAQUE_HOME=~/opaque-sql
export OPAQUE_DATA_DIR=${OPAQUE_HOME}/data/
export SPARK_SCALA_VERSION=2.12
export PRIVATE_KEY_PATH=${OPAQUE_HOME}/src/test/keys/mc2_test_key.pem
export MODE=HARDWARE
export OE_SDK_PATH=/opt/openenclave/

# Generate keys
cd opaque-sql
build/sbt keys

# Set environment variables permanently
echo "export OPAQUE_HOME=~/opaque-sql" >> ~/.bashrc
echo "export OPAQUE_DATA_DIR=${OPAQUE_HOME}/data" >> ~/.bashrc
echo "export SPARK_SCALA_VERSION=2.12" >> ~/.bashrc
echo "export PRIVATE_KEY_PATH=${OPAQUE_HOME}/src/test/keys/mc2_test_key.pem" >> ~/.bashrc
echo "export MODE=HARDWARE" >> ~/.bashrc
echo "export OE_SDK_PATH=/opt/openenclave/" >> ~/.bashrc

# Build Opaque SQL
build/sbt package

