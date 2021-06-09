#!/bin/bash

# Install Java 8
sudo apt-get update
sudo apt-get -y install openjdk-8-jdk openjdk-8-jre

# Build Spark 3.1.1
wget https://archive.apache.org/dist/spark/spark-3.1.1/spark-3.1.1.tgz
tar -xvzf spark-3.1.1.tgz
cd spark-3.1.1
./build/mvn -DskipTests clean package

# Set environment variables
echo "" >> ~/.bashrc
echo "export SPARK_HOME=$PWD" >> ~/.bashrc
echo "export SPARK_SCALA_VERSION=2.12" >> ~/.bashrc
source ~/.bashrc

# Opaque needs these configs to be set
touch $SPARK_HOME/conf/spark-defaults.conf
echo "" >> $SPARK_HOME/conf/spark-defaults.conf
echo "spark.executor.instances 1" >> $SPARK_HOME/conf/spark-defaults.conf
echo "spark.task.maxFailures 10" >> $SPARK_HOME/conf/spark-defaults.conf
