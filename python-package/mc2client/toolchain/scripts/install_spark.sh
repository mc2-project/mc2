#!/bin/bash

# Install Java 8
sudo apt-get update
sudo apt-get -y install openjdk-8-jdk openjdk-8-jre

# Download pre-built Spark
wget https://archive.apache.org/dist/spark/spark-3.1.1/spark-3.1.1-bin-hadoop2.7.tgz
tar -xzvf spark-3.1.1-bin-hadoop2.7.tgz

# Set environment variables
echo "" >> ~/.bashrc
echo "export SPARK_HOME=$PWD/spark-3.1.1-bin-hadoop2.7" >> ~/.bashrc
echo "export SPARK_SCALA_VERSION=2.12" >> ~/.bashrc
source ~/.bashrc

# Opaque needs these configs to be set
touch $SPARK_HOME/conf/spark-defaults.conf
echo "" >> $SPARK_HOME/conf/spark-defaults.conf
echo "spark.executor.instances 1" >> $SPARK_HOME/conf/spark-defaults.conf
echo "spark.task.maxFailures 10" >> $SPARK_HOME/conf/spark-defaults.conf
