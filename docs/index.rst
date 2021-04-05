.. Opaque Client documentation master file, created by
   sphinx-quickstart on Thu Mar  4 20:37:41 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to MC\ :sup:`2` Client's documentation!
=========================================
Born out of research from the `UC Berkeley RISE Lab <https://rise.cs.berkeley.edu/>`_, MC\ :sup:`2` is a platform for running secure analytics and machine learning in an untrusted environment, like the cloud. MC\ :sup:`2` provides compute services that can be cryptographically trusted to correctly and securely perform computation even when the machines they run on have been compromised. MC\ :sup:`2` is open-source and is freely available on `GitHub <https://github.com/mc2-project/mc2>`_.

MC\ :sup:`2` Client enables users of MC\ :sup:`2`'s secure cloud compute services to remotely interface with MC\ :sup:`2`'s cloud services from their local machine. Currently, MC\ :sup:`2` supports `Opaque SQL <https://mc2-project.github.io/opaque/>`_, a secure framework for SQL analytics built on top of Apache Spark, and `Secure XGBoost <https://secure-xgboost.readthedocs.io/en/latest/>`_, a secure library for training (and learning from) gradient boosted decision tree models. Users will first need to start a compute service in the cloud, and then run MC\ :sup:`2` Client locally.

MC\ :sup:`2` Client provides two interfaces, a Python interface and a command line interface, to enable a user to encrypt and upload their data, write and remotely run code, and retrieve results.

.. toctree::
    :maxdepth: 2
    :caption: Contents:

    install
    config
    python/index
    cli/index

