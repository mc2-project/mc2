.. MC\ :sup:`2` Client documentation master file, created by
   sphinx-quickstart on Thu Mar  4 20:37:41 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

MC\ :sup:`2` Client
===================
MC\ :sup:`2` Client is a local trusted client that enables users to securely interface with the MC\ :sup:`2` ecosystem. In particular, MC\ :sup:`2` Client allows users to initialize their identities, launch MC\ :sup:`2`-loaded VMs and other resources on Azure Confidential Computing, start and stop MC\ :sup:`2` compute services (Opaque SQL and Secure XGBoost), transfer their encrypted sensitive data to the cloud for processing, and remotely run secure computation on their data.

MC\ :sup:`2` Client provides two interfaces, a :doc:`Python interface <python/usage>` and a :doc:`command line interface <cli/usage>`. Both rely on a :doc:`configuration file <config/config>` to configure MC\ :sup:`2` Client; the command line interface is simpler but less flexible, while the Python interface gives users finer grained control over what they want to do.

While MC\ :sup:`2` currently offers various compute services, the client is currently only compatible with Opaque SQL. We are currently in the midst of updating Secure XGBoost to be compatible with the client.

.. toctree::
    :maxdepth: 2
    :caption: Contents:

    install
    quickstart
    opaquesql_usage
    config/index
    python/index
    cli/index

