Installation
============

MC\ :sup:`2` Client is written in both C++ and Python. As a result, we'll have to first build the C++ source, and then build and install the Python package.

1. Install dependencies.

.. code-block:: bash

    # CMake
    wget https://github.com/Kitware/CMake/releases/download/v3.15.6/cmake-3.15.6-Linux-x86_64.sh
    sudo bash cmake-3.15.6-Linux-x86_64.sh --skip-license --prefix=/usr/local

    # Mbed TLS and Pip
    sudo apt-get install -y libmbedtls-dev python3-pip

    # MC2 Client Python package dependencies
    git clone --recursive https://github.com/mc2-project/mc2.git
    cd mc2
    pip3 install -r requirements.txt 
    cd ..

    # `sequencefile` Python package
    git clone https://github.com/opaque-systems/sequencefile.git
    cd sequencefile
    sudo python3 setup.py install
    cd ..

Additionally, install Open Enclave by following these `instructions <https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_18.04.md>`_. Be sure to install Open Enclave 0.12.0 in Step 3 by specifying ``open-enclave=0.12.0``.

2. Build the C++ source.

.. code-block:: bash

    cd mc2/src
    mkdir build
    cd build
    cmake ..
    make -j4
    cd ../..

3. Once you've built the binary, install the Python package.

.. code-block:: bash

    cd python-package
    sudo python3 setup.py install


You're done! Try importing the ``mc2client`` Python package to check that your installation was successful.

.. code-block::

    $ python3
    Python 3.8.7 (default, Dec 30 2020, 10:13:08)
    [Clang 12.0.0 (clang-1200.0.32.28)] on darwin
    Type "help", "copyright", "credits" or "license" for more information.

    >>> import mc2client as oc
