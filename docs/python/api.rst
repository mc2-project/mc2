API Reference
==============
MC\ :sup:`2` Client provides a Python interface through the Python package, ``mc2client``. See the Installation section for installation instructions. To use the Python package, we'll need to import it.

.. code-block:: python

    import mc2client as mc2

Global Configuration
~~~~~~~~~~~~~~~~~~~~
.. autofunction:: mc2client.set_config

Cryptographic Utilities
~~~~~~~~~~~~~~~~~~~~~~~
.. autofunction:: mc2client.attest

.. autofunction:: mc2client.decrypt_data

.. autofunction:: mc2client.encrypt_data

.. autofunction:: mc2client.generate_keypair

.. autofunction:: mc2client.generate_symmetric_key

Cloud Management
~~~~~~~~~~~~~~~~
.. autofunction:: mc2client.download_file

.. autofunction:: mc2client.upload_file

