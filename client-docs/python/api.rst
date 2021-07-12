API Reference
==============
|platform| Client provides a Python interface through the Python package, :substitution-code:`|python-package|`. See the Installation section for installation instructions. To use the Python package, we'll need to import it.

.. code-block:: python
   :substitutions:

    import |python-package| as |python-package-short|

Global Configuration
~~~~~~~~~~~~~~~~~~~~
.. autofunction:: mc2client.set_config

Cryptographic Utilities
~~~~~~~~~~~~~~~~~~~~~~~
.. autofunction:: mc2client.configure_job

.. autofunction:: mc2client.decrypt_data

.. autofunction:: mc2client.encrypt_data

.. autofunction:: mc2client.generate_keypair

.. autofunction:: mc2client.generate_symmetric_key

Cloud Management
~~~~~~~~~~~~~~~~
.. autofunction:: mc2client.create_cluster

.. autofunction:: mc2client.create_container

.. autofunction:: mc2client.create_resource_group

.. autofunction:: mc2client.create_storage

.. autofunction:: mc2client.delete_cluster

.. autofunction:: mc2client.delete_container

.. autofunction:: mc2client.delete_resource_group

.. autofunction:: mc2client.delete_storage

.. autofunction:: mc2client.download_file

.. autofunction:: mc2client.get_head_ip

.. autofunction:: mc2client.get_worker_ips

.. autofunction:: mc2client.upload_file

