JSON Web Algorithms (JWA)
=========================

The jwa Module implements the `JSON Web Algorithms`_ standard.
This module provides classes that implement all the cryptographic
algorithms required by the standard. All algorithms are accessible
through the `JWA` class.

.. _JSON Web Algorithms: http://tools.ietf.org/html/rfc7518

Classes
-------

.. autoclass:: jwcrypto.jwa.JWA
   :members:

.. autoclass:: jwcrypto.jwa.JWAAlgorithm
   :members: name, description, keysize, algorithm_usage_location, algorithm_use, input_keysize
   :show-inheritance:

Registries
----------

.. autoattribute:: jwcrypto.jwa.JWA.algorithms_registry

Module Settings
---------------

.. autodata:: jwcrypto.jwa.default_max_pbkdf2_iterations
   :annotation:

.. autodata:: jwcrypto.jwa.default_enforce_hmac_key_length
   :annotation:
