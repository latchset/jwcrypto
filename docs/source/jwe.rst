JSON Web Encryption (JWE)
=========================

The jwe Module implements the `JSON Web Encryption`_ standard.
A JSON Web Encryption is represented by a JWE object, related utility
classes and functions are availbale in this module too.

.. _JSON Web Encryption: https://tools.ietf.org/html/rfc7516

Classes
-------

.. autoclass:: jwcrypto.jwe.JWE
   :members:
   :show-inheritance:

Variables
---------

.. autodata:: jwcrypto.jwe.default_allowed_algs

Exceptions
----------

.. autoclass:: jwcrypto.jwe.InvalidJWEOperation
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwe.InvalidJWEData
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwe.InvalidJWEKeyType
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwe.InvalidJWEKeyLength
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwe.InvalidCEKeyLength
   :members:
   :show-inheritance:

Registries
----------

.. autodata:: jwcrypto.jwe.JWEHeaderRegistry
   :annotation:
