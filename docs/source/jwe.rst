JSON Web Encryption (JWE)
=========================

The jwe Module implements the `JSON Web Encryption`_ draft (currently
version 40).
A JSON Web Encryption is represented by a JWE object, related utility
classes and functions are availbale in this module too.

.. _JSON Web Encryption: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-40

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
