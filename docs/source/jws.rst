JSON Web Signature (JWS)
========================

The jws Module implements the `JSON Web Signature`_ standard.
A JSON Web Signature is represented by a JWS object, related utility
classes and functions are available in this module too.

.. _JSON Web Signature: http://tools.ietf.org/html/rfc7515

Classes
-------

.. autoclass:: jwcrypto.jws.JWS
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jws.JWSCore
   :members:
   :show-inheritance:

Variables
---------

.. autodata:: jwcrypto.jws.default_allowed_algs

Exceptions
----------

.. autoclass:: jwcrypto.jws.InvalidJWSSignature
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jws.InvalidJWSObject
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jws.InvalidJWSOperation
   :members:
   :show-inheritance:

Registries
----------

.. autodata:: jwcrypto.jws.JWSHeaderRegistry
   :annotation:
