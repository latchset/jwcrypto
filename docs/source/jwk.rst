JSON Web Key (JWK)
==================

The jwk Module implements the `JSON Web Key`_ draft (currently version 41).
A JSON Web Key is represented by a JWK object, related utility classes and
functions are availbale in this module too.

.. _JSON Web Key: http://tools.ietf.org/html/draft-ietf-jose-json-web-key-41

Classes
-------

.. autoclass:: jwcrypto.jwk.JWK
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwk.JWKSet
   :members:
   :show-inheritance:

Exceptions
----------

.. autoclass:: jwcrypto.jwk.InvalidJWKType
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwk.InvalidJWKValue
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwk.InvalidJWKOperation
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwk.InvalidJWKUsage
   :members:
   :show-inheritance:

Registries
----------

.. autodata:: jwcrypto.jwk.JWKTypesRegistry
   :annotation:

.. autodata:: jwcrypto.jwk.JWKValuesRegistry
   :annotation:

.. autodata:: jwcrypto.jwk.JWKParamsRegistry
   :annotation:

.. autodata:: jwcrypto.jwk.JWKEllipticCurveRegistry
   :annotation:

.. autodata:: jwcrypto.jwk.JWKUseRegistry
   :annotation:

.. autodata:: jwcrypto.jwk.JWKOperationsRegistry
   :annotation:
