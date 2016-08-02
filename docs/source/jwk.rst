JSON Web Key (JWK)
==================

The jwk Module implements the `JSON Web Key`_ standard.
A JSON Web Key is represented by a JWK object, related utility classes and
functions are availbale in this module too.

.. _JSON Web Key: http://tools.ietf.org/html/rfc7517

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

Examples
--------

Create a 256bit symmetric key::
    >>> from jwcrypto import jwk
    >>> key = jwk.JWK.generate(kty='oct', size=256)

Export the key with::
    >>> key.export()
    '{"k":"X6TBlwY2so8EwKZ2TFXM7XHSgWBKQJhcspzYydp5Y-o","kty":"oct"}'

Create a 2048bit RSA keypair::
    >>> jwk.JWK.generate(kty='RSA', size=2048)

Create a P-256 EC keypair and export the public key::
    >>> key = jwk.JWK.generate(kty='EC', crv='P-256')
    >>> key.export(private_key=False)
    '{"y":"VYlYwBfOTIICojCPfdUjnmkpN-g-lzZKxzjAoFmDRm8",
      "x":"3mdE0rODWRju6qqU01Kw5oPYdNxBOMisFvJFH1vEu9Q",
      "crv":"P-256","kty":"EC"}'

Import a P-256 Public Key::
    >>> expkey = {"y":"VYlYwBfOTIICojCPfdUjnmkpN-g-lzZKxzjAoFmDRm8",
                  "x":"3mdE0rODWRju6qqU01Kw5oPYdNxBOMisFvJFH1vEu9Q",
                  "crv":"P-256","kty":"EC"}
    >>> key = jwk.JWK(**expkey)

Import a Key from a PEM file::
    >>> with open("public.pem", "rb") as pemfile:
    >>>     key = jwk.JWK.from_pem(pemfile.read())
