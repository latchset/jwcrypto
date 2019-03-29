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

Examples
--------

Sign a JWS token::
    >>> from jwcrypto import jwk, jws
    >>> from jwcrypto.common import json_encode
    >>> key = jwk.JWK.generate(kty='oct', size=256)
    >>> payload = "My Integrity protected message"
    >>> jwstoken = jws.JWS(payload.encode('utf-8'))
    >>> jwstoken.add_signature(key, None,
                               json_encode({"alg": "HS256"}),
                               json_encode({"kid": key.thumbprint()}))
    >>> sig = jwstoken.serialize()

Verify a JWS token::
    >>> jwstoken = jws.JWS()
    >>> jwstoken.deserialize(sig)
    >>> jwstoken.verify(key)
    >>> payload = jwstoken.payload
