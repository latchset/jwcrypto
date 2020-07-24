JSON Web Token (JWT)
====================

The jwt Module implements the `JSON Web Token`_ standard.
A JSON Web Token is represented by a JWT object, related utility classes and
functions are available in this module too.

.. _JSON Web Token: http://tools.ietf.org/html/rfc7519

Classes
-------

.. autoclass:: jwcrypto.jwt.JWT
   :members:
   :show-inheritance:

Examples
--------

Create a symmetric key::
    >>> from jwcrypto import jwt, jwk
    >>> key = jwk.JWK(generate='oct', size=256)
    >>> key.export()
    '{"k":"Wal4ZHCBsml0Al_Y8faoNTKsXCkw8eefKXYFuwTBOpA","kty":"oct"}'

Create a signed token with the generated key::
    >>> Token = jwt.JWT(header={"alg": "HS256"},
                        claims={"info": "I'm a signed token"})
    >>> Token.make_signed_token(key)
    >>> Token.serialize()
    u'eyJhbGciOiJIUzI1NiJ9.eyJpbmZvIjoiSSdtIGEgc2lnbmVkIHRva2VuIn0.rjnRMAKcaRamEHnENhg0_Fqv7Obo-30U4bcI_v-nfEM'

Further encrypt the token with the same key::
    >>> Etoken = jwt.JWT(header={"alg": "A256KW", "enc": "A256CBC-HS512"},
                         claims=Token.serialize())
    >>> Etoken.make_encrypted_token(key)
    >>> Etoken.serialize()
    u'eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.ST5RmjqDLj696xo7YFTFuKUhcd3naCrm6yMjBM3cqWiFD6U8j2JIsbclsF7ryNg8Ktmt1kQJRKavV6DaTl1T840tP3sIs1qz.wSxVhZH5GyzbJnPBAUMdzQ.6uiVYwrRBzAm7Uge9rEUjExPWGbgerF177A7tMuQurJAqBhgk3_5vee5DRH84kHSapFOxcEuDdMBEQLI7V2E0F57-d01TFStHzwtgtSmeZRQ6JSIL5XlgJouwHfSxn9Z_TGl5xxq4TksORHED1vnRA.5jPyPWanJVqlOohApEbHmxi3JHp1MXbmvQe2_dVd8FI'

Now decrypt and verify::
    >>> from jwcrypto import jwt, jwk
    >>> k = {"k": "Wal4ZHCBsml0Al_Y8faoNTKsXCkw8eefKXYFuwTBOpA", "kty": "oct"}
    >>> key = jwk.JWK(**k)
    >>> e = u'eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.ST5RmjqDLj696xo7YFTFuKUhcd3naCrm6yMjBM3cqWiFD6U8j2JIsbclsF7ryNg8Ktmt1kQJRKavV6DaTl1T840tP3sIs1qz.wSxVhZH5GyzbJnPBAUMdzQ.6uiVYwrRBzAm7Uge9rEUjExPWGbgerF177A7tMuQurJAqBhgk3_5vee5DRH84kHSapFOxcEuDdMBEQLI7V2E0F57-d01TFStHzwtgtSmeZRQ6JSIL5XlgJouwHfSxn9Z_TGl5xxq4TksORHED1vnRA.5jPyPWanJVqlOohApEbHmxi3JHp1MXbmvQe2_dVd8FI'
    >>> ET = jwt.JWT(key=key, jwt=e)
    >>> ST = jwt.JWT(key=key, jwt=ET.claims)
    >>> ST.claims
    u'{"info":"I\'m a signed token"}'
