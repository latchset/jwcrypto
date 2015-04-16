# Copyright (C) 2015  JWCrypto Project Contributors - see LICENSE file

from jwcrypto.common import json_encode
from jwcrypto.jws import JWS
from jwcrypto.jwe import JWE


class JWT(object):
    """JSON Web token object

    This object represent a generic token.
    """

    def __init__(self, header=None, claims=None, jwt=None, key=None,
                 algs=None):
        """Creates a JWT object.

        :param header: A dict or a JSON string with the JWT Header data.
        :param claims: A dict or a string withthe JWT Claims data.
        :param jwt: a 'raw' JWT token
        :param key: A (:class:`jwcrypto.jwk.JWK`) key to deserialize
         the token.
        :param algs: An optional list of allowed algorithms

        Note: either the header,claims or jwt,key parameters should be
        provided as a deserialization operation (which occurs if the jwt
        is provided will wipe any header os claim provided by setting
        those obtained from the deserialization of the jwt token.
        """

        self._header = None
        self._claims = None
        self._token = None
        self._algs = algs

        if header:
            self.header = header

        if claims:
            self.claims = claims

        if jwt is not None:
            self.deserialize(jwt, key)

    @property
    def header(self):
        if self._header is None:
            raise KeyError("'header' not set")
        return self._header

    @header.setter
    def header(self, h):
        if isinstance(h, dict):
            self._header = json_encode(h)
        else:
            self._header = h

    @property
    def claims(self):
        if self._claims is None:
            raise KeyError("'claims' not set")
        return self._claims

    @claims.setter
    def claims(self, c):
        if isinstance(c, dict):
            self._claims = json_encode(c)
        else:
            self._claims = c

    @property
    def token(self):
        return self._token

    @token.setter
    def token(self, t):
        if isinstance(t, JWS) or isinstance(t, JWE) or isinstance(t, JWT):
            self._token = t
        else:
            raise TypeError("Invalid token type, must be one of JWS,JWE,JWT")

    def make_signed_token(self, key):
        """Signs the payload.

        Creates a JWS token with the header as the JWS protected header and
        the claims as the payload. See (:class:`jwcrypto.jws.JWS`) for
        details on the exceptions that may be reaised.

        :param key: A (:class:`jwcrypto.jwk.JWK`) key.
        """

        t = JWS(self.claims)
        t.add_signature(key, protected=self.header)
        self.token = t

    def make_encrypted_token(self, key):
        """Encrypts the payload.

        Creates a JWE token with the header as the JWE protected header and
        the claims as the plaintext. See (:class:`jwcrypto.jwe.JWE`) for
        details on the exceptions that may be reaised.

        :param key: A (:class:`jwcrypto.jwk.JWK`) key.
        """

        t = JWE(self.claims, self.header)
        t.add_recipient(key)
        self.token = t

    def deserialize(self, jwt, key=None):
        """Deserialize a JWT token.

        NOTE: Destroys any current status and tries to import the raw
        token provided.

        :param jwt: a 'raw' JWT token.
        :param key: A (:class:`jwcrypto.jwk.JWK`) verification or
         decryption key.
        """
        c = jwt.count('.')
        if c == 2:
            self.token = JWS()
        elif c == 4:
            self.token = JWE()
        else:
            raise ValueError("Token format unrecognized")

        # Apply algs restrictions if any, before performing any operation
        if self._algs:
            self.token.allowed_algs = self._algs

        # now deserialize and also decrypt/verify (or raise) if we
        # have a key
        self.token.deserialize(jwt, key)

        if key is not None:
            self.header = self.token.jose_header
            self.claims = self.token.payload.decode('utf-8')

    def serialize(self, compact=True):
        """Serializes the object into a JWS token.

        :param compact(boolean): must be True.

        Note: the compact parameter is provided for general compatibility
        with the serialize() functions of :class:`jwcrypto.jws.JWS` and
        :class:`jwcrypto.jwe.JWE` so that these objects can all be used
        interchangeably. However the only valid JWT representtion is the
        compact representation.
        """
        return self.token.serialize(compact)
