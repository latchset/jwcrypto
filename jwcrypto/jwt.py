# Copyright (C) 2015  JWCrypto Project Contributors - see LICENSE file

from jwcrypto.common import json_encode
from jwcrypto.jws import JWS
from jwcrypto.jwe import JWE


class JWT(object):

    def __init__(self, header=None, claims=None, jwt=None, key=None):

        self._header = None
        self._claims = None
        self._token = None

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
        t = JWS(self.claims)
        t.add_signature(key, protected=self.header)
        self.token = t

    def make_encrypted_token(self, key):
        t = JWE(self.claims, self.header)
        t.add_recipient(key)
        self.token = t

    def deserialize(self, jwt, key=None):
        c = jwt.count('.')
        if c == 2:
            self.token = JWS()
        elif c == 4:
            self.token = JWE()
        else:
            raise ValueError("Token format unrecognized")

        # now deserialize and also decrypt/verify (or raise) if we
        # have a key
        self.token.deserialize(jwt, key)

        if key is not None:
            self.header = self.token.jose_header
            self.claims = self.token.payload.decode('utf-8')

    def serialize(self, compact=True):
        return self.token.serialize(compact)
