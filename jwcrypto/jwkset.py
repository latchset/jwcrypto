# Copyright (C) 2015  JWCrypto Project Contributors - see LICENSE file

import json
from jwcrypto.jwk import JWK


class InvalidJWKSet(Exception):
    pass


class InvalidKeyName(Exception):
    pass


class JWKSet(object):

    def __init__(self, **kwargs):

        if 'keys' not in kwargs:
            raise InvalidJWKSet('No keys argument found')

        self._keys = dict()

        for key_name in kwargs['keys'].keys():
            self._keys[key_name] = JWK(**kwargs['keys'][key_name])

    def export(self):
        d = dict()
        d['keys'] = []
        for key_name in self._keys.keys():
            d['keys'][key_name] = self._keys[key_name].export()
        return json.dumps(d)

    def get_key(self, key_name):
        if key_name in self._keys.keys():
            return self._keys[key_name]
        else:
            raise InvalidKeyName('Key %s not in set' % key_name)

    def get_key_names(self):
        return self._keys.keys()
