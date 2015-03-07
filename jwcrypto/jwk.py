# Copyright (C) 2015  JWCrypto Project Contributors - see LICENSE file

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.common import base64url_decode
import json

# draft-ietf-jose-json-web-algorithms-24 - 7.4
JWKTypesRegistry = {'EC': 'Elliptic Curve',
                    'RSA': 'RSA',
                    'oct': 'Octet sequence'}

# draft-ietf-jose-json-web-algorithms-24 - 7.5
# It is part of the JWK Parameters Registry, but we want a more
# specific map for internal usage
JWKValuesRegistry = {'EC': {'crv': ('Curve', 'Public'),
                            'x': ('X Coordinate', 'Public'),
                            'y': ('Y Coordinate', 'Public'),
                            'd': ('ECC Private Key', 'Private')},
                     'RSA': {'n': ('Modulus', 'Public'),
                             'e': ('Exponent', 'Public'),
                             'd': ('Private Exponent', 'Private'),
                             'p': ('First Prime Factor', 'Private'),
                             'q': ('Second Prime Factor', 'Private'),
                             'dp': ('First Factor CRT Exponent', 'Private'),
                             'dq': ('Second Factor CRT Exponent', 'Private'),
                             'qi': ('First CRT Coefficient', 'Private')},
                     'oct': {'k': ('Key Value', 'Private')}}

JWKParamsRegistry = {'kty': ('Key Type', 'Public', ),
                     'use': ('Public Key Use', 'Public'),
                     'key_ops': ('Key Operations', 'Public'),
                     'alg': ('Algorithm', 'Public'),
                     'kid': ('Key ID', 'Public'),
                     'x5u': ('X.509 URL', 'Public'),
                     'x5c': ('X.509 Certificate Chain', 'Public'),
                     'x5t': ('X.509 Certificate SHA-1 Thumbprint', 'Public'),
                     'x5t#S256': ('X.509 Certificate SHA-256 Thumbprint',
                                  'Public')}

# draft-ietf-jose-json-web-algorithms-24 - 7.6
JWKEllipticCurveRegistry = {'P-256': 'P-256 curve',
                            'P-384': 'P-384 curve',
                            'P-521': 'P-521 curve'}

# draft-ietf-jose-json-web-key-41 - 8.2
JWKUseRegistry = {'sig': 'Digital Signature or MAC',
                  'enc': 'Encryption'}

# draft-ietf-jose-json-web-key-41 - 8.2
JWKOperationsRegistry = {'sign': 'Compute digital Signature or MAC',
                         'verify': 'Verify digital signature or MAC',
                         'encrypt': 'Encrypt content',
                         'decrypt': 'Decrypt content and validate'
                                    ' decryption, if applicable',
                         'wrapKey': 'Encrypt key',
                         'unwrapKey': 'Decrypt key and validate'
                                    ' decryption, if applicable',
                         'deriveKey': 'Derive key',
                         'deriveBits': 'Derive bits not to be used as a key'}


class InvalidJWKType(Exception):

    def __init__(self, value=None):
        super(InvalidJWKType, self).__init__()
        self.value = value

    def __str__(self):
        return 'Unknown type "%s", valid types are: %s' % (
            self.value, JWKTypesRegistry.keys())


class InvalidJWKUsage(Exception):

    def __init__(self, use, value):
        super(InvalidJWKUsage, self).__init__()
        self.value = value
        self.use = use

    def __str__(self):
        if self.use in JWKUseRegistry.keys():
            usage = JWKUseRegistry[self.use]
        else:
            usage = 'Unknown(%s)' % self.use
        if self.value in JWKUseRegistry.keys():
            valid = JWKUseRegistry[self.value]
        else:
            valid = 'Unknown(%s)' % self.value
        return 'Invalid usage requested: "%s". Valid for: "%s"' % (usage,
                                                                   valid)


class InvalidJWKOperation(Exception):

    def __init__(self, operation, values):
        super(InvalidJWKOperation, self).__init__()
        self.op = operation
        self.values = values

    def __str__(self):
        if self.op in JWKOperationsRegistry.keys():
            op = JWKOperationsRegistry[self.op]
        else:
            op = 'Unknown(%s)' % self.op
        valid = list()
        for v in self.values:
            if v in JWKOperationsRegistry.keys():
                valid.append(JWKOperationsRegistry[v])
            else:
                valid.append('Unknown(%s)' % v)
        return 'Invalid operation requested: "%s". Valid for: "%s"' % (op,
                                                                       valid)


class InvalidJWKValue(Exception):
    pass


class JWK(object):

    def __init__(self, **kwargs):

        names = kwargs.keys()

        self._params = dict()
        for name in JWKParamsRegistry.keys():
            if name in kwargs:
                self._params[name] = kwargs[name]
                while name in names:
                    names.remove(name)

        kty = self._params.get('kty', None)
        if kty not in JWKTypesRegistry:
            raise InvalidJWKType(kty)

        self._key = dict()
        for name in JWKValuesRegistry[kty].keys():
            if name in kwargs:
                self._key[name] = kwargs[name]
                while name in names:
                    names.remove(name)

        if len(names) != 0:
            raise InvalidJWKValue('Unknown key parameters: %s' % names)

        if len(self._key) == 0:
            raise InvalidJWKValue('No Key Values found')

    def export(self):
        d = dict()
        d.update(self._params)
        d.update(self._key)
        return json.dumps(d)

    @property
    def key_id(self):
        return self._params.get('kid', None)

    def get_curve(self, arg):
        k = self._key
        if self._params['kty'] != 'EC':
            raise InvalidJWKType('Not an EC key')
        if arg and k['crv'] != arg:
            raise InvalidJWKValue('Curve requested is "%s", but '
                                  'key curve is "%s"' % (arg, k['crv']))
        if k['crv'] == 'P-256':
            return ec.SECP256R1()
        elif k['crv'] == 'P-384':
            return ec.SECP384R1()
        elif k['crv'] == 'P-521':
            return ec.SECP521R1()
        else:
            raise InvalidJWKValue('Unknown Elliptic Curve Type')

    def _check_constraints(self, usage, operation):
        use = self._params.get('use', None)
        if use and use != usage:
            raise InvalidJWKUsage(usage, use)
        ops = self._params.get('key_ops', None)
        if ops:
            if not isinstance(ops, list):
                ops = [ops]
            if operation not in ops:
                raise InvalidJWKOperation(operation, ops)
        # TODO: check alg ?

    def _decode_int(self, n):
        return int(base64url_decode(n).encode('hex'), 16)

    def _rsa_pub(self, k):
        return rsa.RSAPublicNumbers(self._decode_int(k['e']),
                                    self._decode_int(k['n']))

    def _rsa_pri(self, k):
        return rsa.RSAPrivateNumbers(self._decode_int(k['p']),
                                     self._decode_int(k['q']),
                                     self._decode_int(k['d']),
                                     self._decode_int(k['dp']),
                                     self._decode_int(k['dq']),
                                     self._decode_int(k['qi']),
                                     self._rsa_pub(k))

    def _ec_pub(self, k, curve):
        return ec.EllipticCurvePublicNumbers(self._decode_int(k['x']),
                                             self._decode_int(k['y']),
                                             self.get_curve(curve))

    def _ec_pri(self, k, curve):
        return ec.EllipticCurvePrivateNumbers(self._decode_int(k['d']),
                                              self._ec_pub(k, curve))

    def sign_key(self, arg=None):
        self._check_constraints('sig', 'sign')
        if self._params['kty'] == 'oct':
            return self._key['k']
        elif self._params['kty'] == 'RSA':
            return self._rsa_pri(self._key).private_key(default_backend())
        elif self._params['kty'] == 'EC':
            return self._ec_pri(self._key, arg).private_key(default_backend())
        else:
            raise NotImplementedError

    def verify_key(self, arg=None):
        self._check_constraints('sig', 'verify')
        if self._params['kty'] == 'oct':
            return self._key['k']
        elif self._params['kty'] == 'RSA':
            return self._rsa_pub(self._key).public_key(default_backend())
        elif self._params['kty'] == 'EC':
            return self._ec_pub(self._key, arg).public_key(default_backend())
        else:
            raise NotImplementedError

    def encrypt_key(self, arg=None):
        self._check_constraints('enc', 'encrypt')
        if self._params['kty'] == 'oct':
            return self._key['k']
        elif self._params['kty'] == 'RSA':
            return self._rsa_pub(self._key).public_key(default_backend())
        elif self._params['kty'] == 'EC':
            return self._ec_pub(self._key, arg).public_key(default_backend())
        else:
            raise NotImplementedError

    def decrypt_key(self, arg=None):
        self._check_constraints('enc', 'decrypt')
        if self._params['kty'] == 'oct':
            return self._key['k']
        elif self._params['kty'] == 'RSA':
            return self._rsa_pri(self._key).private_key(default_backend())
        elif self._params['kty'] == 'EC':
            return self._ec_pri(self._key, arg).private_key(default_backend())
        else:
            raise NotImplementedError


class JWKSet(set):

    def add(self, elem):
        if not isinstance(elem, JWK):
            raise TypeError('Only JWK objects are valid elements')
        set.add(self, elem)

    def export(self):
        keys = list()
        for jwk in self:
            keys.append(json.loads(jwk.export()))
        return json.dumps({'keys': keys})

    def get_key(self, kid):
        for jwk in self:
            if jwk.key_id == kid:
                return jwk
        return None
