# Copyright (C) 2015  JWCrypto Project Contributors - see LICENSE file

from binascii import hexlify, unhexlify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.common import base64url_decode, base64url_encode
from jwcrypto.common import json_decode, json_encode
import os

# RFC 7518 - 7.4
JWKTypesRegistry = {'EC': 'Elliptic Curve',
                    'RSA': 'RSA',
                    'oct': 'Octet sequence'}
"""Registry of valid Key Types"""

# RFC 7518 - 7.5
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
"""Registry of valid key values"""

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
"""Regstry of valid key parameters"""

# RFC 7518 - 7.6
JWKEllipticCurveRegistry = {'P-256': 'P-256 curve',
                            'P-384': 'P-384 curve',
                            'P-521': 'P-521 curve'}
"""Registry of allowed Elliptic Curves"""

# RFC 7517 - 8.2
JWKUseRegistry = {'sig': 'Digital Signature or MAC',
                  'enc': 'Encryption'}
"""Registry of allowed uses"""

# RFC 7517 - 8.3
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
"""Registry of allowed operations"""


class InvalidJWKType(Exception):
    """Invalid JWK Type Exception.

    This exception is raised when an invalid parameter type is used.
    """

    def __init__(self, value=None):
        super(InvalidJWKType, self).__init__()
        self.value = value

    def __str__(self):
        return 'Unknown type "%s", valid types are: %s' % (
            self.value, list(JWKTypesRegistry.keys()))


class InvalidJWKUsage(Exception):
    """Invalid JWK usage Exception.

    This exception is raised when an invalid key usage is requested,
    based on the key type and declared usage constraints.
    """

    def __init__(self, use, value):
        super(InvalidJWKUsage, self).__init__()
        self.value = value
        self.use = use

    def __str__(self):
        if self.use in list(JWKUseRegistry.keys()):
            usage = JWKUseRegistry[self.use]
        else:
            usage = 'Unknown(%s)' % self.use
        if self.value in list(JWKUseRegistry.keys()):
            valid = JWKUseRegistry[self.value]
        else:
            valid = 'Unknown(%s)' % self.value
        return 'Invalid usage requested: "%s". Valid for: "%s"' % (usage,
                                                                   valid)


class InvalidJWKOperation(Exception):
    """Invalid JWK Operation Exception.

    This exception is raised when an invalid key operation is requested,
    based on the key type and declared usage constraints.
    """

    def __init__(self, operation, values):
        super(InvalidJWKOperation, self).__init__()
        self.op = operation
        self.values = values

    def __str__(self):
        if self.op in list(JWKOperationsRegistry.keys()):
            op = JWKOperationsRegistry[self.op]
        else:
            op = 'Unknown(%s)' % self.op
        valid = list()
        for v in self.values:
            if v in list(JWKOperationsRegistry.keys()):
                valid.append(JWKOperationsRegistry[v])
            else:
                valid.append('Unknown(%s)' % v)
        return 'Invalid operation requested: "%s". Valid for: "%s"' % (op,
                                                                       valid)


class InvalidJWKValue(Exception):
    """Invalid JWK Value Exception.

    This exception is raised when an invalid/unknown value is used in the
    context of an operation that requires specific values to be used based
    on the key type or other constraints.
    """

    pass


class JWK(object):
    """JSON Web Key object

    This object represent a Key.
    It must be instantiated by using the standard defined key/value pairs
    as arguents of the initialization function.
    """

    def __init__(self, **kwargs):
        """Creates a new JWK object.

        The function arguments must be valid parameters as defined in the
        'IANA JSON Web Key Set Parameters registry' and specified in
        the :data:`JWKParamsRegistry` variable. The 'kty' parameter must
        always be provided and its value must be a valid one as defined
        by the 'IANA JSON Web Key Types registry' and specified in the
        :data:`JWKTypesRegistry` variable. The valid key parameters per
        key type are defined in the :data:`JWKValuesregistry` variable.

        Alternatively if the 'generate' parameter is provided, with a
        valid key type as value then a new key will be generated according
        to the defaults or provided key strenght options (type specific).

        Valid options per type, when generating new keys:
         * oct: size(int)
         * RSA: public_exponent(int), size(int)
         * EC: curve(str) (one of P-256, P-384, P-521)

        :raises InvalidJWKType: if the key type is invalid
        :raises InvalidJWKValue: if incorrect or inconsistent parameters
            are provided.
        """
        self._params = dict()
        self._key = dict()
        self._unknown = dict()

        if 'generate' in kwargs:
            self.generate_key(**kwargs)
        else:
            self.import_key(**kwargs)

    def generate_key(self, **kwargs):
        params = kwargs.copy()
        try:
            kty = params['generate']
            del params['generate']
            gen = getattr(self, '_generate_%s' % kty)
        except (KeyError, AttributeError):
            raise InvalidJWKType(kty)

        gen(params)

    def _generate_oct(self, params):
        size = 128
        if 'size' in params:
            size = params['size']
            del params['size']
        key = os.urandom(size // 8)
        params['kty'] = 'oct'
        params['k'] = base64url_encode(key)
        self.import_key(**params)

    def _encode_int(self, i):
        I = hex(i).rstrip("L").lstrip("0x")
        return base64url_encode(unhexlify((len(I) % 2) * '0' + I))

    def _generate_RSA(self, params):
        pubexp = 65537
        size = 2048
        if 'public_exponent' in params:
            pubexp = params['public_exponent']
            del params['public_exponent']
        if 'size' in params:
            size = params['size']
            del params['size']
        key = rsa.generate_private_key(pubexp, size, default_backend())
        pn = key.private_numbers()
        params['kty'] = 'RSA'
        params['n'] = self._encode_int(pn.public_numbers.n)
        params['e'] = self._encode_int(pn.public_numbers.e)
        params['d'] = self._encode_int(pn.d)
        params['p'] = self._encode_int(pn.p)
        params['q'] = self._encode_int(pn.q)
        params['dp'] = self._encode_int(pn.dmp1)
        params['dq'] = self._encode_int(pn.dmq1)
        params['qi'] = self._encode_int(pn.iqmp)
        self.import_key(**params)

    def _get_curve_by_name(self, name):
        if name == 'P-256':
            return ec.SECP256R1()
        elif name == 'P-384':
            return ec.SECP384R1()
        elif name == 'P-521':
            return ec.SECP521R1()
        else:
            raise InvalidJWKValue('Unknown Elliptic Curve Type')

    def _generate_EC(self, params):
        curve = 'P-256'
        if 'curve' in params:
            curve = params['curve']
            del params['curve']
        # 'curve' is for backwards compat, if 'crv' is defined it takes
        # precedence
        if 'crv' in params:
            curve = params['crv']
            del params['crv']
        curve_name = self._get_curve_by_name(curve)
        key = ec.generate_private_key(curve_name, default_backend())
        pn = key.private_numbers()
        params['kty'] = 'EC'
        params['crv'] = curve
        params['x'] = self._encode_int(pn.public_numbers.x)
        params['y'] = self._encode_int(pn.public_numbers.y)
        params['d'] = self._encode_int(pn.private_value)
        self.import_key(**params)

    def import_key(self, **kwargs):
        names = list(kwargs.keys())

        for name in list(JWKParamsRegistry.keys()):
            if name in kwargs:
                self._params[name] = kwargs[name]
                while name in names:
                    names.remove(name)

        kty = self._params.get('kty', None)
        if kty not in JWKTypesRegistry:
            raise InvalidJWKType(kty)

        for name in list(JWKValuesRegistry[kty].keys()):
            if name in kwargs:
                self._key[name] = kwargs[name]
                while name in names:
                    names.remove(name)

        # Unknown key parameters are allowed
        # Let's just store them out of the way
        for name in names:
            self._unknown[name] = kwargs[name]

        if len(self._key) == 0:
            raise InvalidJWKValue('No Key Values found')

        # check key_ops
        if 'key_ops' in self._params:
            for ko in self._params['key_ops']:
                c = 0
                for cko in self._params['key_ops']:
                    if ko == cko:
                        c += 1
                if c != 1:
                    raise InvalidJWKValue('Duplicate values in "key_ops"')

        # check use/key_ops consistency
        if 'use' in self._params and 'key_ops' in self._params:
            sigl = ['sign', 'verify']
            encl = ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey',
                    'deriveKey', 'deriveBits']
            if self._params['use'] == 'sig':
                for op in encl:
                    if op in self._params['key_ops']:
                        raise InvalidJWKValue('Incompatible "use" and'
                                              ' "key_ops" values specified at'
                                              ' the same time')
            elif self._params['use'] == 'enc':
                for op in sigl:
                    if op in self._params['key_ops']:
                        raise InvalidJWKValue('Incompatible "use" and'
                                              ' "key_ops" values specified at'
                                              ' the same time')

    def export(self, private_key=True):
        """Exports the key in the standard JSON format.

        :param private_key(bool): Whether to export the private key.
                                  Defaults to True.
        """
        if private_key is not True:
            return self.export_public()
        d = dict()
        d.update(self._params)
        d.update(self._key)
        d.update(self._unknown)
        return json_encode(d)

    def export_public(self):
        """Exports the public key in the standard JSON format.
           This function is deprecated and maintained only for
           backwards compatibility, use export(private_key=False)
           instead."""
        pub = {}
        preg = JWKParamsRegistry
        for name in preg:
            if preg[name][1] == 'Public':
                if name in self._params:
                    pub[name] = self._params[name]
        reg = JWKValuesRegistry[self._params['kty']]
        for param in reg:
            if reg[param][1] == 'Public':
                pub[param] = self._key[param]
        return json_encode(pub)

    @property
    def key_type(self):
        """The Key type"""
        return self._params.get('kty', None)

    @property
    def key_id(self):
        """The Key ID.
        Provided by the kid parameter if present, otherwise returns None.
        """
        return self._params.get('kid', None)

    def get_curve(self, arg):
        """Gets the Elliptic Curve associated with the key.

        :param arg: an optional curve name

        :raises InvalidJWKType: the key is not an EC key.
        :raises InvalidJWKValue: if the curve names is invalid.
        """
        k = self._key
        if self._params['kty'] != 'EC':
            raise InvalidJWKType('Not an EC key')
        if arg and k['crv'] != arg:
            raise InvalidJWKValue('Curve requested is "%s", but '
                                  'key curve is "%s"' % (arg, k['crv']))

        return self._get_curve_by_name(k['crv'])

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
        return int(hexlify(base64url_decode(n)), 16)

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

    def _get_public_key(self, arg=None):
        if self._params['kty'] == 'oct':
            return self._key['k']
        elif self._params['kty'] == 'RSA':
            return self._rsa_pub(self._key).public_key(default_backend())
        elif self._params['kty'] == 'EC':
            return self._ec_pub(self._key, arg).public_key(default_backend())
        else:
            raise NotImplementedError

    def _get_private_key(self, arg=None):
        if self._params['kty'] == 'oct':
            return self._key['k']
        elif self._params['kty'] == 'RSA':
            return self._rsa_pri(self._key).private_key(default_backend())
        elif self._params['kty'] == 'EC':
            return self._ec_pri(self._key, arg).private_key(default_backend())
        else:
            raise NotImplementedError

    def get_op_key(self, operation=None, arg=None):
        """Get the key object associated to the requested opration.
        For example the public RSA key for the 'verify' operation or
        the private EC key for the 'decrypt' operation.

        :param operation: The requested operation.
         The valid set of operations is availble in the
         :data:`JWKOperationsRegistry` registry.
        :param arg: an optional, context specific, argument
         For example a curve name.

        :raises InvalidJWKOperation: if the operation is unknown or
         not permitted with this key.
        :raises InvalidJWKUsage: if the use constraints do not permit
         the operation.
        """
        validops = self._params.get('key_ops',
                                    list(JWKOperationsRegistry.keys()))
        if validops is not list:
            validops = [validops]
        if operation is None:
            if self._params['kty'] == 'oct':
                return self._key['k']
            raise InvalidJWKOperation(operation, validops)
        elif operation == 'sign':
            self._check_constraints('sig', operation)
            return self._get_private_key(arg)
        elif operation == 'verify':
            self._check_constraints('sig', operation)
            return self._get_public_key(arg)
        elif operation == 'encrypt' or operation == 'wrapKey':
            self._check_constraints('enc', operation)
            return self._get_public_key(arg)
        elif operation == 'decrypt' or operation == 'unwrapKey':
            self._check_constraints('enc', operation)
            return self._get_private_key(arg)
        else:
            raise NotImplementedError


class JWKSet(set):
    """A set of JWK objects.

    Inherits for the standard 'set' bultin type.
    """

    def add(self, elem):
        """Adds a JWK object to the set

        :param elem: the JWK object to add.

        :raises TypeError: if the object is not a JWK.
        """
        if not isinstance(elem, JWK):
            raise TypeError('Only JWK objects are valid elements')
        set.add(self, elem)

    def export(self, private_keys=True):
        """Exports the set using the standard JSON format

        :param private_key(bool): Whether to export private keys.
                                  Defaults to True.
        """
        keys = list()
        for jwk in self:
            keys.append(json_decode(jwk.export(private_keys)))
        return json_encode({'keys': keys})

    def get_key(self, kid):
        """Gets a key from the set.
        :param kid: the 'kid' key identifier.
        """
        for jwk in self:
            if jwk.key_id == kid:
                return jwk
        return None
