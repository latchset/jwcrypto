# Copyright (C) 2015  JWCrypto Project Contributors - see LICENSE file

import os
from binascii import hexlify, unhexlify
from collections import namedtuple
from enum import Enum

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa

from six import iteritems

from jwcrypto.common import JWException
from jwcrypto.common import base64url_decode, base64url_encode
from jwcrypto.common import json_decode, json_encode


class UnimplementedOKPCurveKey(object):
    @classmethod
    def generate(cls):
        raise NotImplementedError

    @classmethod
    def from_public_bytes(cls, *args):
        raise NotImplementedError

    @classmethod
    def from_private_bytes(cls, *args):
        raise NotImplementedError


ImplementedOkpCurves = []


# Handle the best we can older versions of python cryptography that
# do not yet implement these interfaces properly
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey, Ed25519PrivateKey
    )
    ImplementedOkpCurves.append('Ed25519')
except ImportError:
    Ed25519PublicKey = UnimplementedOKPCurveKey
    Ed25519PrivateKey = UnimplementedOKPCurveKey
try:
    from cryptography.hazmat.primitives.asymmetric.ed448 import (
        Ed448PublicKey, Ed448PrivateKey
    )
    ImplementedOkpCurves.append('Ed448')
except ImportError:
    Ed448PublicKey = UnimplementedOKPCurveKey
    Ed448PrivateKey = UnimplementedOKPCurveKey
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PublicKey, X25519PrivateKey
    )
    priv_bytes = getattr(X25519PrivateKey, 'from_private_bytes', None)
    if priv_bytes is None:
        raise ImportError
    ImplementedOkpCurves.append('X25519')
except ImportError:
    X25519PublicKey = UnimplementedOKPCurveKey
    X25519PrivateKey = UnimplementedOKPCurveKey
try:
    from cryptography.hazmat.primitives.asymmetric.x448 import (
        X448PublicKey, X448PrivateKey
    )
    ImplementedOkpCurves.append('X448')
except ImportError:
    X448PublicKey = UnimplementedOKPCurveKey
    X448PrivateKey = UnimplementedOKPCurveKey


_OKP_CURVE = namedtuple('Name', 'pubkey privkey')
_OKP_CURVES_TABLE = {
    'Ed25519': _OKP_CURVE(Ed25519PublicKey, Ed25519PrivateKey),
    'Ed448': _OKP_CURVE(Ed448PublicKey, Ed448PrivateKey),
    'X25519': _OKP_CURVE(X25519PublicKey, X25519PrivateKey),
    'X448': _OKP_CURVE(X448PublicKey, X448PrivateKey)
}


# RFC 7518 - 7.4 , RFC 8037 - 5
JWKTypesRegistry = {'EC': 'Elliptic Curve',
                    'RSA': 'RSA',
                    'oct': 'Octet sequence',
                    'OKP': 'Octet Key Pair'}
"""Registry of valid Key Types"""


# RFC 7518 - 7.5
# It is part of the JWK Parameters Registry, but we want a more
# specific map for internal usage
class ParmType(Enum):
    name = 'A string with a name'
    b64 = 'Base64url Encoded'
    b64u = 'Base64urlUint Encoded'
    unsupported = 'Unsupported Parameter'


JWKParameter = namedtuple('Parameter', 'description public required type')
JWKValuesRegistry = {
    'EC': {
        'crv': JWKParameter('Curve', True, True, ParmType.name),
        'x': JWKParameter('X Coordinate', True, True, ParmType.b64),
        'y': JWKParameter('Y Coordinate', True, True, ParmType.b64),
        'd': JWKParameter('ECC Private Key', False, False, ParmType.b64),
    },
    'RSA': {
        'n': JWKParameter('Modulus', True, True, ParmType.b64),
        'e': JWKParameter('Exponent', True, True, ParmType.b64u),
        'd': JWKParameter('Private Exponent', False, False, ParmType.b64u),
        'p': JWKParameter('First Prime Factor', False, False, ParmType.b64u),
        'q': JWKParameter('Second Prime Factor', False, False, ParmType.b64u),
        'dp': JWKParameter('First Factor CRT Exponent',
                           False, False, ParmType.b64u),
        'dq': JWKParameter('Second Factor CRT Exponent',
                           False, False, ParmType.b64u),
        'qi': JWKParameter('First CRT Coefficient',
                           False, False, ParmType.b64u),
        'oth': JWKParameter('Other Primes Info',
                            False, False, ParmType.unsupported),
    },
    'oct': {
        'k': JWKParameter('Key Value', False, True, ParmType.b64),
    },
    'OKP': {
        'crv': JWKParameter('Curve', True, True, ParmType.name),
        'x': JWKParameter('Public Key', True, True, ParmType.b64),
        'd': JWKParameter('Private Key', False, False, ParmType.b64),
    }
}
"""Registry of valid key values"""

JWKParamsRegistry = {
    'kty': JWKParameter('Key Type', True, None, None),
    'use': JWKParameter('Public Key Use', True, None, None),
    'key_ops': JWKParameter('Key Operations', True, None, None),
    'alg': JWKParameter('Algorithm', True, None, None),
    'kid': JWKParameter('Key ID', True, None, None),
    'x5u': JWKParameter('X.509 URL', True, None, None),
    'x5c': JWKParameter('X.509 Certificate Chain', True, None, None),
    'x5t': JWKParameter('X.509 Certificate SHA-1 Thumbprint',
                        True, None, None),
    'x5t#S256': JWKParameter('X.509 Certificate SHA-256 Thumbprint',
                             True, None, None)
}
"""Regstry of valid key parameters"""

# RFC 7518 - 7.6 , RFC 8037 - 5
JWKEllipticCurveRegistry = {'P-256': 'P-256 curve',
                            'P-384': 'P-384 curve',
                            'P-521': 'P-521 curve',
                            'Ed25519': 'Ed25519 signature algorithm key pairs',
                            'Ed448': 'Ed448 signature algorithm key pairs',
                            'X25519': 'X25519 function key pairs',
                            'X448': 'X448 function key pairs'}
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

JWKpycaCurveMap = {'secp256r1': 'P-256',
                   'secp384r1': 'P-384',
                   'secp521r1': 'P-521'}


class InvalidJWKType(JWException):
    """Invalid JWK Type Exception.

    This exception is raised when an invalid parameter type is used.
    """

    def __init__(self, value=None):
        super(InvalidJWKType, self).__init__()
        self.value = value

    def __str__(self):
        return 'Unknown type "%s", valid types are: %s' % (
            self.value, list(JWKTypesRegistry.keys()))


class InvalidJWKUsage(JWException):
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


class InvalidJWKOperation(JWException):
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


class InvalidJWKValue(JWException):
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
    as arguments of the initialization function.
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

        To generate a new random key call the class method generate() with
        the appropriate 'kty' parameter, and other parameters as needed (key
        size, public exponents, curve types, etc..)

        Valid options per type, when generating new keys:
         * oct: size(int)
         * RSA: public_exponent(int), size(int)
         * EC: crv(str) (one of P-256, P-384, P-521)
         * OKP: crv(str) (one of Ed25519, Ed448, X25519, X448)

        Deprecated:
        Alternatively if the 'generate' parameter is provided, with a
        valid key type as value then a new key will be generated according
        to the defaults or provided key strenght options (type specific).

        :raises InvalidJWKType: if the key type is invalid
        :raises InvalidJWKValue: if incorrect or inconsistent parameters
            are provided.
        """
        self._params = dict()
        self._key = dict()
        self._unknown = dict()

        if 'generate' in kwargs:
            self.generate_key(**kwargs)
        elif kwargs:
            self.import_key(**kwargs)

    @classmethod
    def generate(cls, **kwargs):
        obj = cls()
        kty = None
        try:
            kty = kwargs['kty']
            gen = getattr(obj, '_generate_%s' % kty)
        except (KeyError, AttributeError):
            raise InvalidJWKType(kty)
        gen(kwargs)
        return obj

    def generate_key(self, **params):
        kty = None
        try:
            kty = params.pop('generate')
            gen = getattr(self, '_generate_%s' % kty)
        except (KeyError, AttributeError):
            raise InvalidJWKType(kty)

        gen(params)

    def _get_gen_size(self, params, default_size=None):
        size = default_size
        if 'size' in params:
            size = params.pop('size')
        elif 'alg' in params:
            try:
                from jwcrypto.jwa import JWA
                alg = JWA.instantiate_alg(params['alg'])
            except KeyError:
                raise ValueError("Invalid 'alg' parameter")
            size = alg.keysize
        return size

    def _generate_oct(self, params):
        size = self._get_gen_size(params, 128)
        key = os.urandom(size // 8)
        params['kty'] = 'oct'
        params['k'] = base64url_encode(key)
        self.import_key(**params)

    def _encode_int(self, i, bit_size=None):
        extend = 0
        if bit_size is not None:
            extend = ((bit_size + 7) // 8) * 2
        hexi = hex(i).rstrip("L").lstrip("0x")
        hexl = len(hexi)
        if extend > hexl:
            extend -= hexl
        else:
            extend = hexl % 2
        return base64url_encode(unhexlify(extend * '0' + hexi))

    def _generate_RSA(self, params):
        pubexp = 65537
        size = self._get_gen_size(params, 2048)
        if 'public_exponent' in params:
            pubexp = params.pop('public_exponent')
        key = rsa.generate_private_key(pubexp, size, default_backend())
        self._import_pyca_pri_rsa(key, **params)

    def _import_pyca_pri_rsa(self, key, **params):
        pn = key.private_numbers()
        params.update(
            kty='RSA',
            n=self._encode_int(pn.public_numbers.n),
            e=self._encode_int(pn.public_numbers.e),
            d=self._encode_int(pn.d),
            p=self._encode_int(pn.p),
            q=self._encode_int(pn.q),
            dp=self._encode_int(pn.dmp1),
            dq=self._encode_int(pn.dmq1),
            qi=self._encode_int(pn.iqmp)
        )
        self.import_key(**params)

    def _import_pyca_pub_rsa(self, key, **params):
        pn = key.public_numbers()
        params.update(
            kty='RSA',
            n=self._encode_int(pn.n),
            e=self._encode_int(pn.e)
        )
        self.import_key(**params)

    def _get_curve_by_name(self, name):
        if name == 'P-256':
            return ec.SECP256R1()
        elif name == 'P-384':
            return ec.SECP384R1()
        elif name == 'P-521':
            return ec.SECP521R1()
        elif name in _OKP_CURVES_TABLE:
            return name
        else:
            raise InvalidJWKValue('Unknown Elliptic Curve Type')

    def _generate_EC(self, params):
        curve = 'P-256'
        if 'curve' in params:
            curve = params.pop('curve')
        # 'curve' is for backwards compat, if 'crv' is defined it takes
        # precedence
        if 'crv' in params:
            curve = params.pop('crv')
        curve_name = self._get_curve_by_name(curve)
        key = ec.generate_private_key(curve_name, default_backend())
        self._import_pyca_pri_ec(key, **params)

    def _import_pyca_pri_ec(self, key, **params):
        pn = key.private_numbers()
        key_size = pn.public_numbers.curve.key_size
        params.update(
            kty='EC',
            crv=JWKpycaCurveMap[key.curve.name],
            x=self._encode_int(pn.public_numbers.x, key_size),
            y=self._encode_int(pn.public_numbers.y, key_size),
            d=self._encode_int(pn.private_value, key_size)
        )
        self.import_key(**params)

    def _import_pyca_pub_ec(self, key, **params):
        pn = key.public_numbers()
        params.update(
            kty='EC',
            crv=JWKpycaCurveMap[key.curve.name],
            x=self._encode_int(pn.x),
            y=self._encode_int(pn.y),
        )
        self.import_key(**params)

    def _generate_OKP(self, params):
        if 'crv' not in params:
            raise InvalidJWKValue('Must specify "crv" for OKP key generation')
        try:
            key = _OKP_CURVES_TABLE[params['crv']].privkey.generate()
        except KeyError:
            raise InvalidJWKValue('"%s" is not a supported curve for the '
                                  'OKP key type' % params['crv'])
        self._import_pyca_pri_okp(key, **params)

    def _import_pyca_pri_okp(self, key, **params):
        params.update(
            kty='OKP',
            crv=params['crv'],
            d=base64url_encode(key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption())),
            x=base64url_encode(key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw))
        )
        self.import_key(**params)

    def _import_pyca_pub_okp(self, key, **params):
        params.update(
            kty='OKP',
            crv=params['crv'],
            x=base64url_encode(key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw))
        )
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

        for name, val in iteritems(JWKValuesRegistry[kty]):
            if val.required and name not in self._key:
                raise InvalidJWKValue('Missing required value %s' % name)
            if val.type == ParmType.unsupported and name in self._key:
                raise InvalidJWKValue('Unsupported parameter %s' % name)
            if val.type == ParmType.b64 and name in self._key:
                # Check that the value is base64url encoded
                try:
                    base64url_decode(self._key[name])
                except Exception:  # pylint: disable=broad-except
                    raise InvalidJWKValue(
                        '"%s" is not base64url encoded' % name
                    )
            if val[3] == ParmType.b64u and name in self._key:
                # Check that the value is Base64urlUInt encoded
                try:
                    self._decode_int(self._key[name])
                except Exception:  # pylint: disable=broad-except
                    raise InvalidJWKValue(
                        '"%s" is not Base64urlUInt encoded' % name
                    )

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

    @classmethod
    def from_json(cls, key):
        """Creates a RFC 7517 JWK from the standard JSON format.

        :param key: The RFC 7517 representation of a JWK.
        """
        obj = cls()
        try:
            jkey = json_decode(key)
        except Exception as e:  # pylint: disable=broad-except
            raise InvalidJWKValue(e)
        obj.import_key(**jkey)
        return obj

    def export(self, private_key=True):
        """Exports the key in the standard JSON format.
        Exports the key regardless of type, if private_key is False
        and the key is_symmetric an exceptionis raised.

        :param private_key(bool): Whether to export the private key.
                                  Defaults to True.
        """
        if private_key is True:
            # Use _export_all for backwards compatibility, as this
            # function allows to export symmetrict keys too
            return self._export_all()
        else:
            return self.export_public()

    def export_public(self):
        """Exports the public key in the standard JSON format.
        It fails if one is not available like when this function
        is called on a symmetric key.
        """
        pub = self._public_params()
        return json_encode(pub)

    def _public_params(self):
        if not self.has_public:
            raise InvalidJWKType("No public key available")
        pub = {}
        preg = JWKParamsRegistry
        for name in preg:
            if preg[name].public:
                if name in self._params:
                    pub[name] = self._params[name]
        reg = JWKValuesRegistry[self._params['kty']]
        for param in reg:
            if reg[param].public:
                pub[param] = self._key[param]
        return pub

    def _export_all(self):
        d = dict()
        d.update(self._params)
        d.update(self._key)
        d.update(self._unknown)
        return json_encode(d)

    def export_private(self):
        """Export the private key in the standard JSON format.
        It fails for a JWK that has only a public key or is symmetric.
        """
        if self.has_private:
            return self._export_all()
        raise InvalidJWKType("No private key available")

    def export_symmetric(self):
        if self.is_symmetric:
            return self._export_all()
        raise InvalidJWKType("Not a symmetric key")

    def public(self):
        pub = self._public_params()
        return JWK(**pub)

    @property
    def has_public(self):
        """Whether this JWK has an asymmetric Public key."""
        if self.is_symmetric:
            return False
        reg = JWKValuesRegistry[self._params['kty']]
        for value in reg:
            if reg[value].public and value in self._key:
                return True

    @property
    def has_private(self):
        """Whether this JWK has an asymmetric key Private key."""
        if self.is_symmetric:
            return False
        reg = JWKValuesRegistry[self._params['kty']]
        for value in reg:
            if not reg[value].public and value in self._key:
                return True
        return False

    @property
    def is_symmetric(self):
        """Whether this JWK is a symmetric key."""
        return self.key_type == 'oct'

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

    @property
    def key_curve(self):
        """The Curve Name."""
        if self._params['kty'] not in ['EC', 'OKP']:
            raise InvalidJWKType('Not an EC or OKP key')
        return self._key['crv']

    def get_curve(self, arg):
        """Gets the Elliptic Curve associated with the key.

        :param arg: an optional curve name

        :raises InvalidJWKType: the key is not an EC or OKP key.
        :raises InvalidJWKValue: if the curve names is invalid.
        """
        k = self._key
        if self._params['kty'] not in ['EC', 'OKP']:
            raise InvalidJWKType('Not an EC or OKP key')
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

    def _okp_pub(self, k):
        try:
            pubkey = _OKP_CURVES_TABLE[k['crv']].pubkey
        except KeyError:
            raise InvalidJWKValue('Unknown curve "%s"' % k['crv'])

        return pubkey.from_public_bytes(base64url_decode(k['x']))

    def _okp_pri(self, k):
        try:
            privkey = _OKP_CURVES_TABLE[k['crv']].privkey
        except KeyError:
            raise InvalidJWKValue('Unknown curve "%s"' % k['crv'])

        return privkey.from_private_bytes(base64url_decode(k['d']))

    def _get_public_key(self, arg=None):
        if self._params['kty'] == 'oct':
            return self._key['k']
        elif self._params['kty'] == 'RSA':
            return self._rsa_pub(self._key).public_key(default_backend())
        elif self._params['kty'] == 'EC':
            return self._ec_pub(self._key, arg).public_key(default_backend())
        elif self._params['kty'] == 'OKP':
            return self._okp_pub(self._key)
        else:
            raise NotImplementedError

    def _get_private_key(self, arg=None):
        if self._params['kty'] == 'oct':
            return self._key['k']
        elif self._params['kty'] == 'RSA':
            return self._rsa_pri(self._key).private_key(default_backend())
        elif self._params['kty'] == 'EC':
            return self._ec_pri(self._key, arg).private_key(default_backend())
        elif self._params['kty'] == 'OKP':
            return self._okp_pri(self._key)
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

    def import_from_pyca(self, key):
        if isinstance(key, rsa.RSAPrivateKey):
            self._import_pyca_pri_rsa(key)
        elif isinstance(key, rsa.RSAPublicKey):
            self._import_pyca_pub_rsa(key)
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            self._import_pyca_pri_ec(key)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            self._import_pyca_pub_ec(key)
        elif isinstance(key, (Ed25519PrivateKey, Ed448PrivateKey)):
            self._import_pyca_pri_okp(key)
        elif isinstance(key, (Ed25519PublicKey, Ed448PublicKey)):
            self._import_pyca_pub_okp(key)
        else:
            raise InvalidJWKValue('Unknown key object %r' % key)

    def import_from_pem(self, data, password=None):
        """Imports a key from data loaded from a PEM file.
        The key may be encrypted with a password.
        Private keys (PKCS#8 format), public keys, and X509 certificate's
        public keys can be imported with this interface.

        :param data(bytes): The data contained in a PEM file.
        :param password(bytes): An optional password to unwrap the key.
        """

        try:
            key = serialization.load_pem_private_key(
                data, password=password, backend=default_backend())
        except ValueError as e:
            if password is not None:
                raise e
            try:
                key = serialization.load_pem_public_key(
                    data, backend=default_backend())
            except ValueError:
                try:
                    cert = x509.load_pem_x509_certificate(
                        data, backend=default_backend())
                    key = cert.public_key()
                except ValueError:
                    raise e

        self.import_from_pyca(key)
        self._params['kid'] = self.thumbprint()

    def export_to_pem(self, private_key=False, password=False):
        """Exports keys to a data buffer suitable to be stored as a PEM file.
        Either the public or the private key can be exported to a PEM file.
        For private keys the PKCS#8 format is used. If a password is provided
        the best encryption method available as determined by the cryptography
        module is used to wrap the key.

        :param private_key: Whether the private key should be exported.
         Defaults to `False` which means the public key is exported by default.
        :param password(bytes): A password for wrapping the private key.
         Defaults to False which will cause the operation to fail. To avoid
         encryption the user must explicitly pass None, otherwise the user
         needs to provide a password in a bytes buffer.
        """
        e = serialization.Encoding.PEM
        if private_key:
            if not self.has_private:
                raise InvalidJWKType("No private key available")
            f = serialization.PrivateFormat.PKCS8
            if password is None:
                a = serialization.NoEncryption()
            elif isinstance(password, bytes):
                a = serialization.BestAvailableEncryption(password)
            elif password is False:
                raise ValueError("The password must be None or a bytes string")
            else:
                raise TypeError("The password string must be bytes")
            return self._get_private_key().private_bytes(
                encoding=e, format=f, encryption_algorithm=a)
        else:
            if not self.has_public:
                raise InvalidJWKType("No public key available")
            f = serialization.PublicFormat.SubjectPublicKeyInfo
            return self._get_public_key().public_bytes(encoding=e, format=f)

    @classmethod
    def from_pyca(cls, key):
        obj = cls()
        obj.import_from_pyca(key)
        return obj

    @classmethod
    def from_pem(cls, data, password=None):
        """Creates a key from PKCS#8 formatted data loaded from a PEM file.
           See the function `import_from_pem` for details.

        :param data(bytes): The data contained in a PEM file.
        :param password(bytes): An optional password to unwrap the key.
        """
        obj = cls()
        obj.import_from_pem(data, password)
        return obj

    def thumbprint(self, hashalg=hashes.SHA256()):
        """Returns the key thumbprint as specified by RFC 7638.

        :param hashalg: A hash function (defaults to SHA256)
        """

        t = {'kty': self._params['kty']}
        for name, val in iteritems(JWKValuesRegistry[t['kty']]):
            if val.required:
                t[name] = self._key[name]
        digest = hashes.Hash(hashalg, backend=default_backend())
        digest.update(bytes(json_encode(t).encode('utf8')))
        return base64url_encode(digest.finalize())


class _JWKkeys(set):

    def add(self, elem):
        """Adds a JWK object to the set

        :param elem: the JWK object to add.

        :raises TypeError: if the object is not a JWK.
        """
        if not isinstance(elem, JWK):
            raise TypeError('Only JWK objects are valid elements')
        set.add(self, elem)


class JWKSet(dict):
    """A set of JWK objects.

    Inherits from the standard 'dict' bultin type.
    Creates a special key 'keys' that is of a type derived from 'set'
    The 'keys' attribute accepts only :class:`jwcrypto.jwk.JWK` elements.
    """
    def __init__(self, *args, **kwargs):
        super(JWKSet, self).__init__()
        super(JWKSet, self).__setitem__('keys', _JWKkeys())
        self.update(*args, **kwargs)

    def __iter__(self):
        return self['keys'].__iter__()

    def __contains__(self, key):
        return self['keys'].__contains__(key)

    def __setitem__(self, key, val):
        if key == 'keys':
            self['keys'].add(val)
        else:
            super(JWKSet, self).__setitem__(key, val)

    def update(self, *args, **kwargs):
        for k, v in iteritems(dict(*args, **kwargs)):
            self.__setitem__(k, v)

    def add(self, elem):
        self['keys'].add(elem)

    def export(self, private_keys=True):
        """Exports a RFC 7517 keyset using the standard JSON format

        :param private_key(bool): Whether to export private keys.
                                  Defaults to True.
        """
        exp_dict = dict()
        for k, v in iteritems(self):
            if k == 'keys':
                keys = list()
                for jwk in v:
                    keys.append(json_decode(jwk.export(private_keys)))
                v = keys
            exp_dict[k] = v
        return json_encode(exp_dict)

    def import_keyset(self, keyset):
        """Imports a RFC 7517 keyset using the standard JSON format.

        :param keyset: The RFC 7517 representation of a JOSE Keyset.
        """
        try:
            jwkset = json_decode(keyset)
        except Exception:  # pylint: disable=broad-except
            raise InvalidJWKValue()

        if 'keys' not in jwkset:
            raise InvalidJWKValue()

        for k, v in iteritems(jwkset):
            if k == 'keys':
                for jwk in v:
                    self['keys'].add(JWK(**jwk))
            else:
                self[k] = v

    @classmethod
    def from_json(cls, keyset):
        """Creates a RFC 7517 keyset from the standard JSON format.

        :param keyset: The RFC 7517 representation of a JOSE Keyset.
        """
        obj = cls()
        obj.import_keyset(keyset)
        return obj

    def get_key(self, kid):
        """Gets a key from the set.
        :param kid: the 'kid' key identifier.
        """
        for jwk in self['keys']:
            if jwk.key_id == kid:
                return jwk
        return None
