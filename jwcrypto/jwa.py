# Copyright (C) 2016 JWCrypto Project Contributors - see LICENSE file

import abc
from binascii import hexlify, unhexlify

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils as ec_utils

import six

from jwcrypto.common import InvalidJWAAlgorithm
from jwcrypto.common import base64url_decode

# Implements RFC 7518 - JSON Web Algorithms (JWA)


@six.add_metaclass(abc.ABCMeta)
class JWAAlgorithm(object):

    @abc.abstractproperty
    def name(self):
        """The algorithm Name"""
        pass

    @abc.abstractproperty
    def description(self):
        """A short description"""
        pass

    @abc.abstractproperty
    def min_key_size(self):
        """The recommended/minimum key size or bit strenght"""
        pass

    @abc.abstractproperty
    def algorithm_usage_location(self):
        """One of 'alg', 'enc' or 'JWK'"""
        pass

    @abc.abstractproperty
    def algorithm_use(self):
        """One of 'sig', 'kex', 'enc'"""
        pass


class _RawJWS(object):

    def sign(self, key, payload):
        raise NotImplementedError

    def verify(self, key, payload, signature):
        raise NotImplementedError


class _RawHMAC(_RawJWS):

    def __init__(self, hashfn):
        self.backend = default_backend()
        self.hashfn = hashfn

    def _hmac_setup(self, key, payload):
        h = hmac.HMAC(key, self.hashfn, backend=self.backend)
        h.update(payload)
        return h

    def sign(self, key, payload):
        skey = base64url_decode(key.get_op_key('sign'))
        h = self._hmac_setup(skey, payload)
        return h.finalize()

    def verify(self, key, payload, signature):
        vkey = base64url_decode(key.get_op_key('verify'))
        h = self._hmac_setup(vkey, payload)
        h.verify(signature)


class _RawRSA(_RawJWS):
    def __init__(self, padfn, hashfn):
        self.padfn = padfn
        self.hashfn = hashfn

    def sign(self, key, payload):
        skey = key.get_op_key('sign')
        signer = skey.signer(self.padfn, self.hashfn)
        signer.update(payload)
        return signer.finalize()

    def verify(self, key, payload, signature):
        pkey = key.get_op_key('verify')
        verifier = pkey.verifier(signature, self.padfn, self.hashfn)
        verifier.update(payload)
        verifier.verify()


class _RawEC(_RawJWS):
    def __init__(self, curve, hashfn):
        self._curve = curve
        self.hashfn = hashfn

    @property
    def curve(self):
        return self._curve

    def encode_int(self, n, l):
        e = hex(n).rstrip("L").lstrip("0x")
        ilen = (l + 7) // 8  # number of bytes rounded up
        e = '0' * (ilen * 2 - len(e)) + e  # pad as necessary
        return unhexlify(e)

    def sign(self, key, payload):
        skey = key.get_op_key('sign', self._curve)
        signer = skey.signer(ec.ECDSA(self.hashfn))
        signer.update(payload)
        signature = signer.finalize()
        r, s = ec_utils.decode_rfc6979_signature(signature)
        l = key.get_curve(self._curve).key_size
        return self.encode_int(r, l) + self.encode_int(s, l)

    def verify(self, key, payload, signature):
        pkey = key.get_op_key('verify', self._curve)
        r = signature[:len(signature) // 2]
        s = signature[len(signature) // 2:]
        enc_signature = ec_utils.encode_rfc6979_signature(
            int(hexlify(r), 16), int(hexlify(s), 16))
        verifier = pkey.verifier(enc_signature, ec.ECDSA(self.hashfn))
        verifier.update(payload)
        verifier.verify()


class _RawNone(_RawJWS):

    def sign(self, key, payload):
        return ''

    def verify(self, key, payload, signature):
        raise InvalidSignature('The "none" signature cannot be verified')


class _HS256(_RawHMAC, JWAAlgorithm):

    name = "HS256"
    description = "HMAC using SHA-256"
    min_key_size = 256
    algorithm_usage_location = 'alg'
    algorithm_use = 'sig'

    def __init__(self):
        super(_HS256, self).__init__(hashes.SHA256())


class _HS384(_RawHMAC, JWAAlgorithm):

    name = "HS384"
    description = "HMAC using SHA-384"
    min_key_size = 384
    algorithm_usage_location = 'alg'
    algorithm_use = 'sig'

    def __init__(self):
        super(_HS384, self).__init__(hashes.SHA384())


class _HS512(_RawHMAC, JWAAlgorithm):

    name = "HS512"
    description = "HMAC using SHA-512"
    min_key_size = 512
    algorithm_usage_location = 'alg'
    algorithm_use = 'sig'

    def __init__(self):
        super(_HS512, self).__init__(hashes.SHA512())


class _RS256(_RawRSA, JWAAlgorithm):

    name = "RS256"
    description = "RSASSA-PKCS1-v1_5 using SHA-256"
    min_key_size = 2048
    algorithm_usage_location = 'alg'
    algorithm_use = 'sig'

    def __init__(self):
        super(_RS256, self).__init__(padding.PKCS1v15(), hashes.SHA256())


class _RS384(_RawRSA, JWAAlgorithm):

    name = "RS384"
    description = "RSASSA-PKCS1-v1_5 using SHA-384"
    min_key_size = 2048
    algorithm_usage_location = 'alg'
    algorithm_use = 'sig'

    def __init__(self):
        super(_RS384, self).__init__(padding.PKCS1v15(), hashes.SHA384())


class _RS512(_RawRSA, JWAAlgorithm):

    name = "RS512"
    description = "RSASSA-PKCS1-v1_5 using SHA-512"
    min_key_size = 2048
    algorithm_usage_location = 'alg'
    algorithm_use = 'sig'

    def __init__(self):
        super(_RS512, self).__init__(padding.PKCS1v15(), hashes.SHA512())


class _ES256(_RawEC, JWAAlgorithm):

    name = "ES256"
    description = "ECDSA using P-256 and SHA-256"
    min_key_size = 256
    algorithm_usage_location = 'alg'
    algorithm_use = 'sig'

    def __init__(self):
        super(_ES256, self).__init__('P-256', hashes.SHA256())


class _ES384(_RawEC, JWAAlgorithm):

    name = "ES384"
    description = "ECDSA using P-384 and SHA-384"
    min_key_size = 384
    algorithm_usage_location = 'alg'
    algorithm_use = 'sig'

    def __init__(self):
        super(_ES384, self).__init__('P-384', hashes.SHA384())


class _ES512(_RawEC, JWAAlgorithm):

    name = "ES512"
    description = "ECDSA using P-521 and SHA-512"
    min_key_size = 512
    algorithm_usage_location = 'alg'
    algorithm_use = 'sig'

    def __init__(self):
        super(_ES512, self).__init__('P-521', hashes.SHA512())


class _PS256(_RawRSA, JWAAlgorithm):

    name = "PS256"
    description = "RSASSA-PSS using SHA-256 and MGF1 with SHA-256"
    min_key_size = 2048
    algorithm_usage_location = 'alg'
    algorithm_use = 'sig'

    def __init__(self):
        padfn = padding.PSS(padding.MGF1(hashes.SHA256()),
                            hashes.SHA256.digest_size)
        super(_PS256, self).__init__(padfn, hashes.SHA256())


class _PS384(_RawRSA, JWAAlgorithm):

    name = "PS384"
    description = "RSASSA-PSS using SHA-384 and MGF1 with SHA-384"
    min_key_size = 2048
    algorithm_usage_location = 'alg'
    algorithm_use = 'sig'

    def __init__(self):
        padfn = padding.PSS(padding.MGF1(hashes.SHA384()),
                            hashes.SHA384.digest_size)
        super(_PS384, self).__init__(padfn, hashes.SHA384())


class _PS512(_RawRSA, JWAAlgorithm):

    name = "PS512"
    description = "RSASSA-PSS using SHA-512 and MGF1 with SHA-512"
    min_key_size = 2048
    algorithm_usage_location = 'alg'
    algorithm_use = 'sig'

    def __init__(self):
        padfn = padding.PSS(padding.MGF1(hashes.SHA512()),
                            hashes.SHA512.digest_size)
        super(_PS512, self).__init__(padfn, hashes.SHA512())


class _None(_RawNone, JWAAlgorithm):

    name = "none"
    description = "No digital signature or MAC performed"
    min_key_size = 0
    algorithm_usage_location = 'alg'
    algorithm_use = 'sig'


class JWA(object):
    """JWA Signing Algorithms.

    This class provides access to all JWA algorithms.
    """

    algorithms_registry = {
        'HS256': _HS256,
        'HS384': _HS384,
        'HS512': _HS512,
        'RS256': _RS256,
        'RS384': _RS384,
        'RS512': _RS512,
        'ES256': _ES256,
        'ES384': _ES384,
        'ES512': _ES512,
        'PS256': _PS256,
        'PS384': _PS384,
        'PS512': _PS512,
        'none': _None
    }

    @classmethod
    def signing_alg(cls, name):
        try:
            obj = cls.algorithms_registry[name]()
            if obj.algorithm_use != 'sig':
                raise InvalidJWAAlgorithm(name)
            return obj
        except KeyError:
            raise InvalidJWAAlgorithm(name)
