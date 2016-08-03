# Copyright (C) 2015 JWCrypto Project Contributors - see LICENSE file

import os
import struct
import zlib

from binascii import hexlify, unhexlify

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7

from jwcrypto.common import InvalidJWAAlgorithm
from jwcrypto.common import base64url_decode, base64url_encode
from jwcrypto.common import json_decode, json_encode
from jwcrypto.jwk import JWK


# RFC 7516 - 4.1
# name: (description, supported?)
JWEHeaderRegistry = {'alg': ('Algorithm', True),
                     'enc': ('Encryption Algorithm', True),
                     'zip': ('Compression Algorithm', True),
                     'jku': ('JWK Set URL', False),
                     'jwk': ('JSON Web Key', False),
                     'kid': ('Key ID', True),
                     'x5u': ('X.509 URL', False),
                     'x5c': ('X.509 Certificate Chain', False),
                     'x5t': ('X.509 Certificate SHA-1 Thumbprint', False),
                     'x5t#S256': ('X.509 Certificate SHA-256 Thumbprint',
                                  False),
                     'typ': ('Type', True),
                     'cty': ('Content Type', True),
                     'crit': ('Critical', True)}
"""Registry of valid header parameters"""

default_allowed_algs = [
    # Key Management Algorithms
    'RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256',
    'A128KW', 'A192KW', 'A256KW',
    'dir',
    'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
    'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
    'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
    # Content Encryption Algoritms
    'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512',
    'A128GCM', 'A192GCM', 'A256GCM']
"""Default allowed algorithms"""


# Note: l is the number of bits, which should be a multiple of 16
def _encode_int(n, l):
    e = hex(n).rstrip("L").lstrip("0x")
    elen = len(e)
    ilen = ((l + 7) // 8) * 2  # number of bytes rounded up times 2 chars/bytes
    if elen > ilen:
        e = e[:ilen]
    else:
        e = '0' * (ilen - elen) + e  # pad as necessary
    return unhexlify(e)


def _decode_int(n):
    return int(hexlify(n), 16)


class InvalidJWEData(Exception):
    """Invalid JWE Object.

    This exception is raised when the JWE Object is invalid and/or
    improperly formatted.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = message
        else:
            msg = 'Unknown Data Verification Failure'
        if exception:
            msg += ' {%s}' % str(exception)
        super(InvalidJWEData, self).__init__(msg)


class InvalidCEKeyLength(Exception):
    """Invalid CEK Key Length.

    This exception is raised when a Content Encryption Key does not match
    the required lenght.
    """

    def __init__(self, expected, obtained):
        msg = 'Expected key of length %d, got %d' % (expected, obtained)
        super(InvalidCEKeyLength, self).__init__(msg)


class InvalidJWEOperation(Exception):
    """Invalid JWS Object.

    This exception is raised when a requested operation cannot
    be execute due to unsatisfied conditions.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = message
        else:
            msg = 'Unknown Operation Failure'
        if exception:
            msg += ' {%s}' % repr(exception)
        super(InvalidJWEOperation, self).__init__(msg)


class InvalidJWEKeyType(Exception):
    """Invalid JWE Key Type.

    This exception is raised when the provided JWK Key does not match
    the type required by the sepcified algorithm.
    """

    def __init__(self, expected, obtained):
        msg = 'Expected key type %s, got %s' % (expected, obtained)
        super(InvalidJWEKeyType, self).__init__(msg)


class InvalidJWEKeyLength(Exception):
    """Invalid JWE Key Length.

    This exception is raised when the provided JWK Key does not match
    the lenght required by the sepcified algorithm.
    """

    def __init__(self, expected, obtained):
        msg = 'Expected key of lenght %d, got %d' % (expected, obtained)
        super(InvalidJWEKeyLength, self).__init__(msg)


class _RawKeyMgmt(object):

    def wrap(self, key, keylen, cek, headers):
        raise NotImplementedError

    def unwrap(self, key, keylen, ek, headers):
        raise NotImplementedError


class _RSA(_RawKeyMgmt):

    def __init__(self, padfn):
        self.padfn = padfn

    def _check_key(self, key):
        if not isinstance(key, JWK):
            raise ValueError('key is not a JWK object')
        if key.key_type != 'RSA':
            raise InvalidJWEKeyType('RSA', key.key_type)

    # FIXME: get key size and insure > 2048 bits
    def wrap(self, key, keylen, cek, headers):
        self._check_key(key)
        if not cek:
            cek = os.urandom(keylen)
        rk = key.get_op_key('wrapKey')
        ek = rk.encrypt(cek, self.padfn)
        return {'cek': cek, 'ek': ek}

    def unwrap(self, key, keylen, ek, headers):
        self._check_key(key)
        rk = key.get_op_key('decrypt')
        cek = rk.decrypt(ek, self.padfn)
        if len(cek) != keylen:
            raise InvalidJWEKeyLength(keylen, len(cek))
        return cek


class _Rsa15(_RSA):
    def __init__(self):
        super(_Rsa15, self).__init__(padding.PKCS1v15())

    @property
    def name(self):
        return 'RSA1_5'


class _RsaOaep(_RSA):
    def __init__(self):
        super(_RsaOaep, self).__init__(
            padding.OAEP(padding.MGF1(hashes.SHA1()),
                         hashes.SHA1(), None))

    @property
    def name(self):
        return 'RSA-OAEP'


class _RsaOaep256(_RSA):  # noqa: ignore=N801
    def __init__(self):
        super(_RsaOaep256, self).__init__(
            padding.OAEP(padding.MGF1(hashes.SHA256()),
                         hashes.SHA256(), None))

    @property
    def name(self):
        return 'RSA-OAEP-256'


class _AesKw(_RawKeyMgmt):

    def __init__(self, keysize):
        self.backend = default_backend()
        self.keysize = keysize // 8

    def _get_key(self, key, op):
        if not isinstance(key, JWK):
            raise ValueError('key is not a JWK object')
        if key.key_type != 'oct':
            raise InvalidJWEKeyType('oct', key.key_type)
        rk = base64url_decode(key.get_op_key(op))
        if len(rk) != self.keysize:
            raise InvalidJWEKeyLength(self.keysize * 8, len(rk) * 8)
        return rk

    def wrap(self, key, keylen, cek, headers):
        rk = self._get_key(key, 'encrypt')
        if not cek:
            cek = os.urandom(keylen)

        # Implement RFC 3394 Key Unwrap - 2.2.2
        # TODO: Use cryptography once issue #1733 is resolved
        iv = 'a6a6a6a6a6a6a6a6'
        a = unhexlify(iv)
        r = [cek[i:i + 8] for i in range(0, len(cek), 8)]
        n = len(r)
        for j in range(0, 6):
            for i in range(0, n):
                e = Cipher(algorithms.AES(rk), modes.ECB(),
                           backend=self.backend).encryptor()
                b = e.update(a + r[i]) + e.finalize()
                a = _encode_int(_decode_int(b[:8]) ^ ((n * j) + i + 1), 64)
                r[i] = b[-8:]
        ek = a
        for i in range(0, n):
            ek += r[i]
        return {'cek': cek, 'ek': ek}

    def unwrap(self, key, keylen, ek, headers):
        rk = self._get_key(key, 'decrypt')

        # Implement RFC 3394 Key Unwrap - 2.2.3
        # TODO: Use cryptography once issue #1733 is resolved
        iv = 'a6a6a6a6a6a6a6a6'
        aiv = unhexlify(iv)

        r = [ek[i:i + 8] for i in range(0, len(ek), 8)]
        a = r.pop(0)
        n = len(r)
        for j in range(5, -1, -1):
            for i in range(n - 1, -1, -1):
                da = _decode_int(a)
                atr = _encode_int((da ^ ((n * j) + i + 1)), 64) + r[i]
                d = Cipher(algorithms.AES(rk), modes.ECB(),
                           backend=self.backend).decryptor()
                b = d.update(atr) + d.finalize()
                a = b[:8]
                r[i] = b[-8:]

        if a != aiv:
            raise InvalidJWEData('Decryption Failed')

        cek = b''.join(r)
        if len(cek) != keylen:
            raise InvalidJWEKeyLength(keylen, len(cek))
        return cek


class _A128KW(_AesKw):
    def __init__(self):
        super(_A128KW, self).__init__(128)

    @property
    def name(self):
        return 'A128KW'


class _A192KW(_AesKw):
    def __init__(self):
        super(_A192KW, self).__init__(192)

    @property
    def name(self):
        return 'A192KW'


class _A256KW(_AesKw):
    def __init__(self):
        super(_A256KW, self).__init__(256)

    @property
    def name(self):
        return 'A256KW'


class _AesGcmKw(_RawKeyMgmt):

    def __init__(self, keysize):
        self.backend = default_backend()
        self.keysize = keysize // 8

    def _get_key(self, key, op):
        if not isinstance(key, JWK):
            raise ValueError('key is not a JWK object')
        if key.key_type != 'oct':
            raise InvalidJWEKeyType('oct', key.key_type)
        rk = base64url_decode(key.get_op_key(op))
        if len(rk) != self.keysize:
            raise InvalidJWEKeyLength(self.keysize * 8, len(rk) * 8)
        return rk

    def wrap(self, key, keylen, cek, headers):
        rk = self._get_key(key, 'encrypt')
        if not cek:
            cek = os.urandom(keylen)

        iv = os.urandom(96 // 8)
        cipher = Cipher(algorithms.AES(rk), modes.GCM(iv),
                        backend=self.backend)
        encryptor = cipher.encryptor()
        ek = encryptor.update(cek) + encryptor.finalize()

        tag = encryptor.tag
        return {'cek': cek, 'ek': ek,
                'header': {'iv': base64url_encode(iv),
                           'tag': base64url_encode(tag)}}

    def unwrap(self, key, keylen, ek, headers):
        rk = self._get_key(key, 'decrypt')

        if 'iv' not in headers:
            raise InvalidJWEData('Invalid Header, missing "iv" parameter')
        iv = base64url_decode(headers['iv'])
        if 'tag' not in headers:
            raise InvalidJWEData('Invalid Header, missing "tag" parameter')
        tag = base64url_decode(headers['tag'])

        cipher = Cipher(algorithms.AES(rk), modes.GCM(iv, tag),
                        backend=self.backend)
        decryptor = cipher.decryptor()
        cek = decryptor.update(ek) + decryptor.finalize()
        if len(cek) != keylen:
            raise InvalidJWEKeyLength(keylen, len(cek))
        return cek


class _A128GcmKw(_AesGcmKw):
    def __init__(self):
        super(_A128GcmKw, self).__init__(128)

    @property
    def name(self):
        return 'A128GCMKW'


class _A192GcmKw(_AesGcmKw):
    def __init__(self):
        super(_A192GcmKw, self).__init__(192)

    @property
    def name(self):
        return 'A192GCMKW'


class _A256GcmKw(_AesGcmKw):
    def __init__(self):
        super(_A256GcmKw, self).__init__(256)

    @property
    def name(self):
        return 'A256GCMKW'


class _Pbes2HsAesKw(_RawKeyMgmt):

    @property
    def name(self):
        raise NotImplementedError

    def __init__(self, hashsize, keysize):
        self.backend = default_backend()
        self.hashsize = hashsize
        self.keysize = keysize // 8

    def _get_key(self, alg, key, p2s, p2c):
        if isinstance(key, bytes):
            plain = key
        else:
            plain = key.encode('utf8')
        salt = bytes(self.name.encode('utf8')) + b'\x00' + p2s

        if self.hashsize == 256:
            hashalg = hashes.SHA256()
        elif self.hashsize == 384:
            hashalg = hashes.SHA384()
        elif self.hashsize == 512:
            hashalg = hashes.SHA512()
        else:
            raise InvalidJWEData('Unknown Hash Size')

        kdf = PBKDF2HMAC(algorithm=hashalg, length=self.keysize, salt=salt,
                         iterations=p2c, backend=self.backend)
        rk = kdf.derive(plain)
        if len(rk) != self.keysize:
            raise InvalidJWEKeyLength(self.keysize * 8, len(rk) * 8)
        return JWK(kty="oct", use="enc", k=base64url_encode(rk))

    def wrap(self, key, keylen, cek, headers):
        p2s = os.urandom(16)
        p2c = 8192
        kek = self._get_key(headers['alg'], key, p2s, p2c)

        aeskw = _AesKw(self.keysize * 8)
        ret = aeskw.wrap(kek, keylen, cek, headers)
        ret['header'] = {'p2s': base64url_encode(p2s), 'p2c': p2c}
        return ret

    def unwrap(self, key, keylen, ek, headers):
        if 'p2s' not in headers:
            raise InvalidJWEData('Invalid Header, missing "p2s" parameter')
        if 'p2c' not in headers:
            raise InvalidJWEData('Invalid Header, missing "p2c" parameter')
        p2s = base64url_decode(headers['p2s'])
        p2c = headers['p2c']
        kek = self._get_key(headers['alg'], key, p2s, p2c)

        aeskw = _AesKw(self.keysize * 8)
        return aeskw.unwrap(kek, keylen, ek, headers)


class _Pbes2Hs256A128Kw(_Pbes2HsAesKw):
    def __init__(self):
        super(_Pbes2Hs256A128Kw, self).__init__(256, 128)

    @property
    def name(self):
        return 'PBES2-HS256+A128KW'


class _Pbes2Hs384A192Kw(_Pbes2HsAesKw):
    def __init__(self):
        super(_Pbes2Hs384A192Kw, self).__init__(384, 192)

    @property
    def name(self):
        return 'PBES2-HS384+A192KW'


class _Pbes2Hs512A256Kw(_Pbes2HsAesKw):
    def __init__(self):
        super(_Pbes2Hs512A256Kw, self).__init__(512, 256)

    @property
    def name(self):
        return 'PBES2-HS512+A256KW'


class _Direct(_RawKeyMgmt):

    @property
    def name(self):
        return 'dir'

    def _check_key(self, key):
        if not isinstance(key, JWK):
            raise ValueError('key is not a JWK object')
        if key.key_type != 'oct':
            raise InvalidJWEKeyType('oct', key.key_type)

    def wrap(self, key, keylen, cek, headers):
        self._check_key(key)
        if cek:
            return (cek, None)
        k = base64url_decode(key.get_op_key('encrypt'))
        if len(k) != keylen:
            raise InvalidCEKeyLength(keylen, len(k))
        return {'cek': k}

    def unwrap(self, key, keylen, ek, headers):
        self._check_key(key)
        if ek != b'':
            raise InvalidJWEData('Invalid Encryption Key.')
        cek = base64url_decode(key.get_op_key('decrypt'))
        if len(cek) != keylen:
            raise InvalidJWEKeyLength(keylen, len(cek))
        return cek


class _EcdhEs(_RawKeyMgmt):

    @property
    def name(self):
        return 'ECDH-ES'

    def __init__(self, keydatalen=None):
        self.backend = default_backend()
        self.keydatalen = keydatalen

    def _check_key(self, key):
        if not isinstance(key, JWK):
            raise ValueError('key is not a JWK object')
        if key.key_type != 'EC':
            raise InvalidJWEKeyType('EC', key.key_type)

    def _derive(self, privkey, pubkey, alg, keydatalen, headers):
        # OtherInfo is defined in NIST SP 56A 5.8.1.2.1

        # AlgorithmID
        otherinfo = struct.pack('>I', len(alg))
        otherinfo += bytes(alg.encode('utf8'))

        # PartyUInfo
        apu = base64url_decode(headers['apu']) if 'apu' in headers else b''
        otherinfo += struct.pack('>I', len(apu))
        otherinfo += apu

        # PartyVInfo
        apv = base64url_decode(headers['apv']) if 'apv' in headers else b''
        otherinfo += struct.pack('>I', len(apv))
        otherinfo += apv

        # SuppPubInfo
        otherinfo += struct.pack('>I', keydatalen)

        # no SuppPrivInfo

        shared_key = privkey.exchange(ec.ECDH(), pubkey)
        ckdf = ConcatKDFHash(algorithm=hashes.SHA256(),
                             length=keydatalen // 8,
                             otherinfo=otherinfo,
                             backend=self.backend)
        return ckdf.derive(shared_key)

    def wrap(self, key, keylen, cek, headers):
        self._check_key(key)
        if self.keydatalen is None:
            if cek is not None:
                raise InvalidJWEOperation('ECDH-ES cannot use an existing CEK')
            keydatalen = keylen * 8
            alg = headers['enc']
        else:
            keydatalen = self.keydatalen
            alg = headers['alg']

        epk = JWK.generate(kty=key.key_type, crv=key.key_curve)
        dk = self._derive(epk.get_op_key('unwrapKey'),
                          key.get_op_key('wrapKey'),
                          alg, keydatalen, headers)

        if self.keydatalen is None:
            ret = {'cek': dk}
        else:
            aeskw = _AesKw(keydatalen)
            kek = JWK(kty="oct", use="enc", k=base64url_encode(dk))
            ret = aeskw.wrap(kek, keydatalen // 8, cek, headers)

        ret['header'] = {'epk': json_decode(epk.export_public())}
        return ret

    def unwrap(self, key, keylen, ek, headers):
        if 'epk' not in headers:
            raise InvalidJWEData('Invalid Header, missing "epk" parameter')
        self._check_key(key)
        if self.keydatalen is None:
            keydatalen = keylen * 8
            alg = headers['enc']
        else:
            keydatalen = self.keydatalen
            alg = headers['alg']

        epk = JWK(**headers['epk'])
        dk = self._derive(key.get_op_key('unwrapKey'),
                          epk.get_op_key('wrapKey'),
                          alg, keydatalen, headers)
        if self.keydatalen is None:
            return dk
        else:
            aeskw = _AesKw(keydatalen)
            kek = JWK(kty="oct", use="enc", k=base64url_encode(dk))
            cek = aeskw.unwrap(kek, keydatalen // 8, ek, headers)
            return cek


class _EcdhEsAes128Kw(_EcdhEs):
    def __init__(self):
        super(_EcdhEsAes128Kw, self).__init__(128)

    @property
    def name(self):
        return 'ECDH-ES+A128KW'


class _EcdhEsAes192Kw(_EcdhEs):
    def __init__(self):
        super(_EcdhEsAes192Kw, self).__init__(192)

    @property
    def name(self):
        return 'ECDH-ES+A192KW'


class _EcdhEsAes256Kw(_EcdhEs):
    def __init__(self):
        super(_EcdhEsAes256Kw, self).__init__(256)

    @property
    def name(self):
        return 'ECDH-ES+A256KW'


class _RawJWE(object):

    def encrypt(self, k, a, m):
        raise NotImplementedError

    def decrypt(self, k, a, iv, e, t):
        raise NotImplementedError


class _AesCbcHmacSha2(_RawJWE):

    def __init__(self, hashfn, keybits):
        self.backend = default_backend()
        self.hashfn = hashfn
        self.keysize = keybits // 8
        self.blocksize = algorithms.AES.block_size

    @property
    def key_size(self):
        return self.keysize * 2

    def _mac(self, k, a, iv, e):
        al = _encode_int(len(a * 8), 64)
        h = hmac.HMAC(k, self.hashfn, backend=self.backend)
        h.update(a)
        h.update(iv)
        h.update(e)
        h.update(al)
        m = h.finalize()
        return m[:self.keysize]

    # RFC 7518 - 5.2.2
    def encrypt(self, k, a, m):
        """ Encrypt according to the selected encryption and hashing
        functions.

        :param k: Encryption key (optional)
        :param a: Additional Authentication Data
        :param m: Plaintext

        Returns a dictionary with the computed data.
        """
        hkey = k[:self.keysize]
        ekey = k[self.keysize:]

        # encrypt
        iv = os.urandom(self.blocksize // 8)
        cipher = Cipher(algorithms.AES(ekey), modes.CBC(iv),
                        backend=self.backend)
        encryptor = cipher.encryptor()
        padder = PKCS7(self.blocksize).padder()
        padded_data = padder.update(m) + padder.finalize()
        e = encryptor.update(padded_data) + encryptor.finalize()

        # mac
        t = self._mac(hkey, a, iv, e)

        return (iv, e, t)

    def decrypt(self, k, a, iv, e, t):
        """ Decrypt according to the selected encryption and hashing
        functions.
        :param k: Encryption key (optional)
        :param a: Additional Authenticated Data
        :param iv: Initialization Vector
        :param e: Ciphertext
        :param t: Authentication Tag

        Returns plaintext or raises an error
        """
        hkey = k[:self.keysize]
        dkey = k[self.keysize:]

        # verify mac
        if not constant_time.bytes_eq(t, self._mac(hkey, a, iv, e)):
            raise InvalidJWEData('Failed to verify MAC')

        # decrypt
        cipher = Cipher(algorithms.AES(dkey), modes.CBC(iv),
                        backend=self.backend)
        decryptor = cipher.decryptor()
        d = decryptor.update(e) + decryptor.finalize()
        unpadder = PKCS7(self.blocksize).unpadder()
        return unpadder.update(d) + unpadder.finalize()


class _A128CbcHs256(_AesCbcHmacSha2):
    def __init__(self):
        super(_A128CbcHs256, self).__init__(hashes.SHA256(), 128)

    @property
    def name(self):
        return 'A128CBC-HS256'


class _A192CbcHs384(_AesCbcHmacSha2):
    def __init__(self):
        super(_A192CbcHs384, self).__init__(hashes.SHA384(), 192)

    @property
    def name(self):
        return 'A192CBC-HS384'


class _A256CbcHs512(_AesCbcHmacSha2):
    def __init__(self):
        super(_A256CbcHs512, self).__init__(hashes.SHA512(), 256)

    @property
    def name(self):
        return 'A256CBC-HS512'


class _AesGcm(_RawJWE):

    def __init__(self, keybits):
        self.backend = default_backend()
        self.keysize = keybits // 8

    @property
    def key_size(self):
        return self.keysize

    # RFC 7518 - 5.3
    def encrypt(self, k, a, m):
        """ Encrypt accoriding to the selected encryption and hashing
        functions.

        :param k: Encryption key (optional)
        :param a: Additional Authentication Data
        :param m: Plaintext

        Returns a dictionary with the computed data.
        """
        iv = os.urandom(96 // 8)
        cipher = Cipher(algorithms.AES(k), modes.GCM(iv),
                        backend=self.backend)
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(a)
        e = encryptor.update(m) + encryptor.finalize()

        return (iv, e, encryptor.tag)

    def decrypt(self, k, a, iv, e, t):
        """ Decrypt accoriding to the selected encryption and hashing
        functions.
        :param k: Encryption key (optional)
        :param a: Additional Authenticated Data
        :param iv: Initialization Vector
        :param e: Ciphertext
        :param t: Authentication Tag

        Returns plaintext or raises an error
        """
        cipher = Cipher(algorithms.AES(k), modes.GCM(iv, t),
                        backend=self.backend)
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(a)
        return decryptor.update(e) + decryptor.finalize()


class _A128Gcm(_AesGcm):
    def __init__(self):
        super(_A128Gcm, self).__init__(128)

    @property
    def name(self):
        return 'A128GCM'


class _A192Gcm(_AesGcm):
    def __init__(self):
        super(_A192Gcm, self).__init__(192)

    @property
    def name(self):
        return 'A192GCM'


class _A256Gcm(_AesGcm):
    def __init__(self):
        super(_A256Gcm, self).__init__(256)

    @property
    def name(self):
        return 'A256GCM'


class JWE(object):
    """JSON Web Encryption object

    This object represent a JWE token.
    """

    jwas = {
        'RSA1_5': _Rsa15,
        'RSA-OAEP': _RsaOaep,
        'RSA-OAEP-256': _RsaOaep256,
        'A128KW': _A128KW,
        'A192KW': _A192KW,
        'A256KW': _A256KW,
        'dir': _Direct,
        'ECDH-ES': _EcdhEs,
        'ECDH-ES+A128KW': _EcdhEsAes128Kw,
        'ECDH-ES+A192KW': _EcdhEsAes192Kw,
        'ECDH-ES+A256KW': _EcdhEsAes256Kw,
        'A128GCMKW': _A128GcmKw,
        'A192GCMKW': _A192GcmKw,
        'A256GCMKW': _A256GcmKw,
        'PBES2-HS256+A128KW': _Pbes2Hs256A128Kw,
        'PBES2-HS384+A192KW': _Pbes2Hs384A192Kw,
        'PBES2-HS512+A256KW': _Pbes2Hs512A256Kw,
        'A128CBC-HS256': _A128CbcHs256,
        'A192CBC-HS384': _A192CbcHs384,
        'A256CBC-HS512': _A256CbcHs512,
        'A128GCM': _A128Gcm,
        'A192GCM': _A192Gcm,
        'A256GCM': _A256Gcm
    }

    def __init__(self, plaintext=None, protected=None, unprotected=None,
                 aad=None, algs=None):
        """Creates a JWE token.

        :param plaintext(bytes): An arbitrary plaintext to be encrypted.
        :param protected: A JSON string with the protected header.
        :param unprotected: A JSON string with the shared unprotected header.
        :param aad(bytes): Arbitrary additional authenticated data
        :param algs: An optional list of allowed algorithms
        """
        self._allowed_algs = None
        self.objects = dict()
        self.plaintext = None
        if plaintext is not None:
            if isinstance(plaintext, bytes):
                self.plaintext = plaintext
            else:
                self.plaintext = plaintext.encode('utf-8')
        self.cek = None
        self.decryptlog = None
        if aad:
            self.objects['aad'] = aad
        if protected:
            json_decode(protected)  # check header encoding
            self.objects['protected'] = protected
        if unprotected:
            json_decode(unprotected)  # check header encoding
            self.objects['unprotected'] = unprotected
        if algs:
            self.allowed_algs = algs

    def _jwa(self, name):
        try:
            cls = self.jwas[name]
        except (KeyError):
            raise InvalidJWAAlgorithm()
        allowed = self._allowed_algs or default_allowed_algs
        if name not in allowed:
            raise InvalidJWEOperation('Algorithm not allowed')
        return cls()

    @property
    def allowed_algs(self):
        """Allowed algorithms.

        The list of allowed algorithms.
        Can be changed by setting a list of algorithm names.
        """

        if self._allowed_algs:
            return self._allowed_algs
        else:
            return default_allowed_algs

    @allowed_algs.setter
    def allowed_algs(self, algs):
        if not isinstance(algs, list):
            raise TypeError('Allowed Algs must be a list')
        self._allowed_algs = algs

    def _merge_headers(self, h1, h2):
        for k in list(h1.keys()):
            if k in h2:
                raise InvalidJWEData('Duplicate header: "%s"' % k)
        h1.update(h2)
        return h1

    def _get_jose_header(self, header=None):
        jh = dict()
        if 'protected' in self.objects:
            ph = json_decode(self.objects['protected'])
            jh = self._merge_headers(jh, ph)
        if 'unprotected' in self.objects:
            uh = json_decode(self.objects['unprotected'])
            jh = self._merge_headers(jh, uh)
        if header:
            rh = json_decode(header)
            jh = self._merge_headers(jh, rh)
        return jh

    def _get_alg_enc_from_headers(self, jh):
        algname = jh.get('alg', None)
        if algname is None:
            raise InvalidJWEData('Missing "alg" from headers')
        alg = self._jwa(algname)
        encname = jh.get('enc', None)
        if encname is None:
            raise InvalidJWEData('Missing "enc" from headers')
        enc = self._jwa(encname)
        return alg, enc

    def _encrypt(self, alg, enc, jh):
        aad = base64url_encode(self.objects.get('protected', ''))
        if 'aad' in self.objects:
            aad += '.' + base64url_encode(self.objects['aad'])
        aad = aad.encode('utf-8')

        compress = jh.get('zip', None)
        if compress == 'DEF':
            data = zlib.compress(self.plaintext)[2:-4]
        elif compress is None:
            data = self.plaintext
        else:
            raise ValueError('Unknown compression')

        iv, ciphertext, tag = enc.encrypt(self.cek, aad, data)
        self.objects['iv'] = iv
        self.objects['ciphertext'] = ciphertext
        self.objects['tag'] = tag

    def add_recipient(self, key, header=None):
        """Encrypt the plaintext with the given key.

        :param key: A JWK key or password of appropriate type for the 'alg'
         provided in the JOSE Headers.
        :param header: A JSON string representing the per-recipient header.

        :raises ValueError: if the plaintext is missing or not of type bytes.
        :raises ValueError: if the compression type is unknown.
        :raises InvalidJWAAlgorithm: if the 'alg' provided in the JOSE
         headers is missing or unknown, or otherwise not implemented.
        """
        if self.plaintext is None:
            raise ValueError('Missing plaintext')
        if not isinstance(self.plaintext, bytes):
            raise ValueError("Plaintext must be 'bytes'")

        jh = self._get_jose_header(header)
        alg, enc = self._get_alg_enc_from_headers(jh)

        rec = dict()
        if header:
            rec['header'] = header

        wrapped = alg.wrap(key, enc.key_size, self.cek, jh)
        self.cek = wrapped['cek']

        if 'ek' in wrapped:
            rec['encrypted_key'] = wrapped['ek']

        if 'header' in wrapped:
            h = json_decode(rec.get('header', '{}'))
            nh = self._merge_headers(h, wrapped['header'])
            rec['header'] = json_encode(nh)

        if 'ciphertext' not in self.objects:
            self._encrypt(alg, enc, jh)

        if 'recipients' in self.objects:
            self.objects['recipients'].append(rec)
        elif 'encrypted_key' in self.objects or 'header' in self.objects:
            self.objects['recipients'] = list()
            n = dict()
            if 'encrypted_key' in self.objects:
                n['encrypted_key'] = self.objects['encrypted_key']
                del self.objects['encrypted_key']
            if 'header' in self.objects:
                n['header'] = self.objects['header']
                del self.objects['header']
            self.objects['recipients'].append(n)
            self.objects['recipients'].append(rec)
        else:
            self.objects.update(rec)

    def serialize(self, compact=False):
        """Serializes the object into a JWE token.

        :param compact(boolean): if True generates the compact
         representation, otherwise generates a standard JSON format.

        :raises InvalidJWEOperation: if the object cannot serialized
         with the compact representation and `compact` is True.
        :raises InvalidJWEOperation: if no recipients have been added
         to the object.
        """

        if 'ciphertext' not in self.objects:
            raise InvalidJWEOperation("No available ciphertext")

        if compact:
            for invalid in 'aad', 'unprotected':
                if invalid in self.objects:
                    raise InvalidJWEOperation("Can't use compact encoding")
            if 'recipients' in self.objects:
                if len(self.objects['recipients']) != 1:
                    raise InvalidJWEOperation("Invalid number of recipients")
                rec = self.objects['recipients'][0]
            else:
                rec = self.objects
            if 'header' in rec:
                # The AESGCMKW algorithm generates data (iv, tag) we put in the
                # per-recipient unpotected header by default. Move it to the
                # protected header and re-encrypt the payload, as the protected
                # header is used as additional authenticated data.
                h = json_decode(rec['header'])
                ph = json_decode(self.objects['protected'])
                nph = self._merge_headers(h, ph)
                self.objects['protected'] = json_encode(nph)
                jh = self._get_jose_header()
                alg, enc = self._get_alg_enc_from_headers(jh)
                self._encrypt(alg, enc, jh)
                del rec['header']

            return '.'.join([base64url_encode(self.objects['protected']),
                             base64url_encode(rec.get('encrypted_key', '')),
                             base64url_encode(self.objects['iv']),
                             base64url_encode(self.objects['ciphertext']),
                             base64url_encode(self.objects['tag'])])
        else:
            obj = self.objects
            enc = {'ciphertext': base64url_encode(obj['ciphertext']),
                   'iv': base64url_encode(obj['iv']),
                   'tag': base64url_encode(self.objects['tag'])}
            if 'protected' in obj:
                enc['protected'] = base64url_encode(obj['protected'])
            if 'unprotected' in obj:
                enc['unprotected'] = json_decode(obj['unprotected'])
            if 'aad' in obj:
                enc['aad'] = base64url_encode(obj['aad'])
            if 'recipients' in obj:
                enc['recipients'] = list()
                for rec in obj['recipients']:
                    e = dict()
                    if 'encrypted_key' in rec:
                        e['encrypted_key'] = \
                            base64url_encode(rec['encrypted_key'])
                    if 'header' in rec:
                        e['header'] = json_decode(rec['header'])
                    enc['recipients'].append(e)
            else:
                if 'encrypted_key' in obj:
                    enc['encrypted_key'] = \
                        base64url_encode(obj['encrypted_key'])
                if 'header' in obj:
                    enc['header'] = json_decode(obj['header'])
            return json_encode(enc)

    def _check_crit(self, crit):
        for k in crit:
            if k not in JWEHeaderRegistry:
                raise InvalidJWEData('Unknown critical header: "%s"' % k)
            else:
                if not JWEHeaderRegistry[k][1]:
                    raise InvalidJWEData('Unsupported critical header: '
                                         '"%s"' % k)

    # FIXME: allow to specify which algorithms to accept as valid
    def _decrypt(self, key, ppe):

        jh = self._get_jose_header(ppe.get('header', None))

        # TODO: allow caller to specify list of headers it understands
        self._check_crit(jh.get('crit', dict()))

        alg = self._jwa(jh.get('alg', None))
        enc = self._jwa(jh.get('enc', None))

        aad = base64url_encode(self.objects.get('protected', ''))
        if 'aad' in self.objects:
            aad += '.' + base64url_encode(self.objects['aad'])

        cek = alg.unwrap(key, enc.key_size, ppe.get('encrypted_key', b''), jh)
        data = enc.decrypt(cek, aad.encode('utf-8'),
                           self.objects['iv'],
                           self.objects['ciphertext'],
                           self.objects['tag'])

        self.decryptlog.append('Success')
        self.cek = cek

        compress = jh.get('zip', None)
        if compress == 'DEF':
            self.plaintext = zlib.decompress(data, -zlib.MAX_WBITS)
        elif compress is None:
            self.plaintext = data
        else:
            raise ValueError('Unknown compression')

    def decrypt(self, key):
        """Decrypt a JWE token.

        :param key: The (:class:`jwcrypto.jwk.JWK`) decryption key.
        :param key: A (:class:`jwcrypto.jwk.JWK`) decryption key or a password
         string (optional).

        :raises InvalidJWEOperation: if the key is not a JWK object.
        :raises InvalidJWEData: if the ciphertext can't be decrypted or
         the object is otherwise malformed.
        """

        if 'ciphertext' not in self.objects:
            raise InvalidJWEOperation("No available ciphertext")
        self.decryptlog = list()

        if 'recipients' in self.objects:
            for rec in self.objects['recipients']:
                try:
                    self._decrypt(key, rec)
                except Exception as e:  # pylint: disable=broad-except
                    self.decryptlog.append('Failed: [%s]' % repr(e))
        else:
            try:
                self._decrypt(key, self.objects)
            except Exception as e:  # pylint: disable=broad-except
                self.decryptlog.append('Failed: [%s]' % repr(e))

        if not self.plaintext:
            raise InvalidJWEData('No recipient matched the provided '
                                 'key' + repr(self.decryptlog))

    def deserialize(self, raw_jwe, key=None):
        """Deserialize a JWE token.

        NOTE: Destroys any current status and tries to import the raw
        JWE provided.

        :param raw_jwe: a 'raw' JWE token (JSON Encoded or Compact
         notation) string.
        :param key: A (:class:`jwcrypto.jwk.JWK`) decryption key or a password
         string (optional).
         If a key is provided a decryption step will be attempted after
         the object is successfully deserialized.

        :raises InvalidJWEData: if the raw object is an invaid JWE token.
        :raises InvalidJWEOperation: if the decryption fails.
        """

        self.objects = dict()
        self.plaintext = None
        self.cek = None

        o = dict()
        try:
            try:
                djwe = json_decode(raw_jwe)
                o['iv'] = base64url_decode(str(djwe['iv']))
                o['ciphertext'] = base64url_decode(str(djwe['ciphertext']))
                o['tag'] = base64url_decode(str(djwe['tag']))
                if 'protected' in djwe:
                    p = base64url_decode(str(djwe['protected']))
                    o['protected'] = p.decode('utf-8')
                if 'unprotected' in djwe:
                    o['unprotected'] = json_encode(djwe['unprotected'])
                if 'aad' in djwe:
                    o['aad'] = base64url_decode(str(djwe['aad']))
                if 'recipients' in djwe:
                    o['recipients'] = list()
                    for rec in djwe['recipients']:
                        e = dict()
                        if 'encrypted_key' in rec:
                            e['encrypted_key'] = \
                                base64url_decode(str(rec['encrypted_key']))
                        if 'header' in rec:
                            e['header'] = json_encode(rec['header'])
                        o['recipients'].append(e)
                else:
                    if 'encrypted_key' in djwe:
                        o['encrypted_key'] = \
                            base64url_decode(str(djwe['encrypted_key']))
                    if 'header' in djwe:
                        o['header'] = json_encode(djwe['header'])

            except ValueError:
                c = raw_jwe.split('.')
                if len(c) != 5:
                    raise InvalidJWEData()
                p = base64url_decode(str(c[0]))
                o['protected'] = p.decode('utf-8')
                ekey = base64url_decode(str(c[1]))
                if ekey != '':
                    o['encrypted_key'] = base64url_decode(str(c[1]))
                o['iv'] = base64url_decode(str(c[2]))
                o['ciphertext'] = base64url_decode(str(c[3]))
                o['tag'] = base64url_decode(str(c[4]))

            self.objects = o

        except Exception as e:  # pylint: disable=broad-except
            raise InvalidJWEData('Invalid format', repr(e))

        if key:
            self.decrypt(key)

    @property
    def payload(self):
        if not self.plaintext:
            raise InvalidJWEOperation("Plaintext not available")
        return self.plaintext

    @property
    def jose_header(self):
        jh = self._get_jose_header()
        if len(jh) == 0:
            raise InvalidJWEOperation("JOSE Header not available")
        return jh
