# Copyright (C) 2015 JWCrypto Project Contributors - see LICENSE file

from binascii import hexlify, unhexlify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time, hashes, hmac
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from jwcrypto.common import base64url_encode, base64url_decode
from jwcrypto.common import InvalidJWAAlgorithm
from jwcrypto.common import json_decode, json_encode
from jwcrypto.jwk import JWK
import os
import zlib


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
    el = len(e)
    L = ((l + 7) // 8) * 2  # number of bytes rounded up times 2 chars/bytes
    if el > L:
        e = e[:L]
    else:
        e = '0' * (L - el) + e  # pad as necessary
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


class _raw_key_mgmt(object):

    def wrap(self, key, keylen, cek):
        raise NotImplementedError

    def unwrap(self, key, ek):
        raise NotImplementedError


class _rsa(_raw_key_mgmt):

    def __init__(self, padfn):
        self.padfn = padfn

    def check_key(self, key):
        if key.key_type != 'RSA':
            raise InvalidJWEKeyType('RSA', key.key_type)

    # FIXME: get key size and insure > 2048 bits
    def wrap(self, key, keylen, cek):
        self.check_key(key)
        if not cek:
            cek = os.urandom(keylen)
        rk = key.get_op_key('encrypt')
        ek = rk.encrypt(cek, self.padfn)
        return (cek, ek)

    def unwrap(self, key, ek):
        self.check_key(key)
        rk = key.get_op_key('decrypt')
        cek = rk.decrypt(ek, self.padfn)
        return cek


class _aes_kw(_raw_key_mgmt):

    def __init__(self, keysize):
        self.backend = default_backend()
        self.keysize = keysize // 8

    def get_key(self, key, op):
        if key.key_type != 'oct':
            raise InvalidJWEKeyType('oct', key.key_type)
        rk = base64url_decode(key.get_op_key(op))
        if len(rk) != self.keysize:
            raise InvalidJWEKeyLength(self.keysize * 8, len(rk) * 8)
        return rk

    def wrap(self, key, keylen, cek):
        rk = self.get_key(key, 'encrypt')
        if not cek:
            cek = os.urandom(keylen)

        # Implement RFC 3394 Key Unwrap - 2.2.2
        # TODO: Use cryptography once issue #1733 is resolved
        iv = 'a6a6a6a6a6a6a6a6'
        A = unhexlify(iv)
        R = [cek[i:i+8] for i in range(0, len(cek), 8)]
        n = len(R)
        for j in range(0, 6):
            for i in range(0, n):
                e = Cipher(algorithms.AES(rk), modes.ECB(),
                           backend=self.backend).encryptor()
                B = e.update(A + R[i]) + e.finalize()
                A = _encode_int(_decode_int(B[:8]) ^ ((n*j)+i+1), 64)
                R[i] = B[-8:]
        ek = A
        for i in range(0, n):
            ek += R[i]
        return (cek, ek)

    def unwrap(self, key, ek):
        rk = self.get_key(key, 'decrypt')

        # Implement RFC 3394 Key Unwrap - 2.2.3
        # TODO: Use cryptography once issue #1733 is resolved
        iv = 'a6a6a6a6a6a6a6a6'
        Aiv = unhexlify(iv)

        R = [ek[i:i+8] for i in range(0, len(ek), 8)]
        A = R.pop(0)
        n = len(R)
        for j in range(5, -1, -1):
            for i in range(n - 1, -1, -1):
                AtR = _encode_int((_decode_int(A) ^ ((n*j)+i+1)), 64) + R[i]
                d = Cipher(algorithms.AES(rk), modes.ECB(),
                           backend=self.backend).decryptor()
                B = d.update(AtR) + d.finalize()
                A = B[:8]
                R[i] = B[-8:]

        if A != Aiv:
            raise InvalidJWEData('Decryption Failed')

        cek = b''.join(R)
        return cek


class _direct(_raw_key_mgmt):

    def check_key(self, key):
        if key.key_type != 'oct':
            raise InvalidJWEKeyType('oct', key.key_type)

    def wrap(self, key, keylen, cek):
        self.check_key(key)
        if cek:
            return (cek, None)
        k = base64url_decode(key.get_op_key('encrypt'))
        if len(k) != keylen:
            raise InvalidCEKeyLength(keylen, len(k))
        return (k, '')

    def unwrap(self, key, ek):
        self.check_key(key)
        if ek != b'':
            raise InvalidJWEData('Invalid Encryption Key.')
        return base64url_decode(key.get_op_key('decrypt'))


class _raw_jwe(object):

    def encrypt(self, k, a, m):
        raise NotImplementedError

    def decrypt(self, k, a, iv, e, t):
        raise NotImplementedError


class _aes_cbc_hmac_sha2(_raw_jwe):

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
        """ Encrypt accoriding to the selected encryption and hashing
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
        """ Decrypt accoriding to the selected encryption and hashing
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


class _aes_gcm(_raw_jwe):

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


class JWE(object):
    """JSON Web Encryption object

    This object represent a JWE token.
    """

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
            _ = json_decode(protected)  # check header encoding
            self.objects['protected'] = protected
        if unprotected:
            _ = json_decode(unprotected)  # check header encoding
            self.objects['unprotected'] = unprotected
        if algs:
            self.allowed_algs = algs

    # key wrapping mechanisms
    def _jwa_RSA1_5(self):
        return _rsa(padding.PKCS1v15())

    def _jwa_RSA_OAEP(self):
        return _rsa(padding.OAEP(padding.MGF1(hashes.SHA1()),
                                 hashes.SHA1(),
                                 None))

    def _jwa_RSA_OAEP_256(self):
        return _rsa(padding.OAEP(padding.MGF1(hashes.SHA256()),
                                 hashes.SHA256(),
                                 None))

    def _jwa_A128KW(self):
        return _aes_kw(128)

    def _jwa_A192KW(self):
        return _aes_kw(192)

    def _jwa_A256KW(self):
        return _aes_kw(256)

    def _jwa_dir(self):
        return _direct()

    # content encryption mechanisms
    def _jwa_A128CBC_HS256(self):
        return _aes_cbc_hmac_sha2(hashes.SHA256(), 128)

    def _jwa_A192CBC_HS384(self):
        return _aes_cbc_hmac_sha2(hashes.SHA384(), 192)

    def _jwa_A256CBC_HS512(self):
        return _aes_cbc_hmac_sha2(hashes.SHA512(), 256)

    def _jwa_A128GCM(self):
        return _aes_gcm(128)

    def _jwa_A192GCM(self):
        return _aes_gcm(192)

    def _jwa_A256GCM(self):
        return _aes_gcm(256)

    def _jwa(self, name):
        try:
            attr = '_jwa_%s' % name.replace('-', '_').replace('+', '_')
            fn = getattr(self, attr)
        except (KeyError, AttributeError):
            raise InvalidJWAAlgorithm()
        allowed = self._allowed_algs or default_allowed_algs
        if name not in allowed:
            raise InvalidJWEOperation('Algorithm not allowed')
        return fn()

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

    def add_recipient(self, key, header=None):
        """Encrypt the plaintext with the given key.

        :param key: A JWK key of appropriate type for the 'alg' provided
         in the JOSE Headers.
        :param header: A JSON string representing the per-recipient header.

        :raises ValueError: if the plaintext is missing or not of type bytes.
        :raises ValueError: if the key is not a JWK object.
        :raises ValueError: if the compression type is unknown.
        :raises InvalidJWAAlgorithm: if the 'alg' provided in the JOSE
         headers is missing or unknown, or otherwise not implemented.
        """
        if self.plaintext is None:
            raise ValueError('Missing plaintext')
        if not isinstance(self.plaintext, bytes):
            raise ValueError("Plaintext must be 'bytes'")
        if not isinstance(key, JWK):
            raise ValueError('key is not a JWK object')

        jh = self._get_jose_header(header)
        alg, enc = self._get_alg_enc_from_headers(jh)

        rec = dict()
        if header:
            rec['header'] = header

        self.cek, ek = alg.wrap(key, enc.key_size, self.cek)
        if ek:
            rec['encrypted_key'] = ek

        if 'ciphertext' not in self.objects:
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
         with the compact representation and `compat` is True.
        :raises InvalidJWEOperation: if no recipients have been added
         to the object.
        """

        if 'ciphertext' not in self.objects:
            raise InvalidJWEOperation("No available ciphertext")

        if compact:
            for invalid in 'aad', 'unprotected':
                if invalid in self.objects:
                    raise InvalidJWEOperation("Can't use compact encoding")
            if 'recipiens' in self.objects:
                if len(self.objects['recipients']) != 1:
                    raise InvalidJWEOperation("Invalid number of recipients")
                rec = self.objects['recipients'][0]
            else:
                rec = self.objects
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

        cek = alg.unwrap(key, ppe.get('encrypted_key', b''))
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

        :raises InvalidJWEOperation: if the key is not a JWK object.
        :raises InvalidJWEData: if the ciphertext can't be decrypted or
         the object is otherwise malformed.
        """

        if not isinstance(key, JWK):
            raise ValueError('key is not a JWK object')
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
        :param key: A (:class:`jwcrypto.jwk.JWK`) decryption key (optional).
         If a key is provided a idecryption step will be attempted after
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
