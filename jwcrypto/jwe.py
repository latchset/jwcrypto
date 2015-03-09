# Copyright (C) 2015 JWCrypto Project Contributors - see LICENSE file

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time, hashes, hmac
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from jwcrypto.common import base64url_encode, base64url_decode
from jwcrypto.common import InvalidJWAAlgorithm
from jwcrypto.jwk import JWK
import json
import os
import zlib


# draft-ietf-jose-json-web-encryption-40 - 4.1
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


class InvalidJWEData(Exception):
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
    def __init__(self, expected, obtained):
        msg = 'Expected key og length %d, got %d' % (expected, obtained)
        super(InvalidCEKeyLength, self).__init__(msg)


class InvalidJWEOperation(Exception):
    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = message
        else:
            msg = 'Unknown Operation Failure'
        if exception:
            msg += ' {%s}' % str(exception)
        super(InvalidJWEOperation, self).__init__(msg)


class _raw_key_mgmt(object):

    def wrap(self, key, keylen, cek):
        raise NotImplementedError

    def unwrap(self, key, ek):
        raise NotImplementedError


class _rsa(_raw_key_mgmt):

    def __init__(self, padfn):
        self.padfn = padfn

    def wrap(self, key, keylen, cek):
        if not cek:
            cek = os.urandom(keylen)
        rk = key.encrypt_key()
        ek = rk.encrypt(cek, self.padfn)
        return (cek, ek)

    def unwrap(self, key, ek):
        rk = key.decrypt_key()
        cek = rk.decrypt(ek, self.padfn)
        return cek


class _direct(_raw_key_mgmt):

    def wrap(self, key, keylen, cek):
        if cek:
            return (cek, None)
        k = base64url_decode(key.encrypt_key())
        if len(k) != keylen:
            raise InvalidCEKeyLength(keylen, len(k))
        return (k, '')

    def unwrap(self, key, ek):
        if ek != '':
            raise InvalidJWEData('Invalid Encryption Key.')
        return base64url_decode(key.decrypt_key())


class _raw_jwe(object):

    def encode_int(self, n, l):
        e = hex(n).rstrip("L").lstrip("0x")
        L = (l + 7) / 8  # number of bytes rounded up
        e = '0' * (L * 2 - len(e)) + e  # pad as necessary
        return e.decode('hex')

    def encrypt(self, k, a, m):
        raise NotImplementedError

    def decrypt(self, k, a, iv, e, t):
        raise NotImplementedError


class _aes_cbc_hmac_sha2(_raw_jwe):

    def __init__(self, hashfn, keybits):
        self.backend = default_backend()
        self.hashfn = hashfn
        self.blocksize = keybits / 8

    @property
    def key_size(self):
        return self.blocksize * 2

    def _mac(self, k, a, iv, e):
        al = self.encode_int(len(a * 8), 64)
        h = hmac.HMAC(k, self.hashfn, backend=self.backend)
        h.update(a)
        h.update(iv)
        h.update(e)
        h.update(al)
        m = h.finalize()
        return m[:self.blocksize]

    # draft-ietf-jose-json-web-algorithms-40 - 5.2.2
    def encrypt(self, k, a, m):
        """ Encrypt accoriding to the selected encryption and hashing
        functions.

        :param k: Encryption key (optional)
        :param a: Additional Authentication Data
        :param m: Plaintext

        Returns a dictionary with the computed data.
        """
        hkey = k[:self.blocksize]
        ekey = k[self.blocksize:]

        # encrypt
        iv = os.urandom(self.blocksize)
        cipher = Cipher(algorithms.AES(ekey), modes.CBC(iv),
                        backend=self.backend)
        encryptor = cipher.encryptor()
        padder = PKCS7(self.blocksize * 8).padder()
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
        hkey = k[:self.blocksize]
        dkey = k[self.blocksize:]

        # verify mac
        if not constant_time.bytes_eq(t, self._mac(hkey, a, iv, e)):
            raise InvalidJWEData('Failed to verify MAC')

        # decrypt
        cipher = Cipher(algorithms.AES(dkey), modes.CBC(iv),
                        backend=self.backend)
        decryptor = cipher.decryptor()
        d = decryptor.update(e) + decryptor.finalize()
        unpadder = PKCS7(self.blocksize * 8).unpadder()
        return unpadder.update(d) + unpadder.finalize()


class JWE(object):

    def __init__(self, plaintext=None, protected=None, unprotected=None,
                 aad=None):
        """ Generates or verifies Generic JWE tokens.
            See draft-ietf-jose-json-web-signature-41

        :param plaintext(bytes): An arbitrary plaintext to be encrypted
        :param protected(json): The shared protected header
        :param unprotected(json): The shared unprotected header
        :param aad(bytes): Arbitrary additional authenticated data
        """
        self.objects = dict()
        self.plaintext = plaintext
        self.cek = None
        self.decryptlog = None
        if aad:
            self.objects['aad'] = aad
        if protected:
            _ = json.loads(protected)  # check header encoding
            self.objects['protected'] = protected
        if unprotected:
            _ = json.loads(unprotected)  # check header encoding
            self.objects['unprotected'] = unprotected

    # key wrapping mechanisms
    def _jwa_RSA1_5(self):
        return _rsa(padding.PKCS1v15())

    def _jwa_dir(self):
        return _direct()

    # content encryption mechanisms
    def _jwa_A128CBC_HS256(self):
        return _aes_cbc_hmac_sha2(hashes.SHA256(), 128)

    def _jwa(self, name):
        attr = '_jwa_%s' % name.replace('-', '_').replace('+', '_')
        try:
            return getattr(self, attr)()
        except (KeyError, AttributeError):
            raise InvalidJWAAlgorithm()

    def merge_headers(self, h1, h2):
        for k in h1.keys():
            if k in h2:
                raise InvalidJWEData('Duplicate header: "%s"' % k)
        h1.update(h2)
        return h1

    def add_recipient(self, key, header=None):
        """ Encrypt the provided payload with the given key.

        :param key: A JWK key of appropriate type for the "alg"
                    provided in the 'protected' json string.
                    See draft-ietf-jose-json-web-key-41

        :param header: A JSON string representing the per-recipient header.
        """
        if self.plaintext is None:
            raise ValueError('Missing plaintext')
        if not isinstance(key, JWK):
            raise ValueError('key is not a JWK object')

        ph = json.loads(self.objects['protected'])
        if 'unprotected' in self.objects:
            uh = json.loads(self.objects['unprotected'])
            ph = self.merge_headers(ph, uh)
        if header:
            rh = json.loads(header)
            ph = self.merge_headers(ph, rh)

        alg = self._jwa(ph.get('alg', None))
        enc = self._jwa(ph.get('enc', None))

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

            compress = ph.get('zip', None)
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

        if 'ciphertext' not in self.objects:
            raise InvalidJWEOperation("No available ciphertext")

        if compact:
            for invalid in 'aad', 'unprotected':
                if invalid in self.objects:
                    raise InvalidJWEOperation("Can't use compact encoding")
            if len(self.objects['recipients']) != 1:
                raise InvalidJWEOperation("Invalid number of recipients")
            rec = self.objects['recipients'][0]
            return '.'.join([base64url_encode(self.objects['protected']),
                             base64url_encode(rec['encrypted_key']),
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
                enc['unprotected'] = json.loads(obj['unprotected'])
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
                        e['header'] = json.loads(rec['header'])
                    enc['recipients'].append(e)
            else:
                if 'encrypted_key' in obj:
                    enc['encrypted_key'] = \
                        base64url_encode(obj['encrypted_key'])
                if 'header' in obj:
                    enc['header'] = json.loads(obj['header'])
            return json.dumps(enc)

    def check_crit(self, crit):
        for k in crit:
            if k not in JWEHeaderRegistry:
                raise InvalidJWEData('Unknown critical header: "%s"' % k)
            else:
                if not JWEHeaderRegistry[k][1]:
                    raise InvalidJWEData('Unsupported critical header: '
                                         '"%s"' % k)

    # FIXME: allow to specify which algorithms to accept as valid
    def decrypt(self, key, ppe):

        ph = json.loads(self.objects['protected'])
        if 'unprotected' in self.objects:
            uh = json.loads(self.objects['unprotected'])
            ph = self.merge_headers(ph, uh)
        if 'header' in ppe:
            rh = json.loads(ppe['header'])
            ph = self.merge_headers(ph, rh)
        # TODO: allow caller to specify list of headers it understands
        if 'crit' in ph:
            self.check_crit(ph['crit'])

        alg = self._jwa(ph.get('alg', None))
        enc = self._jwa(ph.get('enc', None))

        aad = base64url_encode(self.objects.get('protected', ''))
        if 'aad' in self.objects:
            aad += '.' + base64url_encode(self.objects['aad'])

        cek = alg.unwrap(key, ppe.get('encrypted_key', None))
        data = enc.decrypt(cek, aad, self.objects['iv'],
                           self.objects['ciphertext'],
                           self.objects['tag'])

        self.decryptlog.append('Success')
        self.cek = cek

        compress = ph.get('zip', None)
        if compress == 'DEF':
            self.plaintext = zlib.decompress(data, -zlib.MAX_WBITS)
        elif compress is None:
            self.plaintext = data
        else:
            raise ValueError('Unknown compression')

    def deserialize(self, raw_jwe, key=None):
        """ Destroys any current status and tries to import the raw
            JWS provided.
        """
        self.objects = dict()
        self.plaintext = None
        self.cek = None

        o = dict()
        try:
            try:
                djwe = json.loads(raw_jwe)
                o['iv'] = base64url_decode(str(djwe['iv']))
                o['ciphertext'] = base64url_decode(str(djwe['ciphertext']))
                o['tag'] = base64url_decode(str(djwe['tag']))
                if 'protected' in djwe:
                    o['protected'] = base64url_decode(str(djwe['protected']))
                if 'unprotected' in djwe:
                    o['unprotected'] = json.dumps(djwe['unprotected'])
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
                            e['header'] = json.dumps(rec['header'])
                        o['recipients'].append(e)
                else:
                    if 'encrypted_key' in djwe:
                        o['encrypted_key'] = \
                            base64url_decode(str(djwe['encrypted_key']))
                    if 'header' in djwe:
                        o['header'] = json.dumps(djwe['header'])

            except ValueError:
                c = raw_jwe.split('.')
                if len(c) != 5:
                    raise InvalidJWEData()
                o['protected'] = base64url_decode(str(c[0]))
                o['iv'] = base64url_decode(str(c[2]))
                o['ciphertext'] = base64url_decode(str(c[3]))
                o['tag'] = base64url_decode(str(c[4]))
                o['encrypted_key'] = base64url_decode(str(c[1]))

            self.objects = o

        except Exception, e:  # pylint: disable=broad-except
            raise InvalidJWEData('Invalid format', e)

        if key:
            if not isinstance(key, JWK):
                raise ValueError('key is not a JWK object')
            if 'ciphertext' not in self.objects:
                raise InvalidJWEOperation("No available ciphertext")
            self.decryptlog = list()

            if 'recipients' in self.objects:
                for rec in self.objects['recipients']:
                    try:
                        self.decrypt(key, rec)
                    except Exception, e:  # pylint: disable=broad-except
                        self.decryptlog.append('Failed: [%s]' % str(e))
            else:
                try:
                    self.decrypt(key, self.objects)
                except Exception, e:  # pylint: disable=broad-except
                    self.decryptlog.append('Failed: [%s]' % str(e))

            if not self.plaintext:
                raise InvalidJWEData('No recipient matches the provided key')
