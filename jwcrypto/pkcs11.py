# Copyright (C) 2018 JWCrypto Project Contributors - see LICENSE file

from binascii import hexlify

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

try:
    from gnutls.library.constants import GNUTLS_DIG_SHA1, GNUTLS_DIG_SHA256, \
        GNUTLS_DIG_SHA384, GNUTLS_DIG_SHA512
    from gnutls.crypto import PrivateKey
    from gnutls.callbacks import gnutls_set_pin_for_keyuri, \
        gnutls_remove_pin_for_keyuri
    found_gnutls = True
except ImportError:
    found_gnutls = False


def _hashfn_to_gnutls(hashfn):
    if isinstance(hashfn, hashes.SHA1):
        return GNUTLS_DIG_SHA1
    if isinstance(hashfn, hashes.SHA256):
        return GNUTLS_DIG_SHA256
    if isinstance(hashfn, hashes.SHA384):
        return GNUTLS_DIG_SHA384
    if isinstance(hashfn, hashes.SHA512):
        return GNUTLS_DIG_SHA512


class PKCS11Key(object):

    def __init__(self, gnutls_key=None):
        self.gnutls_key = gnutls_key

    @classmethod
    def import_from_pkcs11_uri(cls, uri, pin=None):
        if not found_gnutls:
            raise ImportError('python-gnutls not found')
        if pin:
            gnutls_set_pin_for_keyuri(uri, pin)
        pk = cls()
        try:
            pk.gnutls_key = PrivateKey.import_uri(uri)
        finally:
            if pin:
                gnutls_remove_pin_for_keyuri(uri)
        return pk.get_private_key()

    def get_uri(self):
        return self.gnutls_key.get_uri()

    def get_public_key(self):
        return PKCS11PublicKey(self.gnutls_key.get_public_key())

    def get_private_key(self):
        return PKCS11PrivateKey(self.gnutls_key)


class PKCS11PrivateKey(PKCS11Key):

    def __init__(self, gnutls_key):
        super(PKCS11PrivateKey, self).__init__(gnutls_key)

    def sign(self, payload, _padfn, hashfn):
        return self.gnutls_key.sign_data(_hashfn_to_gnutls(hashfn),
                                         0, payload)

    def decrypt(self, ct, _padfn):
        return self.gnutls_key.decrypt_data(0, ct)


class PKCS11PublicKey(object):

    def __init__(self, gnutls_pubkey):
        self.gnutls_pubkey = gnutls_pubkey

    def public_numbers(self):
        n, e = self.gnutls_pubkey.export_rsa_raw()
        return rsa.RSAPublicNumbers(int(hexlify(e), 16),
                                    int(hexlify(n), 16))

    # pylint: disable=redefined-builtin
    def public_bytes(self, encoding, format):
        pk = self.public_numbers().public_key(default_backend())
        return pk.public_bytes(encoding=encoding, format=format)

    def verify(self, signature, payload, _padfn, hashfn):
        return self.gnutls_pubkey.verify_data2(_hashfn_to_gnutls(hashfn),
                                               0, payload, signature)

    def encrypt(self, pt, _padfn):
        return self.gnutls_pubkey.encrypt_data(0, pt)
