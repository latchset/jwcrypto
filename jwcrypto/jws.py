# Copyright (C) 2015  Custoia project Contributors - for license see COPYING

from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature
from jwcrypto.jwk import JWK
import json


# Padding stripping version as described in
# draft-ietf-jose-json-web-signature-41 appendix C
def base64url_encode(payload):
    return urlsafe_b64encode(payload).rstrip('=')


def base64url_decode(payload):
    l = len(payload) % 4
    if l == 2:
        payload += '=='
    elif l == 3:
        payload += '='
    elif l != 0:
        raise ValueError('Invalid base64 string')
    return urlsafe_b64decode(payload)


class InvalidJWSSignature(Exception):
    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = message
        else:
            msg = 'Unknown Signature Verification Failure'
        if exception:
            msg += ' {%s}' % str(exception)
        super(InvalidJWSSignature, self).__init__(msg)


class InvalidJWAAlgorithm(Exception):
    def __init__(self):
        msg = 'Invalid JWS Algorithm name'
        super(InvalidJWAAlgorithm, self).__init__(msg)


class _raw_jws(object):

    def sign(self, key, payload):
        raise NotImplementedError

    def verify(self, key, payload, signature):
        raise NotImplementedError


class _raw_hmac(_raw_jws):

    def __init__(self, hashfn):
        self.backend = default_backend()
        self.hashfn = hashfn

    def _hmac_setup(self, key, payload):
        h = hmac.HMAC(key, self.hashfn, backend=self.backend)
        h.update(payload)
        return h

    def sign(self, key, payload):
        skey = base64url_decode(key.sign_key())
        h = self._hmac_setup(skey, payload)
        return h.finalize()

    def verify(self, key, payload, signature):
        vkey = base64url_decode(key.verify_key())
        h = self._hmac_setup(vkey, payload)
        try:
            h.verify(signature)
        except InvalidSignature, e:
            raise InvalidJWSSignature(exception=e)


class _raw_none(_raw_jws):

    def sign(self, key, payload):
        return ''

    def verify(self, key, payload, signature):
        if signature != '':
            raise InvalidJWSSignature('The "none" signature must be the '
                                      'empty string')


class JWSCore(object):

    def __init__(self, alg, key, header, payload):
        """ Generates or verifies JWS tokens.
            See draft-ietf-jose-json-web-signature-41

        :param alg: The algorithm used to produce the signature.
                    See draft-ietf-jose-json-web-algorithms-24


        :param key: A JWK key of appropriate type for the "alg"
                    provided in the 'protected' json string.
                    See draft-ietf-jose-json-web-key-41

        :param header: A JSON string representing the protected header.

        :param payload(bytes): An arbitrary value

        :raises: InvalidJWAAlgorithm
        """
        self.alg = alg
        self.engine = self._jwa(alg)
        if not isinstance(key, JWK):
            raise ValueError('key is not a JWK object')
        self.key = key

        self.protected = base64url_encode(unicode(header, 'utf-8'))
        self.payload = base64url_encode(payload)

    def _jwa(self, alg):
        _table = {
            'HS256': _raw_hmac(hashes.SHA256()),
            'HS384': _raw_hmac(hashes.SHA384()),
            'HS512': _raw_hmac(hashes.SHA512()),
            'none': _raw_none()
        }

        try:
            return _table[alg]
        except KeyError:
            raise InvalidJWAAlgorithm()

    def sign(self):
        signing_input = str.encode('.'.join([self.protected, self.payload]))
        signature = self.engine.sign(self.key, signing_input)
        return {'protected': self.protected,
                'payload': self.payload,
                'signature': base64url_encode(signature)}

    def verify(self, signature):
        signing_input = '.'.join([self.protected, self.payload])
        raw_signature = base64url_decode(signature)
        try:
            self.engine.verify(self.key, signing_input, raw_signature)
        except Exception, e:  # pylint: disable=broad-except
            raise InvalidJWSSignature('Verification failed', e)
        return True


class JWSAssembler(object):
    def __init__(self, alg, key, header, protected, payload):
        """ Generates or verifies JWS tokens.
            See draft-ietf-jose-json-web-signature-41

            NOTE: Supports only a single signature atm

        :param alg: The algorithm used to produce the signature.
                    See draft-ietf-jose-json-web-algorithms-24

        :param key: A JWK key of appropriate type for the "alg"
                    provided in the header dictionary.
                    See draft-ietf-jose-json-web-key-41

        :param header: A dictionary containing the JOSE Header.
                       (except the protected part)

        :param protected: A dictionary cntaining the protected
                          header.

        :param payload(bytes): An arbitrary value

        :raises: InvalidJWAAlgorithm
        """
        self.alg = alg
        if not isinstance(key, JWK):
            raise ValueError('key is not a JKT object')
        self.key = key

        self.header = header
        if protected:
            p = dict()
            if 'alg' in protected and protected['alg'] != alg:
                raise ValueError('Mismatched "alg" in headers')
            else:
                p['alg'] = alg
            p.update(protected)
        else:
            p = {'alg': alg}
        self.protected = json.dumps(p)

        self.payload = base64url_encode(payload)

    def serialize(self, compact=False):

        if compact:
            raise NotImplementedError
        else:
            ser = {'protected': self.protected,
                   'payload': self.payload,
                   'signature': ''}
            if self.header:
                ser['header'] = self.header
            _ = json.dumps(ser)
            raise NotImplementedError
