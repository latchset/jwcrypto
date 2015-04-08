# Copyright (C) 2015 JWCrypto Project Contributors - see LICENSE file

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as ec_utils
from cryptography.exceptions import InvalidSignature
from jwcrypto.common import base64url_encode, base64url_decode
from jwcrypto.common import InvalidJWAAlgorithm
from jwcrypto.jwk import JWK
import json


# draft-ietf-jose-json-web-signature-41 - 9.1
# name: (description, supported?)
JWSHeaderRegistry = {'alg': ('Algorithm', True),
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


class InvalidJWSObject(Exception):
    def __init__(self, message=None, exception=None):
        msg = 'Invalid JWS Object'
        if message:
            msg += ' [%s]' % message
        if exception:
            msg += ' {%s}' % str(exception)
        super(InvalidJWSObject, self).__init__(msg)


class InvalidJWSOperation(Exception):
    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = message
        else:
            msg = 'Unknown Operation Failure'
        if exception:
            msg += ' {%s}' % str(exception)
        super(InvalidJWSOperation, self).__init__(msg)


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
        skey = base64url_decode(key.get_op_key('sign'))
        h = self._hmac_setup(skey, payload)
        return h.finalize()

    def verify(self, key, payload, signature):
        vkey = base64url_decode(key.get_op_key('verify'))
        h = self._hmac_setup(vkey, payload)
        try:
            h.verify(signature)
        except InvalidSignature, e:
            raise InvalidJWSSignature(exception=e)


class _raw_rsa(_raw_jws):
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


class _raw_ec(_raw_jws):
    def __init__(self, curve, hashfn):
        self.curve = curve
        self.hashfn = hashfn

    def encode_int(self, n, l):
        e = hex(n).rstrip("L").lstrip("0x")
        L = (l + 7) / 8  # number of bytes rounded up
        e = '0' * (L * 2 - len(e)) + e  # pad as necessary
        return e.decode('hex')

    def sign(self, key, payload):
        skey = key.get_op_key('sign', self.curve)
        signer = skey.signer(ec.ECDSA(self.hashfn))
        signer.update(payload)
        signature = signer.finalize()
        r, s = ec_utils.decode_rfc6979_signature(signature)
        l = key.get_curve(self.curve).key_size
        return self.encode_int(r, l) + self.encode_int(s, l)

    def verify(self, key, payload, signature):
        pkey = key.get_op_key('verify', self.curve)
        r = signature[:len(signature)/2]
        s = signature[len(signature)/2:]
        enc_signature = ec_utils.encode_rfc6979_signature(
            int(r.encode('hex'), 16), int(s.encode('hex'), 16))
        verifier = pkey.verifier(enc_signature, ec.ECDSA(self.hashfn))
        verifier.update(payload)
        verifier.verify()


class _raw_none(_raw_jws):

    def sign(self, key, payload):
        return ''

    def verify(self, key, payload, signature):
        if signature != '':
            raise InvalidJWSSignature('The "none" signature must be the '
                                      'empty string')


class JWSCore(object):

    def __init__(self, alg, key, header, payload):
        """ Core JWS token handling.
            See draft-ietf-jose-json-web-signature-41

            NOTE: Users should normally use JWS, not JWSCore,
            as JWS perform necessary checks not performed by JWSCore.

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

    def _jwa_HS256(self):
        return _raw_hmac(hashes.SHA256())

    def _jwa_HS384(self):
        return _raw_hmac(hashes.SHA384())

    def _jwa_HS512(self):
        return _raw_hmac(hashes.SHA512())

    def _jwa_RS256(self):
        return _raw_rsa(padding.PKCS1v15(), hashes.SHA256())

    def _jwa_RS384(self):
        return _raw_rsa(padding.PKCS1v15(), hashes.SHA384())

    def _jwa_RS512(self):
        return _raw_rsa(padding.PKCS1v15(), hashes.SHA512())

    def _jwa_ES256(self):
        return _raw_ec('P-256', hashes.SHA256())

    def _jwa_ES384(self):
        return _raw_ec('P-384', hashes.SHA384())

    def _jwa_ES512(self):
        return _raw_ec('P-521', hashes.SHA512())

    def _jwa_PS256(self):
        return _raw_rsa(padding.PSS(padding.MGF1(hashes.SHA256()),
                                    padding.PSS.MAX_LENGTH),
                        hashes.SHA256())

    def _jwa_PS384(self):
        return _raw_rsa(padding.PSS(padding.MGF1(hashes.SHA384()),
                                    padding.PSS.MAX_LENGTH),
                        hashes.SHA384())

    def _jwa_PS512(self):
        return _raw_rsa(padding.PSS(padding.MGF1(hashes.SHA512()),
                                    padding.PSS.MAX_LENGTH),
                        hashes.SHA512())

    def _jwa_none(self):
        return _raw_none()

    def _jwa(self, name):
        attr = '_jwa_%s' % name
        try:
            return getattr(self, attr)()
        except (KeyError, AttributeError):
            raise InvalidJWAAlgorithm()

    def sign(self):
        signing_input = str.encode('.'.join([self.protected, self.payload]))
        signature = self.engine.sign(self.key, signing_input)
        return {'protected': self.protected,
                'payload': self.payload,
                'signature': base64url_encode(signature)}

    def verify(self, signature):
        try:
            signing_input = '.'.join([self.protected, self.payload])
            self.engine.verify(self.key, signing_input, signature)
        except Exception, e:  # pylint: disable=broad-except
            raise InvalidJWSSignature('Verification failed', repr(e))
        return True


class JWS(object):
    def __init__(self, payload=None):
        """ Generates or verifies Generic JWS tokens.
            See draft-ietf-jose-json-web-signature-41

        :param payload(bytes): An arbitrary value
        """
        self.objects = dict()
        if payload:
            self.objects['payload'] = payload

    def check_crit(self, crit):
        for k in crit:
            if k not in JWSHeaderRegistry:
                raise InvalidJWSSignature('Unknown critical header: '
                                          '"%s"' % k)
            else:
                if not JWSHeaderRegistry[k][1]:
                    raise InvalidJWSSignature('Unsupported critical '
                                              'header: "%s"' % k)

    # TODO: support selecting key with 'kid' and passing in multiple keys
    def verify(self, alg, key, payload, signature, protected, header=None):
        # verify it is a valid JSON object and keep a decode copy
        p = json.loads(protected)
        if not isinstance(p, dict):
            raise InvalidJWSSignature('Invalid Protected header')
        # merge heders, and verify there are no duplicates
        if header:
            h = json.loads(header)
            if not isinstance(h, dict):
                raise InvalidJWSSignature('Invalid Unprotected header')
            for k in p.keys():
                if k in h:
                    raise InvalidJWSSignature('Duplicate header: "%s"' % k)
            p.update(header)
        # verify critical headers
        # TODO: allow caller to specify list of headers it understands
        if 'crit' in p:
            self.check_crit(p['crit'])
        # check 'alg' is present
        if 'alg' not in p:
            raise InvalidJWSSignature('No "alg" in protected header')
        if alg:
            if alg != p['alg']:
                raise InvalidJWSSignature('"alg" mismatch, requested '
                                          '"%s", found "%s"' % (alg,
                                                                p['alg']))
            a = alg
        else:
            a = p['alg']

        # the following will verify the "alg" is upported and the signature
        # verifies
        S = JWSCore(a, key, protected, payload)
        S.verify(signature)

    def deserialize(self, raw_jws, key=None, alg=None, raise_invalid=True):
        """ Destroys any current status and tries to import the raw
            JWS provided.
        """
        self.objects = dict()
        o = dict()
        try:
            try:
                djws = json.loads(raw_jws)
                o['payload'] = base64url_decode(str(djws['payload']))
                if 'signatures' in djws:
                    o['signatures'] = list()
                    valid = False
                    faillog = []
                    for s in djws['signatures']:
                        os = dict()
                        os['protected'] = base64url_decode(str(s['protected']))
                        os['signature'] = base64url_decode(str(s['signature']))
                        if 'header' in s:
                            os['header'] = json.dumps(s['header'])
                        try:
                            self.verify(alg, key, o['payload'],
                                        os['signature'], os['protected'],
                                        os.get('header', None))
                            os['valid'] = True
                            # Ok if at least one verifies
                            valid = True
                        except Exception as e:  # pylint: disable=broad-except
                            faillog.append(str(e))
                            os['valid'] = False
                        o['signatures'].append(os)
                    if raise_invalid and not valid:
                        raise InvalidJWSSignature('Verification failed',
                                                  faillog)
                else:
                    o['protected'] = base64url_decode(str(djws['protected']))
                    o['signature'] = base64url_decode(str(djws['signature']))
                    if 'header' in djws:
                        o['header'] = json.dumps(djws['header'])
                    try:
                        self.verify(alg, key, o['payload'],
                                    o['signature'], o['protected'],
                                    o.get('header', None))
                        o['valid'] = True

                    except InvalidJWSSignature:
                        o['valid'] = False
                        if raise_invalid:
                            raise
                    except Exception as e:  # pylint: disable=broad-except
                        o['valid'] = False
                        if raise_invalid:
                            raise InvalidJWSSignature('Verification failed', e)

            except ValueError:
                c = raw_jws.split('.')
                if len(c) != 3:
                    raise InvalidJWSObject('Unrecognized representation')
                o['protected'] = base64url_decode(str(c[0]))
                o['payload'] = base64url_decode(str(c[1]))
                o['signature'] = base64url_decode(str(c[2]))
                try:
                    self.verify(alg, key, o['payload'], o['signature'],
                                o['protected'], None)
                    o['valid'] = True
                except InvalidJWSSignature:
                    o['valid'] = False
                    if raise_invalid:
                        raise
                except Exception as e:  # pylint: disable=broad-except
                    o['valid'] = False
                    if raise_invalid:
                        raise InvalidJWSSignature('Verification failed', e)

        except InvalidJWSSignature:
            raise
        except Exception, e:  # pylint: disable=broad-except
            raise InvalidJWSObject('Invalid format', e)

        self.objects = o

    def add_signature(self, key, alg=None, protected=None, header=None):
        if not self.objects.get('payload', None):
            raise InvalidJWSObject('Missing Payload')

        o = dict()
        p = None
        if alg is None and protected is None:
            raise ValueError('"alg" not specified')
        if protected:
            p = json.loads(protected)
        else:
            p = {'alg': alg}
            protected = json.dumps(p)
        if alg and alg != p['alg']:
            raise ValueError('"alg" value mismatch, specified "alg" does '
                             'not match "protected" header value')
        a = alg if alg else p['alg']
        # TODO: allow caller to specify list of headers it understands
        if 'crit' in p:
            self.check_crit(p['crit'])

        if header:
            h = json.loads(header)
            for k in p.keys():
                if k in h:
                    raise ValueError('Duplicate header: "%s"' % k)

        S = JWSCore(a, key, protected, self.objects['payload'])
        sig = S.sign()

        o['signature'] = base64url_decode(sig['signature'])
        o['protected'] = protected
        if header:
            o['header'] = h
        o['valid'] = True

        if 'signatures' in self.objects:
            self.objects['signatures'].append(o)
        elif 'signature' in self.objects:
            self.objects['signatures'] = list()
            n = dict()
            n['signature'] = self.objects['signature']
            del self.objects['signature']
            n['protected'] = self.objects['protected']
            del self.objects['protected']
            if 'header' in self.objects:
                n['header'] = self.objects['header']
                del self.objects['header']
            if 'valid' in self.objects:
                n['valid'] = self.objects['valid']
                del self.objects['valid']
            self.objects['signatures'].append(n)
            self.objects['signatures'].append(o)
        else:
            self.objects.update(o)

    def serialize(self, compact=False):

        if compact:
            if 'signatures' in self.objects:
                raise InvalidJWSOperation("Can't use compact encoding with "
                                          "multiple signatures")
            if 'signature' not in self.objects:
                raise InvalidJWSSignature("No available signature")
            if not self.objects.get('valid', False):
                raise InvalidJWSSignature("No valid signature found")
            return '.'.join([base64url_encode(self.objects['protected']),
                             base64url_encode(self.objects['payload']),
                             base64url_encode(self.objects['signature'])])
        else:
            obj = self.objects
            if 'signature' in obj:
                if not obj.get('valid', False):
                    raise InvalidJWSSignature("No valid signature found")
                sig = {'payload': base64url_encode(obj['payload']),
                       'protected': base64url_encode(obj['protected']),
                       'signature': base64url_encode(obj['signature'])}
                if 'header' in obj:
                    sig['header'] = obj['header']
            elif 'signatures' in obj:
                sig = {'payload': base64url_encode(obj['payload']),
                       'signatures': list()}
                for o in obj['signatures']:
                    if not o.get('valid', False):
                        continue
                    s = {'protected': base64url_encode(o['protected']),
                         'signature': base64url_encode(o['signature'])}
                    if 'header' in o:
                        s['header'] = o['header']
                    sig['signatures'].append(s)
                if len(sig['signatures']) == 0:
                    raise InvalidJWSSignature("No valid signature found")
            else:
                raise InvalidJWSSignature("No available signature")
            return json.dumps(sig)
