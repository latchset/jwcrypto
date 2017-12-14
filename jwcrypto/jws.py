# Copyright (C) 2015 JWCrypto Project Contributors - see LICENSE file

from jwcrypto.common import JWException
from jwcrypto.common import base64url_decode, base64url_encode
from jwcrypto.common import json_decode, json_encode
from jwcrypto.jwa import JWA
from jwcrypto.jwk import JWK


# RFC 7515 - 9.1
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
"""Registry of valid header parameters"""

default_allowed_algs = [
    'HS256', 'HS384', 'HS512',
    'RS256', 'RS384', 'RS512',
    'ES256', 'ES384', 'ES512',
    'PS256', 'PS384', 'PS512']
"""Default allowed algorithms"""


class InvalidJWSSignature(JWException):
    """Invalid JWS Signature.

    This exception is raised when a signature cannot be validated.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = str(message)
        else:
            msg = 'Unknown Signature Verification Failure'
        if exception:
            msg += ' {%s}' % str(exception)
        super(InvalidJWSSignature, self).__init__(msg)


class InvalidJWSObject(JWException):
    """Invalid JWS Object.

    This exception is raised when the JWS Object is invalid and/or
    improperly formatted.
    """

    def __init__(self, message=None, exception=None):
        msg = 'Invalid JWS Object'
        if message:
            msg += ' [%s]' % message
        if exception:
            msg += ' {%s}' % str(exception)
        super(InvalidJWSObject, self).__init__(msg)


class InvalidJWSOperation(JWException):
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
            msg += ' {%s}' % str(exception)
        super(InvalidJWSOperation, self).__init__(msg)


class JWSCore(object):
    """The inner JWS Core object.

    This object SHOULD NOT be used directly, the JWS object should be
    used instead as JWS perform necessary checks on the validity of
    the object and requested operations.

    """

    def __init__(self, alg, key, header, payload, algs=None):
        """Core JWS token handling.

        :param alg: The algorithm used to produce the signature.
            See RFC 7518
        :param key: A (:class:`jwcrypto.jwk.JWK`) key of appropriate
            type for the "alg" provided in the 'protected' json string.
        :param header: A JSON string representing the protected header.
        :param payload(bytes): An arbitrary value
        :param algs: An optional list of allowed algorithms

        :raises ValueError: if the key is not a :class:`JWK` object
        :raises InvalidJWAAlgorithm: if the algorithm is not valid, is
            unknown or otherwise not yet implemented.
        """
        self.alg = alg
        self.engine = self._jwa(alg, algs)
        if not isinstance(key, JWK):
            raise ValueError('key is not a JWK object')
        self.key = key

        if header is not None:
            if isinstance(header, dict):
                header = json_encode(header)
            self.protected = base64url_encode(header.encode('utf-8'))
        else:
            self.protected = ''
        self.payload = base64url_encode(payload)

    def _jwa(self, name, allowed):
        if allowed is None:
            allowed = default_allowed_algs
        if name not in allowed:
            raise InvalidJWSOperation('Algorithm not allowed')
        return JWA.signing_alg(name)

    def sign(self):
        """Generates a signature"""
        sigin = ('.'.join([self.protected, self.payload])).encode('utf-8')
        signature = self.engine.sign(self.key, sigin)
        return {'protected': self.protected,
                'payload': self.payload,
                'signature': base64url_encode(signature)}

    def verify(self, signature):
        """Verifies a signature

        :raises InvalidJWSSignature: if the verification fails.
        """
        try:
            sigin = ('.'.join([self.protected, self.payload])).encode('utf-8')
            self.engine.verify(self.key, sigin, signature)
        except Exception as e:  # pylint: disable=broad-except
            raise InvalidJWSSignature('Verification failed', repr(e))
        return True


class JWS(object):
    """JSON Web Signature object

    This object represent a JWS token.
    """

    def __init__(self, payload=None):
        """Creates a JWS object.

        :param payload(bytes): An arbitrary value (optional).
        """
        self.objects = dict()
        if payload:
            self.objects['payload'] = payload
        self.verifylog = None
        self._allowed_algs = None

    def _check_crit(self, crit):
        for k in crit:
            if k not in JWSHeaderRegistry:
                raise InvalidJWSSignature('Unknown critical header: '
                                          '"%s"' % k)
            else:
                if not JWSHeaderRegistry[k][1]:
                    raise InvalidJWSSignature('Unsupported critical '
                                              'header: "%s"' % k)

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

    @property
    def is_valid(self):
        return self.objects.get('valid', False)

    def _merge_headers(self, h1, h2):
        for k in list(h1.keys()):
            if k in h2:
                raise InvalidJWSObject('Duplicate header: "%s"' % k)
        h1.update(h2)
        return h1

    # TODO: support selecting key with 'kid' and passing in multiple keys
    def _verify(self, alg, key, payload, signature, protected, header=None):
        # verify it is a valid JSON object and keep a decode copy
        if protected is not None:
            p = json_decode(protected)
        else:
            p = dict()
        if not isinstance(p, dict):
            raise InvalidJWSSignature('Invalid Protected header')
        # merge heders, and verify there are no duplicates
        if header:
            if not isinstance(header, dict):
                raise InvalidJWSSignature('Invalid Unprotected header')
            p = self._merge_headers(p, header)
        # verify critical headers
        # TODO: allow caller to specify list of headers it understands
        if 'crit' in p:
            self._check_crit(p['crit'])
        # check 'alg' is present
        if alg is None and 'alg' not in p:
            raise InvalidJWSSignature('No "alg" in headers')
        if alg:
            if 'alg' in p and alg != p['alg']:
                raise InvalidJWSSignature('"alg" mismatch, requested '
                                          '"%s", found "%s"' % (alg,
                                                                p['alg']))
            a = alg
        else:
            a = p['alg']

        # the following will verify the "alg" is supported and the signature
        # verifies
        c = JWSCore(a, key, protected, payload, self._allowed_algs)
        c.verify(signature)

    def verify(self, key, alg=None):
        """Verifies a JWS token.

        :param key: The (:class:`jwcrypto.jwk.JWK`) verification key.
        :param alg: The signing algorithm (optional). usually the algorithm
            is known as it is provided with the JOSE Headers of the token.

        :raises InvalidJWSSignature: if the verification fails.
        """

        self.verifylog = list()
        self.objects['valid'] = False
        obj = self.objects
        if 'signature' in obj:
            try:
                self._verify(alg, key,
                             obj['payload'],
                             obj['signature'],
                             obj.get('protected', None),
                             obj.get('header', None))
                obj['valid'] = True
            except Exception as e:  # pylint: disable=broad-except
                self.verifylog.append('Failed: [%s]' % repr(e))

        elif 'signatures' in obj:
            for o in obj['signatures']:
                try:
                    self._verify(alg, key,
                                 obj['payload'],
                                 o['signature'],
                                 o.get('protected', None),
                                 o.get('header', None))
                    # Ok if at least one verifies
                    obj['valid'] = True
                except Exception as e:  # pylint: disable=broad-except
                    self.verifylog.append('Failed: [%s]' % repr(e))
        else:
            raise InvalidJWSSignature('No signatures availble')

        if not self.is_valid:
            raise InvalidJWSSignature('Verification failed for all '
                                      'signatures' + repr(self.verifylog))

    def deserialize(self, raw_jws, key=None, alg=None):
        """Deserialize a JWS token.

        NOTE: Destroys any current status and tries to import the raw
        JWS provided.

        :param raw_jws: a 'raw' JWS token (JSON Encoded or Compact
         notation) string.
        :param key: A (:class:`jwcrypto.jwk.JWK`) verification key (optional).
         If a key is provided a verification step will be attempted after
         the object is successfully deserialized.
        :param alg: The signing algorithm (optional). usually the algorithm
         is known as it is provided with the JOSE Headers of the token.

        :raises InvalidJWSObject: if the raw object is an invaid JWS token.
        :raises InvalidJWSSignature: if the verification fails.
        """
        self.objects = dict()
        o = dict()
        try:
            try:
                djws = json_decode(raw_jws)
                o['payload'] = base64url_decode(str(djws['payload']))
                if 'signatures' in djws:
                    o['signatures'] = list()
                    for s in djws['signatures']:
                        os = dict()
                        os['signature'] = base64url_decode(str(s['signature']))
                        if 'protected' in s:
                            p = base64url_decode(str(s['protected']))
                            os['protected'] = p.decode('utf-8')
                        if 'header' in s:
                            os['header'] = s['header']
                        o['signatures'].append(os)
                else:
                    o['signature'] = base64url_decode(str(djws['signature']))
                    if 'protected' in djws:
                        p = base64url_decode(str(djws['protected']))
                        o['protected'] = p.decode('utf-8')
                    if 'header' in djws:
                        o['header'] = djws['header']

            except ValueError:
                c = raw_jws.split('.')
                if len(c) != 3:
                    raise InvalidJWSObject('Unrecognized representation')
                p = base64url_decode(str(c[0]))
                if len(p) > 0:
                    o['protected'] = p.decode('utf-8')
                o['payload'] = base64url_decode(str(c[1]))
                o['signature'] = base64url_decode(str(c[2]))

            self.objects = o

        except Exception as e:  # pylint: disable=broad-except
            raise InvalidJWSObject('Invalid format', repr(e))

        if key:
            self.verify(key, alg)

    def add_signature(self, key, alg=None, protected=None, header=None):
        """Adds a new signature to the object.

        :param key: A (:class:`jwcrypto.jwk.JWK`) key of appropriate for
         the "alg" provided.
        :param alg: An optional algorithm name. If already provided as an
         element of the protected or unprotected header it can be safely
         omitted.
        :param potected: The Protected Header (optional)
        :param header: The Unprotected Header (optional)

        :raises InvalidJWSObject: if no payload has been set on the object.
        :raises ValueError: if the key is not a :class:`JWK` object.
        :raises ValueError: if the algorithm is missing or is not provided
         by one of the headers.
        :raises InvalidJWAAlgorithm: if the algorithm is not valid, is
         unknown or otherwise not yet implemented.
        """

        if not self.objects.get('payload', None):
            raise InvalidJWSObject('Missing Payload')

        p = dict()
        if protected:
            if isinstance(protected, dict):
                protected = json_encode(protected)
            p = json_decode(protected)
            # TODO: allow caller to specify list of headers it understands
            if 'crit' in p:
                self._check_crit(p['crit'])

        if header:
            if isinstance(header, dict):
                header = json_encode(header)
            h = json_decode(header)
            p = self._merge_headers(p, h)

        if 'alg' in p:
            if alg is None:
                alg = p['alg']
            elif alg != p['alg']:
                raise ValueError('"alg" value mismatch, specified "alg" '
                                 'does not match JOSE header value')

        if alg is None:
            raise ValueError('"alg" not specified')

        c = JWSCore(alg, key, protected, self.objects['payload'])
        sig = c.sign()

        o = dict()
        o['signature'] = base64url_decode(sig['signature'])
        if protected:
            o['protected'] = protected
        if header:
            o['header'] = h
        o['valid'] = True

        if 'signatures' in self.objects:
            self.objects['signatures'].append(o)
        elif 'signature' in self.objects:
            self.objects['signatures'] = list()
            n = dict()
            n['signature'] = self.objects.pop('signature')
            if 'protected' in self.objects:
                n['protected'] = self.objects.pop('protected')
            if 'header' in self.objects:
                n['header'] = self.objects.pop('header')
            if 'valid' in self.objects:
                n['valid'] = self.objects.pop('valid')
            self.objects['signatures'].append(n)
            self.objects['signatures'].append(o)
        else:
            self.objects.update(o)

    def serialize(self, compact=False):
        """Serializes the object into a JWS token.

        :param compact(boolean): if True generates the compact
         representation, otherwise generates a standard JSON format.

        :raises InvalidJWSOperation: if the object cannot serialized
         with the compact representation and `compat` is True.
        :raises InvalidJWSSignature: if no signature has been added
         to the object, or no valid signature can be found.
        """

        if compact:
            if 'signatures' in self.objects:
                raise InvalidJWSOperation("Can't use compact encoding with "
                                          "multiple signatures")
            if 'signature' not in self.objects:
                raise InvalidJWSSignature("No available signature")
            if not self.objects.get('valid', False):
                raise InvalidJWSSignature("No valid signature found")
            if 'protected' in self.objects:
                protected = base64url_encode(self.objects['protected'])
            else:
                protected = ''
            return '.'.join([protected,
                             base64url_encode(self.objects['payload']),
                             base64url_encode(self.objects['signature'])])
        else:
            obj = self.objects
            if 'signature' in obj:
                if not obj.get('valid', False):
                    raise InvalidJWSSignature("No valid signature found")
                sig = {'payload': base64url_encode(obj['payload']),
                       'signature': base64url_encode(obj['signature'])}
                if 'protected' in obj:
                    sig['protected'] = base64url_encode(obj['protected'])
                if 'header' in obj:
                    sig['header'] = obj['header']
            elif 'signatures' in obj:
                sig = {'payload': base64url_encode(obj['payload']),
                       'signatures': list()}
                for o in obj['signatures']:
                    if not o.get('valid', False):
                        continue
                    s = {'signature': base64url_encode(o['signature'])}
                    if 'protected' in o:
                        s['protected'] = base64url_encode(o['protected'])
                    if 'header' in o:
                        s['header'] = o['header']
                    sig['signatures'].append(s)
                if len(sig['signatures']) == 0:
                    raise InvalidJWSSignature("No valid signature found")
            else:
                raise InvalidJWSSignature("No available signature")
            return json_encode(sig)

    @property
    def payload(self):
        if 'payload' not in self.objects:
            raise InvalidJWSOperation("Payload not available")
        if not self.is_valid:
            raise InvalidJWSOperation("Payload not verified")
        return self.objects['payload']

    @property
    def jose_header(self):
        obj = self.objects
        if 'signature' in obj:
            jh = dict()
            if 'protected' in obj:
                p = json_decode(obj['protected'])
                jh = self._merge_headers(jh, p)
            jh = self._merge_headers(jh, obj.get('header', dict()))
            return jh
        elif 'signatures' in self.objects:
            jhl = list()
            for o in obj['signatures']:
                jh = dict()
                if 'protected' in o:
                    p = json_decode(o['protected'])
                    jh = self._merge_headers(jh, p)
                jh = self._merge_headers(jh, o.get('header', dict()))
                jhl.append(jh)
            return jhl
        else:
            raise InvalidJWSOperation("JOSE Header(s) not available")
