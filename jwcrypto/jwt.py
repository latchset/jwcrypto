# Copyright (C) 2015  JWCrypto Project Contributors - see LICENSE file

import time
import uuid

from six import string_types

from jwcrypto.common import JWException, json_decode, json_encode
from jwcrypto.jwe import JWE
from jwcrypto.jwk import JWK, JWKSet
from jwcrypto.jws import JWS


# RFC 7519 - 4.1
# name: description
JWTClaimsRegistry = {'iss': 'Issuer',
                     'sub': 'Subject',
                     'aud': 'Audience',
                     'exp': 'Expiration Time',
                     'nbf': 'Not Before',
                     'iat': 'Issued At',
                     'jti': 'JWT ID'}


class JWTExpired(JWException):
    """Json Web Token is expired.

    This exception is raised when a token is expired accoring to its claims.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = str(message)
        else:
            msg = 'Token expired'
        if exception:
            msg += ' {%s}' % str(exception)
        super(JWTExpired, self).__init__(msg)


class JWTNotYetValid(JWException):
    """Json Web Token is not yet valid.

    This exception is raised when a token is not valid yet according to its
    claims.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = str(message)
        else:
            msg = 'Token not yet valid'
        if exception:
            msg += ' {%s}' % str(exception)
        super(JWTNotYetValid, self).__init__(msg)


class JWTMissingClaim(JWException):
    """Json Web Token claim is invalid.

    This exception is raised when a claim does not match the expected value.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = str(message)
        else:
            msg = 'Invalid Claim Value'
        if exception:
            msg += ' {%s}' % str(exception)
        super(JWTMissingClaim, self).__init__(msg)


class JWTInvalidClaimValue(JWException):
    """Json Web Token claim is invalid.

    This exception is raised when a claim does not match the expected value.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = str(message)
        else:
            msg = 'Invalid Claim Value'
        if exception:
            msg += ' {%s}' % str(exception)
        super(JWTInvalidClaimValue, self).__init__(msg)


class JWTInvalidClaimFormat(JWException):
    """Json Web Token claim format is invalid.

    This exception is raised when a claim is not in a valid format.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = str(message)
        else:
            msg = 'Invalid Claim Format'
        if exception:
            msg += ' {%s}' % str(exception)
        super(JWTInvalidClaimFormat, self).__init__(msg)


# deprecated and not used anymore
class JWTMissingKeyID(JWException):
    """Json Web Token is missing key id.

    This exception is raised when trying to decode a JWT with a key set
    that does not have a kid value in its header.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = str(message)
        else:
            msg = 'Missing Key ID'
        if exception:
            msg += ' {%s}' % str(exception)
        super(JWTMissingKeyID, self).__init__(msg)


class JWTMissingKey(JWException):
    """Json Web Token is using a key not in the key set.

    This exception is raised if the key that was used is not available
    in the passed key set.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = str(message)
        else:
            msg = 'Missing Key'
        if exception:
            msg += ' {%s}' % str(exception)
        super(JWTMissingKey, self).__init__(msg)


class JWT(object):
    """JSON Web token object

    This object represent a generic token.
    """

    def __init__(self, header=None, claims=None, jwt=None, key=None,
                 algs=None, default_claims=None, check_claims=None):
        """Creates a JWT object.

        :param header: A dict or a JSON string with the JWT Header data.
        :param claims: A dict or a string with the JWT Claims data.
        :param jwt: a 'raw' JWT token
        :param key: A (:class:`jwcrypto.jwk.JWK`) key to deserialize
         the token. A (:class:`jwcrypto.jwk.JWKSet`) can also be used.
        :param algs: An optional list of allowed algorithms
        :param default_claims: An optional dict with default values for
         registered claims. A None value for NumericDate type claims
         will cause generation according to system time. Only the values
         from RFC 7519 - 4.1 are evaluated.
        :param check_claims: An optional dict of claims that must be
         present in the token, if the value is not None the claim must
         match exactly.

        Note: either the header,claims or jwt,key parameters should be
        provided as a deserialization operation (which occurs if the jwt
        is provided) will wipe any header or claim provided by setting
        those obtained from the deserialization of the jwt token.

        Note: if check_claims is not provided the 'exp' and 'nbf' claims
        are checked if they are set on the token but not enforced if not
        set. Any other RFC 7519 registered claims are checked only for
        format conformance.
        """

        self._header = None
        self._claims = None
        self._token = None
        self._algs = algs
        self._reg_claims = None
        self._check_claims = None
        self._leeway = 60  # 1 minute clock skew allowed
        self._validity = 600  # 10 minutes validity (up to 11 with leeway)
        self.deserializelog = None

        if header:
            self.header = header

        if default_claims is not None:
            self._reg_claims = default_claims

        if check_claims is not None:
            self._check_claims = check_claims

        if claims:
            self.claims = claims

        if jwt is not None:
            self.deserialize(jwt, key)

    @property
    def header(self):
        if self._header is None:
            raise KeyError("'header' not set")
        return self._header

    @header.setter
    def header(self, h):
        if isinstance(h, dict):
            eh = json_encode(h)
        else:
            eh = h
            h = json_decode(eh)

        if h.get('b64') is False:
            raise ValueError("b64 header is invalid."
                             "JWTs cannot use unencoded payloads")
        self._header = eh

    @property
    def claims(self):
        if self._claims is None:
            raise KeyError("'claims' not set")
        return self._claims

    @claims.setter
    def claims(self, c):
        if self._reg_claims and not isinstance(c, dict):
            # decode c so we can set default claims
            c = json_decode(c)

        if isinstance(c, dict):
            self._add_default_claims(c)
            self._claims = json_encode(c)
        else:
            self._claims = c

    @property
    def token(self):
        return self._token

    @token.setter
    def token(self, t):
        if isinstance(t, JWS) or isinstance(t, JWE) or isinstance(t, JWT):
            self._token = t
        else:
            raise TypeError("Invalid token type, must be one of JWS,JWE,JWT")

    @property
    def leeway(self):
        return self._leeway

    @leeway.setter
    def leeway(self, lwy):
        self._leeway = int(lwy)

    @property
    def validity(self):
        return self._validity

    @validity.setter
    def validity(self, v):
        self._validity = int(v)

    def _add_optional_claim(self, name, claims):
        if name in claims:
            return
        val = self._reg_claims.get(name, None)
        if val is not None:
            claims[name] = val

    def _add_time_claim(self, name, claims, defval):
        if name in claims:
            return
        if name in self._reg_claims:
            if self._reg_claims[name] is None:
                claims[name] = defval
            else:
                claims[name] = self._reg_claims[name]

    def _add_jti_claim(self, claims):
        if 'jti' in claims or 'jti' not in self._reg_claims:
            return
        claims['jti'] = str(uuid.uuid4())

    def _add_default_claims(self, claims):
        if self._reg_claims is None:
            return

        now = int(time.time())
        self._add_optional_claim('iss', claims)
        self._add_optional_claim('sub', claims)
        self._add_optional_claim('aud', claims)
        self._add_time_claim('exp', claims, now + self.validity)
        self._add_time_claim('nbf', claims, now)
        self._add_time_claim('iat', claims, now)
        self._add_jti_claim(claims)

    def _check_string_claim(self, name, claims):
        if name not in claims:
            return
        if not isinstance(claims[name], string_types):
            raise JWTInvalidClaimFormat("Claim %s is not a StringOrURI type")

    def _check_array_or_string_claim(self, name, claims):
        if name not in claims:
            return
        if isinstance(claims[name], list):
            if any(not isinstance(claim, string_types) for claim in claims):
                raise JWTInvalidClaimFormat(
                    "Claim %s contains non StringOrURI types" % (name, ))
        elif not isinstance(claims[name], string_types):
            raise JWTInvalidClaimFormat(
                "Claim %s is not a StringOrURI type" % (name, ))

    def _check_integer_claim(self, name, claims):
        if name not in claims:
            return
        try:
            int(claims[name])
        except ValueError:
            raise JWTInvalidClaimFormat(
                "Claim %s is not an integer" % (name, ))

    def _check_exp(self, claim, limit, leeway):
        if claim < limit - leeway:
            raise JWTExpired('Expired at %d, time: %d(leeway: %d)' % (
                             claim, limit, leeway))

    def _check_nbf(self, claim, limit, leeway):
        if claim > limit + leeway:
            raise JWTNotYetValid('Valid from %d, time: %d(leeway: %d)' % (
                                 claim, limit, leeway))

    def _check_default_claims(self, claims):
        self._check_string_claim('iss', claims)
        self._check_string_claim('sub', claims)
        self._check_array_or_string_claim('aud', claims)
        self._check_integer_claim('exp', claims)
        self._check_integer_claim('nbf', claims)
        self._check_integer_claim('iat', claims)
        self._check_string_claim('jti', claims)

        if self._check_claims is None:
            if 'exp' in claims:
                self._check_exp(claims['exp'], time.time(), self._leeway)
            if 'nbf' in claims:
                self._check_nbf(claims['nbf'], time.time(), self._leeway)

    def _check_provided_claims(self):
        # check_claims can be set to False to skip any check
        if self._check_claims is False:
            return

        try:
            claims = json_decode(self.claims)
            if not isinstance(claims, dict):
                raise ValueError()
        except ValueError:
            if self._check_claims is not None:
                raise JWTInvalidClaimFormat(
                    "Claims check requested but claims is not a json dict")
            return

        self._check_default_claims(claims)

        if self._check_claims is None:
            return

        for name, value in self._check_claims.items():
            if name not in claims:
                raise JWTMissingClaim("Claim %s is missing" % (name, ))

            if name in ['iss', 'sub', 'jti']:
                if value is not None and value != claims[name]:
                    raise JWTInvalidClaimValue(
                        "Invalid '%s' value. Expected '%s' got '%s'" % (
                            name, value, claims[name]))

            elif name == 'aud':
                if value is not None:
                    if value == claims[name]:
                        continue
                    if isinstance(claims[name], list):
                        if value in claims[name]:
                            continue
                    raise JWTInvalidClaimValue(
                        "Invalid '%s' value. Expected '%s' to be in '%s'" % (
                            name, claims[name], value))

            elif name == 'exp':
                if value is not None:
                    self._check_exp(claims[name], value, 0)
                else:
                    self._check_exp(claims[name], time.time(), self._leeway)

            elif name == 'nbf':
                if value is not None:
                    self._check_nbf(claims[name], value, 0)
                else:
                    self._check_nbf(claims[name], time.time(), self._leeway)

            else:
                if value is not None and value != claims[name]:
                    raise JWTInvalidClaimValue(
                        "Invalid '%s' value. Expected '%s' got '%s'" % (
                            name, value, claims[name]))

    def make_signed_token(self, key):
        """Signs the payload.

        Creates a JWS token with the header as the JWS protected header and
        the claims as the payload. See (:class:`jwcrypto.jws.JWS`) for
        details on the exceptions that may be raised.

        :param key: A (:class:`jwcrypto.jwk.JWK`) key.
        """

        t = JWS(self.claims)
        if self._algs:
            t.allowed_algs = self._algs
        t.add_signature(key, protected=self.header)
        self.token = t

    def make_encrypted_token(self, key):
        """Encrypts the payload.

        Creates a JWE token with the header as the JWE protected header and
        the claims as the plaintext. See (:class:`jwcrypto.jwe.JWE`) for
        details on the exceptions that may be raised.

        :param key: A (:class:`jwcrypto.jwk.JWK`) key.
        """

        t = JWE(self.claims, self.header)
        t.add_recipient(key)
        self.token = t

    def deserialize(self, jwt, key=None):
        """Deserialize a JWT token.

        NOTE: Destroys any current status and tries to import the raw
        token provided.

        :param jwt: a 'raw' JWT token.
        :param key: A (:class:`jwcrypto.jwk.JWK`) verification or
         decryption key, or a (:class:`jwcrypto.jwk.JWKSet`) that
         contains a key indexed by the 'kid' header.
        """
        c = jwt.count('.')
        if c == 2:
            self.token = JWS()
        elif c == 4:
            self.token = JWE()
        else:
            raise ValueError("Token format unrecognized")

        # Apply algs restrictions if any, before performing any operation
        if self._algs:
            self.token.allowed_algs = self._algs

        self.deserializelog = list()
        # now deserialize and also decrypt/verify (or raise) if we
        # have a key
        if key is None:
            self.token.deserialize(jwt, None)
        elif isinstance(key, JWK):
            self.token.deserialize(jwt, key)
            self.deserializelog.append("Success")
        elif isinstance(key, JWKSet):
            self.token.deserialize(jwt, None)
            if 'kid' in self.token.jose_header:
                kid_key = key.get_key(self.token.jose_header['kid'])
                if not kid_key:
                    raise JWTMissingKey('Key ID %s not in key set'
                                        % self.token.jose_header['kid'])
                self.token.deserialize(jwt, kid_key)
            else:
                for k in key:
                    try:
                        self.token.deserialize(jwt, k)
                        self.deserializelog.append("Success")
                        break
                    except Exception as e:  # pylint: disable=broad-except
                        keyid = k.key_id
                        if keyid is None:
                            keyid = k.thumbprint()
                        self.deserializelog.append('Key [%s] failed: [%s]' % (
                            keyid, repr(e)))
                        continue
                if "Success" not in self.deserializelog:
                    raise JWTMissingKey('No working key found in key set')
        else:
            raise ValueError("Unrecognized Key Type")

        if key is not None:
            self.header = self.token.jose_header
            self.claims = self.token.payload.decode('utf-8')
            self._check_provided_claims()

    def serialize(self, compact=True):
        """Serializes the object into a JWS token.

        :param compact(boolean): must be True.

        Note: the compact parameter is provided for general compatibility
        with the serialize() functions of :class:`jwcrypto.jws.JWS` and
        :class:`jwcrypto.jwe.JWE` so that these objects can all be used
        interchangeably. However the only valid JWT representation is the
        compact representation.
        """
        return self.token.serialize(compact)
