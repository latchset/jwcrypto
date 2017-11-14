# Copyright (C) 2015 JWCrypto Project Contributors - see LICENSE file

import json
from base64 import urlsafe_b64decode, urlsafe_b64encode


# Padding stripping versions as described in
# RFC 7515 Appendix C


def base64url_encode(payload):
    if not isinstance(payload, bytes):
        payload = payload.encode('utf-8')
    encode = urlsafe_b64encode(payload)
    return encode.decode('utf-8').rstrip('=')


def base64url_decode(payload):
    size = len(payload) % 4
    if size == 2:
        payload += '=='
    elif size == 3:
        payload += '='
    elif size != 0:
        raise ValueError('Invalid base64 string')
    return urlsafe_b64decode(payload.encode('utf-8'))


# JSON encoding/decoding helpers with good defaults

def json_encode(string):
    if isinstance(string, bytes):
        string = string.decode('utf-8')
    return json.dumps(string, separators=(',', ':'), sort_keys=True)


def json_decode(string):
    if isinstance(string, bytes):
        string = string.decode('utf-8')
    return json.loads(string)


class JWException(Exception):
    pass


class InvalidJWAAlgorithm(JWException):
    def __init__(self, message=None):
        msg = 'Invalid JWA Algorithm name'
        if message:
            msg += ' (%s)' % message
        super(InvalidJWAAlgorithm, self).__init__(msg)


class InvalidCEKeyLength(JWException):
    """Invalid CEK Key Length.

    This exception is raised when a Content Encryption Key does not match
    the required lenght.
    """

    def __init__(self, expected, obtained):
        msg = 'Expected key of length %d bits, got %d' % (expected, obtained)
        super(InvalidCEKeyLength, self).__init__(msg)


class InvalidJWEOperation(JWException):
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


class InvalidJWEKeyType(JWException):
    """Invalid JWE Key Type.

    This exception is raised when the provided JWK Key does not match
    the type required by the sepcified algorithm.
    """

    def __init__(self, expected, obtained):
        msg = 'Expected key type %s, got %s' % (expected, obtained)
        super(InvalidJWEKeyType, self).__init__(msg)


class InvalidJWEKeyLength(JWException):
    """Invalid JWE Key Length.

    This exception is raised when the provided JWK Key does not match
    the lenght required by the sepcified algorithm.
    """

    def __init__(self, expected, obtained):
        msg = 'Expected key of lenght %d, got %d' % (expected, obtained)
        super(InvalidJWEKeyLength, self).__init__(msg)
