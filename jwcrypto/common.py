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
    l = len(payload) % 4
    if l == 2:
        payload += '=='
    elif l == 3:
        payload += '='
    elif l != 0:
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


class InvalidJWAAlgorithm(Exception):
    def __init__(self, message=None):
        msg = 'Invalid JWS Algorithm name'
        if message:
            msg += ' (%s)' % message
        super(InvalidJWAAlgorithm, self).__init__(msg)
