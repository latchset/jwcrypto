# Copyright (C) 2015  JWCrypto Project Contributors - see LICENSE file

from __future__ import unicode_literals

import copy

import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa

from jwcrypto import jwe
from jwcrypto import jwk
from jwcrypto import jws
from jwcrypto import jwt
from jwcrypto.common import base64url_decode, base64url_encode
from jwcrypto.common import json_decode, json_encode

# RFC 7517 - A.1
PublicKeys = {"keys": [
              {"kty": "EC",
               "crv": "P-256",
               "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
               "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
               "use": "enc",
               "kid": "1"},
              {"kty": "RSA",
               "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbf"
                    "AAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknj"
                    "hMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65"
                    "YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQ"
                    "vRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lF"
                    "d2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzK"
                    "nqDKgw",
               "e": "AQAB",
               "alg": "RS256",
               "kid": "2011-04-29"}],
              "thumbprints": ["cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s",
                              "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"]}

# RFC 7517 - A.2
PrivateKeys = {"keys": [
               {"kty": "EC",
                "crv": "P-256",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
                "use": "enc",
                "kid": "1"},
               {"kty": "RSA",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbb"
                     "fAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3ok"
                     "njhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v"
                     "-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu"
                     "6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0"
                     "fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8a"
                     "wapJzKnqDKgw",
                "e": "AQAB",
                "d": "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7d"
                     "x5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_"
                     "YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywb"
                     "ReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5Zi"
                     "G7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z"
                     "4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc"
                     "0X4jfcKoAC8Q",
                "p": "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVn"
                     "wD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XO"
                     "uVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O"
                     "0nVbfs",
                "q": "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumq"
                     "jVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VV"
                     "S78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb"
                     "6yelxk",
                "dp": "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimY"
                      "wxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA"
                      "77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8Y"
                      "eiKkTiBj0",
                "dq": "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUv"
                      "MfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqU"
                      "fLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txX"
                      "w494Q_cgk",
                "qi": "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgU"
                      "IZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_"
                      "mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia"
                      "6zTKhAVRU",
                "alg": "RS256",
                "kid": "2011-04-29"}]}

# RFC 7517 - A.3
SymmetricKeys = {"keys": [
                 {"kty": "oct",
                  "alg": "A128KW",
                  "k": "GawgguFyGrWKav7AX4VKUg"},
                 {"kty": "oct",
                  "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH7"
                       "5aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
                  "kid": "HMAC key used in JWS A.1 example"}]}

# RFC 7517 - B
Useofx5c = {"kty": "RSA",
            "use": "sig",
            "kid": "1b94c",
            "n": "vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK"
                 "_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j"
                 "8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYW"
                 "Achc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHM"
                 "TplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMv"
                 "VfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ",
            "e": "AQAB",
            "x5c": ["MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJ"
                    "BgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRww"
                    "GgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5Ccmlh"
                    "biBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVa"
                    "MGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVu"
                    "dmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQD"
                    "Ew5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC"
                    "AQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9"
                    "if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u"
                    "3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK"
                    "0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8u"
                    "gMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBR"
                    "DWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f"
                    "4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSl"
                    "cI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWs"
                    "nrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3"
                    "PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrps"
                    "HzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5r"
                    "FXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR"
                    "+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="
                    ]}

# RFC 7517 - C.1
RSAPrivateKey = {"kty": "RSA",
                 "kid": "juliet@capulet.lit",
                 "use": "enc",
                 "n": "t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNq"
                      "FMSQRyO125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR"
                      "0-Iqom-QFcNP8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQ"
                      "lO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-"
                      "AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L"
                      "32-lSeZO-Os6U15_aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i"
                      "744FPFGGcG1qs2Wz-Q",
                 "e": "AQAB",
                 "d": "GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTea"
                      "STyWfSNkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWa"
                      "Cl3hdlPKXy9UvqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo"
                      "4_PMaenNnPiQgO0xnuToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDms"
                      "XOfUENOyMqADC6p1M3h33tsurY15k9qMSpG9OX_IJAXmxzAh_tWiZO"
                      "wk2K4yxH9tS3Lq1yX8C1EWmeRDkK2ahecG85-oLKQt5VEpWHKmjOi_"
                      "gJSdSgqcN96X52esAQ",
                 "p": "2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9u"
                      "w-PIHfQP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPP"
                      "SYB9yk31s0Q8UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3r"
                      "CT5T3yJws",
                 "q": "1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjs"
                      "Zu0c6Iedis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjV"
                      "tG6TlV8CLCYKrYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5"
                      "B0f808I4s",
                 "dp": "KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwK"
                       "qvVDq3tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_l"
                       "hqigI4y_kqS1wY52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttW"
                       "txVqLCRViD6c",
                 "dq": "AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1"
                       "xDkbN9GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCz"
                       "kOkmxIe3KRbBymXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRF"
                       "COJ3xDea-ots",
                 "qi": "lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEo"
                       "PwmUqqabu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDM"
                       "eAvmj4sm-Fp0oYu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu"
                       "9HCJ-UsfSOI8"}


class TestJWK(unittest.TestCase):
    def test_create_pubKeys(self):
        keylist = PublicKeys['keys']
        for key in keylist:
            jwk.JWK(**key)

    def test_create_priKeys(self):
        keylist = PrivateKeys['keys']
        for key in keylist:
            jwk.JWK(**key)

    def test_create_symKeys(self):
        keylist = SymmetricKeys['keys']
        for key in keylist:
            jwkey = jwk.JWK(**key)
            jwkey.get_op_key('sign')
            jwkey.get_op_key('verify')
            e = jwkey.export()
            self.assertEqual(json_decode(e), key)

        jwk.JWK(**Useofx5c)
        jwk.JWK(**RSAPrivateKey)

    def test_generate_keys(self):
        jwk.JWK.generate(kty='oct', size=256)
        jwk.JWK.generate(kty='RSA', size=4096)
        jwk.JWK.generate(kty='EC', curve='P-521')
        k = jwk.JWK.generate(kty='oct', size=256, kid='MySymmetricKey')
        self.assertEqual(k.key_id, 'MySymmetricKey')

    def test_export_public_keys(self):
        k = jwk.JWK(**RSAPrivateKey)
        jk = k.export_public()
        self.assertFalse('d' in json_decode(jk))
        k2 = jwk.JWK(**json_decode(jk))
        self.assertEqual(k.key_id, k2.key_id)

    def test_generate_oct_key(self):
        key = jwk.JWK.generate(kty='oct', size=128)
        e = jwe.JWE('test', '{"alg":"A128KW","enc":"A128GCM"}')
        e.add_recipient(key)
        enc = e.serialize()
        e.deserialize(enc, key)
        self.assertEqual(e.payload.decode('utf-8'), 'test')

    def test_generate_EC_key(self):
        # Backwards compat curve
        key = jwk.JWK.generate(kty='EC', curve='P-256')
        key.get_curve('P-256')
        # New param
        key = jwk.JWK.generate(kty='EC', crv='P-521')
        key.get_curve('P-521')
        # New param prevails
        key = jwk.JWK.generate(kty='EC', curve='P-256', crv='P-521')
        key.get_curve('P-521')

    def test_import_pyca_keys(self):
        rsa1 = rsa.generate_private_key(65537, 1024, default_backend())
        krsa1 = jwk.JWK.from_pyca(rsa1)
        self.assertEqual(krsa1.key_type, 'RSA')
        krsa2 = jwk.JWK.from_pyca(rsa1.public_key())
        self.assertEqual(krsa1.get_op_key('verify').public_numbers().n,
                         krsa2.get_op_key('verify').public_numbers().n)
        ec1 = ec.generate_private_key(ec.SECP256R1(), default_backend())
        kec1 = jwk.JWK.from_pyca(ec1)
        self.assertEqual(kec1.key_type, 'EC')
        kec2 = jwk.JWK.from_pyca(ec1.public_key())
        self.assertEqual(kec1.get_op_key('verify').public_numbers().x,
                         kec2.get_op_key('verify').public_numbers().x)
        self.assertRaises(jwk.InvalidJWKValue,
                          jwk.JWK.from_pyca, dict())

    def test_jwkset(self):
        k = jwk.JWK(**RSAPrivateKey)
        ks = jwk.JWKSet()
        ks.add(k)
        ks2 = jwk.JWKSet().import_keyset(ks.export())
        self.assertEqual(len(ks), len(ks2))
        self.assertEqual(len(ks), 1)
        k1 = ks.get_key(RSAPrivateKey['kid'])
        k2 = ks2.get_key(RSAPrivateKey['kid'])
        # pylint: disable=protected-access
        self.assertEqual(k1._key, k2._key)
        # pylint: disable=protected-access
        self.assertEqual(k1._key['d'], RSAPrivateKey['d'])
        # test class method import too
        ks3 = jwk.JWKSet.from_json(ks.export())
        self.assertEqual(len(ks), len(ks3))

    def test_thumbprint(self):
        for i in range(0, len(PublicKeys['keys'])):
            k = jwk.JWK(**PublicKeys['keys'][i])
            self.assertEqual(
                k.thumbprint(),
                PublicKeys['thumbprints'][i])


# RFC 7515 - A.1
A1_protected = \
    [123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32,
     34, 97, 108, 103, 34, 58, 34, 72, 83, 50, 53, 54, 34, 125]
A1_payload = \
    [123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10,
     32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56,
     48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97,
     109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111,
     111, 116, 34, 58, 116, 114, 117, 101, 125]
A1_signature = \
    [116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
     187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
     132, 141, 121]
A1_example = {'key': SymmetricKeys['keys'][1],
              'alg': 'HS256',
              'protected': bytes(bytearray(A1_protected)).decode('utf-8'),
              'payload': bytes(bytearray(A1_payload)),
              'signature': bytes(bytearray(A1_signature))}

# RFC 7515 - A.2
A2_protected = \
    [123, 34, 97, 108, 103, 34, 58, 34, 82, 83, 50, 53, 54, 34, 125]
A2_payload = A1_payload
A2_key = \
    {"kty": "RSA",
     "n": "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx"
          "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs"
          "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH"
          "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV"
          "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8"
          "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
     "e": "AQAB",
     "d": "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I"
          "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0"
          "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn"
          "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT"
          "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh"
          "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
     "p": "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi"
          "YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG"
          "BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
     "q": "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa"
          "ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA"
          "-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
     "dp": "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q"
           "CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb"
           "34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
     "dq": "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa"
           "7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky"
           "NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
     "qi": "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o"
           "y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU"
           "W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"}
A2_signature = \
    [112, 46, 33, 137, 67, 232, 143, 209, 30, 181, 216, 45, 191, 120, 69,
     243, 65, 6, 174, 27, 129, 255, 247, 115, 17, 22, 173, 209, 113, 125,
     131, 101, 109, 66, 10, 253, 60, 150, 238, 221, 115, 162, 102, 62, 81,
     102, 104, 123, 0, 11, 135, 34, 110, 1, 135, 237, 16, 115, 249, 69,
     229, 130, 173, 252, 239, 22, 216, 90, 121, 142, 232, 198, 109, 219,
     61, 184, 151, 91, 23, 208, 148, 2, 190, 237, 213, 217, 217, 112, 7,
     16, 141, 178, 129, 96, 213, 248, 4, 12, 167, 68, 87, 98, 184, 31,
     190, 127, 249, 217, 46, 10, 231, 111, 36, 242, 91, 51, 187, 230, 244,
     74, 230, 30, 177, 4, 10, 203, 32, 4, 77, 62, 249, 18, 142, 212, 1,
     48, 121, 91, 212, 189, 59, 65, 238, 202, 208, 102, 171, 101, 25, 129,
     253, 228, 141, 247, 127, 55, 45, 195, 139, 159, 175, 221, 59, 239,
     177, 139, 93, 163, 204, 60, 46, 176, 47, 158, 58, 65, 214, 18, 202,
     173, 21, 145, 18, 115, 160, 95, 35, 185, 232, 56, 250, 175, 132, 157,
     105, 132, 41, 239, 90, 30, 136, 121, 130, 54, 195, 212, 14, 96, 69,
     34, 165, 68, 200, 242, 122, 122, 45, 184, 6, 99, 209, 108, 247, 202,
     234, 86, 222, 64, 92, 178, 33, 90, 69, 178, 194, 85, 102, 181, 90,
     193, 167, 72, 160, 112, 223, 200, 163, 42, 70, 149, 67, 208, 25, 238,
     251, 71]
A2_example = {'key': A2_key,
              'alg': 'RS256',
              'protected': bytes(bytearray(A2_protected)).decode('utf-8'),
              'payload': bytes(bytearray(A2_payload)),
              'signature': bytes(bytearray(A2_signature))}

# RFC 7515 - A.3
A3_protected = \
    [123, 34, 97, 108, 103, 34, 58, 34, 69, 83, 50, 53, 54, 34, 125]
A3_payload = A2_payload
A3_key = \
    {"kty": "EC",
     "crv": "P-256",
     "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
     "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
     "d": "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}
A3_signature = \
    [14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88,
     7, 212, 2, 163, 178, 40, 3, 58, 249, 124, 126, 23, 129,
     154, 195, 22, 158, 166, 101] + \
    [197, 10, 7, 211, 140, 60, 112, 229, 216, 241, 45, 175,
     8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154,
     143, 63, 127, 138, 131, 163, 84, 213]
A3_example = {'key': A3_key,
              'alg': 'ES256',
              'protected': bytes(bytearray(A3_protected)).decode('utf-8'),
              'payload': bytes(bytearray(A3_payload)),
              'signature': bytes(bytearray(A3_signature))}


# RFC 7515 - A.4
A4_protected = \
    [123, 34, 97, 108, 103, 34, 58, 34, 69, 83, 53, 49, 50, 34, 125]
A4_payload = [80, 97, 121, 108, 111, 97, 100]
A4_key = \
    {"kty": "EC",
     "crv": "P-521",
     "x": "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_"
          "NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
     "y": "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDl"
          "y79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",
     "d": "AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPA"
          "xerEzgdRhajnu0ferB0d53vM9mE15j2C"}
A4_signature = \
    [1, 220, 12, 129, 231, 171, 194, 209, 232, 135, 233, 117, 247, 105,
     122, 210, 26, 125, 192, 1, 217, 21, 82, 91, 45, 240, 255, 83, 19,
     34, 239, 71, 48, 157, 147, 152, 105, 18, 53, 108, 163, 214, 68,
     231, 62, 153, 150, 106, 194, 164, 246, 72, 143, 138, 24, 50, 129,
     223, 133, 206, 209, 172, 63, 237, 119, 109] + \
    [0, 111, 6, 105, 44, 5, 41, 208, 128, 61, 152, 40, 92, 61, 152, 4,
     150, 66, 60, 69, 247, 196, 170, 81, 193, 199, 78, 59, 194, 169,
     16, 124, 9, 143, 42, 142, 131, 48, 206, 238, 34, 175, 83, 203,
     220, 159, 3, 107, 155, 22, 27, 73, 111, 68, 68, 21, 238, 144, 229,
     232, 148, 188, 222, 59, 242, 103]
A4_example = {'key': A4_key,
              'alg': 'ES512',
              'protected': bytes(bytearray(A4_protected)).decode('utf-8'),
              'payload': bytes(bytearray(A4_payload)),
              'signature': bytes(bytearray(A4_signature))}


# RFC 7515 - A.4
A5_protected = 'eyJhbGciOiJub25lIn0'
A5_payload = A2_payload
A5_key = \
    {"kty": "oct", "k": ""}
A5_signature = b''
A5_example = {'key': A5_key,
              'alg': 'none',
              'protected': base64url_decode(A5_protected).decode('utf-8'),
              'payload': bytes(bytearray(A5_payload)),
              'signature': A5_signature}

A6_serialized = \
    '{' + \
    '"payload":' + \
    '"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF' + \
    'tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",' + \
    '"signatures":[' + \
    '{"protected":"eyJhbGciOiJSUzI1NiJ9",' + \
    '"header":' + \
    '{"kid":"2010-12-29"},' + \
    '"signature":' + \
    '"cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZ' + \
    'mh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjb' + \
    'KBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHl' + \
    'b1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZES' + \
    'c6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AX' + \
    'LIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"},' + \
    '{"protected":"eyJhbGciOiJFUzI1NiJ9",' + \
    '"header":' + \
    '{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},' + \
    '"signature":' + \
    '"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS' + \
    'lSApmWQxfKTUJqPP3-Kg6NU1Q"}]' + \
    '}'
A6_example = {
    'payload': bytes(bytearray(A2_payload)),
    'key1': jwk.JWK(**A2_key),
    'protected1': bytes(bytearray(A2_protected)).decode('utf-8'),
    'header1': json_encode({"kid": "2010-12-29"}),
    'key2': jwk.JWK(**A3_key),
    'protected2': bytes(bytearray(A3_protected)).decode('utf-8'),
    'header2': json_encode({"kid": "e9bc097a-ce51-4036-9562-d2ade882db0d"}),
    'serialized': A6_serialized}

A7_example = \
    '{' + \
    '"payload":' + \
    '"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF' + \
    'tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",' + \
    '"protected":"eyJhbGciOiJFUzI1NiJ9",' + \
    '"header":' + \
    '{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},' + \
    '"signature":' + \
    '"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS' + \
    'lSApmWQxfKTUJqPP3-Kg6NU1Q"' + \
    '}'

E_negative = \
    'eyJhbGciOiJub25lIiwNCiAiY3JpdCI6WyJodHRwOi8vZXhhbXBsZS5jb20vVU5ERU' + \
    'ZJTkVEIl0sDQogImh0dHA6Ly9leGFtcGxlLmNvbS9VTkRFRklORUQiOnRydWUNCn0.' + \
    'RkFJTA.'


class TestJWS(unittest.TestCase):
    def check_sign(self, test):
        s = jws.JWSCore(test['alg'],
                        jwk.JWK(**test['key']),
                        test['protected'],
                        test['payload'],
                        test.get('allowed_algs', None))
        sig = s.sign()
        decsig = base64url_decode(sig['signature'])
        s.verify(decsig)
        # ECDSA signatures are always different every time
        # they are generated unlike RSA or symmetric ones
        if test['key']['kty'] != 'EC':
            self.assertEqual(decsig, test['signature'])
        else:
            # Check we can verify the test signature independently
            # this is so taht we can test the ECDSA agaist a known
            # good signature
            s.verify(test['signature'])

    def test_A1(self):
        self.check_sign(A1_example)

    def test_A2(self):
        self.check_sign(A2_example)

    def test_A3(self):
        self.check_sign(A3_example)

    def test_A4(self):
        self.check_sign(A4_example)

    def test_A5(self):
        self.assertRaises(jws.InvalidJWSOperation,
                          self.check_sign, A5_example)
        a5_bis = {'allowed_algs': ['none']}
        a5_bis.update(A5_example)
        self.check_sign(a5_bis)

    def test_A6(self):
        s = jws.JWS(A6_example['payload'])
        s.add_signature(A6_example['key1'], None,
                        A6_example['protected1'],
                        A6_example['header1'])
        s.add_signature(A6_example['key2'], None,
                        A6_example['protected2'],
                        A6_example['header2'])
        s.verify(A6_example['key1'])
        s.verify(A6_example['key2'])
        sig = s.serialize()
        s.deserialize(sig, A6_example['key1'])
        s.deserialize(A6_serialized, A6_example['key2'])

    def test_A7(self):
        s = jws.JWS(A6_example['payload'])
        s.deserialize(A7_example, A6_example['key2'])

    def test_E(self):
        s = jws.JWS(A6_example['payload'])
        with self.assertRaises(jws.InvalidJWSSignature):
            jws.InvalidJWSSignature(s.deserialize, E_negative)
            s.verify(None)


E_A1_plaintext = \
    [84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110, 32,
     111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99,
     101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110, 111, 119, 108,
     101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109, 97, 103, 105,
     110, 97, 116, 105, 111, 110, 46]
E_A1_protected = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ"
E_A1_key = \
    {"kty": "RSA",
     "n": "oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW"
          "cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S"
          "psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a"
          "sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS"
          "tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj"
          "YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
     "e": "AQAB",
     "d": "kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N"
          "WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9"
          "3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk"
          "qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl"
          "t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd"
          "VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
     "p": "1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-"
          "SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf"
          "fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",
     "q": "wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm"
          "UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX"
          "IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",
     "dp": "ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL"
           "hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827"
           "rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",
     "dq": "Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj"
           "ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB"
           "UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",
     "qi": "VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7"
           "AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3"
           "eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY"}
E_A1_vector = \
    "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ." \
    "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe" \
    "ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb" \
    "Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV" \
    "mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8" \
    "1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi" \
    "6UklfCpIMfIjf7iGdXKHzg." \
    "48V1_ALb6US04U3b." \
    "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji" \
    "SdiwkIr3ajwQzaBtQD_A." \
    "XFBoMYUZodetZdvTiFvSkQ"

E_A1_ex = {'key': jwk.JWK(**E_A1_key),
           'protected': base64url_decode(E_A1_protected),
           'plaintext': bytes(bytearray(E_A1_plaintext)),
           'vector': E_A1_vector}

E_A2_plaintext = "Live long and prosper."
E_A2_protected = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
E_A2_key = \
    {"kty": "RSA",
     "n": "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl"
          "UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre"
          "cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_"
          "7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI"
          "Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU"
          "7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
     "e": "AQAB",
     "d": "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq"
          "1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry"
          "nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_"
          "0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj"
          "-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj"
          "T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
     "p": "9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68"
          "ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP"
          "krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
     "q": "uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y"
          "BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN"
          "-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
     "dp": "w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv"
           "ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra"
           "Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
     "dq": "o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff"
           "7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_"
           "odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
     "qi": "eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC"
           "tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ"
           "B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo"}
E_A2_vector = \
    "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." \
    "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm" \
    "1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc" \
    "HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF" \
    "NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8" \
    "rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv" \
    "-B3oWh2TbqmScqXMR4gp_A." \
    "AxY8DCtDaGlsbGljb3RoZQ." \
    "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." \
    "9hH0vgRfYgPnAHOd8stkvw"

E_A2_ex = {'key': jwk.JWK(**E_A2_key),
           'protected': base64url_decode(E_A2_protected),
           'plaintext': E_A2_plaintext,
           'vector': E_A2_vector}

E_A3_plaintext = "Live long and prosper."
E_A3_protected = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
E_A3_key = {"kty": "oct", "k": "GawgguFyGrWKav7AX4VKUg"}
E_A3_vector = \
    "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." \
    "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." \
    "AxY8DCtDaGlsbGljb3RoZQ." \
    "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." \
    "U0m_YmjN04DJvceFICbCVQ"

E_A3_ex = {'key': jwk.JWK(**E_A3_key),
           'protected': base64url_decode(E_A3_protected).decode('utf-8'),
           'plaintext': E_A3_plaintext,
           'vector': E_A3_vector}

E_A4_protected = "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
E_A4_unprotected = {"jku": "https://server.example.com/keys.jwks"}
E_A4_vector = \
    '{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",' \
    '"unprotected":{"jku":"https://server.example.com/keys.jwks"},' \
    '"recipients":[' \
    '{"header":{"alg":"RSA1_5","kid":"2011-04-29"},' \
    '"encrypted_key":'\
    '"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-' \
    'kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKx' \
    'GHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3' \
    'YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPh' \
    'cCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPg' \
    'wCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"},' \
    '{"header":{"alg":"A128KW","kid":"7"},' \
    '"encrypted_key":' \
    '"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],' \
    '"iv":"AxY8DCtDaGlsbGljb3RoZQ",' \
    '"ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",' \
    '"tag":"Mz-VPPyU4RlcuYv1IwIvzw"}'

E_A4_ex = {'key1': jwk.JWK(**E_A2_key),
           'header1': '{"alg":"RSA1_5","kid":"2011-04-29"}',
           'key2': jwk.JWK(**E_A3_key),
           'header2': '{"alg":"A128KW","kid":"7"}',
           'protected': base64url_decode(E_A4_protected),
           'unprotected': json_encode(E_A4_unprotected),
           'plaintext': E_A3_plaintext,
           'vector': E_A4_vector}

E_A5_ex = \
    '{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",' \
    '"unprotected":{"jku":"https://server.example.com/keys.jwks"},' \
    '"header":{"alg":"A128KW","kid":"7"},' \
    '"encrypted_key":' \
    '"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",' \
    '"iv":"AxY8DCtDaGlsbGljb3RoZQ",' \
    '"ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",' \
    '"tag":"Mz-VPPyU4RlcuYv1IwIvzw"}'


class TestJWE(unittest.TestCase):
    def check_enc(self, plaintext, protected, key, vector):
        e = jwe.JWE(plaintext, protected)
        e.add_recipient(key)
        # Encrypt and serialize using compact
        enc = e.serialize()
        # And test that we can decrypt our own
        e.deserialize(enc, key)
        # Now test the Spec Test Vector
        e.deserialize(vector, key)

    def test_A1(self):
        self.check_enc(E_A1_ex['plaintext'], E_A1_ex['protected'],
                       E_A1_ex['key'], E_A1_ex['vector'])

    def test_A2(self):
        self.check_enc(E_A2_ex['plaintext'], E_A2_ex['protected'],
                       E_A2_ex['key'], E_A2_ex['vector'])

    def test_A3(self):
        self.check_enc(E_A3_ex['plaintext'], E_A3_ex['protected'],
                       E_A3_ex['key'], E_A3_ex['vector'])

    def test_A4(self):
        e = jwe.JWE(E_A4_ex['plaintext'], E_A4_ex['protected'])
        e.add_recipient(E_A4_ex['key1'], E_A4_ex['header1'])
        e.add_recipient(E_A4_ex['key2'], E_A4_ex['header2'])
        enc = e.serialize()
        e.deserialize(enc, E_A4_ex['key1'])
        e.deserialize(enc, E_A4_ex['key2'])
        # Now test the Spec Test Vector
        e.deserialize(E_A4_ex['vector'], E_A4_ex['key1'])
        e.deserialize(E_A4_ex['vector'], E_A4_ex['key2'])

    def test_A5(self):
        e = jwe.JWE()
        e.deserialize(E_A5_ex, E_A4_ex['key2'])
        with self.assertRaises(jwe.InvalidJWEData):
            e = jwe.JWE(algs=['A256KW'])
            e.deserialize(E_A5_ex, E_A4_ex['key2'])


# RFC 7519
A1_header = {
    "alg": "RSA1_5",
    "enc": "A128CBC-HS256"}

A1_claims = {
    "iss": "joe",
    "exp": 1300819380,
    "http://example.com/is_root": True}

A1_token = \
    "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." + \
    "QR1Owv2ug2WyPBnbQrRARTeEk9kDO2w8qDcjiHnSJflSdv1iNqhWXaKH4MqAkQtM" + \
    "oNfABIPJaZm0HaA415sv3aeuBWnD8J-Ui7Ah6cWafs3ZwwFKDFUUsWHSK-IPKxLG" + \
    "TkND09XyjORj_CHAgOPJ-Sd8ONQRnJvWn_hXV1BNMHzUjPyYwEsRhDhzjAD26ima" + \
    "sOTsgruobpYGoQcXUwFDn7moXPRfDE8-NoQX7N7ZYMmpUDkR-Cx9obNGwJQ3nM52" + \
    "YCitxoQVPzjbl7WBuB7AohdBoZOdZ24WlN1lVIeh8v1K4krB8xgKvRU8kgFrEn_a" + \
    "1rZgN5TiysnmzTROF869lQ." + \
    "AxY8DCtDaGlsbGljb3RoZQ." + \
    "MKOle7UQrG6nSxTLX6Mqwt0orbHvAKeWnDYvpIAeZ72deHxz3roJDXQyhxx0wKaM" + \
    "HDjUEOKIwrtkHthpqEanSBNYHZgmNOV7sln1Eu9g3J8." + \
    "fiK51VwhsxJ-siBMR-YFiA"

A2_token = \
    "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldU" + \
    "In0." + \
    "g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M" + \
    "qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE" + \
    "b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh" + \
    "DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D" + \
    "YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq" + \
    "JGTO_z3Wfo5zsqwkxruxwA." + \
    "UmVkbW9uZCBXQSA5ODA1Mg." + \
    "VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB" + \
    "BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT" + \
    "-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10" + \
    "l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY" + \
    "Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr" + \
    "ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2" + \
    "8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE" + \
    "l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U" + \
    "zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd" + \
    "_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ." + \
    "AVO9iT5AV4CzvDJCdhSFlQ"


class TestJWT(unittest.TestCase):

    def test_A1(self):
        key = jwk.JWK(**E_A2_key)
        # first encode/decode ourselves
        t = jwt.JWT(A1_header, A1_claims)
        t.make_encrypted_token(key)
        token = t.serialize()
        t.deserialize(token)
        # then try the test vector
        t = jwt.JWT(jwt=A1_token, key=key, check_claims=False)
        # then try the test vector with explicit expiration date
        t = jwt.JWT(jwt=A1_token, key=key, check_claims={'exp': 1300819380})
        # Finally check it raises for expired tokens
        self.assertRaises(jwt.JWTExpired, jwt.JWT, jwt=A1_token, key=key)

    def test_A2(self):
        sigkey = jwk.JWK(**A2_example['key'])
        touter = jwt.JWT(jwt=A2_token, key=E_A2_ex['key'])
        tinner = jwt.JWT(jwt=touter.claims, key=sigkey, check_claims=False)
        self.assertEqual(A1_claims, json_decode(tinner.claims))

        with self.assertRaises(jwe.InvalidJWEData):
            jwt.JWT(jwt=A2_token, key=E_A2_ex['key'],
                    algs=['RSA_1_5', 'AES256GCM'])

    def test_decrypt_keyset(self):
        key = jwk.JWK(kid='testkey', **E_A2_key)
        keyset = jwk.JWKSet()
        # decrypt without keyid
        t = jwt.JWT(A1_header, A1_claims)
        t.make_encrypted_token(key)
        token = t.serialize()
        self.assertRaises(jwt.JWTMissingKeyID, jwt.JWT, jwt=token,
                          key=keyset)
        # encrypt a new JWT
        header = copy.copy(A1_header)
        header['kid'] = 'testkey'
        t = jwt.JWT(header, A1_claims)
        t.make_encrypted_token(key)
        token = t.serialize()
        # try to decrypt without key
        self.assertRaises(jwt.JWTMissingKey, jwt.JWT, jwt=token, key=keyset)
        # now decrypt with key
        keyset.add(key)
        jwt.JWT(jwt=token, key=keyset, check_claims={'exp': 1300819380})


class ConformanceTests(unittest.TestCase):

    def test_unknown_key_params(self):
        key = jwk.JWK(kty='oct', k='secret', unknown='mystery')
        # pylint: disable=protected-access
        self.assertEqual('mystery', key._unknown['unknown'])

    def test_key_ops_values(self):
        self.assertRaises(jwk.InvalidJWKValue, jwk.JWK,
                          kty='RSA', n=1, key_ops=['sign'], use='enc')
        self.assertRaises(jwk.InvalidJWKValue, jwk.JWK,
                          kty='RSA', n=1, key_ops=['sign', 'sign'])

    def test_jwe_no_protected_header(self):
        enc = jwe.JWE(plaintext='plain')
        enc.add_recipient(jwk.JWK(kty='oct', k=base64url_encode(b'A' * 16)),
                          '{"alg":"A128KW","enc":"A128GCM"}')

    def test_jwe_no_alg_in_jose_headers(self):
        enc = jwe.JWE(plaintext='plain')
        self.assertRaises(jwe.InvalidJWEData, enc.add_recipient,
                          jwk.JWK(kty='oct', k=base64url_encode(b'A' * 16)),
                          '{"enc":"A128GCM"}')

    def test_jwe_no_enc_in_jose_headers(self):
        enc = jwe.JWE(plaintext='plain')
        self.assertRaises(jwe.InvalidJWEData, enc.add_recipient,
                          jwk.JWK(kty='oct', k=base64url_encode(b'A' * 16)),
                          '{"alg":"A128KW"}')

    def test_aes_128(self):
        enc = jwe.JWE(plaintext='plain')
        key128 = jwk.JWK(kty='oct', k=base64url_encode(b'A' * (128 // 8)))
        enc.add_recipient(key128, '{"alg":"A128KW","enc":"A128CBC-HS256"}')
        enc.add_recipient(key128, '{"alg":"A128KW","enc":"A128GCM"}')

    def test_aes_192(self):
        enc = jwe.JWE(plaintext='plain')
        key192 = jwk.JWK(kty='oct', k=base64url_encode(b'B' * (192 // 8)))
        enc.add_recipient(key192, '{"alg":"A192KW","enc":"A192CBC-HS384"}')
        enc.add_recipient(key192, '{"alg":"A192KW","enc":"A192GCM"}')

    def test_aes_256(self):
        enc = jwe.JWE(plaintext='plain')
        key256 = jwk.JWK(kty='oct', k=base64url_encode(b'C' * (256 // 8)))
        enc.add_recipient(key256, '{"alg":"A256KW","enc":"A256CBC-HS512"}')
        enc.add_recipient(key256, '{"alg":"A256KW","enc":"A256GCM"}')

    def test_jws_loopback(self):
        sign = jws.JWS(payload='message')
        sign.add_signature(jwk.JWK(kty='oct', k=base64url_encode(b'A' * 16)),
                           alg="HS512")
        o = sign.serialize()
        check = jws.JWS()
        check.deserialize(o, jwk.JWK(kty='oct', k=base64url_encode(b'A' * 16)),
                          alg="HS512")
        self.assertTrue(check.objects['valid'])
