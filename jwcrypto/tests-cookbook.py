# Copyright (C) 2015  JWCrypto Project Contributors - see LICENSE file

from jwcrypto.common import base64url_decode  # , base64url_encode
from jwcrypto import jwk
from jwcrypto import jws
# from jwcrypto import jwe
import json
import unittest

# Based on: draft-ietf-jose-cookbook-08

EC_Public_Key_3_1 = {
    "kty": "EC",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "sig",
    "crv": "P-521",
    "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9"
         "A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
    "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy"
         "SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"}

EC_Private_Key_3_2 = {
    "kty": "EC",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "sig",
    "crv": "P-521",
    "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9"
         "A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
    "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy"
         "SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
    "d": "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb"
         "KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"}

RSA_Public_Key_3_3 = {
    "kty": "RSA",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "sig",
    "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT"
         "-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV"
         "wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-"
         "oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde"
         "3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC"
         "LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g"
         "HdrNP5zw",
    "e": "AQAB"}

RSA_Private_Key_3_4 = {
    "kty": "RSA",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "sig",
    "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT"
         "-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV"
         "wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-"
         "oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde"
         "3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC"
         "LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g"
         "HdrNP5zw",
    "e": "AQAB",
    "d": "bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e"
         "iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld"
         "Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b"
         "MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU"
         "6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj"
         "d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc"
         "OpBrQzwQ",
    "p": "3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR"
         "aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG"
         "peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8"
         "bUq0k",
    "q": "uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT"
         "8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an"
         "V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0"
         "s7pFc",
    "dp": "B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q"
          "1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn"
          "-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX"
          "59ehik",
    "dq": "CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pEr"
          "AMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJK"
          "bi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdK"
          "T1cYF8",
    "qi": "3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-N"
          "ZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDh"
          "jJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpP"
          "z8aaI4"}

Symmetric_Key_MAC_3_5 = {
    "kty": "oct",
    "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
    "use": "sig",
    "alg": "HS256",
    "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"}

Symmetric_Key_Enc_3_6 = {
    "kty": "oct",
    "kid": "1e571774-2e08-40da-8308-e8d68773842d",
    "use": "enc",
    "alg": "A256GCM",
    "k": "AAPapAv4LbFbiVawEjagUBluYqN5rhna-8nuldDvOx8"}

Payload_plaintext_b64_4 = \
    "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH" + \
    "lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk" + \
    "b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm" + \
    "UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4"

# 4.1
JWS_Protected_Header_4_1_2 = \
    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX" + \
    "hhbXBsZSJ9"

JWS_Signature_4_1_2 = \
    "MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmK" + \
    "ZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4J" + \
    "IwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8w" + \
    "W1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluP" + \
    "xUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_f" + \
    "cIe8u9ipH84ogoree7vjbU5y18kDquDg"

JWS_compact_4_1_3 = \
    "%s.%s.%s" % (JWS_Protected_Header_4_1_2,
                  Payload_plaintext_b64_4,
                  JWS_Signature_4_1_2)

JWS_general_4_1_3 = {
    "payload": Payload_plaintext_b64_4,
    "signatures": [{
        "protected": JWS_Protected_Header_4_1_2,
        "signature": JWS_Signature_4_1_2}]}

JWS_flattened_4_1_3 = {
    "payload": Payload_plaintext_b64_4,
    "protected": JWS_Protected_Header_4_1_2,
    "signature": JWS_Signature_4_1_2}

# 4.2
JWS_Protected_Header_4_2_2 = \
    "eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX" + \
    "hhbXBsZSJ9"

JWS_Signature_4_2_2 = \
    "cu22eBqkYDKgIlTpzDXGvaFfz6WGoz7fUDcfT0kkOy42miAh2qyBzk1xEsnk2I" + \
    "pN6-tPid6VrklHkqsGqDqHCdP6O8TTB5dDDItllVo6_1OLPpcbUrhiUSMxbbXU" + \
    "vdvWXzg-UD8biiReQFlfz28zGWVsdiNAUf8ZnyPEgVFn442ZdNqiVJRmBqrYRX" + \
    "e8P_ijQ7p8Vdz0TTrxUeT3lm8d9shnr2lfJT8ImUjvAA2Xez2Mlp8cBE5awDzT" + \
    "0qI0n6uiP1aCN_2_jLAeQTlqRHtfa64QQSUmFAAjVKPbByi7xho0uTOcbH510a" + \
    "6GYmJUAfmWjwZ6oD4ifKo8DYM-X72Eaw"

JWS_compact_4_2_3 = \
    "%s.%s.%s" % (JWS_Protected_Header_4_2_2,
                  Payload_plaintext_b64_4,
                  JWS_Signature_4_2_2)

JWS_general_4_2_3 = {
    "payload": Payload_plaintext_b64_4,
    "signatures": [{
        "protected": JWS_Protected_Header_4_2_2,
        "signature": JWS_Signature_4_2_2}]}

JWS_flattened_4_2_3 = {
    "payload": Payload_plaintext_b64_4,
    "protected": JWS_Protected_Header_4_2_2,
    "signature": JWS_Signature_4_2_2}

# 4.3
JWS_Protected_Header_4_3_2 = \
    "eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX" + \
    "hhbXBsZSJ9"

JWS_Signature_4_3_2 = \
    "AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvb" + \
    "u9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kv" + \
    "AD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2"

JWS_compact_4_3_3 = \
    "%s.%s.%s" % (JWS_Protected_Header_4_3_2,
                  Payload_plaintext_b64_4,
                  JWS_Signature_4_3_2)

JWS_general_4_3_3 = {
    "payload": Payload_plaintext_b64_4,
    "signatures": [{
        "protected": JWS_Protected_Header_4_3_2,
        "signature": JWS_Signature_4_3_2}]}

JWS_flattened_4_3_3 = {
    "payload": Payload_plaintext_b64_4,
    "protected": JWS_Protected_Header_4_3_2,
    "signature": JWS_Signature_4_3_2}

# 4.4
JWS_Protected_Header_4_4_2 = \
    "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LW" + \
    "VlZjMxNGJjNzAzNyJ9"

JWS_Signature_4_4_2 = "s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"

JWS_compact_4_4_3 = \
    "%s.%s.%s" % (JWS_Protected_Header_4_4_2,
                  Payload_plaintext_b64_4,
                  JWS_Signature_4_4_2)

JWS_general_4_4_3 = {
    "payload": Payload_plaintext_b64_4,
    "signatures": [{
        "protected": JWS_Protected_Header_4_4_2,
        "signature": JWS_Signature_4_4_2}]}

JWS_flattened_4_4_3 = {
    "payload": Payload_plaintext_b64_4,
    "protected": JWS_Protected_Header_4_4_2,
    "signature": JWS_Signature_4_4_2}

# 4.5 - TBD, see Issue #4

# 4.6
JWS_Protected_Header_4_6_2 = "eyJhbGciOiJIUzI1NiJ9"

JWS_Unprotected_Header_4_6_2 = {"kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037"}

JWS_Signature_4_6_2 = "bWUSVaxorn7bEF1djytBd0kHv70Ly5pvbomzMWSOr20"

JWS_general_4_6_3 = {
    "payload": Payload_plaintext_b64_4,
    "signatures": [{
        "protected": JWS_Protected_Header_4_6_2,
        "header": JWS_Unprotected_Header_4_6_2,
        "signature": JWS_Signature_4_6_2}]}

JWS_flattened_4_6_3 = {
    "payload": Payload_plaintext_b64_4,
    "protected": JWS_Protected_Header_4_6_2,
    "header": JWS_Unprotected_Header_4_6_2,
    "signature": JWS_Signature_4_6_2}

# 4.7
JWS_Unprotected_Header_4_7_2 = {"alg": "HS256",
                                "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037"}

JWS_Signature_4_7_2 = "xuLifqLGiblpv9zBpuZczWhNj1gARaLV3UxvxhJxZuk"

JWS_general_4_7_3 = {
    "payload": Payload_plaintext_b64_4,
    "signatures": [{
        "header": JWS_Unprotected_Header_4_7_2,
        "signature": JWS_Signature_4_7_2}]}

JWS_flattened_4_7_3 = {
    "payload": Payload_plaintext_b64_4,
    "header": JWS_Unprotected_Header_4_7_2,
    "signature": JWS_Signature_4_7_2}

# 4.8
JWS_Protected_Header_4_8_2 = "eyJhbGciOiJSUzI1NiJ9"

JWS_Unprotected_Header_4_8_2 = {"kid": "bilbo.baggins@hobbiton.example"}

JWS_Signature_4_8_2 = \
    "MIsjqtVlOpa71KE-Mss8_Nq2YH4FGhiocsqrgi5NvyG53uoimic1tcMdSg-qpt" + \
    "rzZc7CG6Svw2Y13TDIqHzTUrL_lR2ZFcryNFiHkSw129EghGpwkpxaTn_THJTC" + \
    "glNbADko1MZBCdwzJxwqZc-1RlpO2HibUYyXSwO97BSe0_evZKdjvvKSgsIqjy" + \
    "tKSeAMbhMBdMma622_BG5t4sdbuCHtFjp9iJmkio47AIwqkZV1aIZsv33uPUqB" + \
    "BCXbYoQJwt7mxPftHmNlGoOSMxR_3thmXTCm4US-xiNOyhbm8afKK64jU6_TPt" + \
    "QHiJeQJxz9G3Tx-083B745_AfYOnlC9w"

JWS_Unprotected_Header_4_8_3 = {"alg": "ES512",
                                "kid": "bilbo.baggins@hobbiton.example"}

JWS_Signature_4_8_3 = \
    "ARcVLnaJJaUWG8fG-8t5BREVAuTY8n8YHjwDO1muhcdCoFZFFjfISu0Cdkn9Yb" + \
    "dlmi54ho0x924DUz8sK7ZXkhc7AFM8ObLfTvNCrqcI3Jkl2U5IX3utNhODH6v7" + \
    "xgy1Qahsn0fyb4zSAkje8bAWz4vIfj5pCMYxxm4fgV3q7ZYhm5eD"

JWS_Protected_Header_4_8_4 = \
    "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LW" + \
    "VlZjMxNGJjNzAzNyJ9"

JWS_Signature_4_8_4 = "s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"

JWS_general_4_8_5 = {
    "payload": Payload_plaintext_b64_4,
    "signatures": [
        {"protected": JWS_Protected_Header_4_8_2,
         "header": JWS_Unprotected_Header_4_8_2,
         "signature": JWS_Signature_4_8_2},
        {"header": JWS_Unprotected_Header_4_8_3,
         "signature": JWS_Signature_4_8_3},
        {"protected": JWS_Protected_Header_4_8_4,
         "signature": JWS_Signature_4_8_4}]}


class Cookbook08JWSTests(unittest.TestCase):

    def test_4_1_signing(self):
        plaintext = base64url_decode(Payload_plaintext_b64_4)
        protected = base64url_decode(JWS_Protected_Header_4_1_2)
        pub_key = jwk.JWK(**RSA_Public_Key_3_3)  # pylint: disable=star-args
        pri_key = jwk.JWK(**RSA_Private_Key_3_4)  # pylint: disable=star-args
        S = jws.JWS(payload=plaintext)
        S.add_signature(pri_key, None, protected)
        self.assertEqual(JWS_compact_4_1_3, S.serialize(compact=True))
        S.deserialize(json.dumps(JWS_general_4_1_3), pub_key)
        S.deserialize(json.dumps(JWS_flattened_4_1_3), pub_key)

    def test_4_2_signing(self):
        plaintext = base64url_decode(Payload_plaintext_b64_4)
        protected = base64url_decode(JWS_Protected_Header_4_2_2)
        pub_key = jwk.JWK(**RSA_Public_Key_3_3)  # pylint: disable=star-args
        pri_key = jwk.JWK(**RSA_Private_Key_3_4)  # pylint: disable=star-args
        S = jws.JWS(payload=plaintext)
        S.add_signature(pri_key, None, protected)
        # Can't compare signature with reference because RSASSA-PSS uses
        # random nonces every time a signature is generated.
        sig = S.serialize()
        S.deserialize(sig, pub_key)
        # Just deserialize each example form
        S.deserialize(JWS_compact_4_2_3, pub_key)
        S.deserialize(json.dumps(JWS_general_4_2_3), pub_key)
        S.deserialize(json.dumps(JWS_flattened_4_2_3), pub_key)

    def test_4_3_signing(self):
        plaintext = base64url_decode(Payload_plaintext_b64_4)
        protected = base64url_decode(JWS_Protected_Header_4_3_2)
        pub_key = jwk.JWK(**EC_Public_Key_3_1)  # pylint: disable=star-args
        pri_key = jwk.JWK(**EC_Private_Key_3_2)  # pylint: disable=star-args
        S = jws.JWS(payload=plaintext)
        S.add_signature(pri_key, None, protected)
        # Can't compare signature with reference because ECDSA uses
        # random nonces every time a signature is generated.
        sig = S.serialize()
        S.deserialize(sig, pub_key)
        # Just deserialize each example form
        S.deserialize(JWS_compact_4_3_3, pub_key)
        S.deserialize(json.dumps(JWS_general_4_3_3), pub_key)
        S.deserialize(json.dumps(JWS_flattened_4_3_3), pub_key)

    def test_4_4_signing(self):
        plaintext = base64url_decode(Payload_plaintext_b64_4)
        protected = base64url_decode(JWS_Protected_Header_4_4_2)
        key = jwk.JWK(**Symmetric_Key_MAC_3_5)  # pylint: disable=star-args
        S = jws.JWS(payload=plaintext)
        S.add_signature(key, None, protected)
        sig = S.serialize(compact=True)
        S.deserialize(sig, key)
        self.assertEqual(sig, JWS_compact_4_4_3)
        # Just deserialize each example form
        S.deserialize(JWS_compact_4_4_3, key)
        S.deserialize(json.dumps(JWS_general_4_4_3), key)
        S.deserialize(json.dumps(JWS_flattened_4_4_3), key)

    def test_4_6_signing(self):
        plaintext = base64url_decode(Payload_plaintext_b64_4)
        protected = base64url_decode(JWS_Protected_Header_4_6_2)
        header = json.dumps(JWS_Unprotected_Header_4_6_2)
        key = jwk.JWK(**Symmetric_Key_MAC_3_5)  # pylint: disable=star-args
        S = jws.JWS(payload=plaintext)
        S.add_signature(key, None, protected, header)
        sig = S.serialize()
        S.deserialize(sig, key)
        self.assertEqual(json.loads(sig), JWS_flattened_4_6_3)
        # Just deserialize each example form
        S.deserialize(json.dumps(JWS_general_4_6_3), key)
        S.deserialize(json.dumps(JWS_flattened_4_6_3), key)

    def test_4_7_signing(self):
        plaintext = base64url_decode(Payload_plaintext_b64_4)
        header = json.dumps(JWS_Unprotected_Header_4_7_2)
        key = jwk.JWK(**Symmetric_Key_MAC_3_5)  # pylint: disable=star-args
        S = jws.JWS(payload=plaintext)
        S.add_signature(key, None, None, header)
        sig = S.serialize()
        S.deserialize(sig, key)
        self.assertEqual(json.loads(sig), JWS_flattened_4_7_3)
        # Just deserialize each example form
        S.deserialize(json.dumps(JWS_general_4_7_3), key)
        S.deserialize(json.dumps(JWS_flattened_4_7_3), key)

    def test_4_8_signing(self):
        plaintext = base64url_decode(Payload_plaintext_b64_4)
        S = jws.JWS(payload=plaintext)
        # 4_8_2
        protected = base64url_decode(JWS_Protected_Header_4_8_2)
        header = json.dumps(JWS_Unprotected_Header_4_8_2)
        pri_key = jwk.JWK(**RSA_Private_Key_3_4)  # pylint: disable=star-args
        S.add_signature(pri_key, None, protected, header)
        # 4_8_3
        header = json.dumps(JWS_Unprotected_Header_4_8_3)
        pri_key = jwk.JWK(**EC_Private_Key_3_2)  # pylint: disable=star-args
        S.add_signature(pri_key, None, None, header)
        # 4_8_4
        protected = base64url_decode(JWS_Protected_Header_4_8_4)
        sym_key = jwk.JWK(**Symmetric_Key_MAC_3_5)  # pylint: disable=star-args
        S.add_signature(sym_key, None, protected)
        sig = S.serialize()
        # Can't compare signature with reference because ECDSA uses
        # random nonces every time a signature is generated.
        rsa_key = jwk.JWK(**RSA_Public_Key_3_3)  # pylint: disable=star-args
        ec_key = jwk.JWK(**EC_Public_Key_3_1)  # pylint: disable=star-args
        S.deserialize(sig, rsa_key)
        S.deserialize(sig, ec_key)
        S.deserialize(sig, sym_key)
        # Just deserialize each example form
        S.deserialize(json.dumps(JWS_general_4_8_5), rsa_key)
        S.deserialize(json.dumps(JWS_general_4_8_5), ec_key)
        S.deserialize(json.dumps(JWS_general_4_8_5), sym_key)
