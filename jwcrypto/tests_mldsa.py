# Copyright (C) 2015  JWCrypto Project Contributors - see LICENSE file

import unittest
from binascii import unhexlify

from jwcrypto import jwk
from jwcrypto import jws
from jwcrypto.common import base64url_decode, base64url_encode
from jwcrypto.common import json_decode, json_encode

# RFC 9964 Appendix A - JOSE Header and Signature Test Vectors
#
# Each entry corresponds to one of the three ML-DSA parameter sets
# (ML-DSA-44, ML-DSA-65, ML-DSA-87).
#
# All test vectors use the all-zeros seed (32 bytes of 0x00) as the
# private key seed for deterministic key generation.
#
# Fields per algorithm:
#   kid            - JWK Thumbprint (RFC 7638) of the public key,
#                    computed per RFC 9964 Section 6 (includes "alg"
#                    in the thumbprint input).
#   raw_public_key - Hex-encoded raw public key bytes.
#   jws            - A compact JWS signing the payload
#                    "It’s a dangerous business, Frodo, going out
#                    your door." with the corresponding private key.

RFC9964_VECTORS = {
    'ML-DSA-44': {
        'kid': 'T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o',
        'raw_public_key': (
            'ba71f9f64e11baeb58fa9c6fbb6e14e61f18643dab495b47539a9166ca019813'
            '1c44f826bbd56e34e55db5e5e2d733485e39ea260fc6000c5ea4ba80d3455cde'
            '53b46f34482aedfd5450fc2e1ba4f25d15f9c144242fb39bb52287189030c504'
            '98e1717b7c758b190a6748ea9aa3f7acaaf2c7cb526ed717c9f79aeb84214fa5'
            'cd8ded92a0c3fa1558810f12c7050a367708d196cd24e5af974904aed8e4ce88'
            '72e8696b0b7bca50e452cd7d30ea9a4adac0311d672c6bde8496240b07431463'
            '708895cd9bafc31632d7397649388fdafcbf7d305a3de9a495eca7433a8f83ba'
            '0f0b25c413c6e39c96eb7d691b34d37ce37f1eead1cf217e25ef34eecf3f7c60'
            'f84b8edfdde8405d4f832576c61ef98e0a2f28da187700953924f686b9461470'
            '5bcf53d33fedd4348edddbdf28b5065e1f20775043e85cf931f829179363a1a7'
            'e7404a838ec00086b0976386fe637c98244757e3f769ddd4467471bfad670f9a'
            '05f8246ee50a7b1eaf87fc4069c3ae2aa2033258117792f0bcd49e083fd1bc74'
            '96abff29cc94e4868b21214ed316525399a610fbdd4a80e7c80715f29578e2a8'
            '4bb40bdddbd9f47a11b6e7da118a1b658d359e8aef55eb46b5376b5b65597998'
            '4a922beebfc59bcd600d5309dccd72dbf0787db8ba757b537c1eafd5c0f50ea4'
            'bc9583549e2829a42c28cac248c96d78124c47159b18aedd754aba17b19d430f'
            'b78f633ea9d26f54a9bd50f8d8f6b73594f828976e7ea09c53bbb9f11a56c950'
            '7fb89b9a5ebc037a37267a95f85b8d64ca97192b10a66f417b3f61fe9ca57130'
            'a48fd925eae2ab5502d571c8a51903c1d398f4c1f76a7e11743976afdbc697f2'
            '3094a3cd761ff9685de32e09fb3c28add453490300bc7c89dc01780096071722'
            '945775f264e1b0623bcf4619c712c838761205d87691b75ef360196cbb9e9b92'
            'a0d4c4ed62326e5024d77510b8ee2c7426cc22eae209dc9f13bde6bf08f5e718'
            '1bd3b459450b451a51539a715c21d67dd330eb5970db00d9edbfb2822b036fa1'
            '3bafeb86d8dc78866e3f8d43e53d78cca5595a6faf886b5dc112f1cf4adcfa87'
            '5800d90b48883af97316fe1506873fc157e570eacbfd222868d14234101966af'
            'b6bf9940829253a953ada89fc756b6a849f70acb9838e69faa50bba75e3e89c2'
            'adb57e86d088ab9b04a28e670709172243ec5e0008a5ceaf3f8722f487302596'
            'ffd755ad1b82a49c34b3469515b46aa290cd86ee38ea7a9be3f103610335b531'
            'cca333ddfe32b14510f4b07ef95fc6684e8c454a92c10dbb5d59c7a7c63fb305'
            'fe881967d99e669eb632840582560bb403431d40f75a4954908482278292821f'
            '4ea91e42e78fa48caee3c836146dcfd738d117e92e9a15137d28e8e6a4b46226'
            '50cb413504cb3a335d44beec5746c1c294b1e8cb99cb608d928f8ce3563632c5'
            '21f23d13c61a8f61c01df8c96c7360db4f3c68aa5d2fdd342a62ff3459c11638'
            '9421ab43e8584c45882b50e6e4e96db6f0b8fde890d5dbfadcd88690b449e642'
            '40ddb2023747f308363e301aa77757169fc6150628d5920b5aa1ab1c8cbf44cb'
            '00e025d7879d72b479e3af5311c785725590da9c89b9fc3b8450769554eb44d2'
            '03eba2bbaef9cad2237011c2ea44eff00f299a48ffe28ca93ddf85f76608242e'
            'f8d6cc24610a1e2078fcac4f9385c314905ecaa82e553916d94d1a7c1ec652aa'
            '08897083daa2ebb1775fbc471ae27777d7904ea9f1b92bcac3d8a3158426087b'
            '645b1108f0d65fec93789c053743ca14fd63d05e98b652df2b9c2ff9ce05f194'
            '0703ffb273f80e0e2732eca9960d981b4cfd3b7bb8045b3c3830546b9dd8db0d'
        ),
        'jws': (
            'eyJhbGciOiJNTC1EU0EtNDQiLCJraWQiOiJUNHhsNzBTN01UNlplcTZyOVY5ZlBK'
            'R1ZuNzZ3Zm5YSjIxLWd5bzBHdTZvIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2lu'
            'ZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.knI1Q_9CIzLH5Xy94Kkc'
            '7WVKqZcAgtJ3mNf0GUj1uLA6YXAWFJfXkh-zQxUtEl3UIC7zPCiUwKTDR6ZsuUmF'
            'j8Ctb_6aH64hElN7weS_1m5okCy8GqHNL2lsfclCH3Y2f4QNP-DLVS1XsuboDA7D'
            'w3ir2IdYKIfWJyIU7ROHgd24nuun1zJbxcLJC2EKt2M8R0wZudcIE9nm5oPzYXq0'
            'z-hPsKoXp9leVYkqgMmO9Lo8SP_1YYIEth3B8v-GuP249KDTFRKPjISmK4aPCknj'
            'tjihHsQVv2XePXxKExatHl4qhsiiW-y-EJXa1Kfw4WYpLA7B4_5Ids--cIJmIx7f'
            '6xxAWKh5qoBWq1QIOaaFuzsAraRW3NOEuzThew1En85gI3GcRTZGp-VDGyxHm0Al'
            '04cyWo2bxAVOF0fbDc265iP2mCNw6Qg10jIJeAhGB4OAMYcBUWJAG0l1MN1U_koE'
            'mGh5dXKnQTRl461ea_Cq3DLkcA2Dj2woWUFyDTmQ8oO_yheASfJacyRm7_suj88z'
            '5XFNo8F53P8OxTG9xUPlrwvH-TAq7AH3NU4SNXApyVKTU3zhx1tJ34nlTILcTujX'
            'VJVo_f0DZfUxr6JSCYqvy4z1Kl0wDQzd55aopyFtQxvOPhcCHbAN34g2Ug750Jm8'
            '35fl7NOxcqoMbuTcgH68kr37M-Pdh2K9WazXUJgCupgdIWW8WjfOjmTiF59CrVtf'
            'VtK2qDzF40OENCfqtNPQlZe5cN5p0P8arj4USB8HCPh7NdqQBAeWrw0wsYhdiM39'
            'lrSkA8mLRYMhZnqKGCTPCrHXDdEjRKYRNaqIUT44laYl5c27K0v-ozjKPu6tzEhk'
            'YSC4XZ3LehEFtmAzOE0mHbhKMgXqjoPJjOrGIPibX3jwK8_Q5RmMOXtXo8R3vXfB'
            'aUdQoLeeyywNYE0nIcsl4z5a8_utwEFiVf0VK2pdviyiOPVSi3zOMAmqz6gFhVy8'
            'aMMQOWZAEAuTyDw7ZWG6diwptmrgSXZotW63I19S2ZH7keCXRIq_pFLuYhOuG6dD'
            '4MkouILRdC9bXZMLrNDq7COpUOO86aQVlYd0pR935WpUw-V6obSRnHlRFZSmUSIB'
            '7h1Q0ImciRzojN93Xhw7qpzGzdzDEO3OOTayXaSG_0YHQyy-eH4hBbmgt_LBx120'
            'g1eY4XHeHFRfTfetHkL5ZZusX1jQ_nk9ez4XBG_6hRtTNSuVBsYlH8-KUuR5-qTP'
            '8dkvRf8Wk2hHoUr2sz5YO_xDFCMMTrt8ahiMyfjo5ih5Fwo3riFbFUGKibniTLXs'
            'pFd4spcNK_WchlZLRgkPK4jh6Z_X8JJkHxvQhpyouHQFyGxgBrl24x-_EB1zbWMh'
            'Jthmm8DiKt-nzKaJz8Cju1-HwCpg76CRqRsEz2hyKEpbb4M5KQSj3AsENCroVmQ5'
            'QIv3K2XNRkve4vjBmP6sV2b6GSY_UeRvPElA7SUgBGTKbn-c0aYhBuB8plPhRTBa'
            '55_cFqAmNmavF1-fdMktJuIaH2f-K0zZCzbHw54998T7kIWgyMsyGCAvynEB_khO'
            'qwT7tCjg5HQ8SIjdnRYW0kjZfjt5LJbGA-PnRo8gPVQVGeYDP2vsSXhNJY94AitK'
            'CY1srcSsuYDrhNBKrnoJ1uEsMPVHsgFw_ZHMyAEaVQughSNW4fm8q6_1Nv4zLutD'
            'ITzmAL6a6i6-WS6QRIs_4VUtwr5cXXIFDDeHVWeGcNivQ6W9urEUP4crguiq7z_D'
            'TiYaGfUksub-T7mw0zU8ZoOSd5pUTpJLv-IYIUAl6CscHvunnRLEKqpW1Sa1dcFZ'
            's5VP4AfR3mg7wX4Vlq1AHnpFxE2L1LZiKoTc9jDEOvTDkxr86gMkwMm6RdyPF_q4'
            '8AVJ1br8Qp88-4B84X52zZ5cw-IJYe-HiVJ29LpeYm340_rWivpy-UB5i9TKlMrx'
            'f94y1okzZTPbP3_v1_XX0nE7RTLz98EA96euJ7l3EpbEqks7mh6i1FJNnvvlM_u2'
            '9sYobJ6PUT-i1VlQnF_JBARKEz74pBXm1l5Y5Lo15rsIlaQHinUBCO8fHCHI59LA'
            'fKusN4JmodDqLYwkWijEL_sfrC6LtrbXqpM1pw09zSrs_tS1RQ-LnWHuPrU5KLCz'
            'v53JKrh8lU_cdBowe_F-Ib_Ui4bQ2FME-0mnyG0XijHUsrGMZ9dfowvIkr83Jpqw'
            'lFOZAwMmSGPNPEJRw9kDshjotndUB5S1UCfv_U4IoVn7WgvxeCS-BBxqyWfh7YTd'
            'f73EnmGwVYxVjlXaHCeeTZmUacnT4MQUAcbFjTq6BBlboAQGWP2FZWpd6HNnruv7'
            '44VeWmfgLk9z5567wFhwuXMkmE2xvDo4wP80xutjUfsePx5YkLxhY1XsWqTZr19t'
            'InxJWWq8RLZsWPmtq5wZ5ucBMasCLpOABenYZdSAcQNhC73wLS0Z2s1HQhBoIl7l'
            'r1p372LZs_Seu1u_8Fo7DoJqRpKaNoc2_JUMmn7TUZS8zLyzxgeq8R8iNbRP20Dw'
            'DBNXocsTDBKaQrtB-QiEPySQtJa4G61XeNZyh5aGzfoWZ9OmjZG9pbbehcqwIrt-'
            'ESjPyeT6sfSrvOfTZr7fBXwpUs2rS4BrlNse5g_h8CQiik8aaOTOEPkXiyg4s5De'
            'wRlgDZHS-3g-YXPUIBNO62_HxknkMpkJvKW-tkvDbgtxvy4nG80ul6W_KeRsoEKD'
            'TRYNKZWxXjZITNa0h6agnwNCJKEbFg3Qhre394c0i60mfP9YIgKTXrCX3Yt2eX-6'
            'mPzYmLbSbV5jH69v6WZqYV2WAj-9DU0diR4hOfYQaJnBZhTtKb-SQsYiFuN1BDJ3'
            'v9eM9K8hq91NBdCHVa-Thk9Dov-JkcTZnZGRRyW5yXHUV4NOEltBXh8GkjjDvs5Y'
            'o3u-2rPCXjK1aGPSI1W8BaUJLQY5sbfAVCAuUHBv-Vlh5Qamt-lgeKguhqTSuy-t'
            'jabOb5kiBOG7xGQt3z-XYXtnWFDCii-5h11XfZsQ-xQxy8gSfdMz4hDK9Nw_VQt6'
            'fzWiQY0Th_dHzVki0MUfVfsDUjgblhD6j0wgbs3zdj-GM3rtt8oit0wXx11bIOaO'
            'Kgf07tP0wimVXMRqRWe7LCUAKTE5PkRKU1x_h4iusrzi5uwKDhc4SmRwm6KssNrm'
            'CAkiNDZCREVKd3yMnrjA4PAGDzdKWVplcHJ6jKmrsbrEztHd9QAAAAAAAAAAAAAA'
            'ABIfMEQ'
        ),
    },
    'ML-DSA-65': {
        'kid': 'Suiu29qbfuaBaR4Ats-c6XQBePB_OpAxAwcTR_0KXVM',
        'raw_public_key': (
            '424b2f267e58d5b3b44d71acfc6a656bb26950d57c61db1c880bcfa1feab443f'
            '0942ab8bdbad7d708abbc356078f6d99a252271fe62c74091eb94afb9b9264c5'
            '0a888e0dfed80cd5fb2cbd3667e60d539ebe44930219cd4faed15dbb3455a264'
            '802b9f49bce42ee7550feffdd4642a55ade693868a460cbec03f4fc99a4e30bc'
            'cffa8a475e5395396674ebb81a94937587880f6dbd27bf1c4f5a9ee43cdd8b0e'
            '53b3b7fb49c73adfbc2d4f8c54303520c29bf97e26ee57db342d957c89393652'
            '2d0942b41d82ee3772a00570adfb545c1143922b0496f826a0a970064b36ddf5'
            '34b5f8e1c1cd0b5565ea846b45431f0618143ece89777bb3f61179ad20295fe0'
            'a6e062ae6eecbc2ef38f2ac1a22dc93b7b126336223c55b61eb8c0795542bbb2'
            'dc65e722eadc6866ffa9683beb8a999ad7a83e5e6e016c2e4c35f6f7649ad3bd'
            '52ec67ec1c5c6e7b9972771218be9554bba7727f0b84c44b9b0a8bd831fcff2c'
            '9779ccd4ca30c6ad75b04983e41de893ee5f39ea7355180b709c7045c22d33a0'
            '83f6ae07a114746d1bfdccbee5b9043879bb5a2e120e2a4636283f4a1cd4924a'
            '2de6a4aa3d99ddd88f48aaa4e88bfd1ea769d82c10779f2ded796db542971ca2'
            '89b76863ede5997b7e9ce183b43ccec278b10d92b87442ce0435bb1625171db5'
            '554b470239c50d2a0c3a41b2a38807db070b47bfb3e7d10f3cd979d69963c8d7'
            '9f8029cc4a48eb04fcb3d708844febaa8b6ddff01ab64d59358e6505c4ec1d7c'
            'bb14ed2212df458ecefc03fe03037b1505a4c9444322f5f98dfa91a4cb8c4586'
            '0a2dadc7515350bb6d431e49a6bc8f5ba956e682b0e513321a97d1962602891c'
            '9078f62a8a9646a31387a6f09684264837899e0d8ec7d11c565901298b20b345'
            '081690eb4c562c1aa3a25bef06566cb34c79bc0b25e4095d6ba793e81311e41a'
            '3329152686f00d4897f84fc4edf4b26d545365785ead8d63aef64a87c0b91a2e'
            '5500383956cdf5f6e37cf9d5482d1c8e3a5be38f17259ac45c9fa1c4bd3bf177'
            'd312ee52a6da023c05722a8738274dda8d1b04e99831cf57c87282a256c565c2'
            '96d0524a063a3a41a48a83009978d98d8abf61af68e8013b594fe151d9bec199'
            '902c4c70b49584201743c6b53103d2fd24bdf078dc90b5a188b4f8d772179988'
            'd0416c94d4c57c0860b9d7b53d4cd261f332a1851565d52ac37f008747cafe32'
            '0f363d9beb6e4117db43fd8aeebe5e0ce2f54e3f0367eb3cc971bbe0c301a8e5'
            '2f96094936035c6ee3ca2d13db483a0dd04dc16247de0e0894ad7cb7e1ae7ebd'
            '4f8f900582b20021e77f70254501c6ac3dd15d43bbb7931c5283244312158c2e'
            'b1b3e1117e194f0a1e4c783efbc62c9f81c21562d0d34a5f042b5eaaf32f31f9'
            '5c5b055f4e7a2070fb096f56c415549cde74f3864e8b9fc27e3299724b463998'
            '6044b55928fd6972785b280c25a3e21aab814ecbfb0c3cbec0914907ec907f25'
            'a1d88bce3d319ae8222a35945db62af7cc75cd29c1f5d98fcb93f750dc303107'
            '6979bb51dfc37d23e8eea78073a24d3e26c68e7bb10e459f2577b90080359ae0'
            'aec10318dcd9e0f9e34029c31b3e54b1855645db420618783346dad5b55eddb4'
            'f977b326a655525ebe2195eca9cec38a3c0d2273b77d3e68f1901c2ca5149734'
            'a51177bcb089476b18cba09fa8b9b46d94a2946f358e1decb1998652c58a9085'
            '2423e2c85e79d19724461627e6390d1a81fb1a72f9c7edc4bd747dd5c85217b5'
            '856141028414ddbe71458f0a0b2b589df2e1b051783b8f718676b1defbae98ba'
            '496c2a935e92eeadea0a8393ef59f9e914f0743fe65640ddf9981cea6dbdd957'
            'a534ad4e790efc974ee89938ad99d53c5b680775399326834729bb37b082e795'
            'f8d87f52e6c8a8db68e515c277bbea82a7570d4280896c987a0608903e306c63'
            '2a223c55f0ea3682039c4a3f5440f4b5ac3e6ed2b2dc900cecc72b72f50e49b2'
            '629ad30f0487b2707b86286f8c4f55659b25f9bdd7a6af460cc3c57a3982663b'
            'b717461581e196894929d84153d87a7f482d284b5b894ce1a78216b2a011f2b8'
            '8742cee52d5133e8fe77edae242f5af91637c37ffca32430509b2fe4756303a9'
            'a3659fe32528af1e10d8d43bea991b2d109786cc66d35b1d78df254b92cdaa40'
            'f91a987e4a922ca81050e5bc3530ca85493bdf2a825374d0a8310a6860284ec3'
            'ec732326eeeffc42bbd42bc91b73e5e7c6b599d016490637629f3876c3e42f8d'
            'b590e66a85a7838c818f78fffb4853cbef09434989803545dca87657cf7c7e7e'
            '6afa71382bc10fa0bb6480f243eea1b861101006fa0cff3275621943cc58eb4d'
            'c3a0428a5e425670fe82268de71c511d8ffbdc11b0d0f961120e971015ad5f44'
            '8886b802e3fac11672319d487c84f1001339cb969784cb57344f2807f8b425f1'
            'd73caf8496d742ed237f4c9fcd5a4e84fba7e27fb1a8ae12c4f0427ae24e910d'
            '951bd8c35d61f8a678db01caea8ef789a95b62ee1b8c5d32c6baa536ba88a107'
            '0ea61aabbf59294e3f6f974c4c91cafc5bbf6b7ecfd57a18fb7557d71e06e900'
            'd281b0b49aa00feabb35714af33870edd7ac2393d93177f79ee5606c9df176f0'
            '25ce49a6e5ff51a2a412ebf86ac0f40471c96ad4c119df230be6173df530ed65'
            '6cbd8069214741ecdd0271c603fb6c4a8614ff878d33e726cac6693e938ca3fb'
            'a82c4995c14a2d4af9014fe4c4c50b794cac596b52189f66a7106fb325b526ea'
        ),
        'jws': (
            'eyJhbGciOiJNTC1EU0EtNjUiLCJraWQiOiJTdWl1MjlxYmZ1YUJhUjRBdHMtYzZY'
            'UUJlUEJfT3BBeEF3Y1RSXzBLWFZNIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2lu'
            'ZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.zmO9_0bLgJAegoVNymfR'
            'o4nGPK5lVtSFGnDbzfzYAD5mUEXpaBUg4itvZ8rAUZi4HLb59QqDQSBSpMXC0axa'
            'jXOMV_YttfmwGgC6FMyaMRZkx-A92bGiNLutqX9jcwRLJqXjMkUGhz2YpHe_mV9Q'
            'pxokRCH9K6jkyFZp4hZIwFXhRt1z0OGIa5rOoHKsxOCAUZhTXKiASb3vk9lUASW0'
            '-Y58WKT4rVmst7_dvk7FVbe9A9I21IH-Tqlg1zSMoI8ozh1aBSG92uPursBd5KRc'
            'OlJwhNUYJDgHScIHXM6Hzk6u98W5orKPHu1rDIK7rHJI4Zrui4wBjmQLsPE01LcZ'
            'HRx4zexDCTMCGSojbL1FiT9CU3oUep4oWOytTEAf2eCi3qDD0iSrp5IslCueoNjt'
            'GOFSnUKlsnCeiZF-tNqTy1KpJ3ErTaNPcCzCvsEalhJwFa7NOWyQOEJUzcLaPY_V'
            'EFwcCX1Gk4bEI-1rLDiyZqkXgny-U2oRnll0d3u-e2S_Rg-_eL1H_XEbPs_km-82'
            '2G7JY9li4muZ5KVvfQf_5hza1V4GweqvmeWuZL1gBU2HPS7x1tWL798ALOk1rMnx'
            'svBOPiSLxAEdPoIuw0_qMlKjTavJcDFaihgCgGMUk5SjU65IWQS9t4rgxv9Idu0O'
            'Csozo9iCBqrVcnaOwUpkMhV6KeiXA7kQNcegVaMio40cjSyMiEkhGIOEOf8L6eoh'
            'Oh_bPPRYs-8NrZ-VOBJCa0ubJcDU1cTuGNCa7nWWxAqfVjcMyNDx9XHBYBnSOcFN'
            'fMP7S9nvqw3KC50U_t2PH5SfwS9w4DLvcgrlEP_gwSgOXuf-i0tRGLQly3IMB7O8'
            'QOnkofyFaCUDZeurFkGTpoBfT6lzbJznQAMIDPNcWUsRlNTXsH7atC1nxl4xDJLm'
            'mPLCxiErfxbCW5gMWox0kLDwfsFj57hsXG75cZ4jiBbq9b0VjD7Vkf8xlc06Exdz'
            'BhGXz8oJiaT5WHDsuzGtrFmh6diN1cO4Cxjr6KdNE8IlyxsfXxQ4AI-0ke3gMyi0'
            'DOGeHgHuNc-JHD7oZ6njUMSTBkR1aUMNT7n_2nfFTDCdqW1HaMsMwIHfLOk6dayK'
            'XE1oMqY5Op8S5k_SAaknR0vNxmhlTA5h3bZJ28NZxM6R7D00_eBEYrH20rmRP7G7'
            'kXKzLvmWeaKAh4oQHiqjVhgauiePDRiMmjx0OhdQnMCtO8PWbx06SiviRn_5hswd'
            'VV08B48MVHqbM2AxCLLJYinC2Ep0302Uo0DI-rTNZ1Znn58kM7VCskcxDLsH9AYv'
            'Pz-HQr3H7Xg0ElwjYn-jJXgZ_cdnLFt4_TuKQdpw_qhvyrNjOx0Mdc-1PrwoWqpA'
            '9sSv_pS5lwI2qNVHI2Vj2mZHByod1QUeOQExf3SBjP_FHEAUzUu1OK8M-1SQZGzJ'
            'T2su3a6ZnMnp0U5qdXyMONFoI2jJ2hDjt7QEQsLx-rvaLxZMJtc2z0MHdwJGAC_k'
            'ug7XjH3SWQZzBu7zzreIaSwr2A2oobeZiAydwb8LX2QsY9Jr_NphGAMAqzrpkuaM'
            'yBd_pFTKMp9s0GYxwyG1ZD9uRuPI9imA4CS7bt-O8YvbWg6eQ-qa9OqDlxNt3Xc3'
            '2TniQFVxVxN6PDY33XXU-Rpvd1w47NZ48nkyJzjD8Xlbvk9p2ynxWHr-Sto5HXZd'
            'ru4j8ETUW7ri3mEG1m_dxAbAe2kVbsBp2I1vQppugbmRexuMRLdYFIKqNm0qpQoW'
            'Tr_k2t5KHnWolrSbFH7Usm8Pwyi4sNhh4_yRHADO2q2o19zCCx2plDSMeYI74CQP'
            'RGLlK_GLM4E5Bzfny3E2eaE5_gQBTSGNHpQtJB0ipPwDjqsjDCXqXupCkRta1vxn'
            'g4coi2-vWYvKu6mq9HhdovHAaWrZRyvuPPI4ZDN_NkmfQR8HogR6NLVhLlRp1cwM'
            'ArSSDA3f8QlnjdbaeutxRXvFnCCjBk79ws8VGdWAuRmIWgoEFeVAVxkJjJ07zOW8'
            'I3kNfB6pnxsZmJwWAGqWc1UlPmkNBstmSXinAzbdl-W-kn1XRDuhzTafHnkCbKS5'
            'XgJKsWD2FrhcnCaxxRxuxIGxijofjD4ihmJoYDFh1FYs9IcC-szEfMSekanWOIZC'
            'Hd1fVzTSbLr5bNaOXR2sO1muFX7w22m8pBVD3fyOHK2JnK4FBCnEBrruMIDaqqu8'
            'Z4xesAHKfxY67w-25eUuvVCGL3xpXSyp90684ICkG4STztP1shLVsxKDA-37sKKp'
            'lqemERlMPY4vDM1Np8JlVawbSGIuom20g6p2KV_zpIPwx9vd1nAiaeZbryf3N5gt'
            'L-dOq-c6uZhTCx9OLBtLGE3BcAmn5JFjMGQFxyTL07BluNu24Kf-lttGj9jzbwPZ'
            'Yrok-SnMilXGFEqB3D3cKCOlWjsgg_3cUW1uMp4KlWQvkimV9Pd7cY70w607jcYB'
            'J3MlFZ8EeWeYPZ9qu6xwidA8XlLHxXxfLIJOgfpU8MTppfxdnMhqNSvH_Hx57oDp'
            'hbUks5K1Z8-O4dSnNqQ-ZWbhaAydYQFDKuUF6HYTAvaWhJmACxhTkTp2t6-P3bev'
            '-FcdFIdszJC9LxWtJ96LY_GV4Qvp0hiIdyP1BukWNHtsXK2Rxres3_4Cndg2BOGx'
            'VcKZ9YpQDCUy76GRbTCenqjD-SG5sVUEVha5yxbKArPr2-Xpgk8cuZBRSAdmPNRd'
            'xCgUtldfCLeL7xhJvryMouxfQ75PMBaImHcsMd95075ePt_VkClUaUj55Y9E81Fb'
            'OEchPfud2w3TtSvRPvB8-RgY8sLJUAclxcUGE4PnKSZJ7TIBUtHD6uyZ0-nC5KGx'
            'bXZsBEzUeHns4ix0Wmo6-6vAM4PGK3qRA1VAhtKXyvNcAfVccVi8KJMK9Mz2eIOX'
            'PATvyRy34Ltrcg8tcgK0ftYqEWYpAZ2fVpZBXcYfTIinuLN0-qLra388EZuu59jv'
            'mRD7mUv1msMWVMGVeBoNP3lJaJGGWK8iYyu4q7Grq-6WXr5qCz_7kwAtVJdb-zW8'
            'U3jLJ3tRSYlyjlpzeVAGjDQ6Yni5y9x4BF-5QUqcoGMLLglyx2WOCELT8IW7nsV2'
            '1QnqqAbtCzZ76UtEdmUuEOTyqiKQZ0lrjMRm3YrCvJKxtR5thhTRka708NzBvwSR'
            's-JxGG__EWjHhT-aB4VL3IL_oz3mt3iQoszfA-SzHcKU1laZMBuUCyxks6KiJgQG'
            'ZRPXyaxxDtqZdaRP8Ic5CmuPeyu3kafi0L6LFijsUxnSGxTpgu7hfvcmowQijfE9'
            '_ylvg8k_EbI2miG11giODVCYb7k9Yjyriwc9dSUUZ7XoiS24hWYUX6BGGQNN3wVH'
            'PkDkOVSDBYTjto99ulquryx4K_UMCu9sQVNxBfMh8tLN7O9-MXlnJbHfKfqFHiPG'
            'dIYOBpwuqJdAJiyiuSG3gJxMG_wuwNkBWoO--iOm6PIarCyvL8_P-tuUfT4zIgjJ'
            'J3o6YJhbo-q2K82ZFmHuILyzfDSGtHDZpZIR7XnRQWet90cJEHL5k653kvyEHJg0'
            'iUiE0iwNA5d_4gBq3vmw1J74hwAHx0Z_iYEcPS6hDGow8M8D7UJTZDkUV_86zj2Y'
            'qGm_QC_aAeD__NP6sa61bI9-gTOzvYc0JiExKTDjOK9fIvHaV-HN4xr2vWner8o6'
            'jPyETvGM8D7aEezlUVOEFwALmhJPSMAq_Fk9JlcIUuC-ITJZNtNz9Awfiru3wkPj'
            'a1bXN76WAuRHjia0x5ptgMCy2py_vSHZybfIS85ZjsOQ-i_e_niBzhyzXwzBaLEy'
            'EitbF4ZQx5c88lXKDMpe9tirAI6XAcqLf4UZkD8Wm2YV7hhVfxLQ1AWLekWE9DZl'
            'jCtE-SbS1EWNGR8faXKCvaZznRyoqdWz8IN3w7KvaA_ZrEKkIXkkreztG6pI06Dl'
            'DHCl_sU6rCOoyQf6y1AY77Ob4SdkSRoBHGgR6Uv-LrxHpyJ6trzccu0kqxubHrkW'
            '2yHcqe6enVf43zYwWKUeJJZ10bt3a92ziSne-3aj6v3guiKoJoLnV_9h8rUF6zor'
            'TWE-Tq58tYfb5SmGf4iCJ5cy9LTY0COIfwJtPkUmyBCZwUhWJnV24P5pOZPe_Cck'
            'Q28xv5J7Zf4Bvqrq_rhubFEhTJ5JvdMfz8Whc56WSHX7GRKEMqXVp3pHohBvOyT9'
            'BmotzIlibVklJy4gzkzUcjJJOld-BOaM_cnMiHpoyKXSJAXTNwXngzEpbvDP2Y0f'
            'nrgqDpO3RR3gINaZLRmeG0WI4wWBMMfw8PHjpyV17C_1hmfRI-darbZcX7PD3N4R'
            'w4lBACyk_wnOHBcAS-5cLZEzNmFmhc4iO4msz_seQ1N0drbB0NoUVWBmcY3pGC9T'
            'iY6f6Pn-FBUnQkuBhIyPtgAAAAAAAAAABgwVHCUv'
        ),
    },
    'ML-DSA-87': {
        'kid': 'tRn1JNIkgMsABVQBlXeDHxAIcclh-2IX0UdDEzPt5XU',
        'raw_public_key': (
            'e45ffc8cc73db885dc662e62a18cd8e3803297117fa5658814a985b5ff1db7b4'
            '68cfc82bb929f1d86b77ed14f5ae16a65368772ce51912410105e0456975ae91'
            'fdb643b512f124d5e60bd68b8c7e31fe01c7b0dc65ae470501cc565a6e1dfcfc'
            'fd12565433c4afedd511821e2e9610c45275e2836dee35ced69d7efa672fd1e4'
            '318bef5eb6e897e8b451aa202ded042b2aaef77a7be3f699146da229a8bdb3ff'
            'a496445967e75217bfbc9048f9956443d8731f833eb30de10dac96fffe7cf65e'
            'a0445c3e31e8601e133be6a100764fe3196e267726441f31751fbf9a6f588064'
            '4f4e7275e57de2b0f105e4db055d50dd1c9c934fddf535b8de28b0c74c0449f2'
            '22cd2ed0bb8fbc775ccee8c940665b40f712f4f7e00750e9e1e4cd9cff25d194'
            '5c3e9bca53ccd4f12eee7581856ebd68f26845956e3e7beb761f0fe75bdd31bf'
            'e2fa018113397b387bd59d62a68b8af7fa245ab932e69f778e2ceefd21304fbb'
            '8099ea13d8ea57c1813197a2f75ae251075b51dad38f853669e9d5f98a365509'
            '8941993a1594860fba71fe530ee5c29f58f2978af688ccb75a5838a359c112e9'
            '8e25a8583ac8dac1f861fd58e2afba5de5a52e020904f5b42bc0874e35befcf3'
            'e6119684768f36e008f04712177cebe627607381e56eaaee161c1729b8de51db'
            'de474d48cc68249ea27162b87993e60c84ed6cc6423cb3676d9eb50b2cab5a3a'
            '049ef131381d623fa6fbcbc9db1e7cc025ea0418b9dad2cc6ccd4e95fa2cec24'
            'feeca70318a751716b7213f63edbf65a63338357f838f94ec071822c24851248'
            '885107b3d1c4e924678c7614ea1af038104619f2ae372940becfa69e29cbb5ff'
            '6c3e20a47be4a4f74bac34c133c00a6a706accc6ffd3d8e4fbd69a99704e1283'
            'c850d8c58d1e5753cd9587b83c4c346cb9a58137213ec10834c66adfe2bb5c50'
            '1a8ef2ecadd1b677a3df1a6deb86ebf0722c4f5030e20f9018dd5b6fc53eea24'
            'fd92b7b5b4025feae996d3e48fd4c650d82dbad7eaf936639698512f26253d2e'
            'f6847c8518e8565cc9a5495c6fff57cde7323882c54a7db470ab2daf8ffd2bf7'
            '94fa7c692d9e7fbd532eecc1d7880e2ca0b3216128be28b4a9f1d151fac97808'
            'b0bd98b7b43a612a9ac865812bfeac6f47460277840b52a3b087f916ca7cedc0'
            'f768ea2bd19ea21155f84b4a04c4000ad2ae0587154d560bc0a477a4f9329a89'
            '84dd31eb1f2a05e3d918701d630cfca9af61ef088d2c5581acb463e439902e5d'
            '425719e956b8d6df7305b28e0ff27d3ad0de2085d292499b19a3390d4396fb3b'
            'ac9a8d8cbead2a7a4290fc9ac6fca045f98a614a45a39cbe24360f84d14f8e47'
            '2712aceb74dbf45b53d49a0e4737e476ffc4d5b2f7cd247aa186d3b764ad9e9c'
            'feee456a73c291d8de3912414ac43911c372173ad7b472af35c6853ced2fe7b5'
            'fe0a89565ab33baa6f65cdd928319d7065e040e7a5e84f9aa903f7648094bad0'
            '7136b16927b8ec6dbc2bef0cc2856de1e795923e1412c49f24deeb6c21f6c8a9'
            '765c9c7986e0da4b4c67d8e0d0c8d466824fb923d8573148990cd2ef133c78ce'
            'ecab72ed9dd285c5a3766852d54534207ffd34027f6c76ede8fd1a32d72c3004'
            '8bbaa797d5df6fde27d087de5721ad7b7fa3e8d3f70d6bfc3ab2e252335368bb'
            'fa15acb5cb37d4694e8b23cebe25de9c925a221a183b904d3f85df9929a919c5'
            '4d6f87457373a0d6ecc1403e4cbbe620999435e80696634cd1a8e4747e9825bf'
            'a336e5bbad14f73640f1b9febe800dbaefe1630c61fae635b074c564eaa9db18'
            '9c9e7302873fc64e6d497bc5c29080987a07a21d4af210703a4fa07f2fd816f1'
            '2fd1e29b4c0f44afe9bd4a1eaa8a7ae6f02a5b4258f52caf6127f62632a67cf4'
            'e8310be56a7c28c86b2e277600c3e92c8d23d42586244c571e90568df202f2f6'
            'd81f860a565f9eb91a3c78372e2a8b1be61c5418cf49bf2d6c8955d4a482a991'
            '9b7660b3f9a4404ffc454ea073e1e4b2689ab2cca4e46bd7004a6c491fa26ee7'
            'a57d60f35edb2b821e6266442c8f335d452d524c772e0353724c23c7dd15b7aa'
            '155e91442022140c5fcb0153147edcf3e8952f6f0399a3c88066a72756c94099'
            '15de63f64fa797841c57c796c6fc550ef745dfe9f179457f94755ae5a2506a76'
            '4f327e550be3dc14dd41f3b04b147d454938c63a8d69b2ea4c5710ec0b36e3a6'
            'c72571fa5d59dde036c42033df35af056966ff0cd1204008971aa6ba9fb97b68'
            '5ab9ffa2a9d1778104cd2c3b326de1fcbc242e94d0311c3275b12850ed30ceea'
            'd3a2ee6d060508411d4396f5421d8b6d067cf7cb5e826785fbe119e05e21bd87'
            '9b64f57cb0cd1972c2815f20abe7ce6ab34d0f471af44baad179e90644122f5f'
            '33288e689ddddc5ce833e9755df1e73c65c5a201c4ede2ffa6b19274927719d2'
            'd38fdb7a65aa43708b7fa9a94aa7d3210253d78d3b181e1020d0000bd0a1dc05'
            'd447f9f58ebeb84c65b36c8afcb83727a1508994e826957a663b0b9b8a003325'
            'ab6d6d6462ee4e106019c0dffe10323b7bde7d82a38f85fd08786e860ba66c16'
            '1b64b0708c363de5c6af62d8db3c243d1e1b712cb1d59e942b9b6b4295a5a500'
            'b182cbd5fd1bc6ce9376d91b47a2284f1fbe0ad1c048cc2cfbb4afa3a9eb9697'
            '503b69feca990eba7e9441af9ca44cb3ac6b5ed66e591c201fe30efa8a7c471d'
            'c613d6254c263a8e132104bec47f1aacb3b2fcd4051b69b5e3fcb1c147a65c2f'
            '90c4b5188bafc521cab03c12a309da50b5a7517727ed41228ed123fe1b152f6a'
            '6319cd623bf34ad7b8e064ab993260bcbd405f5b7fff9b2fa40ba5ed56302425'
            '39e5d96823e89dc818a13d16675ee3079d976f694f5acc9760ae789e9b3391b2'
            '89e0e22a7ef17cc6a4577157b6d95c09baa4fd532e3ee0a290810ed35e56bb19'
            'd9b61fb98a97c617425b06093d98a5cf0ee2dd127f0eea600b9a0c67fbe761db'
            '9b77e5d5bba9701da1b883e521a0cfe88451f57bd36085b67e56f061f84a2e6a'
            '152a71bce6e522daab6a0a33ce22e537fa9793d28b617e6c0a4176a83aa3be57'
            '8afac0f2f5547c5516d218984755b7445c7143afa4e551fce0071bdb873b34e6'
            'b9e2b9e79ed0c69d288ed6421f237e860a0c6492ebbdd2a44c2c4f368dbe9994'
            '1b1e8561d859d3859f496cee3d741f252973f8fcc539c409e35cc80a5ed6df23'
            'cc3a65601313f5d681fd9540c5291a9e30a72e38c96413c47c61ff84fde78d01'
            '1b01b4154d1b920af003f7abb1e1999dea6a766cf9fd2702b3ce0ee57af931b6'
            '2124b0861b163a3b91aa4bea28076c3432df3b29b6c4e1ba588def420071fc15'
            '7de90eb2722ecc9ab00df3c669383a61a91bb67bd287ce349b4745ee7a479dbc'
            'eef166b9acc412eb579fcd6437307edda253d606b7be7599c38092bc52a85984'
            '80edab8b82b1d21c565d2137ceae0b6642619b16133d91205d6355029e9cdfeb'
            '9a28b373d95916b6b707d4c712c09cf36daf1a511b2bedb1aa70ee58d46a0666'
            'bb287784b0a3840c589a7a04d5d6f2216be90aa4a512d5632f5c9bfe7b8b1338'
            '2f999b95d367c7c46b968074ce315197a5ff3545c7b77a804ade56a95b5c24cd'
            'ece5937b5c0366d93ad03da9bc5db1b551dfb91e9b343d2b57b763439686d4a3'
        ),
        'jws': (
            'eyJhbGciOiJNTC1EU0EtODciLCJraWQiOiJ0Um4xSk5Ja2dNc0FCVlFCbFhlREh4'
            'QUljY2xoLTJJWDBVZERFelB0NVhVIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2lu'
            'ZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.hmMrKkUgZwGPQV_WUoXU'
            'Vq_Z9WOenDZbfMmHpKritl0btWi29TC8eIyQyT1FAuW2kg3h6ALsvCrjX5tn3QKF'
            'QZYC0sBdRt0VNiDm0BjyJ4jWcomSCgb0-cGXaLlODAz-njGridYfO1DpGMwHHshu'
            'KuvECv4qnX3XgZPE-6C8La43TZrYO8brzBXGiuyGMLq-TSmXavOeiadtpp6iTUqJ'
            'DBgQSYvPB6PvipeCPlQH2ZQi8qkraxspi0lgy8Jh2aRYj44DX2ZKq-Ml-hfBJB4i'
            'HRpWmwPpEH7Ed4LkBIlaqZoPccrPgpGQpyz4_FcahrJc8CGGtTO5I34o5BcuZej7'
            'WOQvJ6mRmvYqIrYwoLs-3_YFZkVdX4KU38oprMvAHjObOhy_vZZArMnCgfYlCKrA'
            'NbhOZG8O0BXgqow5Bqv_oRIztGQZMrivp_1CS0hELarwkwjdqyH5R747ndV26IQk'
            'eyn6y9daXRZIWxaC9KmAaDSm5-YsRVpiAAr0QmfaV51z065_r5qZmOMFIBERVi9B'
            'bm_Z7ipJkoIL2SqVsePATfHeWB8huFpVFxdeEkJUPDuBtthax0HhxpRuECpFNJf2'
            'xA70Hp5C5VZIsi5EO21HuRpixiNKmXP5whhsn_uv_B7R4f4DX6X6A53lFrUfpFIr'
            'TfOQvBAvmEUUTSGcPeT-F7f_1lz34uFyN3ZT4FCeCh4n4yyZY1fSPVMNtOfK8GrL'
            'rRoWdi8gMk30oTKgb9zFkFU7uZhVEVRV86A_060bgFSHWDz5dlXLfyCoJsbsHlO9'
            'WBibTCkrMv6lnjh4czprro2prRtJAJB2jVwS1dv2mo4wP1lFYqY63yM9I9deU4fx'
            'y6mkwig7XwcVJskg8jX_0agATqmrKfYWMI4yGQ9fciYacgN8X2uSHqiPU1cgQ8VU'
            'GsSAsw4POdZpmcUt_DacVLT8-qwnq6NWpm8bqm_uUQu3JjqcHKLz7zWKopeLG_ZY'
            '7a45IqUQpwbMg9ICE1ZNTe5nsMHAJnevgLfWk14wnvVQyRVvlSvatdUTg0EjBc6P'
            '35a4lY12vIOq2ENpA-m52TfXeXxXK0vtZfT9SY33thi4EfZABWL_jQyiio6b6Akr'
            'h6_PgQ-bh2H2Fpu8Z3GImrbHodcbnqFpmKYlMLwxDHnKPxY7PpyyV8HsWfEjqVlA'
            'X56stAIIG4_owwzMZMcFwgucAP176TwjaXJqm9v2-DXisD2cNjyGlJ_rec670rv6'
            '1thjiJF2uZrB9Z2zoQVYnc3Y9sJMMPPmunUcXpNVZWSsPlFDoPa1ABoFnRbP8rO-'
            'qbNGP5N7xY2DuPRYOp3CdyxeyDPmGBC2556FNeLRj-PhPAkd61fgXsQZyS9N2jHm'
            'FUIKbL8o-e3bQnqW7ebEn7zAjS_LQ2DtgIdIneUu84hh8AduoW9ky_aOpqvBUmdn'
            'HUwZHQiSSdeCPnEOssVBbuDd3gbcQf_VWvplwcjTTrJPsqqZpirjfVGPFUCVAz6k'
            'D0vhFcvTdQt6DGqys61xg_VOfj6wxpKsXuXDuqwaeb4KpGniHx-23nECgKG86N_1'
            'BBX8RRAvYnksxIIxIxgyrng-y44CV9FL_wGfP0Plx6JjSUFOL1gDZTc5NrAPoOzt'
            'Eo1FbJ2Lq8gqBR9Ku9Yza3aYANAJQvAraTXzA0t1j6qcmh-WtXeI1GE-8neOJtlR'
            'VbzT5RvPiRJZAVmu9Pg97wbLLQNPJoqIYp-c9mieGsDxAi75C2M1ArRnCa4kJJXr'
            'upgzQzzFefWyaRkIvC2MP9MwB_Z_NY3mp3opcNlT1TdKLr1sncLUkk3qJ0Pwyr-5'
            'dsKrC6aenapBHO7G0OnA0qTi8-Oy91VqJYYcVjcOUQaxNeMtnk-pLJL7j3MzqNiD'
            'kc-OfR19fcWvDmmd9Z8wtj20khL4mTDn7qTUo-PsVR7GnpqkImmEmE8sa4ZlPHa4'
            '_IcZGFbdcwp9xuOndINlzWGrIKywFPQ1x26zXDEa7fOx5f01aX8dIU_KWNAGdaZx'
            'PIlqLW5qbC6dipSqf9NwblZLJs5DCiLV8nHS-QM26xQJVUNH22n_3Z_8z1SA8AX8'
            'd7j0-g1Pf7NZC8e8Ipnm4B3YGpA7nn471aTbJb4OUamfgys17MV_hPDK_f7FF7NX'
            'p06-dtVYDmcs-87ZkrDuluOkUaRivKULwjEtSbiiKZAKirGfAOuwyCbbzygEpqYv'
            'EztABSmDYd_F_autklob_0deKuvvRYFpVCaxeaYQ7WIkpfBbMxeh9Qci7kPfgyB5'
            'H9ajWEJV3fgRk10Q1RaWyTUddQ_jWaluiDa3GD_t39sUrG7QhXc2Oz1NPPNoY6-A'
            '4jFbFCtXSF1muztqy0xaworcNiHY18yeL4Cw2iYLJ1Q3O4NnFo3E-wIXmYF4CLxZ'
            'ifr2Jkd6Ix1w-wlsN6vyCcDs8JeAgeJn0_Oahk1mgvRhVz8FFeidSdFqJBxGKbfZ'
            '32F_auJwrsLyjN_ShxTSFofyKQy2XCfoVMko4eu5o6md66xBmjZvTvItXL7f-eD0'
            'JxISBsBkZG3mFrApZKbdpI1lEa681ZbCxRTYpxUR7McTbs0Q5S9PCN5ElUz_axfe'
            'upIIbCTE4S0-ZQuIdQcQ2pn1j-4t2c04jtLE6WFI-1ASBCedlZmrZUiRegbezE01'
            'hMiFnfN32BhBu7ZcnlBCdWwj9hUfpEduJIgaA3acXhysGs40nqRzR9imvX9CBQYJ'
            'ZjrCHr-wORF6svmvF5FADRgwbM7Cc9puJgLBiQwXrhD43B6kjX_OXi5O2UNZFkAP'
            'r0WONBJsip8CgR6pt1u_mIKlIrYM9kM-idJGGT0DZ9UU4LMx0-9_2KCCkjDqgYN1'
            'rS9DA__GP9tS3dJ-XLSlk2URQuoHm4Xubv4vwgjUS7JzAxcQWHB0HtHFoZ3-tYVw'
            '_GRbRwyODm3E-N5O3L_R-pva9fvlPjkCNMrf2IlxAxBKML1gCxsSqhFr5yoPeW40'
            'LTxMF_dYPNLjC3l7mRRl_wfY_FhvayI7hrgCYfMgWeb-cXyx5eXumt9lMFOD3dQt'
            'EG1IUbdE7pVXG-barWK0Zl43DtQMNQzoCK_BLxfCsambyRRcI6E4QTfqe5lWtVf8'
            'Wi4KproenWyCjjzEjJQdWw4g-ae_bjGjfZCp38RgsXtWgI_tuzKyRF5WwjyN9VEo'
            'RXd8W2DctmBejHF2XDYzbMFkJ-384SokPX6intnlqBGMs0ssxriJhsFOA-vgDra6'
            'REx3DUMb8_u_Umc-zp4E6isX4D-eRYgElmj0ez945nqxp3YliO8mRLMW6E4OupLt'
            'hfw4vmK3YqTAuXcnGxYrf7JqAkMfz5uAPi0SqPWDQZq7ycu9BmkMXAIhMb19XBDj'
            'L7hZGDwDRrn9yBBcYlPaFPNXjMJWJH_xxUKNsTFGg5-J_WdxXi8Zn6tDMxbxqqjI'
            'pw_FUaM00jJ2MhpbkzhEx7X85pBR47ScRgr6WJpf4ZLSFuV7NT1WI3PIBa_bYeCi'
            'q29fp3ShM-1bRFdJG_lGZd97TuAMF_QU6-KDXBv5i8kUZ1NXdJUz-YaA0RRVNFgM'
            'GM5n0pKB5IFncAPK-taTzHLIZJ9uuBdP2y2Hxwbw8YQlmy2-MT5XE5Ae_9kxuvII'
            'lSzjpfLN9012HSnX4tZ8x3aWwof3E7s3jjzw7qbBtoUkYYpIGVOKf2EpmhEqevSl'
            'XYWpBYN3X2ZYjsrA9CL9PTvrPdyWLwKBmfh7cDJbjNXJSQLeKL7oHzicrllABzR9'
            'Ckkz7b24XGV1Klcat_Og4oB9qxiO2zJZWz2GDTAL0hosUlHLWnrQYvqFzzdIOzGl'
            'ifwIyGgoRNb44IRMzzsErxuoqkdjZewVc4PzruHRlV3cWK6M7ZUiWLtxtMzas2sf'
            'AERy8BdS7ISLzj5PERoWyYXSW-898WD3ze5MJcpSsAYNEmPCBtdxF9l-Qz1LxuDa'
            '8hOCQ2Wzef1a2WFF5pCBaZRcAK_kef65xRst6WFpjWZGCLZUqHBhFDLEOd7Ikbw7'
            'd9V8dc4nAO65NQcxfT9JDUZadS2jmQJip8GLD4P9lGS1Ry-8rHCnMN7zXDp43Tfy'
            'YhSgv9uj4xKi2wmAMMYBl0n2RNemx8nt-K_dknGgYYGOybDkg2uAUoXdxP33KfiR'
            'jbRpYqZVAiq0S45QLAIxxGiDJoZRnyIscdM6lryQtXj0PO67vRf6ifxC3wLv97HH'
            'UKergpXcAg-4_rNj_Zx_xiHMfCAe2q3DG1a_DcSmu5u1OPkBHmzHB9Vs8HV0E2-z'
            '44sl3Exqb5L8pMYpDnZ7QW-Qb1-S-zoESUy__AKhkRWPC7GmvmJJJHur6SRGSK0X'
            '2KyszkEYoe-8NhwpvLrYnNuVk7QknBS91KH2q8C0B8FKqcY40S5ILkImP9iOGIXY'
            'l5ZVRleoDBpH9BootWH2az5l7c_e-vfBGs7XpudoAq5wzhe_-AMBvKPCm0BoCX5B'
            '_NGUasXvEWobqUb61mpKCuVJdzVtexk-m8Jfvmdc8ooPJEYD_oosY5_S1LuHoc7G'
            'HLnoYdDVb2FhIPhOJCLQCef-Y3dtNThqOEo534Zg7R72nSeSQhdQ1hcBUsc50U2o'
            'F9OlOnV9z5hsfNwIxdUO9bdoXRYFmosmtpmDfGxAem0s5iPJ0EJ_8szlaX2pi6k6'
            'VP-ci-n7J8pEBwL2R3c-ei2iqB7JdLi7Gg6iXVMpQIFTxswh0HbgGtyZXgR_-AM9'
            '1XRszm_kAlqAHTAJ7B-0Z5bJgMGEY2StBdhGzel_gNPVaxemC3DT0904GbCU2Z3a'
            'vUHcedebI02_MdILdQxyXbw145KjqC15CqeaG--6x6WzpAuSjrFQRuz6Z5UyibW6'
            'Ay9R3P25c-gwmaRM8rPW5YkQtQdfzrtvGZ6wyhIcBXvbpU02OoChfRDF4xI2Lvna'
            'W3g6hQIUGe5lueI13ArYRAhZC0LHKPuVfv5OKeMqxYRtcN3YK6Ddc1t61rsA7MU1'
            'cAKzOGsiQ7aNyNBQHOV6z-W4-ws_DnZKYRMz0D_hwbeHO0ZKhciXng5VDCX4hyb4'
            '7LExmO5N1mfihN3iHEkX_19rIgunfkSb9gd9B_AaazAttBEPPLtbsoZneQXBRl3P'
            'WiDpC_yXiLTWAd13AOBYHzBMKeJ4hplUqsAGTaGSztbpvV92wz_YX9kMEucHMu5h'
            'oM-TJbuWoheiiiKSFBNRK_g_rqXZo1UZjDOnHpHGJxOnlJBPp94Zvwh8sKLOpOd4'
            'qeOMLbnYKiag00al5x_3fBXq-KI0Y31OJfgDdCaKAQ0DUX71HN6XDOlvU1Iwh48i'
            'ASJHdQGDmjhcS8YoeX9omwPiYhcbGJGzEVrn3H7h24eIf_7bVRpicMhjwghB0xtq'
            'TT0eVam1l8kr1-5kem7Dr2Kyqm2HpEwbi3KPXKYDXQRbHElEhazMCYr2wnjx_Bx2'
            'ai2uZa8uQyjN1zh1cjWHH0TicL2eAyc6YPKfKpmc5QwLrgT0ddQDhvXkCkN50fOR'
            '1Sbl56iFoAL8goFl3QA5wBk51vsDsquEt7nlz6sGTHzknENb-eEayrXnw-Q5FueF'
            'wqzoJpUrEYDXTxgOU8XVhrPv0Ot-BO6ORfzn3_1gREcHjhrc6RdF01NNqyzyVG0B'
            'dckywvAnzUGskWdCfP62dKdx46lAIRVPd3xG4tViaQ79GAeMVnqSeCLXbOyqfnJw'
            'hOT2fgQzLwxcj1tqGBBd3Pfx2d5-10WiL_mis0ven6golqaLq1EQsveb9AJpkYgJ'
            'xdBeyHZXxNLMh4_XAuK1ZIs9F8Cz1vFEVcAFipev-cFyRvsdcNI2-HK2nOGkypEc'
            'uVATyLtA0jKeyPtE4TJ3_l8KXltEZjWycQAd_8Tj9is3wisC8bfzjll8UBjFZp-r'
            'zmCr8kA4cZih9gl27TiCmhyKhgMfDUIUmuDL_Rn9DLxEAT3Ebl1SW0ToCciNtKTH'
            '9oO-wnkPd-jg1HCooLcg-K_QkOTptJNZRFbXpooKqwH5Z9qsCxurZxnS_MscnE0q'
            'Ta4EqrlpiDnj4FBs4q9SEPlKequfYzFmjQis1iwsReutf6pHmsvRmz9gx5vd6NMI'
            'kI05IeLNDElvlOGD04m1vR4ZISdmdHaAgaW9_AUPGx0vP1Rqe36cvebwUYSnzdbZ'
            '7y1s7PH7GXF5r7zNEzY9bHmXvsjb3N_u9BkenwkQfZGS6ez0AAAAAAAAAAALGSAl'
            'Kzg7Qw'
        ),
    },
}


class TestMLDSA(unittest.TestCase):

    def _skip_if_unsupported(self, alg):
        if alg not in jwk.ImplementedAKPAlgorithms:
            self.skipTest('%s not supported' % alg)

    def test_generate_AKP_keys(self):
        for alg in ('ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'):
            self._skip_if_unsupported(alg)
            key = jwk.JWK.generate(kty='AKP', alg=alg)
            self.assertEqual(key['kty'], 'AKP')
            self.assertEqual(key['alg'], alg)
            self.assertIn('pub', key)
            self.assertIn('priv', key)

    def test_generate_AKP_missing_alg(self):
        with self.assertRaises(jwk.InvalidJWKValue):
            jwk.JWK.generate(kty='AKP')

    def test_generate_AKP_invalid_alg(self):
        with self.assertRaises(jwk.InvalidJWKValue):
            jwk.JWK.generate(kty='AKP', alg='INVALID')

    def test_import_AKP_missing_alg(self):
        with self.assertRaises(jwk.InvalidJWKValue):
            jwk.JWK(kty='AKP', pub='AAAA')

    def test_import_AKP_invalid_alg(self):
        with self.assertRaises(jwk.InvalidJWKValue):
            jwk.JWK(kty='AKP', alg='INVALID', pub='AAAA')

    def test_create_pubKeys_mldsa(self):
        for alg in ('ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'):
            self._skip_if_unsupported(alg)
            key = jwk.JWK.generate(kty='AKP', alg=alg)
            pub_dict = key.export_public(as_dict=True)
            self.assertNotIn('priv', pub_dict)
            pub_key = jwk.JWK(**pub_dict)
            self.assertEqual(pub_key['kty'], 'AKP')
            self.assertEqual(pub_key['alg'], alg)
            self.assertTrue(pub_key.has_public)
            self.assertFalse(pub_key.has_private)

    def test_create_priKeys_mldsa(self):
        for alg in ('ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'):
            self._skip_if_unsupported(alg)
            key = jwk.JWK.generate(kty='AKP', alg=alg)
            pri_dict = key.export_private(as_dict=True)
            pri_key = jwk.JWK(**pri_dict)
            self.assertEqual(pri_key['kty'], 'AKP')
            self.assertTrue(pri_key.has_private)

    def test_public_mldsa(self):
        for alg in ('ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'):
            self._skip_if_unsupported(alg)
            key = jwk.JWK.generate(kty='AKP', alg=alg)
            self.assertTrue(key.has_private)
            pub = key.public()
            self.assertTrue(pub.has_public)
            self.assertFalse(pub.has_private)
            self.assertEqual(pub['alg'], alg)
            self.assertNotIn('priv', pub)

    def test_mldsa_json_roundtrip(self):
        for alg in ('ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'):
            self._skip_if_unsupported(alg)
            key = jwk.JWK.generate(kty='AKP', alg=alg)
            exported = key.export()
            reimported = jwk.JWK.from_json(exported)
            self.assertEqual(key.thumbprint(), reimported.thumbprint())
            self.assertEqual(reimported['kty'], 'AKP')
            self.assertEqual(reimported['alg'], alg)

    def test_thumbprint_mldsa(self):
        for alg in ('ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'):
            self._skip_if_unsupported(alg)
            key = jwk.JWK.generate(kty='AKP', alg=alg)
            t = key.thumbprint()
            self.assertIsNotNone(t)
            key2 = jwk.JWK.from_json(key.export())
            self.assertEqual(t, key2.thumbprint())
            pub_key = key.public()
            self.assertEqual(t, pub_key.thumbprint())

    def test_import_pyca_mldsa_keys(self):
        for alg in ('ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'):
            self._skip_if_unsupported(alg)
            key = jwk.JWK.generate(kty='AKP', alg=alg)
            pyca_pri = key.get_op_key('sign')
            k_pri = jwk.JWK.from_pyca(pyca_pri)
            self.assertEqual(k_pri['kty'], 'AKP')
            self.assertEqual(k_pri['alg'], alg)
            self.assertTrue(k_pri.has_private)

            pyca_pub = key.get_op_key('verify')
            k_pub = jwk.JWK.from_pyca(pyca_pub)
            self.assertEqual(k_pub['kty'], 'AKP')
            self.assertEqual(k_pub['alg'], alg)
            self.assertFalse(k_pub.has_private)

    def test_mldsa_signing_and_verification(self):
        for alg in ('ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'):
            self._skip_if_unsupported(alg)
            key = jwk.JWK.generate(kty='AKP', alg=alg)
            payload = ('ML-DSA test payload for %s' % alg).encode()
            protected_header = {"alg": alg}

            jws_token = jws.JWS(payload)
            jws_token.add_signature(key, None,
                                    json_encode(protected_header), None)
            compact = jws_token.serialize(compact=True)

            pub_key = key.public()
            jws_verify = jws.JWS()
            jws_verify.deserialize(compact, pub_key)
            self.assertTrue(jws_verify.is_valid)
            self.assertEqual(jws_verify.payload, payload)

    def test_mldsa_tampered_signature(self):
        for alg in ('ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'):
            self._skip_if_unsupported(alg)
            key = jwk.JWK.generate(kty='AKP', alg=alg)
            payload = b'tamper test'
            jws_token = jws.JWS(payload)
            jws_token.add_signature(key, None,
                                    json_encode({"alg": alg}), None)
            compact = jws_token.serialize(compact=True)

            parts = compact.split('.')
            sig_bytes = bytearray(base64url_decode(parts[2]))
            sig_bytes[0] ^= 0xFF
            parts[2] = base64url_encode(bytes(sig_bytes))
            tampered = '.'.join(parts)

            jws_verify = jws.JWS()
            jws_verify.deserialize(tampered)
            with self.assertRaises(jws.InvalidJWSSignature):
                jws_verify.verify(key.public())

    def test_mldsa_seed_roundtrip(self):
        for alg in ('ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'):
            self._skip_if_unsupported(alg)
            key = jwk.JWK.generate(kty='AKP', alg=alg)
            seed1 = key['priv']
            key2 = jwk.JWK(**json_decode(key.export()))
            self.assertEqual(seed1, key2['priv'])
            payload = b'seed test'
            s1 = key.get_op_key('sign').sign(payload, context=b"")
            key.get_op_key('verify').verify(s1, payload, context=b"")
            s2 = key2.get_op_key('sign').sign(payload, context=b"")
            key2.get_op_key('verify').verify(s2, payload, context=b"")

    def test_mldsa_wrong_key_type(self):
        for alg in ('ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'):
            self._skip_if_unsupported(alg)
            akp_key = jwk.JWK.generate(kty='AKP', alg=alg)
            ec_key = jwk.JWK.generate(kty='EC', crv='P-256')
            payload = b'wrong key type test'
            jws_token = jws.JWS(payload)
            jws_token.add_signature(akp_key, None,
                                    json_encode({"alg": alg}), None)
            compact = jws_token.serialize(compact=True)
            jws_verify = jws.JWS()
            jws_verify.deserialize(compact)
            with self.assertRaises(Exception):
                jws_verify.verify(ec_key)

    def test_mldsa_key_in_jwkset(self):
        for alg in ('ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'):
            self._skip_if_unsupported(alg)
            key = jwk.JWK.generate(kty='AKP', alg=alg)
            kid = key.thumbprint()
            key['kid'] = kid
            keyset = jwk.JWKSet()
            keyset.add(key)
            exported = keyset.export()
            reimported = jwk.JWKSet.from_json(exported)
            self.assertEqual(len(reimported), 1)
            found = reimported.get_key(kid)
            self.assertEqual(found['kty'], 'AKP')
            self.assertEqual(found['alg'], alg)

    # RFC 9964 Appendix A.1 - Verify that thumbprints computed from
    # the test vector public keys match the expected kid values.
    def test_rfc9964_thumbprints(self):
        for alg, vec in RFC9964_VECTORS.items():
            self._skip_if_unsupported(alg)
            pub_bytes = unhexlify(vec['raw_public_key'])
            seed_bytes = b'\x00' * 32
            key = jwk.JWK(
                kty='AKP', alg=alg,
                pub=base64url_encode(pub_bytes),
                priv=base64url_encode(seed_bytes))
            self.assertEqual(key.thumbprint(), vec['kid'])

    # RFC 9964 Appendix A.1 - Verify the JWS test vector signatures
    # using the public keys from the test vectors.
    def test_rfc9964_jws_verify(self):
        for alg, vec in RFC9964_VECTORS.items():
            self._skip_if_unsupported(alg)
            pub_bytes = unhexlify(vec['raw_public_key'])
            key = jwk.JWK(
                kty='AKP', alg=alg,
                pub=base64url_encode(pub_bytes))
            jws_obj = jws.JWS()
            jws_obj.deserialize(vec['jws'], key)
            self.assertTrue(jws_obj.is_valid)

    # RFC 9964 Appendix A.1 - Sign a payload with the all-zeros-seed
    # private key and verify with the corresponding public key.
    def test_rfc9964_jws_sign_verify(self):
        for alg, vec in RFC9964_VECTORS.items():
            self._skip_if_unsupported(alg)
            pub_bytes = unhexlify(vec['raw_public_key'])
            seed_bytes = b'\x00' * 32
            key = jwk.JWK(
                kty='AKP', alg=alg,
                pub=base64url_encode(pub_bytes),
                priv=base64url_encode(seed_bytes))
            payload = (
                b'It\xe2\x80\x99s a dangerous business, '
                b'Frodo, going out your door.')
            jws_token = jws.JWS(payload)
            jws_token.add_signature(
                key, None,
                json_encode({"alg": alg, "kid": vec['kid']}),
                None)
            compact = jws_token.serialize(compact=True)
            pub_key = key.public()
            jws_verify = jws.JWS()
            jws_verify.deserialize(compact, pub_key)
            self.assertTrue(jws_verify.is_valid)
            self.assertEqual(jws_verify.payload, payload)
