# python-pgp A Python OpenPGP implementation
# Copyright (C) 2014 Richard Mitchell
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import unittest
import warnings

from Crypto.SelfTest.Cipher.common import make_block_tests

from pgp.cipher import camellia


# This is a list of (plaintext, ciphertext, key) tuples.
test_data = [
    # Test vectors from RFC 3713, A
    ('0123456789abcdeffedcba9876543210', '67673138549669730857065648eabe43',
     '0123456789abcdeffedcba9876543210',
     '128-bit key'),

    ('0123456789abcdeffedcba9876543210', 'b4993401b3e996f84ee5cee7d79b09b9',
     '0123456789abcdeffedcba98765432100011223344556677',
     '192-bit key'),

    ('0123456789abcdeffedcba9876543210', '9acc237dff16d76c20ef7c919e3a7509',
     '0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff',
     '256-bit key'),

    # Test vectors from CryptX
    # https://metacpan.org/release/CryptX
    # http://bit.ly/R2HGpB

    # ECB-CAMELLIA128.Encrypt and ECB-CAMELLIA128.Decrypt
    ('6bc1bee22e409f96e93d7e117393172a', '432fc5dcd628115b7c388d770b270c96',
     '2b7e151628aed2a6abf7158809cf4f3c',
     'ECB-CAMELLIA128 1'),

    ('ae2d8a571e03ac9c9eb76fac45af8e51', '0be1f14023782a22e8384c5abb7fab2b',
     '2b7e151628aed2a6abf7158809cf4f3c',
     'ECB-CAMELLIA128 2'),

    ('30c81c46a35ce411e5fbc1191a0a52ef', 'a0a1abcd1893ab6fe0fe5b65df5f8636',
     '2b7e151628aed2a6abf7158809cf4f3c',
     'ECB-CAMELLIA128 3'),

    ('f69f2445df4f9b17ad2b417be66c3710', 'e61925e0d5dfaa9bb29f815b3076e51a',
     '2b7e151628aed2a6abf7158809cf4f3c',
     'ECB-CAMELLIA128 4'),

    # ECB-CAMELLIA192.Encrypt and ECB-CAMELLIA192.Decrypt
    ('6bc1bee22e409f96e93d7e117393172a', 'cccc6c4e138b45848514d48d0d3439d3',
     '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
     'ECB-CAMELLIA192 1'),

    ('ae2d8a571e03ac9c9eb76fac45af8e51', '5713c62c14b2ec0f8393b6afd6f5785a',
     '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
     'ECB-CAMELLIA192 2'),

    ('30c81c46a35ce411e5fbc1191a0a52ef', 'b40ed2b60eb54d09d030cf511feef366',
     '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
     'ECB-CAMELLIA192 3'),

    ('f69f2445df4f9b17ad2b417be66c3710', '909dbd95799096748cb27357e73e1d26',
     '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
     'ECB-CAMELLIA192 4'),

    # ECB-CAMELLIA256.Encrypt and ECB-CAMELLIA256.Decrypt
    ('6bc1bee22e409f96e93d7e117393172a', 'befd219b112fa00098919cd101c9ccfa',
     '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
     'ECB-CAMELLIA256 1'),

    ('ae2d8a571e03ac9c9eb76fac45af8e51', 'c91d3a8f1aea08a9386cf4b66c0169ea',
     '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
     'ECB-CAMELLIA256 2'),

    ('30c81c46a35ce411e5fbc1191a0a52ef', 'a623d711dc5f25a51bb8a80d56397d28',
     '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
     'ECB-CAMELLIA256 3'),

    ('f69f2445df4f9b17ad2b417be66c3710', '7960109fb6dc42947fcfe59ea3c5eb6b',
     '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
     'ECB-CAMELLIA256 4'),

    # CBC-CAMELLIA128.Encrypt and CBC-CAMELLIA128.Decrypt
    ('6bc1bee22e409f96e93d7e117393172a', '1607cf494b36bbf00daeb0b503c831ab',
     '2b7e151628aed2a6abf7158809cf4f3c',
     'CBC-CAMELLIA128 1',
     dict(mode='CBC', iv='000102030405060708090a0b0c0d0e0f')
     ),

    ('ae2d8a571e03ac9c9eb76fac45af8e51', 'a2f2cf671629ef7840c5a5dfb5074887',
     '2b7e151628aed2a6abf7158809cf4f3c',
     'CBC-CAMELLIA128 2',
     dict(mode='CBC', iv='1607cf494b36bbf00daeb0b503c831ab')
     ),

    ('30c81c46a35ce411e5fbc1191a0a52ef', '0f06165008cf8b8b5a63586362543e54',
     '2b7e151628aed2a6abf7158809cf4f3c',
     'CBC-CAMELLIA128 3',
     dict(mode='CBC', iv='a2f2cf671629ef7840c5a5dfb5074887')
     ),

    ('f69f2445df4f9b17ad2b417be66c3710', '74c64268cdb8b8faf5b34e8af3732980',
     '2b7e151628aed2a6abf7158809cf4f3c',
     'CBC-CAMELLIA128 4',
     dict(mode='CBC', iv='36a84cdafd5f9a85ada0f0a993d6d577')
     ),

    # CBC-CAMELLIA192.Encrypt and CBC-CAMELLIA192.Decrypt
    ('6bc1bee22e409f96e93d7e117393172a', '2a4830ab5ac4a1a2405955fd2195cf93',
     '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
     'CBC-CAMELLIA192 1',
     dict(mode='CBC', iv='000102030405060708090a0b0c0d0e0f')
     ),

    ('ae2d8a571e03ac9c9eb76fac45af8e51', '5d5a869bd14ce54264f892a6dd2ec3d5',
     '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
     'CBC-CAMELLIA192 2',
     dict(mode='CBC', iv='2a4830ab5ac4a1a2405955fd2195cf93')
     ),

    ('30c81c46a35ce411e5fbc1191a0a52ef', '37d359c3349836d884e310addf68c449',
     '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
     'CBC-CAMELLIA192 3',
     dict(mode='CBC', iv='5d5a869bd14ce54264f892a6dd2ec3d5')
     ),

    ('f69f2445df4f9b17ad2b417be66c3710', '01faaa930b4ab9916e9668e1428c6b08',
     '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
     'CBC-CAMELLIA192 4',
     dict(mode='CBC', iv='37d359c3349836d884e310addf68c449')
     ),

    # CBC-CAMELLIA256.Encrypt and CBC-CAMELLIA256.Decrypt
    ('6bc1bee22e409f96e93d7e117393172a', 'e6cfa35fc02b134a4d2c0b6737ac3eda',
     '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
     'CBC-CAMELLIA256 1',
     dict(mode='CBC', iv='000102030405060708090a0b0c0d0e0f')
     ),

    ('ae2d8a571e03ac9c9eb76fac45af8e51', '36cbeb73bd504b4070b1b7de2b21eb50',
     '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
     'CBC-CAMELLIA256 2',
     dict(mode='CBC', iv='e6cfa35fc02b134a4d2c0b6737ac3eda')
     ),

    ('30c81c46a35ce411e5fbc1191a0a52ef', 'e31a6055297d96ca3330cdf1b1860a83',
     '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
     'CBC-CAMELLIA256 3',
     dict(mode='CBC', iv='36cbeb73bd504b4070b1b7de2b21eb50')
     ),

    ('f69f2445df4f9b17ad2b417be66c3710', '5d563f6d1cccf236051c0c5c1c58f28f',
     '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
     'CBC-CAMELLIA256 4',
     dict(mode='CBC', iv='e31a6055297d96ca3330cdf1b1860a83')
     ),

    # CFB128-CAMELLIA128.Encrypt
    ('6bc1bee22e409f96e93d7e117393172a', '14f7646187817eb586599146b82bd719',
     '2b7e151628aed2a6abf7158809cf4f3c',
     'CFB128-CAMELLIA128 1',
     dict(mode='CFB', iv='000102030405060708090a0b0c0d0e0f', segment_size=128)
     ),

    ('ae2d8a571e03ac9c9eb76fac45af8e51', 'a53d28bb82df741103ea4f921a44880b',
     '2b7e151628aed2a6abf7158809cf4f3c',
     'CFB128-CAMELLIA128 2',
     dict(mode='CFB', iv='14f7646187817eb586599146b82bd719', segment_size=128)
     ),

    ('30c81c46a35ce411e5fbc1191a0a52ef', '9c2157a664626d1def9ea420fde69b96',
     '2b7e151628aed2a6abf7158809cf4f3c',
     'CFB128-CAMELLIA128 3',
     dict(mode='CFB', iv='a53d28bb82df741103ea4f921a44880b', segment_size=128)
     ),

    ('f69f2445df4f9b17ad2b417be66c3710', '742a25f0542340c7baef24ca8482bb09',
     '2b7e151628aed2a6abf7158809cf4f3c',
     'CFB128-CAMELLIA128 4',
     dict(mode='CFB', iv='9c2157a664626d1def9ea420fde69b96', segment_size=128)
     ),

    # CFB128-CAMELLIA192.Encrypt
    ('6bc1bee22e409f96e93d7e117393172a', 'c832bb9780677daa82d9b6860dcd565e',
     '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
     'CFB128-CAMELLIA192 1',
     dict(mode='CFB', iv='000102030405060708090a0b0c0d0e0f', segment_size=128)
     ),

    ('ae2d8a571e03ac9c9eb76fac45af8e51', '86f8491627906d780c7a6d46ea331f98',
     '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
     'CFB128-CAMELLIA192 2',
     dict(mode='CFB', iv='c832bb9780677daa82d9b6860dcd565e', segment_size=128)
     ),

    ('30c81c46a35ce411e5fbc1191a0a52ef', '69511cce594cf710cb98bb63d7221f01',
     '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
     'CFB128-CAMELLIA192 3',
     dict(mode='CFB', iv='86f8491627906d780c7a6d46ea331f98', segment_size=128)
     ),

    ('f69f2445df4f9b17ad2b417be66c3710', 'd5b5378a3abed55803f25565d8907b84',
     '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
     'CFB128-CAMELLIA192 4',
     dict(mode='CFB', iv='69511cce594cf710cb98bb63d7221f01', segment_size=128)
     ),

    # CFB128-CAMELLIA256.Encrypt
    ('6bc1bee22e409f96e93d7e117393172a', 'cf6107bb0cea7d7fb1bd31f5e7b06c93',
     '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
     'CFB128-CAMELLIA256 1',
     dict(mode='CFB', iv='000102030405060708090a0b0c0d0e0f', segment_size=128)
     ),

    ('ae2d8a571e03ac9c9eb76fac45af8e51', '89bedb4ccdd864ea11ba4cbe849b5e2b',
     '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
     'CFB128-CAMELLIA256 2',
     dict(mode='CFB', iv='cf6107bb0cea7d7fb1bd31f5e7b06c93', segment_size=128)
     ),

    ('30c81c46a35ce411e5fbc1191a0a52ef', '555fc3f34bdd2d54c62d9e3bf338c1c4',
     '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
     'CFB128-CAMELLIA256 3',
     dict(mode='CFB', iv='89bedb4ccdd864ea11ba4cbe849b5e2b', segment_size=128)
     ),

    ('f69f2445df4f9b17ad2b417be66c3710', '5953adce14db8c7f39f1bd39f359bffa',
     '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
     'CFB128-CAMELLIA256 4',
     dict(mode='CFB', iv='555fc3f34bdd2d54c62d9e3bf338c1c4', segment_size=128)
     ),

    # OFB-CAMELLIA128.Encrypt
    ('6bc1bee22e409f96e93d7e117393172a', '14f7646187817eb586599146b82bd719',
     '2b7e151628aed2a6abf7158809cf4f3c',
     'OFB-CAMELLIA128 1',
     dict(mode='OFB', iv='000102030405060708090a0b0c0d0e0f')
     ),

    ('ae2d8a571e03ac9c9eb76fac45af8e51', '25623db569ca51e01482649977e28d84',
     '2b7e151628aed2a6abf7158809cf4f3c',
     'OFB-CAMELLIA128 2',
     dict(mode='OFB', iv='50fe67cc996d32b6da0937e99bafec60')
     ),

    ('30c81c46a35ce411e5fbc1191a0a52ef', 'c776634a60729dc657d12b9fca801e98',
     '2b7e151628aed2a6abf7158809cf4f3c',
     'OFB-CAMELLIA128 3',
     dict(mode='OFB', iv='d9a4dada0892239f6b8b3d7680e15674')
     ),

    ('f69f2445df4f9b17ad2b417be66c3710', 'd776379be0e50825e681da1a4c980e8e',
     '2b7e151628aed2a6abf7158809cf4f3c',
     'OFB-CAMELLIA128 4',
     dict(mode='OFB', iv='a78819583f0308e7a6bf36b1386abf23')
     ),

    # OFB-CAMELLIA192.Encrypt
    ('6bc1bee22e409f96e93d7e117393172a', 'c832bb9780677daa82d9b6860dcd565e',
     '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
     'OFB-CAMELLIA192 1',
     dict(mode='OFB', iv='000102030405060708090a0b0c0d0e0f')
     ),

    ('ae2d8a571e03ac9c9eb76fac45af8e51', '8eceb7d0350d72c7f78562aebdf99339',
     '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
     'OFB-CAMELLIA192 2',
     dict(mode='OFB', iv='a609b38df3b1133dddff2718ba09565e')
     ),

    ('30c81c46a35ce411e5fbc1191a0a52ef', 'bdd62dbbb9700846c53b507f544696f0',
     '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
     'OFB-CAMELLIA192 3',
     dict(mode='OFB', iv='52ef01da52602fe0975f78ac84bf8a50')
     ),

    ('f69f2445df4f9b17ad2b417be66c3710', 'e28014e046b802f385c4c2e13ead4a72',
     '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
     'OFB-CAMELLIA192 4',
     dict(mode='OFB', iv='bd5286ac63aabd7eb067ac54b553f71d')
     ),

    # OFB-CAMELLIA256.Encrypt
    ('6bc1bee22e409f96e93d7e117393172a', 'cf6107bb0cea7d7fb1bd31f5e7b06c93',
     '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
     'OFB-CAMELLIA256 1',
     dict(mode='OFB', iv='000102030405060708090a0b0c0d0e0f')
     ),

    ('ae2d8a571e03ac9c9eb76fac45af8e51', '127ad97e8e3994e4820027d7ba109368',
     '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
     'OFB-CAMELLIA256 2',
     dict(mode='OFB', iv='b7bf3a5df43989dd97f0fa97ebce2f4a')
     ),

    ('30c81c46a35ce411e5fbc1191a0a52ef', '6bff6265a6a6b7a535bc65a80b17214e',
     '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
     'OFB-CAMELLIA256 3',
     dict(mode='OFB', iv='e1c656305ed1a7a6563805746fe03edc')
     ),

    ('f69f2445df4f9b17ad2b417be66c3710', '0a4a0404e26aa78a27cb271e8bf3cf20',
     '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
     'OFB-CAMELLIA256 4',
     dict(mode='OFB', iv='41635be625b48afc1666dd42a09d96e7')
     ),
]


def get_tests(config={}):
    return make_block_tests(camellia, "Camellia", test_data)


def test_camellia():
    if camellia is None:
        warnings.warn(
            "Camellia not available on this system. Skipping its tests."
            )
        return

    for testcase in get_tests():
        # Hack for Nose
        yield getattr(testcase, testcase._testMethodName)


if hasattr(unittest, 'skip'):
    # Python >= 3.1
    test_camellia = unittest.skipIf(
                        camellia is None,
                        "Camellia not available on this system."
                    )(test_camellia)
