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

from Crypto.SelfTest.Cipher.common import make_block_tests

from pgp.cipher import aidea


# This is a list of (plaintext, ciphertext, key) tuples.
test_data = [

        # Project NESSIE test vectors
        # http://bit.ly/1kMAzsR
        ('0000000000000000', 'b1f5f7f87901370f',
         '80000000000000000000000000000000',
         'IDEA NESSIE, Set 1, vector 0'),

        ('0000000000000000', 'b3927dffb6358626',
         '40000000000000000000000000000000',
         'IDEA NESSIE, Set 1, vector 1'),

        ('8000000000000000', '8001000180008000',
         '00000000000000000000000000000000',
         'IDEA NESSIE, Set 2, vector 0'),

        ('4000000000000000', 'c00180014000c000',
         '00000000000000000000000000000000',
         'IDEA NESSIE, Set 2, vector 1'),

        ('0000000000000000', '0001000100000000',
         '00000000000000000000000000000000',
         'IDEA NESSIE, Set 3, vector 0'),

        ('0101010101010101', 'e3f8aff7a3795615',
         '01010101010101010101010101010101',
         'IDEA NESSIE, Set 3, vector 1'),

        ('0011223344556677', 'f526ab9a62c0d258',
         '000102030405060708090a0b0c0d0e0f',
         'IDEA NESSIE, Set 4, vector 0'),

        ('ea024714ad5c4d84', 'c8fb51d3516627a8',
         '2bd6459f82c5b300952c49104881ff48',
         'IDEA NESSIE, Set 4, vector 1'),

        ('78071ee87f0130e8', '0000000000000000',
         '80000000000000000000000000000000',
         'IDEA NESSIE, Set 5, vector 0'),

        ('98aa167965b52792', '0000000000000000',
         '40000000000000000000000000000000',
         'IDEA NESSIE, Set 5, vector 1'),

        ('8001000180008000', '8000000000000000',
         '00000000000000000000000000000000',
         'IDEA NESSIE, Set 6, vector 0'),

        ('c00180014000c000', '4000000000000000',
         '00000000000000000000000000000000',
         'IDEA NESSIE, Set 6, vector 1'),

        ('0001000100000000', '0000000000000000',
         '00000000000000000000000000000000',
         'IDEA NESSIE, Set 7, vector 0'),

        ('6d33179ce8b3c1fa', '0101010101010101',
         '01010101010101010101010101010101',
         'IDEA NESSIE, Set 7, vector 1'),

        ('db2d4a92aa68273f', '0011223344556677',
         '000102030405060708090a0b0c0d0e0f',
         'IDEA NESSIE, Set 8, vector 0'),

        ('f129a6601ef62a47', 'ea024714ad5c4d84',
         '2bd6459f82c5b300952c49104881ff48',
         'IDEA NESSIE, Set 8, vector 1'),

        # from PyCA's cryptography package:
        # http://bit.ly/1j3pnGT
        ('45cf12964fc824ab76616ae2f4bf0822',
         '2cb10d22ac22a375c0021ab6732936c1',
         '1f8e4973953f3fb0bd6b16662e9a3c17',
         'PyCA, CBC',
         dict(mode='CBC', iv='2fe2b333ceda8f98')),

        ('4b5a872260293312eea1a570fd39c788',
         '5d9c48bf7dc115f28e153dc93dfcff96',
         '085b8af6788fa6bc1a0b47dcf50fbd35',
         'PyCA, CFB',
         dict(mode='CFB', iv='58cb2b12bb52c6f1', segment_size=64)),

        ('81883f22165282ba6a442a8dd2a768d4',
         '770e7b0eacc089b7eef410d98d886e9e',
         'd7d57bd847154af9722a8df096e61a42',
         'PyCA, CFB',
         dict(mode='OFB', iv='fdde201c91e401d9')),
    ]


def get_testcases(config={}):
    testcases = make_block_tests(aidea, "AIDEA", test_data)
    return testcases


def test_aidea():
    for testcase in get_testcases():
        # Hack for Nose
        yield getattr(testcase, testcase._testMethodName)
