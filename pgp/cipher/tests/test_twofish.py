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


# This is a list of (plaintext, ciphertext, key) tuples.
test_data = [
    # Test vectors from Schneier
    # https://www.schneier.com/code/ecb_ival.txt
    ('00000000000000000000000000000000', '9F589F5CF6122C32B6BFEC2F2AE8C35A',
     '00000000000000000000000000000000',
     '128-bit key'),

    ('00000000000000000000000000000000', 'CFD1D2E5A9BE9CDF501F13B892BD2248',
     '0123456789ABCDEFFEDCBA98765432100011223344556677',
     '192-bit key'),

    ('00000000000000000000000000000000', '37527BE0052334B89F0CFCCAE87CFA20',
     '0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF',
     '256-bit key'),
]


def get_tests(config={}):
    from pgp.cipher import twofish
    from Crypto.SelfTest.Cipher.common import make_block_tests
    return make_block_tests(twofish, "Twofish", test_data)


def test_twofish():
    for testcase in get_tests():
        yield testcase
