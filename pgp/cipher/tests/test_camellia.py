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
    # Test vectors from RFC 3713, A
    ('0123456789abcdeffedcba9876543210', '67673138549669730857065648eabe43',
     '0123456789abcdeffedcba9876543210',
     '128-bit key'),

    ('0123456789abcdeffedcba9876543210', 'b4993401b3e996f84ee5cee7d79b09b9',
     '0123456789abcdeffedcba98765432100011223344556677',
     '192-bit key'),

    ('0123456789abcdeffedcba9876543210', '9acc237dff16d76c20ef7c919e3a7509',
     '0123456789abcdeffedcba98765432100011223344556677889900aabbccddeeff',
     '256-bit key'),
]


def get_tests(config={}):
    from pgp.cipher import camellia
    from Crypto.SelfTest.Cipher.common import make_block_tests
    return make_block_tests(camellia, "Camellia", test_data)


def test_camellia():
    for testcase in get_tests():
        yield testcase
