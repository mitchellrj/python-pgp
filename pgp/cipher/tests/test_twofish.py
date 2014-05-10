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

from pgp.cipher import twofish


# This is a list of (plaintext, ciphertext, key) tuples.
test_data = [
    # Test vectors from Schneier
    # https://www.schneier.com/code/twofish-kat.zip

    # ecb_ival.txt
    ('00000000000000000000000000000000', '9F589F5CF6122C32B6BFEC2F2AE8C35A',
     '00000000000000000000000000000000',
     '128-bit key'),

    ('00000000000000000000000000000000', 'CFD1D2E5A9BE9CDF501F13B892BD2248',
     '0123456789ABCDEFFEDCBA98765432100011223344556677',
     '192-bit key'),

    ('00000000000000000000000000000000', '37527BE0052334B89F0CFCCAE87CFA20',
     '0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF',
     '256-bit key'),

    # ecb_tbl.txt
    ('00000000000000000000000000000000', '9F589F5CF6122C32B6BFEC2F2AE8C35A',
     '00000000000000000000000000000000',
     '128-bit key'),

    ('00000000000000000000000000000000', 'EFA71F788965BD4453F860178FC19101',
     '000000000000000000000000000000000000000000000000',
     '192-bit key'),

    ('00000000000000000000000000000000', '57FF739D4DC92C1BD7FC01700CC8216F',
     '0000000000000000000000000000000000000000000000000000000000000000',
     '256-bit key'),

    # ecb_vk.txt
    ('00000000000000000000000000000000', '6BFD32804A1C3206C4BF85EB11241F89',
     '80000000000000000000000000000000',
     '128-bit key'),

    ('00000000000000000000000000000000', 'B5AED133641004F4121B66E7DB8F2FF0',
     '800000000000000000000000000000000000000000000000',
     '192-bit key'),

    ('00000000000000000000000000000000', '785229B51B515F30A1FCC88B969A4E47',
     '8000000000000000000000000000000000000000000000000000000000000000',
     '256-bit key'),

    # ecb_vt.txt
    ('80000000000000000000000000000000', '73B9FF14CF2589901FF52A0D6F4B7EDE',
     '00000000000000000000000000000000',
     '128-bit key'),

    ('80000000000000000000000000000000', '62EF193EDB7D399ACA50EC1CBE5398D8',
     '000000000000000000000000000000000000000000000000',
     '192-bit key'),

    ('80000000000000000000000000000000', '23A385F617F313DAC05BCB7EABD61807',
     '0000000000000000000000000000000000000000000000000000000000000000',
     '256-bit key'),

    # cbc_e_m.txt - the examples in this file appear to be just wrong
    # I verified the results below using
    # http://twofish.online-domain-tools.com/ as a reference implementation
    ('00000000000000000000000000000000', '9F589F5CF6122C32B6BFEC2F2AE8C35A',
     '00000000000000000000000000000000',
     '128-bit key',
     dict(mode='CBC', iv='00000000000000000000000000000000')),

    ('00000000000000000000000000000000', 'EFA71F788965BD4453F860178FC19101',
     '000000000000000000000000000000000000000000000000',
     '192-bit key',
     dict(mode='CBC', iv='00000000000000000000000000000000')),

    ('00000000000000000000000000000000', '57FF739D4DC92C1BD7FC01700CC8216F',
     '0000000000000000000000000000000000000000000000000000000000000000',
     '256-bit key',
     dict(mode='CBC', iv='00000000000000000000000000000000')),

]


def get_tests(config={}):
    return make_block_tests(twofish, "Twofish", test_data)


def test_twofish():
    if twofish is None:
        warnings.warn(
            "Twofish not available on this system. Skipping its tests."
            )
        return
    for testcase in get_tests():
        yield testcase


if hasattr(unittest, 'skip'):
    # Python >= 3.1
    test_camellia = unittest.skipIf(
                        twofish is None,
                        "Twofish not available on this system."
                    )(test_twofish)
