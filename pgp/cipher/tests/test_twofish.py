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
    ('00000000000000000000000000000000', '9f589f5cf6122c32b6bfec2f2ae8c35a',
     '00000000000000000000000000000000',
     '128-bit key'),

    ('00000000000000000000000000000000', 'cfd1d2e5a9be9cdf501f13b892bd2248',
     '0123456789abcdeffedcba98765432100011223344556677',
     '192-bit key'),

    ('00000000000000000000000000000000', '37527be0052334b89f0cfccae87cfa20',
     '0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff',
     '256-bit key'),

    # ecb_tbl.txt
    ('00000000000000000000000000000000', '9f589f5cf6122c32b6bfec2f2ae8c35a',
     '00000000000000000000000000000000',
     '128-bit key'),

    ('00000000000000000000000000000000', 'efa71f788965bd4453f860178fc19101',
     '000000000000000000000000000000000000000000000000',
     '192-bit key'),

    ('00000000000000000000000000000000', '57ff739d4dc92c1bd7fc01700cc8216f',
     '0000000000000000000000000000000000000000000000000000000000000000',
     '256-bit key'),

    # ecb_vk.txt
    ('00000000000000000000000000000000', '6bfd32804a1c3206c4bf85eb11241f89',
     '80000000000000000000000000000000',
     '128-bit key'),

    ('00000000000000000000000000000000', 'b5aed133641004f4121b66e7db8f2ff0',
     '800000000000000000000000000000000000000000000000',
     '192-bit key'),

    ('00000000000000000000000000000000', '785229b51b515f30a1fcc88b969a4e47',
     '8000000000000000000000000000000000000000000000000000000000000000',
     '256-bit key'),

    # ecb_vt.txt
    ('80000000000000000000000000000000', '73b9ff14cf2589901ff52a0d6f4b7ede',
     '00000000000000000000000000000000',
     '128-bit key'),

    ('80000000000000000000000000000000', '62ef193edb7d399aca50ec1cbe5398d8',
     '000000000000000000000000000000000000000000000000',
     '192-bit key'),

    ('80000000000000000000000000000000', '23a385f617f313dac05bcb7eabd61807',
     '0000000000000000000000000000000000000000000000000000000000000000',
     '256-bit key'),

    # cbc_e_m.txt - the examples in this file appear to be just wrong
    # I verified the results below using
    # http://twofish.online-domain-tools.com/ as a reference implementation
    ('00000000000000000000000000000000', '9f589f5cf6122c32b6bfec2f2ae8c35a',
     '00000000000000000000000000000000',
     '128-bit key',
     dict(mode='CBC', iv='00000000000000000000000000000000')),

    ('00000000000000000000000000000000', 'efa71f788965bd4453f860178fc19101',
     '000000000000000000000000000000000000000000000000',
     '192-bit key',
     dict(mode='CBC', iv='00000000000000000000000000000000')),

    ('00000000000000000000000000000000', '57ff739d4dc92c1bd7fc01700cc8216f',
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
        # Hack for Nose
        yield getattr(testcase, testcase._testMethodName)


if hasattr(unittest, 'skip'):
    # Python >= 3.1
    test_camellia = unittest.skipIf(
                        twofish is None,
                        "Twofish not available on this system."
                    )(test_twofish)
