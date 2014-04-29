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

try:
    from io import StringIO
except ImportError:
    from StringIO import StringIO
import os.path
import time
import unittest

try:
    from unittest import mock
except ImportError:
    import mock

from pgp import exceptions
from pgp import parse
from pgp import test_keys
from pgp.utils import bytearray_to_hex


def load_data(filename):
    filepath = os.path.join(
        os.path.dirname(__file__),
        'test_data',
        filename
        )
    with open(filepath, 'rb') as fh:
        return fh.read()


SAMPLE_JPG_DATA = load_data('jpg.jpg')
SAMPLE_PNG_DATA = load_data('png.png')


class TestParseNotation(unittest.TestCase):

    def test_parse_notation(self):
        """Parse an ordinary, plain-text notation"""

        subpacket = test_keys.make_notation_subpacket(
                u'pyks.org', u'Test Key', u'Test Value', True, False, True
                )
        result = parse.parse_notation(subpacket['data'],
                                      subpacket['hashed'])
        expected = {
            u'name': u'Test Key',
            u'value': u'Test Value',
            u'namespace': u'pyks.org',
            u'hashed': True,
            u'human_readable': True,
            }
        self.assertEqual(result, expected)

    def test_parse_notation_bad_flags(self):
        """Test parsing a notation with incorrect flag data yields
        None.
        """

        subpacket = test_keys.make_notation_subpacket(
                u'pyks.org', u'Test Key', u'Test Value', True, False, True
                )
        subpacket['data'][1] = 0x01
        result = parse.parse_notation(subpacket['data'],
                                      subpacket['hashed'])
        self.assertEqual(result, None)

    def test_parse_notation_unicode(self):
        """Test a notation with unicode characters is decoded
        properly."""

        subpacket = test_keys.make_notation_subpacket(
                u'pyks.\u2603', u'Test\u2603Key', u'Test\u2603Value', True,
                False, True
                )
        result = parse.parse_notation(subpacket['data'],
                                      subpacket['hashed'])
        expected = {
            u'name': u'Test\u2603Key',
            u'value': u'Test\u2603Value',
            u'namespace': u'pyks.\u2603',
            u'hashed': True,
            u'human_readable': True,
            }
        self.assertEqual(result, expected)

    def test_parse_notation_not_human_readable(self):
        """Test parsing of non-text notations works and returns data
        encoded using the specified function.
        """

        subpacket = test_keys.make_notation_subpacket(
                u'pyks.org', u'Test Key', b'\x00\x01\x02\x03\x04\x05', False,
                False, True
                )
        result = parse.parse_notation(subpacket['data'],
                                      subpacket['hashed'],
                                      encode_non_readable=lambda x: x[::-1])
        expected = {
            u'name': u'Test Key',
            u'value': bytearray([0x05, 0x04, 0x03, 0x02, 0x01, 0x00]),
            u'namespace': u'pyks.org',
            u'hashed': True,
            u'human_readable': False,
            }
        self.assertEqual(result, expected)

    def test_parse_notation_not_hashed(self):
        """Check notation parsing yields the correct value indicating
        if the subpacket was hashed or not.
        """

        subpacket = test_keys.make_notation_subpacket(
                u'pyks.org', u'Test Key', u'Test Value', True, False, False
                )
        result = parse.parse_notation(subpacket['data'],
                                      subpacket['hashed'])
        expected = {
            u'name': u'Test Key',
            u'value': u'Test Value',
            u'namespace': u'pyks.org',
            u'hashed': False,
            u'human_readable': True,
            }
        self.assertEqual(result, expected)


class TestParseEmbeddedSignature(unittest.TestCase):

    def setUp(self):
        self.MockPacketClass = mock.Mock()
        self.mock_parse_fn = mock.Mock()

    def test_parse_embedded_signature(self):
        data = bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])
        hashed = True
        result = parse.parse_embedded_signature(
                    data, hashed, self.MockPacketClass, self.mock_parse_fn)
        self.assertEqual(self.MockPacketClass.call_count, 1)
        self.assertEqual(self.MockPacketClass.call_args[0][0], 2)
        self.assertEqual(self.MockPacketClass.call_args[0][2], True)
        self.assertEqual(self.MockPacketClass.call_args[0][3], data)
        signature_packet = self.MockPacketClass.return_value
        self.assertEqual(self.mock_parse_fn.call_count, 1)
        self.assertEqual(self.mock_parse_fn.call_args[0][0], signature_packet)
        self.assertEqual(self.mock_parse_fn.call_args[0][1], 2,
                         "Signature parse function called with wrong parent "
                         "packet type")
        if len(self.mock_parse_fn.call_args[0]) == 3:
            self.assertEqual(self.mock_parse_fn.call_args[0][2], hashed)
        elif 'sig_hashed' in self.mock_parse_fn.call_args[1]:
            self.assertEqual(self.mock_parse_fn.call_args[1]['sig_hashed'],
                             hashed)
        else:
            self.failIf(True, "Parent hashed argument not passed to embedded "
                              "signature parse function correctly.")

        self.assertEqual(result, self.mock_parse_fn.return_value)

    def test_parse_embedded_signature_not_hashed(self):
        data = bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])
        hashed = False
        result = parse.parse_embedded_signature(
                    data, hashed, self.MockPacketClass, self.mock_parse_fn)
        self.assertEqual(self.MockPacketClass.call_count, 1)
        self.assertEqual(self.MockPacketClass.call_args[0][0], 2)
        self.assertEqual(self.MockPacketClass.call_args[0][2], True)
        self.assertEqual(self.MockPacketClass.call_args[0][3], data)
        signature_packet = self.MockPacketClass.return_value
        self.assertEqual(self.mock_parse_fn.call_count, 1)
        self.assertEqual(self.mock_parse_fn.call_args[0][0], signature_packet)
        self.assertEqual(self.mock_parse_fn.call_args[0][1], 2,
                         "Signature parse function called with wrong parent "
                         "packet type")
        if len(self.mock_parse_fn.call_args[0]) == 3:
            self.assertEqual(self.mock_parse_fn.call_args[0][2], hashed)
        elif 'sig_hashed' in self.mock_parse_fn.call_args[1]:
            self.assertEqual(self.mock_parse_fn.call_args[1]['sig_hashed'],
                             hashed)
        else:
            self.failIf(True, "Parent hashed argument not passed to embedded "
                              "signature parse function correctly.")

        self.assertEqual(result, self.mock_parse_fn.return_value)


class TestParseSignatureSubpacket(unittest.TestCase):

    @classmethod
    def make_dummy_subpacket(cls, sub_data):
        dummy = mock.Mock()
        dummy.subtype = sub_data['type']
        dummy.data = sub_data['data']
        dummy.hashed = sub_data['hashed']
        dummy.critical = sub_data['critical']
        return dummy

    def test_parse_creation_time_subpacket(self):
        t = int(time.time())
        sub_data = test_keys.make_creation_time_subpacket(t, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {'creation_time': t})

    def test_parse_creation_time_subpacket_unhashed(self):
        t = int(time.time())
        sub_data = test_keys.make_creation_time_subpacket(t, False, False)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {})

    def test_parse_expiration_time_subpacket(self):
        t = 2592000  # 30 days
        sub_data = test_keys.make_expiration_time_subpacket(t, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {'expiration_seconds': t})

    def test_parse_expiration_time_subpacket_zero(self):
        t = 0  # no expiration
        sub_data = test_keys.make_expiration_time_subpacket(t, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {})

    def test_parse_exportable_true(self):
        sub_data = test_keys.make_exportable_subpacket(True, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {'exportable': True})

    def test_parse_exportable_false(self):
        sub_data = test_keys.make_exportable_subpacket(False, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        self.assertRaises(
                exceptions.LocalCertificationSignature,
                parse.parse_signature_subpacket,
                sub, signature, signature_owner_type
                )
        self.assertEqual(signature, {})

    def test_parse_trust(self):
        sub_data = test_keys.make_trust_signature_subpacket(3, 60, False,
                                                            True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {'trust_level': 3, 'trust_amount': 60})

    def test_parse_regex(self):
        sub_data = test_keys.make_regex_subpacket('(spam|ham)', False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        expected = [{
            'regex': '(spam|ham)',
            'hashed': True
            }]
        validate_regex = lambda x: None
        parse.parse_signature_subpacket(
                    sub, signature, signature_owner_type,
                    validate_subpacket_regex=validate_regex)
        self.assertEqual(signature, {'regexes': expected})

    def test_parse_regex_not_hashed(self):
        sub_data = test_keys.make_regex_subpacket('(spam|ham)', False, False)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        validate_regex = lambda x: None
        parse.parse_signature_subpacket(
                    sub, signature, signature_owner_type,
                    validate_subpacket_regex=validate_regex)
        expected = [{
            'regex': '(spam|ham)',
            'hashed': False
            }]
        self.assertEqual(signature, {'regexes': expected})

    def test_parse_regex_sig_hashed(self):
        sub_data = test_keys.make_regex_subpacket('(spam|ham)', False, False)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        validate_regex = lambda x: None
        parse.parse_signature_subpacket(
                    sub, signature, signature_owner_type,
                    signature_hashed=True,
                    validate_subpacket_regex=validate_regex)
        expected = [{
            'regex': '(spam|ham)',
            'hashed': True
            }]
        self.assertEqual(signature, {'regexes': expected})

    def test_parse_regex_appends(self):
        sub_data = test_keys.make_regex_subpacket('(spam|ham)', False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'regexes': [{'regex': '[eggs]', 'hashed':True}]}
        signature_owner_type = 6
        validate_regex = lambda x: None
        parse.parse_signature_subpacket(
                    sub, signature, signature_owner_type,
                    validate_subpacket_regex=validate_regex)
        expected = [
            {
            'regex': '[eggs]',
            'hashed':True
            },
            {
            'regex': '(spam|ham)',
            'hashed': True,
            }]
        self.assertEqual(signature, {'regexes': expected})

    def test_parse_regex_invalid(self):
        sub_data = test_keys.make_regex_subpacket('(', False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6

        def validate_regex(*args):
            raise exceptions.RegexValueError(0, '(')

        parse.parse_signature_subpacket(
                    sub, signature, signature_owner_type,
                    validate_subpacket_regex=validate_regex)
        self.assertEqual(signature, {})

    def test_parse_revocable_true(self):
        sub_data = test_keys.make_revocable_subpacket(True, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {'revocable': True})

    def test_parse_revocable_false(self):
        sub_data = test_keys.make_revocable_subpacket(False, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {'revocable': False})

    def test_parse_key_expiration_time(self):
        t = 2592000  # 30 days
        sub_data = test_keys.make_key_expiration_time_subpacket(t, False,
                                                                True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {'key_expiration_seconds': t, 'selfsig': True}
        self.assertEqual(signature, expected)

    def test_parse_key_expiration_time_zero(self):
        t = 0  # 30 days
        sub_data = test_keys.make_key_expiration_time_subpacket(t, False,
                                                                True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {'selfsig': True}
        self.assertEqual(signature, expected)

    def test_parse_key_expiration_time_not_selfsig(self):
        t = 0  # 30 days
        sub_data = test_keys.make_key_expiration_time_subpacket(t, False,
                                                                True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': False}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {'selfsig': False}
        self.assertEqual(signature, expected)

    def test_parse_preferred_sym_algorithms(self):
        types = [9, 2, 1]
        sub_data = test_keys.make_preferred_sym_algorithms_subpacket(
                            types, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {'selfsig': True, 'preferred_sym_algorithms': [9, 2, 1]}
        self.assertEqual(signature, expected)

    def test_parse_preferred_sym_algorithms_not_selfsig(self):
        types = [9, 2, 1]
        sub_data = test_keys.make_preferred_sym_algorithms_subpacket(
                            types, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': False}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {'selfsig': False}
        self.assertEqual(signature, expected)

    def test_parse_revocation_key(self):
        fingerprint = '0123456789ABCDEF0123456789ABCDEF01234567'
        pub_algorithm_type = 1
        sub_data = test_keys.make_revocation_key_subpacket(
                        fingerprint, pub_algorithm_type, False, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature_owner_type = 6
        signature = {}
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
                'revocation_key_sensitive': False,
                'revocation_key_pub_algorithm_type': pub_algorithm_type,
                'revocation_key': fingerprint,
            }
        self.assertEqual(signature, expected)

    def test_parse_revocation_key_bad_data(self):
        fingerprint = '0123456789ABCDEF0123456789ABCDEF01234567'
        pub_algorithm_type = 1
        sub_data = test_keys.make_revocation_key_subpacket(
                        fingerprint, pub_algorithm_type, False, False, True)
        sub_data['data'][0] -= 0x80
        sub = self.make_dummy_subpacket(sub_data)
        signature_owner_type = 6
        signature = {}
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {})

    def test_parse_revocation_key_sensitive(self):
        fingerprint = '0123456789ABCDEF0123456789ABCDEF01234567'
        pub_algorithm_type = 1
        sub_data = test_keys.make_revocation_key_subpacket(
                        fingerprint, pub_algorithm_type, True, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature_owner_type = 6
        signature = {}
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
                'revocation_key_sensitive': True,
                'revocation_key_pub_algorithm_type': pub_algorithm_type,
                'revocation_key': fingerprint,
            }
        self.assertEqual(signature, expected)

    def test_parse_issuer(self):
        key_id = b'0123456789ABCDEF'
        sub_data = test_keys.make_issuer_key_subpacket(key_id, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature_owner_type = 6
        signature = {}
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {'key_ids': [{'key_id': key_id, 'hashed': True}]}
        self.assertEqual(signature, expected)

    def test_parse_issuer_not_hashed(self):
        key_id = b'0123456789ABCDEF'
        sub_data = test_keys.make_issuer_key_subpacket(key_id, False, False)
        sub = self.make_dummy_subpacket(sub_data)
        signature_owner_type = 6
        signature = {}
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {'key_ids': [{'key_id': key_id, 'hashed': False}]}
        self.assertEqual(signature, expected)

    def test_parse_issuer_appends(self):
        key_id = b'0123456789ABCDEF'
        sub_data = test_keys.make_issuer_key_subpacket(key_id, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature_owner_type = 6
        signature = {'key_ids': [{'key_id': key_id[::-1], 'hashed': True}]}
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {'key_ids': [{'key_id': key_id[::-1], 'hashed': True},
                                {'key_id': key_id, 'hashed': True}]}
        self.assertEqual(signature, expected)

    def test_parse_issuer_sig_hashed(self):
        key_id = b'0123456789ABCDEF'
        sub_data = test_keys.make_issuer_key_subpacket(key_id, False, False)
        sub = self.make_dummy_subpacket(sub_data)
        signature_owner_type = 6
        signature = {}
        parse.parse_signature_subpacket(sub, signature, signature_owner_type,
                                        signature_hashed=True)
        expected = {'key_ids': [{'key_id': key_id, 'hashed': True}]}
        self.assertEqual(signature, expected)

    def test_parse_notation(self):
        notation = {
            u'name': u'Test Key',
            u'value': u'Test Value',
            u'namespace': u'pyks.org',
            u'hashed': True,
            }
        sub_data = test_keys.make_notation_subpacket(
                        is_text=True, critical=False, **notation)
        sub = self.make_dummy_subpacket(sub_data)
        signature_owner_type = 6
        signature = {}

        def mock_parse_notation(data, hashed):
            self.assertEqual(data, sub_data['data'])
            self.assertEqual(hashed, notation['hashed'])
            return notation

        parse.parse_signature_subpacket(sub, signature, signature_owner_type,
                                        parse_notation=mock_parse_notation)
        self.assertEqual(signature, {'notations': [notation]})

    def test_parse_notation_appends(self):
        notation = {
            u'name': u'Test Key',
            u'value': u'Test Value',
            u'namespace': u'pyks.org',
            u'hashed': True,
            }
        sub_data = test_keys.make_notation_subpacket(
                        is_text=True, critical=False, **notation)
        sub = self.make_dummy_subpacket(sub_data)
        signature_owner_type = 6
        existing_notation = {
            u'name': u'Test Key 2',
            u'value': u'Test Value 2',
            u'namespace': u'python.org',
            u'hashed': False,
            }
        signature = {'notations': [
            existing_notation,
            ]}

        def mock_parse_notation(data, hashed):
            self.assertEqual(data, sub_data['data'])
            self.assertEqual(hashed, notation['hashed'])
            return notation

        parse.parse_signature_subpacket(sub, signature, signature_owner_type,
                                        parse_notation=mock_parse_notation)
        expected = {'notations': [existing_notation, notation]}
        self.assertEqual(signature, expected)

    def test_parse_notation_invalid(self):
        notation = {
            u'name': u'Test Key',
            u'value': u'Test Value',
            u'namespace': u'pyks.org',
            u'hashed': True,
            }
        sub_data = test_keys.make_notation_subpacket(
                        is_text=True, critical=False, **notation)
        sub = self.make_dummy_subpacket(sub_data)
        signature_owner_type = 6
        existing_notation = {
            u'name': u'Test Key 2',
            u'value': u'Test Value 2',
            u'namespace': u'python.org',
            u'hashed': False,
            }
        signature = {'notations': [
            existing_notation,
            ]}

        def mock_parse_notation(data, hashed):
            self.assertEqual(data, sub_data['data'])
            self.assertEqual(hashed, notation['hashed'])
            return None

        parse.parse_signature_subpacket(sub, signature, signature_owner_type,
                                        parse_notation=mock_parse_notation)
        expected = {'notations': [existing_notation]}
        self.assertEqual(signature, expected)

    def test_parse_notation_critical(self):
        notation = {
            u'name': u'Test Key',
            u'value': u'Test Value',
            u'namespace': u'pyks.org',
            u'hashed': True,
            }
        sub_data = test_keys.make_notation_subpacket(
                        is_text=True, critical=True, **notation)
        sub = self.make_dummy_subpacket(sub_data)
        signature_owner_type = 6
        signature = {}

        def mock_parse_notation(data, hashed):
            self.assertEqual(data, sub_data['data'])
            self.assertEqual(hashed, notation['hashed'])
            return notation

        self.assertRaises(
                exceptions.CannotParseCriticalNotation,
                parse.parse_signature_subpacket,
                sub, signature, signature_owner_type,
                parse_notation=mock_parse_notation
                )
        self.assertEqual(signature, {})

    def test_parse_preferred_hash_algorithms(self):
        types = [9, 2, 1]
        sub_data = test_keys.make_preferred_hash_algorithms_subpacket(
                            types, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {'selfsig': True, 'preferred_hash_algorithms': [9, 2, 1]}
        self.assertEqual(signature, expected)

    def test_parse_preferred_hash_algorithms_not_selfsig(self):
        types = [9, 2, 1]
        sub_data = test_keys.make_preferred_hash_algorithms_subpacket(
                            types, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': False}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {'selfsig': False}
        self.assertEqual(signature, expected)

    def test_parse_preferred_compression_algorithms(self):
        types = [9, 2, 1]
        sub_data = test_keys.make_preferred_compression_algorithms_subpacket(
                            types, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {'selfsig': True,
                    'preferred_compression_algorithms': [9, 2, 1]}
        self.assertEqual(signature, expected)

    def test_parse_preferred_compression_algorithms_not_selfsig(self):
        types = [9, 2, 1]
        sub_data = test_keys.make_preferred_compression_algorithms_subpacket(
                            types, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': False}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {'selfsig': False}
        self.assertEqual(signature, expected)

    def test_parse_key_server_preferences(self):
        sub_data = test_keys.make_key_server_prefs_subpacket(True, False,
                                                             True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {'selfsig': True, 'key_server_no_modify': True}
        self.assertEqual(signature, expected)

    def test_parse_key_server_preferences_no_modify_false(self):
        sub_data = test_keys.make_key_server_prefs_subpacket(False, False,
                                                             True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {'selfsig': True, 'key_server_no_modify': False}
        self.assertEqual(signature, expected)

    def test_parse_key_server_preferences_not_selfsig(self):
        sub_data = test_keys.make_key_server_prefs_subpacket(True, False,
                                                             True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': False}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {'selfsig': False}
        self.assertEqual(signature, expected)

    def test_parse_key_server_preferences_bad_first_packet(self):
        sub_data = test_keys.make_key_server_prefs_subpacket(True, False,
                                                             True)
        sub_data['data'][0] += 1
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {'selfsig': True}
        self.assertEqual(signature, expected)

    def test_parse_key_server_preferences_bad_extra_packets(self):
        sub_data = test_keys.make_key_server_prefs_subpacket(True, False,
                                                             True)
        sub_data['data'].append(1)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {'selfsig': True}
        self.assertEqual(signature, expected)

    def test_parse_key_server_preferences_sane_extra_packets(self):
        sub_data = test_keys.make_key_server_prefs_subpacket(True, False,
                                                             True)
        sub_data['data'].append(0)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {'selfsig': True, 'key_server_no_modify': True}
        self.assertEqual(signature, expected)

    def test_parse_preferred_key_server(self):
        sub_data = test_keys.make_preferred_key_server_subpacket(
                            u'https://pyks.org/'
                        )
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {'preferred_key_server': u'https://pyks.org/'}
        self.assertEqual(signature, expected)

    def test_parse_preferred_key_server_unicode(self):
        sub_data = test_keys.make_preferred_key_server_subpacket(
                            u'https://pyks.org/\u2603'
                        )
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {'preferred_key_server': u'https://pyks.org/\u2603'}
        self.assertEqual(signature, expected)

    def test_parse_primary_true(self):
        sub_data = test_keys.make_primary_user_id_subpacket(True, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True}
        signature_owner_type = 13
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {'selfsig': True, 'primary': 1})

    def test_parse_primary_int_value(self):
        sub_data = test_keys.make_primary_user_id_subpacket(5, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True}
        signature_owner_type = 13
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {'selfsig': True, 'primary': 5})

    def test_parse_primary_false(self):
        sub_data = test_keys.make_primary_user_id_subpacket(False, False,
                                                            True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True}
        signature_owner_type = 13
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {'selfsig': True, 'primary': 0})

    def test_parse_primary_not_selfsig(self):
        sub_data = test_keys.make_primary_user_id_subpacket(True, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': False}
        signature_owner_type = 13
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {'selfsig': False})

    def test_parse_primary_wrong_packet_type(self):
        sub_data = test_keys.make_primary_user_id_subpacket(True, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {'selfsig': True})

    def test_parse_policy_uri(self):
        sub_data = test_keys.make_policy_uri_subpacket(
                        u'http://pyks.org/policy', False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {'policy_uri': u'http://pyks.org/policy'})

    def test_parse_policy_uri_unicode(self):
        sub_data = test_keys.make_policy_uri_subpacket(
                        u'http://pyks.org/\u2603', False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {'policy_uri': u'http://pyks.org/\u2603'})

    def test_parse_flags(self):
        sub_data = test_keys.make_flags_subpacket(
                            may_certify=True,
                            may_sign=True,
                            may_encrypt_comms=True,
                            may_encrypt_storage=True,
                            may_have_been_split=True,
                            may_be_used_for_auth=True,
                            may_be_shared=True,
                            critical=False,
                            hashed=True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True, 'sig_type': 0x1f}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'selfsig': True,
            'sig_type': 0x1f,
            'may_certify_others': True,
            'may_sign_data': True,
            'may_encrypt_comms': True,
            'may_encrypt_storage': True,
            'may_be_used_for_auth': True,
            'may_have_been_split': True,
            'may_have_multiple_owners': True,
            }
        self.assertEqual(signature, expected)

    def test_parse_flags_subkey_binding_sig(self):
        sub_data = test_keys.make_flags_subpacket(
                            may_certify=True,
                            may_sign=True,
                            may_encrypt_comms=True,
                            may_encrypt_storage=True,
                            may_have_been_split=True,
                            may_be_used_for_auth=True,
                            may_be_shared=True,
                            critical=False,
                            hashed=True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True, 'sig_type': 0x18}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'selfsig': True,
            'sig_type': 0x18,
            'may_certify_others': True,
            'may_sign_data': True,
            'may_encrypt_comms': True,
            'may_encrypt_storage': True,
            'may_be_used_for_auth': True,
            'may_have_been_split': True,
            'may_have_multiple_owners': True,
            }
        self.assertEqual(signature, expected)

    def test_parse_flags_values(self):
        sub_data = test_keys.make_flags_subpacket(
                            may_certify=False,
                            may_sign=True,
                            may_encrypt_comms=True,
                            may_encrypt_storage=True,
                            may_have_been_split=True,
                            may_be_used_for_auth=True,
                            may_be_shared=True,
                            critical=False,
                            hashed=True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True, 'sig_type': 0x1f}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'selfsig': True,
            'sig_type': 0x1f,
            'may_certify_others': False,
            'may_sign_data': True,
            'may_encrypt_comms': True,
            'may_encrypt_storage': True,
            'may_have_been_split': True,
            'may_be_used_for_auth': True,
            'may_have_multiple_owners': True,
            }
        self.assertEqual(signature, expected)

        sub_data = test_keys.make_flags_subpacket(
                            may_certify=True,
                            may_sign=False,
                            may_encrypt_comms=True,
                            may_encrypt_storage=True,
                            may_have_been_split=True,
                            may_be_used_for_auth=True,
                            may_be_shared=True,
                            critical=False,
                            hashed=True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True, 'sig_type': 0x1f}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'selfsig': True,
            'sig_type': 0x1f,
            'may_certify_others': True,
            'may_sign_data': False,
            'may_encrypt_comms': True,
            'may_encrypt_storage': True,
            'may_have_been_split': True,
            'may_be_used_for_auth': True,
            'may_have_multiple_owners': True,
            }
        self.assertEqual(signature, expected)

        sub_data = test_keys.make_flags_subpacket(
                            may_certify=True,
                            may_sign=True,
                            may_encrypt_comms=False,
                            may_encrypt_storage=True,
                            may_have_been_split=True,
                            may_be_used_for_auth=True,
                            may_be_shared=True,
                            critical=False,
                            hashed=True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True, 'sig_type': 0x1f}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'selfsig': True,
            'sig_type': 0x1f,
            'may_certify_others': True,
            'may_sign_data': True,
            'may_encrypt_comms': False,
            'may_encrypt_storage': True,
            'may_have_been_split': True,
            'may_be_used_for_auth': True,
            'may_have_multiple_owners': True,
            }
        self.assertEqual(signature, expected)

        sub_data = test_keys.make_flags_subpacket(
                            may_certify=True,
                            may_sign=True,
                            may_encrypt_comms=True,
                            may_encrypt_storage=False,
                            may_have_been_split=True,
                            may_be_used_for_auth=True,
                            may_be_shared=True,
                            critical=False,
                            hashed=True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True, 'sig_type': 0x1f}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'selfsig': True,
            'sig_type': 0x1f,
            'may_certify_others': True,
            'may_sign_data': True,
            'may_encrypt_comms': True,
            'may_encrypt_storage': False,
            'may_have_been_split': True,
            'may_be_used_for_auth': True,
            'may_have_multiple_owners': True,
            }
        self.assertEqual(signature, expected)

        sub_data = test_keys.make_flags_subpacket(
                            may_certify=True,
                            may_sign=True,
                            may_encrypt_comms=True,
                            may_encrypt_storage=True,
                            may_have_been_split=False,
                            may_be_used_for_auth=True,
                            may_be_shared=True,
                            critical=False,
                            hashed=True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True, 'sig_type': 0x1f}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'selfsig': True,
            'sig_type': 0x1f,
            'may_certify_others': True,
            'may_sign_data': True,
            'may_encrypt_comms': True,
            'may_encrypt_storage': True,
            'may_have_been_split': False,
            'may_be_used_for_auth': True,
            'may_have_multiple_owners': True,
            }
        self.assertEqual(signature, expected)

        sub_data = test_keys.make_flags_subpacket(
                            may_certify=True,
                            may_sign=True,
                            may_encrypt_comms=True,
                            may_encrypt_storage=True,
                            may_have_been_split=True,
                            may_be_used_for_auth=False,
                            may_be_shared=True,
                            critical=False,
                            hashed=True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True, 'sig_type': 0x1f}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'selfsig': True,
            'sig_type': 0x1f,
            'may_certify_others': True,
            'may_sign_data': True,
            'may_encrypt_comms': True,
            'may_encrypt_storage': True,
            'may_have_been_split': True,
            'may_be_used_for_auth': False,
            'may_have_multiple_owners': True,
            }
        self.assertEqual(signature, expected)

        sub_data = test_keys.make_flags_subpacket(
                            may_certify=True,
                            may_sign=True,
                            may_encrypt_comms=True,
                            may_encrypt_storage=True,
                            may_have_been_split=True,
                            may_be_used_for_auth=True,
                            may_be_shared=False,
                            critical=False,
                            hashed=True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True, 'sig_type': 0x1f}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'selfsig': True,
            'sig_type': 0x1f,
            'may_certify_others': True,
            'may_sign_data': True,
            'may_encrypt_comms': True,
            'may_encrypt_storage': True,
            'may_have_been_split': True,
            'may_be_used_for_auth': True,
            'may_have_multiple_owners': False,
            }
        self.assertEqual(signature, expected)

    def test_parse_flags_not_selfsig(self):
        sub_data = test_keys.make_flags_subpacket(
                            may_certify=True,
                            may_sign=True,
                            may_encrypt_comms=True,
                            may_encrypt_storage=True,
                            may_have_been_split=True,
                            may_be_used_for_auth=True,
                            may_be_shared=True,
                            critical=False,
                            hashed=True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': False, 'sig_type': 0x1f}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'selfsig': False,
            'sig_type': 0x1f,
            'may_certify_others': True,
            'may_sign_data': True,
            'may_encrypt_comms': True,
            'may_encrypt_storage': True,
            'may_be_used_for_auth': True,
            }
        self.assertEqual(signature, expected)

    def test_parse_flags_wrong_sig_type(self):
        sub_data = test_keys.make_flags_subpacket(
                            may_certify=True,
                            may_sign=True,
                            may_encrypt_comms=True,
                            may_encrypt_storage=True,
                            may_have_been_split=True,
                            may_be_used_for_auth=True,
                            may_be_shared=True,
                            critical=False,
                            hashed=True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': False, 'sig_type': 0x10}
        signature_owner_type = 13
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'selfsig': False,
            'sig_type': 0x10,
            'may_certify_others': True,
            'may_sign_data': True,
            'may_encrypt_comms': True,
            'may_encrypt_storage': True,
            'may_be_used_for_auth': True,
            }
        self.assertEqual(signature, expected)

    def test_parse_user_id(self):
        sub_data = test_keys.make_user_id_subpacket(
                        u'Fred Bloggs', False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {'user_id': u'Fred Bloggs'})

    def test_parse_user_id_unicode(self):
        sub_data = test_keys.make_user_id_subpacket(
                        u'Fred\u2603Bloggs', False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {'user_id': u'Fred\u2603Bloggs'})

    def test_parse_revocation_reason(self):
        sub_data = test_keys.make_revocation_reason_subpacket(
                        1, u'Superceded by 0x012345678', False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'sig_type': 0x20}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'sig_type': 0x20,
            'revocation_code': 1,
            'revocation_reason': u'Superceded by 0x012345678',
            }
        self.assertEqual(signature, expected)

    def test_parse_revocation_reason_unicode(self):
        sub_data = test_keys.make_revocation_reason_subpacket(
                        1, u'Superceded by \u2603', False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'sig_type': 0x20}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'sig_type': 0x20,
            'revocation_code': 1,
            'revocation_reason': u'Superceded by \u2603',
            }
        self.assertEqual(signature, expected)

    def test_parse_revocation_reason_experimental_code(self):
        sub_data = test_keys.make_revocation_reason_subpacket(
                        100, u'Superceded by 0x012345678', False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'sig_type': 0x20}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'sig_type': 0x20,
            'revocation_code': 100,
            'revocation_reason': u'Superceded by 0x012345678',
            }
        self.assertEqual(signature, expected)
        sub_data = test_keys.make_revocation_reason_subpacket(
                        110, u'Superceded by 0x012345678', False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'sig_type': 0x20}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'sig_type': 0x20,
            'revocation_code': 110,
            'revocation_reason': u'Superceded by 0x012345678',
            }
        self.assertEqual(signature, expected)

    def test_parse_revocation_reason_bad_code(self):
        sub_data = test_keys.make_revocation_reason_subpacket(
                        111, u'Superceded by 0x012345678', False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'sig_type': 0x20}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'sig_type': 0x20,
            }
        self.assertEqual(signature, expected)
        sub_data = test_keys.make_revocation_reason_subpacket(
                        99, u'Superceded by 0x012345678', False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'sig_type': 0x20}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'sig_type': 0x20,
            }
        self.assertEqual(signature, expected)
        sub_data = test_keys.make_revocation_reason_subpacket(
                        5, u'Superceded by 0x012345678', False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'sig_type': 0x20}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'sig_type': 0x20,
            }
        self.assertEqual(signature, expected)

    def test_parse_revocation_reason_bad_sig_type(self):
        sub_data = test_keys.make_revocation_reason_subpacket(
                        1, u'Superceded by 0x012345678', False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'sig_type': 0x10}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'sig_type': 0x10,
            }
        self.assertEqual(signature, expected)

    def test_parse_features(self):
        sub_data = test_keys.make_features_subpacket(True, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'selfsig': True,
            'supports_modification_detection': True,
            }
        self.assertEqual(signature, expected)

    def test_parse_features_not_selfsig(self):
        sub_data = test_keys.make_features_subpacket(True, False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': False}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'selfsig': False,
            }
        self.assertEqual(signature, expected)

    def test_parse_features_bad_data(self):
        sub_data = test_keys.make_features_subpacket(True, False, True)
        sub_data['data'][0] += 4
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'selfsig': True,
            }
        self.assertEqual(signature, expected)

    def test_parse_features_sane_extra_data(self):
        sub_data = test_keys.make_features_subpacket(True, False, True)
        sub_data['data'].append(0)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'selfsig': True,
            'supports_modification_detection': True,
            }
        self.assertEqual(signature, expected)

    def test_parse_features_bad_extra_data(self):
        sub_data = test_keys.make_features_subpacket(True, False, True)
        sub_data['data'].append(1)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {'selfsig': True}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'selfsig': True,
            }
        self.assertEqual(signature, expected)

    def test_parse_target(self):
        sub_data = test_keys.make_target_subpacket(
                        1, 5, bytearray([0x01, 0x02, 0x03]), False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'target_pub_key_algorithm': 1,
            'target_hash_algorithm': 5,
            'target_hash': '010203'
            }
        self.assertEqual(signature, expected)

    def test_parse_target_all_data(self):
        sub_data = test_keys.make_target_subpacket(
                        1, 5, bytearray([0x01, 0x02, 0x03] * 100),
                        False, True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        expected = {
            'target_pub_key_algorithm': 1,
            'target_hash_algorithm': 5,
            'target_hash': '010203' * 100
            }
        self.assertEqual(signature, expected)

    def test_parse_embedded_signature(self):
        sig_data = bytearray([0x01, 0x02, 0x03, 0x04, 0x05])
        sub_data = test_keys.make_signature_subpacket(32, sig_data, False,
                                                      True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6

        def parse_embedded_signature(data, hashed):
            self.assertEqual(data, sig_data)
            self.assertEqual(hashed, True)
            return {'data': data, 'hashed': hashed}

        parse.parse_signature_subpacket(
                    sub, signature, signature_owner_type,
                    parse_embedded_signature=parse_embedded_signature)
        expected = {
            'embedded_signatures': [{'data': sig_data, 'hashed': True}]
            }
        self.assertEqual(signature, expected)

    def test_parse_embedded_signature_appends(self):
        sig_data = bytearray([0x01, 0x02, 0x03, 0x04, 0x05])
        sub_data = test_keys.make_signature_subpacket(32, sig_data, False,
                                                      True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {
            'embedded_signatures': [
                {
                    'data': sig_data[::-1],
                    'hashed': False
                }
            ]
        }
        signature_owner_type = 6

        def parse_embedded_signature(data, hashed):
            self.assertEqual(data, sig_data)
            self.assertEqual(hashed, True)
            return {'data': data, 'hashed': hashed}

        parse.parse_signature_subpacket(
                    sub, signature, signature_owner_type,
                    parse_embedded_signature=parse_embedded_signature)
        expected = {
            'embedded_signatures': [
                {
                    'data': sig_data[::-1],
                    'hashed': False
                },
                {
                    'data': sig_data,
                    'hashed': True
                }
            ]}
        self.assertEqual(signature, expected)

    def test_parse_embedded_signature_sig_hashed(self):
        sig_data = bytearray([0x01, 0x02, 0x03, 0x04, 0x05])
        sub_data = test_keys.make_signature_subpacket(32, sig_data, False,
                                                      False)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6

        def parse_embedded_signature(data, hashed):
            self.assertEqual(data, sig_data)
            self.assertEqual(hashed, True)
            return {'data': data, 'hashed': hashed}

        parse.parse_signature_subpacket(
                    sub, signature, signature_owner_type,
                    signature_hashed=True,
                    parse_embedded_signature=parse_embedded_signature)
        expected = {
            'embedded_signatures': [{'data': sig_data, 'hashed': True}]
            }
        self.assertEqual(signature, expected)

    def test_parse_unknown(self):
        sub_data = test_keys.make_signature_subpacket(33, bytearray(), False,
                                                      True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {})

    def test_parse_reserved(self):
        sub_data = test_keys.make_signature_subpacket(18, bytearray(), False,
                                                      True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {})

    def test_parse_private_experimental(self):
        sub_data = test_keys.make_signature_subpacket(100, bytearray(), False,
                                                      True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        parse.parse_signature_subpacket(sub, signature, signature_owner_type)
        self.assertEqual(signature, {})

    def test_parse_unknown_critical(self):
        sub_data = test_keys.make_signature_subpacket(33, bytearray(), True,
                                                      True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        self.assertRaises(
                exceptions.CannotParseCritical,
                parse.parse_signature_subpacket,
                sub, signature, signature_owner_type)
        self.assertEqual(signature, {})

    def test_parse_reserved_critical(self):
        sub_data = test_keys.make_signature_subpacket(18, bytearray(), True,
                                                      True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        self.assertRaises(
                exceptions.CannotParseCritical,
                parse.parse_signature_subpacket,
                sub, signature, signature_owner_type)
        self.assertEqual(signature, {})

    def test_parse_private_experimental_critical(self):
        sub_data = test_keys.make_signature_subpacket(100, bytearray(), True,
                                                      True)
        sub = self.make_dummy_subpacket(sub_data)
        signature = {}
        signature_owner_type = 6
        self.assertRaises(
                exceptions.CannotParseCritical,
                parse.parse_signature_subpacket,
                sub, signature, signature_owner_type)
        self.assertEqual(signature, {})


class TestParseSignaturePacket(unittest.TestCase):

    def setUp(self):
        self.creation_time = int(time.time())
        self.secret_key, self.public_key = test_keys.make_key_objects(1, 1024)

        # Make a set public key data and self-signature data with an
        # unsupported version
        self.vn_public_key_packet = test_keys.make_public_key_packet(
                        1, self.creation_time, 0, self.public_key, 1)
        self.vn_sig_data = test_keys.make_signature_packet(
                        self.secret_key,
                        self.vn_public_key_packet,
                        self.vn_public_key_packet,
                        1,
                        0x1f,
                        1,  # RSA
                        2,  # SHA1
                        creation_time=self.creation_time,
                        expiration_time=0,
                        key_id=self.vn_public_key_packet['key_id'])

        # Make a v3 set of public key data and self-signature data
        self.v3_public_key_packet = test_keys.make_public_key_packet(
                        3, self.creation_time, 0, self.public_key, 1)
        self.v3_sig_data = test_keys.make_signature_packet(
                        self.secret_key,
                        self.v3_public_key_packet,
                        self.v3_public_key_packet,
                        3,
                        0x1f,
                        1,  # RSA
                        2,  # SHA1
                        creation_time=self.creation_time,
                        expiration_time=0,
                        key_id=self.v3_public_key_packet['key_id'])

        # Make a v4 set of public key data and self-signature data
        self.v4_public_key_packet = test_keys.make_public_key_packet(
                        4, self.creation_time, 0, self.public_key, 1)
        sub_data = [
            test_keys.make_creation_time_subpacket(self.creation_time),
            test_keys.make_expiration_time_subpacket(0),
            test_keys.make_issuer_key_subpacket(
                        self.v4_public_key_packet['key_id']
                    ),
            test_keys.make_regex_subpacket('(spam|ham)')
        ]
        self.v4_sig_data = test_keys.make_signature_packet(
                        self.secret_key,
                        self.v4_public_key_packet,
                        self.v4_public_key_packet,
                        4,
                        0x1f,
                        1,  # RSA
                        2,  # SHA1
                        subpackets=sub_data)

    @classmethod
    def make_dummy_packet(cls, sig_data):
        packet = mock.Mock()
        packet.raw = 2
        packet.raw_hash_algorithm = sig_data['hash_algorithm_type']
        packet.raw_pub_algorithm = sig_data['pub_algorithm_type']
        packet.raw_sig_type = sig_data['sig_type']
        packet.hash2 = sig_data['hash2']
        packet.sig_version = sig_data['sig_version']
        packet.key_id = sig_data.get('key_id', None)
        packet.raw_creation_time = sig_data.get('creation_time', None)
        packet.raw_expiration_time = sig_data.get('expiration_seconds', None)
        packet.subpackets = list(map(
                TestParseSignatureSubpacket.make_dummy_subpacket,
                sig_data.get('subpackets', [])
            ))
        packet.original_data = test_keys.signature_to_bytes(sig_data)
        return packet

    def test_parse_v3_signature_packet(self):
        packet = self.make_dummy_packet(self.v3_sig_data)
        mock_parse_subpacket_fn = mock.Mock()
        result = parse.parse_signature_packet(
                    packet, 6, [self.v3_public_key_packet['key_id']],
                    parse_signature_subpacket=mock_parse_subpacket_fn)
        expected = {
            'validated': None,
            'hash_algorithm_type': self.v3_sig_data['hash_algorithm_type'],
            'pub_algorithm_type': self.v3_sig_data['pub_algorithm_type'],
            'sig_type': self.v3_sig_data['sig_type'],
            'sig_version': self.v3_sig_data['sig_version'],
            'hash2': bytearray_to_hex(self.v3_sig_data['hash2']),
            'key_ids': [{
                    'key_id': self.v3_public_key_packet['key_id'],
                    'hashed': True
                }],
            'selfsig': True,
            'creation_time': self.creation_time,
            'hashed': [
                'hash_algorithm_type', 'pub_algorithm_type', 'sig_type',
                'sig_version', 'creation_time'
                ]
            }
        self.assertEqual(result, expected)

    def test_parse_v3_signature_packet_with_expiration(self):
        packet = self.make_dummy_packet(self.v3_sig_data)
        mock_parse_subpacket_fn = mock.Mock()
        result = parse.parse_signature_packet(
                    packet, 6, [self.v3_public_key_packet['key_id']],
                    parse_signature_subpacket=mock_parse_subpacket_fn)
        expected = {
            'validated': None,
            'hash_algorithm_type': self.v3_sig_data['hash_algorithm_type'],
            'pub_algorithm_type': self.v3_sig_data['pub_algorithm_type'],
            'sig_type': self.v3_sig_data['sig_type'],
            'sig_version': self.v3_sig_data['sig_version'],
            'hash2': bytearray_to_hex(self.v3_sig_data['hash2']),
            'key_ids': [{
                    'key_id': self.v3_public_key_packet['key_id'],
                    'hashed': True
                }],
            'selfsig': True,
            'creation_time': self.creation_time,
            'hashed': [
                'hash_algorithm_type', 'pub_algorithm_type', 'sig_type',
                'sig_version', 'creation_time',
                ]
            }
        self.assertEqual(result, expected)

    def test_parse_v4_signature_packet(self):
        packet = self.make_dummy_packet(self.v4_sig_data)
        result = parse.parse_signature_packet(
                    packet, 6, [self.v4_public_key_packet['key_id']])
        expected = {
            'validated': None,
            'hash_algorithm_type': self.v4_sig_data['hash_algorithm_type'],
            'pub_algorithm_type': self.v4_sig_data['pub_algorithm_type'],
            'sig_type': self.v4_sig_data['sig_type'],
            'sig_version': self.v4_sig_data['sig_version'],
            'hash2': bytearray_to_hex(self.v4_sig_data['hash2']),
            'key_ids': [{
                    'key_id': self.v4_public_key_packet['key_id'],
                    'hashed': True
                }],
            'selfsig': True,
            'creation_time': self.creation_time,
            'regexes': [{
                    'regex': '(spam|ham)',
                    'hashed': True,
                }],
            'hashed': [
                'hash_algorithm_type', 'pub_algorithm_type', 'sig_type',
                'sig_version', 'creation_time', 'expiration_seconds',
                ]
            }
        self.assertEqual(result, expected)

    def test_parse_v4_signature_packet_with_unhashed_packet(self):
        for sp in self.v4_sig_data['subpackets']:
            if sp['type'] == 3:
                # Expiration
                sp['hashed'] = False
        packet = self.make_dummy_packet(self.v4_sig_data)
        result = parse.parse_signature_packet(
                    packet, 6, [self.v4_public_key_packet['key_id']])
        expected = {
            'validated': None,
            'hash_algorithm_type': self.v4_sig_data['hash_algorithm_type'],
            'pub_algorithm_type': self.v4_sig_data['pub_algorithm_type'],
            'sig_type': self.v4_sig_data['sig_type'],
            'sig_version': self.v4_sig_data['sig_version'],
            'hash2': bytearray_to_hex(self.v4_sig_data['hash2']),
            'key_ids': [{
                    'key_id': self.v4_public_key_packet['key_id'],
                    'hashed': True
                }],
            'selfsig': True,
            'regexes': [{
                    'regex': '(spam|ham)',
                    'hashed': True,
                }],
            'creation_time': self.creation_time,
            'hashed': [
                'hash_algorithm_type', 'pub_algorithm_type', 'sig_type',
                'sig_version', 'creation_time',
                ]
            }
        self.assertEqual(result, expected)

    def test_parse_v4_signature_packet_no_subpackets(self):
        packet = self.make_dummy_packet(self.v4_sig_data)
        packet.subpackets = []
        result = parse.parse_signature_packet(
                    packet, 6, [self.v4_public_key_packet['key_id']])
        expected = {
            'validated': None,
            'hash_algorithm_type': self.v4_sig_data['hash_algorithm_type'],
            'pub_algorithm_type': self.v4_sig_data['pub_algorithm_type'],
            'sig_type': self.v4_sig_data['sig_type'],
            'sig_version': self.v4_sig_data['sig_version'],
            'hash2': bytearray_to_hex(self.v4_sig_data['hash2']),
            'selfsig': False,
            'hashed': [
                'hash_algorithm_type', 'pub_algorithm_type', 'sig_type',
                'sig_version',
                ]
            }
        self.assertEqual(result, expected)

    def test_parse_unknown_version_signature_packet(self):
        packet = self.make_dummy_packet(self.vn_sig_data)
        mock_parse_subpacket_fn = mock.Mock()
        self.assertRaises(
                exceptions.UnsupportedSignatureVersion,
                parse.parse_signature_packet,
                packet, 6, [self.v3_public_key_packet['key_id']],
                parse_signature_subpacket=mock_parse_subpacket_fn
            )


class TestSkipToNextKey(unittest.TestCase):

    def make_dummy_packet(self, n):
        packet = mock.Mock()
        packet.raw = n
        return packet

    def make_dummy_generator(self, list_, raise_at=None):
        i = -1
        for item in list_:
            i += 1
            if raise_at is not None and raise_at == i:
                raise RuntimeError
            yield item

    def test_skip_packets(self):
        packets = [
            self.make_dummy_packet(13),
            self.make_dummy_packet(2),
            self.make_dummy_packet(17),
            self.make_dummy_packet(7),
            self.make_dummy_packet(6),
            self.make_dummy_packet(5),
            ]
        packet_generator = self.make_dummy_generator(packets)
        packet, skipped = parse.skip_to_next_key(packet_generator)
        self.assertEqual(packet, packets[4])
        self.assertEqual(skipped, 5)

    def test_skip_packets_first_packet_satisifies(self):
        packets = [
            self.make_dummy_packet(6),
            self.make_dummy_packet(5),
            ]
        packet_generator = self.make_dummy_generator(packets)
        packet, skipped = parse.skip_to_next_key(packet_generator)
        self.assertEqual(packet, packets[0])
        self.assertEqual(skipped, 1)

    def test_skip_packets_no_more_packets(self):
        packets = []
        packet_generator = self.make_dummy_generator(packets)
        packet, skipped = parse.skip_to_next_key(packet_generator)
        self.assertEqual(packet, None)
        self.assertEqual(skipped, 1)

    def test_skip_packets_generator_raises_error(self):
        packets = [
            self.make_dummy_packet(13),
            self.make_dummy_packet(2),
            self.make_dummy_packet(17),
            self.make_dummy_packet(7),
            self.make_dummy_packet(6),
            self.make_dummy_packet(5),
            ]
        packet_generator = self.make_dummy_generator(packets, raise_at=1)
        packet, skipped = parse.skip_to_next_key(packet_generator)
        self.assertEqual(packet, None)
        self.assertEqual(skipped, 3)


class TestParseUserAttributeSubpackets(unittest.TestCase):

    @classmethod
    def make_dummy_packet(cls, att_data):
        packet_data = test_keys.user_attribute_to_bytes(att_data)
        packet = mock.Mock()
        packet.raw = 17
        packet.data = packet_data
        return packet

    def test_user_attribute(self):
        image_data = SAMPLE_JPG_DATA
        subpacket_data = test_keys.make_user_attribute_subpacket(image_data)
        att_data = test_keys.make_user_attribute_packet(4, [subpacket_data])
        packet = self.make_dummy_packet(att_data)
        result = list(parse.parse_user_attribute_subpackets(packet))
        expected = [
            {
            'sub_type': 1,
            'content_data': bytearray(image_data),
            'mimetype': 'image/jpeg',
            }]
        self.assertEqual(result, expected)

    def test_user_attribute_multiple_packets(self):
        image_data = SAMPLE_JPG_DATA
        subpacket_data = test_keys.make_user_attribute_subpacket(image_data)
        att_data = test_keys.make_user_attribute_packet(
                            4, [subpacket_data, subpacket_data]
                        )
        packet = self.make_dummy_packet(att_data)
        result = list(parse.parse_user_attribute_subpackets(packet))
        expected = [
            {
            'sub_type': 1,
            'content_data': bytearray(image_data),
            'mimetype': 'image/jpeg',
            },
            {
            'sub_type': 1,
            'content_data': bytearray(image_data),
            'mimetype': 'image/jpeg',
            },
            ]
        self.assertEqual(result, expected)

    def test_user_attribute_bad_header_length(self):
        image_data = SAMPLE_JPG_DATA
        subpacket_data = test_keys.make_user_attribute_subpacket(image_data)
        subpacket_data['header_length'] = 20
        att_data = test_keys.make_user_attribute_packet(4, [subpacket_data])
        packet = self.make_dummy_packet(att_data)
        result = list(parse.parse_user_attribute_subpackets(packet))
        expected = []
        self.assertEqual(result, expected)

    def test_user_attribute_bad_header_data(self):
        image_data = SAMPLE_JPG_DATA
        subpacket_data = test_keys.make_user_attribute_subpacket(image_data)
        att_data = test_keys.make_user_attribute_packet(4, [subpacket_data])
        packet = self.make_dummy_packet(att_data)
        packet.data[9] = 1
        result = list(parse.parse_user_attribute_subpackets(packet))
        expected = []
        self.assertEqual(result, expected)

    def test_user_attribute_unknown_header_version(self):
        image_data = SAMPLE_JPG_DATA
        subpacket_data = test_keys.make_user_attribute_subpacket(image_data)
        subpacket_data['header_version'] = 2
        att_data = test_keys.make_user_attribute_packet(4, [subpacket_data])
        packet = self.make_dummy_packet(att_data)
        result = list(parse.parse_user_attribute_subpackets(packet))
        expected = []
        self.assertEqual(result, expected)

    def test_user_attribute_unknown_subtype(self):
        image_data = SAMPLE_JPG_DATA
        subpacket_data = test_keys.make_user_attribute_subpacket(image_data)
        subpacket_data['subtype'] = 2
        att_data = test_keys.make_user_attribute_packet(4, [subpacket_data])
        packet = self.make_dummy_packet(att_data)
        result = list(parse.parse_user_attribute_subpackets(packet))
        expected = []
        self.assertEqual(result, expected)

    def test_user_attribute_unknown_image_format(self):
        image_data = SAMPLE_JPG_DATA
        subpacket_data = test_keys.make_user_attribute_subpacket(image_data)
        subpacket_data['image_format'] = 2
        att_data = test_keys.make_user_attribute_packet(4, [subpacket_data])
        packet = self.make_dummy_packet(att_data)
        result = list(parse.parse_user_attribute_subpackets(packet))
        expected = []
        self.assertEqual(result, expected)

    def test_user_attribute_experimental_image_format(self):
        image_data = SAMPLE_PNG_DATA
        subpacket_data = test_keys.make_user_attribute_subpacket(image_data)
        subpacket_data['image_format'] = 100
        att_data = test_keys.make_user_attribute_packet(4, [subpacket_data])
        packet = self.make_dummy_packet(att_data)
        result = list(parse.parse_user_attribute_subpackets(packet))
        expected = [
            {
            'sub_type': 1,
            'content_data': image_data,
            'mimetype': 'image/png',
            },
            ]
        self.assertEqual(result, expected)

    def test_user_attribute_unknown_header_version_allowable(self):
        image_data = SAMPLE_PNG_DATA
        subpacket_data = test_keys.make_user_attribute_subpacket(image_data)
        subpacket_data['header_version'] = 2
        att_data = test_keys.make_user_attribute_packet(4, [subpacket_data])
        packet = self.make_dummy_packet(att_data)
        result = list(parse.parse_user_attribute_subpackets(packet, True))
        expected = [
            {
            'sub_type': 1,
            'content_data': bytearray(image_data),
            'mimetype': 'image/png',
            },
            ]
        self.assertEqual(result, expected)

    def test_user_attribute_partial_subpackets(self):
        image_data = SAMPLE_JPG_DATA
        subpacket_data = test_keys.make_user_attribute_subpacket(image_data)
        att_data = test_keys.make_user_attribute_packet(4, [subpacket_data])
        packet = self.make_dummy_packet(att_data)
        packet.data[0] = 254
        result = list(parse.parse_user_attribute_subpackets(packet))
        expected = []
        self.assertEqual(result, expected)


class TestParseKey(unittest.TestCase):

    @classmethod
    def make_dummy_public_key_packet(cls, public_key_data, type_):
        packet = mock.Mock()
        packet.raw = type_
        packet.key_id = public_key_data['key_id']
        packet.fingerprint = public_key_data['fingerprint']
        packet.raw_creation_time = public_key_data['creation_time']
        packet.raw_days_valid = public_key_data.get('expiration_days', None)
        packet.raw_pub_algorithm = public_key_data['pub_algorithm_type']
        packet.pubkey_version = public_key_data['version']
        packet.modulus = public_key_data.get('modulus', None)
        packet.exponent = public_key_data.get('exponent', None)
        packet.prime = public_key_data.get('prime', None)
        packet.group_order = public_key_data.get('group_order', None)
        packet.group_gen = public_key_data.get('group_gen', None)
        packet.key_value = public_key_data.get('key_value', None)
        packet.data = test_keys.public_key_to_bytes(public_key_data)
        packet.original_data = test_keys.packet_to_bytes(public_key_data)
        return packet

    @classmethod
    def make_dummy_user_id_packet(cls, user_id_data):
        packet = mock.Mock()
        packet.raw = 13
        packet.version = user_id_data['version']
        packet.user = user_id_data['user']
        packet.original_data = test_keys.packet_to_bytes(user_id_data)
        return packet

    @classmethod
    def make_dummy_user_attr_packet(cls, user_attr_data):
        packet = mock.Mock()
        packet.raw = 17
        packet.version = user_attr_data['version']
        packet.image_data = user_attr_data['subpackets'][0]['image_data']
        packet.image_format = user_attr_data['subpackets'][0]['image_format']
        packet.data = test_keys.user_attribute_to_bytes(user_attr_data)
        packet.original_data = test_keys.packet_to_bytes(user_attr_data)
        return packet

    def setUp(self):
        self.mock_hash_key = mock.Mock()
        self.mock_hash_key.return_value = bytearray()

        self.creation_time = int(time.time())
        self.secret_key, self.public_key = test_keys.make_key_objects(1, 1024)
        self.v4_key_packet_data = test_keys.make_public_key_packet(
                    4, self.creation_time, 0, self.public_key, 1)
        self.v4_key_packet = self.make_dummy_public_key_packet(
                                self.v4_key_packet_data, 6)
        sub_data = [
            test_keys.make_creation_time_subpacket(self.creation_time),
            test_keys.make_expiration_time_subpacket(0),
            test_keys.make_issuer_key_subpacket(
                        self.v4_key_packet_data['key_id']
                    ),
        ]
        self.v4_sig_data = test_keys.make_signature_packet(
                        self.secret_key,
                        self.v4_key_packet_data,
                        self.v4_key_packet_data,
                        4,
                        0x1f,
                        1,  # RSA
                        2,  # SHA1
                        subpackets=sub_data)
        self.v4_sig_packet = TestParseSignaturePacket.make_dummy_packet(
                                self.v4_sig_data)

        self.v4_user_id_data = test_keys.make_user_id_packet(4, u'Test User')
        self.v4_user_id_packet = self.make_dummy_user_id_packet(
                                        self.v4_user_id_data)
        user_id_sig_sub_data = [
            test_keys.make_creation_time_subpacket(self.creation_time),
            test_keys.make_expiration_time_subpacket(0),
            test_keys.make_issuer_key_subpacket(
                        self.v4_key_packet_data['key_id']
                    ),
        ]
        self.v4_user_id_sig_data = test_keys.make_signature_packet(
                        self.secret_key,
                        self.v4_key_packet_data,
                        self.v4_user_id_data,
                        4,
                        0x10,
                        1,  # RSA
                        2,  # SHA1
                        subpackets=user_id_sig_sub_data)
        self.v4_user_id_sig_packet = \
            TestParseSignaturePacket.make_dummy_packet(
                    self.v4_user_id_sig_data
                )

        self.secret_subkey, self.public_subkey = \
            test_keys.make_key_objects(1, 1024)
        self.v4_subkey_data = test_keys.make_public_subkey_packet(
                    4, self.creation_time, 0, self.public_subkey, 1)
        self.v4_subkey_packet = self.make_dummy_public_key_packet(
                                        self.v4_subkey_data, 14)
        subkey_sig_sub_data = [
            test_keys.make_creation_time_subpacket(self.creation_time),
            test_keys.make_expiration_time_subpacket(0),
            test_keys.make_issuer_key_subpacket(
                        self.v4_key_packet_data['key_id']
                    ),
        ]
        self.v4_subkey_sig_data = test_keys.make_signature_packet(
                        self.secret_key,
                        self.v4_key_packet_data,
                        self.v4_subkey_data,
                        4,
                        0x18,
                        1,  # RSA
                        2,  # SHA1
                        subpackets=subkey_sig_sub_data)
        self.v4_subkey_sig_packet = \
            TestParseSignaturePacket.make_dummy_packet(
                    self.v4_subkey_sig_data
                )

        self.v4_user_attr_sub_data = \
            test_keys.make_user_attribute_subpacket(SAMPLE_JPG_DATA)
        attr_subs = [self.v4_user_attr_sub_data]
        self.v4_user_attr_data = \
            test_keys.make_user_attribute_packet(4, attr_subs)
        self.v4_user_attr_packet = self.make_dummy_user_attr_packet(
                                        self.v4_user_attr_data)
        user_attr_sig_sub_data = [
            test_keys.make_creation_time_subpacket(self.creation_time),
            test_keys.make_expiration_time_subpacket(0),
            test_keys.make_issuer_key_subpacket(
                        self.v4_key_packet_data['key_id']
                    ),
        ]
        self.v4_user_attr_sig_data = test_keys.make_signature_packet(
                        self.secret_key,
                        self.v4_key_packet_data,
                        self.v4_user_attr_data,
                        4,
                        0x10,
                        1,  # RSA
                        2,  # SHA1
                        subpackets=user_attr_sig_sub_data)
        self.v4_user_attr_sig_packet = \
            TestParseSignaturePacket.make_dummy_packet(
                    self.v4_user_attr_sig_data
                )

    def test_parse_key_no_packets(self):
        result = parse.parse_key([], hash_key_data=self.mock_hash_key)
        expected = {
            'data': bytearray(),
            'key_hash': bytearray()
            }
        self.assertEqual(result, expected)

    def test_parse_key_public_key_packet(self):
        packets = [self.v4_key_packet]
        result = parse.parse_key(packets, hash_key_data=self.mock_hash_key)
        expected = {
            '_data': self.v4_key_packet.original_data,
            '_raw_type': 6,
            'key_hash': bytearray(),
            'key_id': self.v4_key_packet_data['key_id'],
            'fingerprint': self.v4_key_packet_data['fingerprint'],
            'creation_time': self.v4_key_packet_data['creation_time'],
            'expiration_days':
                self.v4_key_packet_data.get('expiration_days', None),
            'pub_algorithm_type':
                self.v4_key_packet_data['pub_algorithm_type'],
            'pubkey_version': self.v4_key_packet_data['version'],
            'modulus': self.v4_key_packet_data.get('modulus', None),
            'exponent': self.v4_key_packet_data.get('exponent', None),
            'prime': self.v4_key_packet_data.get('prime', None),
            'group_gen': self.v4_key_packet_data.get('group_gen', None),
            'group_order': self.v4_key_packet_data.get('group_order', None),
            'key_value': self.v4_key_packet_data.get('key_value', None),
            'bitlen': 1024,
            'data': self.v4_key_packet.original_data,
            }
        self.assertEqual(result, expected)

    def test_parse_key_signature_packet(self):
        packets = [self.v4_key_packet, self.v4_sig_packet]
        mock_parse_signature_packet = mock.Mock()
        result = parse.parse_key(
                     packets, hash_key_data=self.mock_hash_key,
                     parse_signature_packet=mock_parse_signature_packet)
        expected_args = (
            packets[1], 6,
            [
                self.v4_key_packet_data['key_id'],
                self.v4_key_packet_data['key_id'],
            ]
            )
        self.assertEqual(mock_parse_signature_packet.call_args[0],
                         expected_args)
        expected = {
            '_data': self.v4_key_packet.original_data,
            '_raw_type': 6,
            'key_hash': bytearray(),
            'key_id': self.v4_key_packet_data['key_id'],
            'fingerprint': self.v4_key_packet_data['fingerprint'],
            'creation_time': self.v4_key_packet_data['creation_time'],
            'expiration_days':
                self.v4_key_packet_data.get('expiration_days', None),
            'pub_algorithm_type':
                self.v4_key_packet_data['pub_algorithm_type'],
            'pubkey_version': self.v4_key_packet_data['version'],
            'modulus': self.v4_key_packet_data.get('modulus', None),
            'exponent': self.v4_key_packet_data.get('exponent', None),
            'prime': self.v4_key_packet_data.get('prime', None),
            'group_gen': self.v4_key_packet_data.get('group_gen', None),
            'group_order': self.v4_key_packet_data.get('group_order', None),
            'key_value': self.v4_key_packet_data.get('key_value', None),
            'bitlen': 1024,
            'data': (
                    self.v4_key_packet.original_data +
                    self.v4_sig_packet.original_data
                ),
            'signatures': [mock_parse_signature_packet.return_value],
            }
        self.assertEqual(result, expected)

    def test_parse_key_local_certification_signature_packet(self):
        packets = [self.v4_key_packet, self.v4_sig_packet]
        mock_parse_signature_packet = mock.Mock()
        mock_parse_signature_packet.side_effect = \
            exceptions.LocalCertificationSignature
        result = parse.parse_key(
                     packets, hash_key_data=self.mock_hash_key,
                     parse_signature_packet=mock_parse_signature_packet)
        expected_args = (
            packets[1], 6,
            [
                self.v4_key_packet_data['key_id'],
                self.v4_key_packet_data['key_id'],
            ]
            )
        self.assertEqual(mock_parse_signature_packet.call_args[0],
                         expected_args)
        expected = {
            '_data': self.v4_key_packet.original_data,
            '_raw_type': 6,
            'key_hash': bytearray(),
            'key_id': self.v4_key_packet_data['key_id'],
            'fingerprint': self.v4_key_packet_data['fingerprint'],
            'creation_time': self.v4_key_packet_data['creation_time'],
            'expiration_days':
                self.v4_key_packet_data.get('expiration_days', None),
            'pub_algorithm_type':
                self.v4_key_packet_data['pub_algorithm_type'],
            'pubkey_version': self.v4_key_packet_data['version'],
            'modulus': self.v4_key_packet_data.get('modulus', None),
            'exponent': self.v4_key_packet_data.get('exponent', None),
            'prime': self.v4_key_packet_data.get('prime', None),
            'group_gen': self.v4_key_packet_data.get('group_gen', None),
            'group_order': self.v4_key_packet_data.get('group_order', None),
            'key_value': self.v4_key_packet_data.get('key_value', None),
            'bitlen': 1024,
            'data': (
                    self.v4_key_packet.original_data +
                    self.v4_sig_packet.original_data
                ),
            }
        self.assertEqual(result, expected)

    def test_parse_key_unparsable_critical_signature_packet(self):
        packets = [self.v4_key_packet, self.v4_sig_packet]
        mock_parse_signature_packet = mock.Mock()
        mock_parse_signature_packet.side_effect = \
            exceptions.CannotParseCritical
        result = parse.parse_key(
                     packets, hash_key_data=self.mock_hash_key,
                     parse_signature_packet=mock_parse_signature_packet)
        expected_args = (
            packets[1], 6,
            [
                self.v4_key_packet_data['key_id'],
                self.v4_key_packet_data['key_id'],
            ]
            )
        self.assertEqual(mock_parse_signature_packet.call_args[0],
                         expected_args)
        expected = {
            '_data': self.v4_key_packet.original_data,
            '_raw_type': 6,
            'key_hash': bytearray(),
            'key_id': self.v4_key_packet_data['key_id'],
            'fingerprint': self.v4_key_packet_data['fingerprint'],
            'creation_time': self.v4_key_packet_data['creation_time'],
            'expiration_days':
                self.v4_key_packet_data.get('expiration_days', None),
            'pub_algorithm_type':
                self.v4_key_packet_data['pub_algorithm_type'],
            'pubkey_version': self.v4_key_packet_data['version'],
            'modulus': self.v4_key_packet_data.get('modulus', None),
            'exponent': self.v4_key_packet_data.get('exponent', None),
            'prime': self.v4_key_packet_data.get('prime', None),
            'group_gen': self.v4_key_packet_data.get('group_gen', None),
            'group_order': self.v4_key_packet_data.get('group_order', None),
            'key_value': self.v4_key_packet_data.get('key_value', None),
            'bitlen': 1024,
            'data': (
                    self.v4_key_packet.original_data +
                    self.v4_sig_packet.original_data
                ),
            }
        self.assertEqual(result, expected)

    def test_parse_key_user_id_packet(self):
        packets = [self.v4_key_packet, self.v4_sig_packet,
                   self.v4_user_id_packet, self.v4_user_id_sig_packet]
        mock_parse_signature_packet = mock.Mock()
        mock_parse_signature_packet.side_effect =\
            lambda p, t, k: p
        result = parse.parse_key(
                     packets, hash_key_data=self.mock_hash_key,
                     parse_signature_packet=mock_parse_signature_packet)
        expected_args = (
            packets[1], 6,
            [
                self.v4_key_packet_data['key_id'],
                self.v4_key_packet_data['key_id'],
            ]
            )
        self.assertEqual(mock_parse_signature_packet.call_args_list[0][0],
                         expected_args)
        expected_args = (
            packets[3], 13,
            [
                self.v4_key_packet_data['key_id'],
                None
            ]
            )
        self.assertEqual(mock_parse_signature_packet.call_args_list[1][0],
                         expected_args)
        expected = {
            '_data': self.v4_key_packet.original_data,
            '_raw_type': 6,
            'key_hash': bytearray(),
            'key_id': self.v4_key_packet_data['key_id'],
            'fingerprint': self.v4_key_packet_data['fingerprint'],
            'creation_time': self.v4_key_packet_data['creation_time'],
            'expiration_days':
                self.v4_key_packet_data.get('expiration_days', None),
            'pub_algorithm_type':
                self.v4_key_packet_data['pub_algorithm_type'],
            'pubkey_version': self.v4_key_packet_data['version'],
            'modulus': self.v4_key_packet_data.get('modulus', None),
            'exponent': self.v4_key_packet_data.get('exponent', None),
            'prime': self.v4_key_packet_data.get('prime', None),
            'group_gen': self.v4_key_packet_data.get('group_gen', None),
            'group_order': self.v4_key_packet_data.get('group_order', None),
            'key_value': self.v4_key_packet_data.get('key_value', None),
            'bitlen': 1024,
            'data': (
                    self.v4_key_packet.original_data +
                    self.v4_sig_packet.original_data +
                    self.v4_user_id_packet.original_data +
                    self.v4_user_id_sig_packet.original_data
                ),
            'signatures': [self.v4_sig_packet],
            'user_ids': [
                {
                    '_raw_type': 13,
                    'user_id': self.v4_user_id_data['user'],
                    '_data': self.v4_user_id_packet.original_data,
                    'signatures': [self.v4_user_id_sig_packet]
                }]
            }
        self.assertEqual(result, expected)

    def test_parse_key_subkey_packet(self):
        packets = [self.v4_key_packet, self.v4_sig_packet,
                   self.v4_subkey_packet, self.v4_subkey_sig_packet]
        mock_parse_signature_packet = mock.Mock()
        mock_parse_signature_packet.side_effect =\
            lambda p, t, k: p
        result = parse.parse_key(
                     packets, hash_key_data=self.mock_hash_key,
                     parse_signature_packet=mock_parse_signature_packet)
        expected_args = (
            packets[1], 6,
            [
                self.v4_key_packet_data['key_id'],
                self.v4_key_packet_data['key_id'],
            ]
            )
        self.assertEqual(mock_parse_signature_packet.call_args_list[0][0],
                         expected_args)
        expected_args = (
            packets[3], 14,
            [
                self.v4_key_packet_data['key_id'],
                self.v4_subkey_data['key_id'],
            ]
            )
        self.assertEqual(mock_parse_signature_packet.call_args_list[1][0],
                         expected_args)
        expected_main = {
            '_data': self.v4_key_packet.original_data,
            '_raw_type': 6,
            'key_hash': bytearray(),
            'key_id': self.v4_key_packet_data['key_id'],
            'fingerprint': self.v4_key_packet_data['fingerprint'],
            'creation_time': self.v4_key_packet_data['creation_time'],
            'expiration_days':
                self.v4_key_packet_data.get('expiration_days', None),
            'pub_algorithm_type':
                self.v4_key_packet_data['pub_algorithm_type'],
            'pubkey_version': self.v4_key_packet_data['version'],
            'modulus': self.v4_key_packet_data.get('modulus', None),
            'exponent': self.v4_key_packet_data.get('exponent', None),
            'prime': self.v4_key_packet_data.get('prime', None),
            'group_gen': self.v4_key_packet_data.get('group_gen', None),
            'group_order': self.v4_key_packet_data.get('group_order', None),
            'key_value': self.v4_key_packet_data.get('key_value', None),
            'bitlen': 1024,
            'data': (
                    self.v4_key_packet.original_data +
                    self.v4_sig_packet.original_data +
                    self.v4_subkey_packet.original_data +
                    self.v4_subkey_sig_packet.original_data
                ),
            'signatures': [self.v4_sig_packet],
            }
        expected_subkey = {
                '_data': self.v4_subkey_packet.original_data,
                '_raw_type': 14,
                'key_id': self.v4_subkey_data['key_id'],
                'fingerprint': self.v4_subkey_data['fingerprint'],
                'creation_time': self.creation_time,
                'expiration_days': None,
                'pub_algorithm_type': 1,
                'pubkey_version': 4,
                'modulus': self.v4_subkey_data.get('modulus', None),
                'exponent': self.v4_subkey_data.get('exponent', None),
                'prime': None,
                'group_gen': None,
                'group_order': None,
                'key_value': None,
                'bitlen': 1024,
                'signatures': [self.v4_subkey_sig_packet],
            }
        result_main = result
        result_subkeys = result.pop('subkeys')
        self.assertEqual(result_main, expected_main)
        self.assertEqual(len(result_subkeys), 1)
        result_subkey = result_subkeys[0]
        result_subkey.pop('parent')
        self.assertEqual(result_subkey, expected_subkey)

    def test_parse_key_user_attribute_packet(self):
        packets = [self.v4_key_packet, self.v4_sig_packet,
                   self.v4_user_attr_packet, self.v4_user_attr_sig_packet]
        mock_parse_signature_packet = mock.Mock()
        mock_parse_signature_packet.side_effect =\
            lambda p, t, k: p
        mock_parse_user_attr_subpackets = mock.Mock()
        mock_parse_user_attr_subpackets.side_effect =\
            lambda p: [p]
        result = parse.parse_key(
             packets, hash_key_data=self.mock_hash_key,
             parse_signature_packet=mock_parse_signature_packet,
             parse_user_attribute_subpackets=mock_parse_user_attr_subpackets)
        expected_args = (
            packets[1], 6,
            [
                self.v4_key_packet_data['key_id'],
                self.v4_key_packet_data['key_id'],
            ]
            )
        self.assertEqual(mock_parse_signature_packet.call_args_list[0][0],
                         expected_args)
        expected_args = (
            packets[3], 17,
            [
                self.v4_key_packet_data['key_id'],
                None
            ]
            )
        self.assertEqual(mock_parse_signature_packet.call_args_list[1][0],
                         expected_args)
        expected = {
            '_data': self.v4_key_packet.original_data,
            '_raw_type': 6,
            'key_hash': bytearray(),
            'key_id': self.v4_key_packet_data['key_id'],
            'fingerprint': self.v4_key_packet_data['fingerprint'],
            'creation_time': self.v4_key_packet_data['creation_time'],
            'expiration_days':
                self.v4_key_packet_data.get('expiration_days', None),
            'pub_algorithm_type':
                self.v4_key_packet_data['pub_algorithm_type'],
            'pubkey_version': self.v4_key_packet_data['version'],
            'modulus': self.v4_key_packet_data.get('modulus', None),
            'exponent': self.v4_key_packet_data.get('exponent', None),
            'prime': self.v4_key_packet_data.get('prime', None),
            'group_gen': self.v4_key_packet_data.get('group_gen', None),
            'group_order': self.v4_key_packet_data.get('group_order', None),
            'key_value': self.v4_key_packet_data.get('key_value', None),
            'bitlen': 1024,
            'data': (
                    self.v4_key_packet.original_data +
                    self.v4_sig_packet.original_data +
                    self.v4_user_attr_packet.original_data +
                    self.v4_user_attr_sig_packet.original_data
                ),
            'signatures': [self.v4_sig_packet],
            'user_attributes': [
                {
                    '_raw_type': 17,
                    'subpackets': [self.v4_user_attr_packet],
                    '_data': self.v4_user_attr_packet.original_data,
                    'signatures': [self.v4_user_attr_sig_packet]
                }]
            }
        self.assertEqual(result, expected)

    def test_parse_key_unsupported_packet(self):
        packet = mock.Mock()
        packet.raw = 99
        self.assertRaises(
                exceptions.UnsupportedPacketType,
                parse.parse_key,
                [packet],
                hash_key_data=self.mock_hash_key
            )


class TestValidateTransferrablePublicKey(unittest.TestCase):

    @classmethod
    def make_mock_packet(cls, type_, **kwargs):
        packet = mock.Mock()
        packet.raw = type_
        for k, v in kwargs.items():
            setattr(packet, k, v)
        return packet

    def test_validate_transferrable_public_key(self):
        packets = [
            self.make_mock_packet(6, pubkey_version=4),
            self.make_mock_packet(2, sig_type=0x1f),
            self.make_mock_packet(2, sig_type=0x20),
            self.make_mock_packet(13),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(17),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(14),
            self.make_mock_packet(2, sig_type=0x18),
            self.make_mock_packet(2, sig_type=0x28),
            ]
        try:
            parse.validate_transferrable_public_key(packets)
        except exceptions.InvalidKey:
            self.failIf(True, "Validation should not have raised an error.")

    def test_validate_transferrable_public_key_first_packet_not_pk(self):
        packets = [
            self.make_mock_packet(2, sig_type=0x1f),
            self.make_mock_packet(6, pubkey_version=4),
            self.make_mock_packet(13),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(17),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(14),
            self.make_mock_packet(2, sig_type=0x18),
            ]
        self.assertRaises(
            exceptions.InvalidKeyPacketOrder,
            parse.validate_transferrable_public_key,
            packets
            )

    def test_valid_transferrable_public_key_pk_not_first(self):
        packets = [
            self.make_mock_packet(6, pubkey_version=4),
            self.make_mock_packet(6, pubkey_version=4),
            self.make_mock_packet(2, sig_type=0x1f),
            self.make_mock_packet(13),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(17),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(14),
            self.make_mock_packet(2, sig_type=0x18),
            ]
        self.assertRaises(
            exceptions.InvalidKeyPacketOrder,
            parse.validate_transferrable_public_key,
            packets
            )

    def test_valid_transferrable_public_key_sig_on_key_not_after_pk(self):
        packets = [
            self.make_mock_packet(6, pubkey_version=4),
            self.make_mock_packet(2, sig_type=0x1f),
            self.make_mock_packet(13),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(17),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(14),
            self.make_mock_packet(2, sig_type=0x18),
            self.make_mock_packet(2, sig_type=0x1f),
            ]
        self.assertRaises(
            exceptions.InvalidKeyPacketOrder,
            parse.validate_transferrable_public_key,
            packets
            )

    def test_valid_transferrable_public_key_sub_binding_not_after_sk(self):
        packets = [
            self.make_mock_packet(6, pubkey_version=4),
            self.make_mock_packet(2, sig_type=0x1f),
            self.make_mock_packet(2, sig_type=0x18),
            self.make_mock_packet(13),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(17),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(14),
            self.make_mock_packet(2, sig_type=0x18),
            ]
        self.assertRaises(
            exceptions.InvalidKeyPacketOrder,
            parse.validate_transferrable_public_key,
            packets
            )

    def test_valid_transferrable_public_key_sk_not_followed_by_skb(self):
        packets = [
            self.make_mock_packet(6, pubkey_version=4),
            self.make_mock_packet(2, sig_type=0x1f),
            self.make_mock_packet(13),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(17),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(14),
            self.make_mock_packet(2, sig_type=0x1f),
            ]
        self.assertRaises(
            exceptions.InvalidKeyPacketOrder,
            parse.validate_transferrable_public_key,
            packets
            )

    def test_valid_transferrable_public_key_pk_rev_not_after_pk(self):
        packets = [
            self.make_mock_packet(6, pubkey_version=4),
            self.make_mock_packet(2, sig_type=0x1f),
            self.make_mock_packet(13),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(17),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(14),
            self.make_mock_packet(2, sig_type=0x18),
            self.make_mock_packet(2, sig_type=0x20),
            ]
        self.assertRaises(
            exceptions.InvalidKeyPacketOrder,
            parse.validate_transferrable_public_key,
            packets
            )

    def test_valid_transferrable_public_key_sk_rev_not_after_sk(self):
        packets = [
            self.make_mock_packet(6, pubkey_version=4),
            self.make_mock_packet(2, sig_type=0x1f),
            self.make_mock_packet(2, sig_type=0x28),
            self.make_mock_packet(13),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(17),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(14),
            self.make_mock_packet(2, sig_type=0x18),
            ]
        self.assertRaises(
            exceptions.InvalidKeyPacketOrder,
            parse.validate_transferrable_public_key,
            packets
            )

        packets = [
            self.make_mock_packet(6, pubkey_version=4),
            self.make_mock_packet(2, sig_type=0x1f),
            self.make_mock_packet(2, sig_type=0x28),
            self.make_mock_packet(13),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(17),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(14),
            self.make_mock_packet(2, sig_type=0x28),
            self.make_mock_packet(2, sig_type=0x18),
            ]
        self.assertRaises(
            exceptions.InvalidKeyPacketOrder,
            parse.validate_transferrable_public_key,
            packets
            )

    def test_valid_transferrable_public_key_cert_sig_position_wrong(self):
        packets = [
            self.make_mock_packet(6, pubkey_version=4),
            self.make_mock_packet(2, sig_type=0x1f),
            self.make_mock_packet(13),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(2, sig_type=0x11),
            self.make_mock_packet(2, sig_type=0x12),
            self.make_mock_packet(2, sig_type=0x13),
            self.make_mock_packet(17),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(2, sig_type=0x11),
            self.make_mock_packet(2, sig_type=0x12),
            self.make_mock_packet(2, sig_type=0x13),
            self.make_mock_packet(14),
            self.make_mock_packet(2, sig_type=0x18),
            ]
        try:
            parse.validate_transferrable_public_key(packets)
        except exceptions.InvalidKeyPacketOrder:
            self.failIf(True, "Validation should not have raised an error.")

        packets = [
            self.make_mock_packet(6, pubkey_version=4),
            self.make_mock_packet(2, sig_type=0x1f),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(13),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(17),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(14),
            self.make_mock_packet(2, sig_type=0x18),
            ]
        self.assertRaises(
            exceptions.InvalidKeyPacketOrder,
            parse.validate_transferrable_public_key,
            packets
            )

    def test_valid_transferrable_public_key_invalid_sig_type(self):
        packets = [
            self.make_mock_packet(6, pubkey_version=4),
            self.make_mock_packet(2, sig_type=0x1f),
            self.make_mock_packet(13),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(2, sig_type=0xff),
            self.make_mock_packet(17),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(14),
            self.make_mock_packet(2, sig_type=0x18),
            ]
        self.assertRaises(
            exceptions.InvalidKeyPacketType,
            parse.validate_transferrable_public_key,
            packets
            )

    def test_valid_transferrable_public_key_user_id_wrong_pos(self):
        packets = [
            self.make_mock_packet(6, pubkey_version=4),
            self.make_mock_packet(2, sig_type=0x1f),
            self.make_mock_packet(17),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(13),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(14),
            self.make_mock_packet(2, sig_type=0x18),
            ]
        self.assertRaises(
            exceptions.InvalidKeyPacketOrder,
            parse.validate_transferrable_public_key,
            packets
            )

        packets = [
            self.make_mock_packet(6, pubkey_version=4),
            self.make_mock_packet(2, sig_type=0x1f),
            self.make_mock_packet(17),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(14),
            self.make_mock_packet(2, sig_type=0x18),
            self.make_mock_packet(13),
            self.make_mock_packet(2, sig_type=0x10),
            ]
        self.assertRaises(
            exceptions.InvalidKeyPacketOrder,
            parse.validate_transferrable_public_key,
            packets
            )

    def test_valid_transferrable_public_key_user_attr_wrong_pos(self):
        packets = [
            self.make_mock_packet(6, pubkey_version=4),
            self.make_mock_packet(2, sig_type=0x1f),
            self.make_mock_packet(13),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(14),
            self.make_mock_packet(2, sig_type=0x18),
            self.make_mock_packet(17),
            self.make_mock_packet(2, sig_type=0x10),
            ]
        self.assertRaises(
            exceptions.InvalidKeyPacketOrder,
            parse.validate_transferrable_public_key,
            packets
            )

    def test_valid_transferrable_public_key_v3_subkey(self):
        packets = [
            self.make_mock_packet(6, pubkey_version=3),
            self.make_mock_packet(2, sig_type=0x1f),
            self.make_mock_packet(13),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(17),
            self.make_mock_packet(2, sig_type=0x10),
            self.make_mock_packet(14),
            self.make_mock_packet(2, sig_type=0x18),
            ]
        self.assertRaises(
            exceptions.InvalidKeyPacketType,
            parse.validate_transferrable_public_key,
            packets
            )

    def test_valid_transferrable_public_key_unknown_packet_type(self):
        packets = [
            self.make_mock_packet(6, pubkey_version=3),
            self.make_mock_packet(99),
            ]
        self.assertRaises(
            exceptions.InvalidKeyPacketType,
            parse.validate_transferrable_public_key,
            packets
            )


class TestParse(unittest.TestCase):

    @classmethod
    def make_mock_packet(cls, type_, **kwargs):
        packet = mock.Mock()
        packet.raw = type_
        for k, v in kwargs.items():
            setattr(packet, k, v)
        return packet

    @classmethod
    def make_mock_parser(cls, packets, raise_at=None):
        parser = mock.Mock()

        def gen():
            i = 0
            for packet in packets:
                if raise_at is not None and i == raise_at:
                    raise ValueError('Test')
                yield packet
                i += 1

        parser.packets.side_effect = gen
        return parser

    @classmethod
    def mock_parse_key_packets(cls, packets):
        return packets

    @classmethod
    def mock_validate_transferrable_public_key(cls, packets):
        return None

    def test_parse(self):
        packets = [
            self.make_mock_packet(6),
            self.make_mock_packet(2),
            self.make_mock_packet(13),
            self.make_mock_packet(2),
            self.make_mock_packet(17),
            self.make_mock_packet(2),
            self.make_mock_packet(14),
            self.make_mock_packet(2),

            self.make_mock_packet(6),
            self.make_mock_packet(2),
            self.make_mock_packet(13),
            self.make_mock_packet(2),
            self.make_mock_packet(17),
            self.make_mock_packet(2),
            self.make_mock_packet(14),
            self.make_mock_packet(2),
            ]
        parser = self.make_mock_parser(packets)

        result = list(
            parse.parse(
                parser,
                parse_key_packets=self.mock_parse_key_packets,
                validate_transferrable_public_key=(
                    self.mock_validate_transferrable_public_key),
                ))
        self.assertEqual(result, [packets[:8], packets[8:]])

    def test_parse_exception(self):
        packets = [
            self.make_mock_packet(6),
            self.make_mock_packet(2),
            self.make_mock_packet(13),
            self.make_mock_packet(2),
            self.make_mock_packet(17),
            self.make_mock_packet(2),
            self.make_mock_packet(14),
            self.make_mock_packet(2),

            self.make_mock_packet(6),
            self.make_mock_packet(2),
            self.make_mock_packet(13),
            self.make_mock_packet(2),
            self.make_mock_packet(17),
            self.make_mock_packet(2),
            self.make_mock_packet(14),
            self.make_mock_packet(2),
            ]
        parser = self.make_mock_parser(packets, raise_at=12)
        errs = StringIO()

        result = list(
            parse.parse(
                parser,
                err_stream=errs,
                parse_key_packets=self.mock_parse_key_packets,
                validate_transferrable_public_key=(
                    self.mock_validate_transferrable_public_key),
                ))
        self.assertEqual(result, [packets[:8]])
