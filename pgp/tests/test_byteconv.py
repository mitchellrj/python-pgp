import unittest

from pgp import utils


class IntToBytesTest(unittest.TestCase):
    def test_int1(self):
        self.assertEqual(bytes(utils.int_to_bytes(1)), b'\x01')

    def test_int65(self):
        self.assertEqual(
            bytes(utils.int_to_bytes(
                18446744073709551615 + 2)),  # UINT64_MAX + 2
            b'\x01\x00\x00\x00\x00\x00\x00\x00\x01')

    def test_somevalue(self):
        # Big endian, it is.
        self.assertEqual(
            bytes(utils.int_to_bytes(
                98765432109876543210)),
            b'\x05\x5a\xa5\x4d\x38\xe5\x26\x7e\xea')


class BytesIntTest(unittest.TestCase):
    def test_int1(self):
        self.assertEqual(utils.bytes_to_int(b'\x01', 0, 1), 1)

    def test_int65(self):
        self.assertEqual(utils.bytes_to_int(
            b'\x01\x00\x00\x00\x00\x00\x00\x00\x01', 0, 9),
            18446744073709551615 + 2)  # UINT64_MAX + 2

    def test_offset(self):
        # Big endian, it is.
        self.assertEqual(utils.bytes_to_int(
            b'\x01\x02\x03\x04\x05\x06\x07\x08', 2, 2),
            0x304)
