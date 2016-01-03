from datetime import datetime
import os.path
import unittest

from pgp import message, read_key_file
from pgp.detached_signature import DetachedSignature
from pgp.exceptions import SignatureVerificationFailed
from pgp.packets import parse_ascii_packet_data


RSA_SIGNED_EXAMPLE = '''
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

This is an RSA-key signed message.
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1

iJwEAQECAAYFAlaJJ1oACgkQrzhsS/ozv1sAnAP/flKRwcVCbKothGDMsClAJATv
oaDC6FJQQgxQ+o2ml1qifT7ZDT1RGvbF+65ag+yHq0ZmdCxK7r0UY3LUseVC8cKd
XeTxvDaFElYOa1go1rftIJzAt4s7jjNMQ82Upx1L4qs3bnGxxNgRWz41kP/IdqfX
KA6VY0mjqbu18NryIrw=
=9297
-----END PGP SIGNATURE-----
'''
RSA_EXAMPLE = 'This is an RSA-key signed message.'

DSA_SIGNED_EXAMPLE = '''
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

This is a DSA-key signed message.
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1

iEYEARECAAYFAlaJJ20ACgkQ2DMK4FgpO/cBMACgglP3b0tnqMFh//7ryMle1Ona
v80AoK2vvJ2vXe8bcNGHv4z8zdZ2lNP+
=aknQ
-----END PGP SIGNATURE-----
'''
DSA_EXAMPLE = 'This is a DSA-key signed message.'


class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.dsa_keyfile = os.path.join(
            os.path.dirname(__file__),
            'data/key-example-walter-dsa-elgamal.pub')
        self.rsa_keyfile = os.path.join(
            os.path.dirname(__file__),
            'data/key-example-walter-rsa-rsa.pub')

    def check_that_signed_starts_with_expected(self, signed, expected):
        # First, confirm that the message looks like:
        # "BEGIN SIGNED <expected> BEGIN SIGNATURE <sig>"
        self.assertTrue(
            signed.strip().startswith(
                ('-----BEGIN PGP SIGNED MESSAGE-----\n'
                 '{header}\n\n{expected}\n'
                 '-----BEGIN PGP SIGNATURE-----\n').format(
                     header='Hash: SHA1', expected=expected)))

    def verify(self, keyfile, signed, expected):
        # Get public key.
        key = read_key_file(keyfile, armored=True)

        # Extract <signature>.
        pre_signature, signature = signed.split('\n-----BEGIN PGP SIGNATURE')
        signature = '-----BEGIN PGP SIGNATURE' + signature
        packets = list(parse_ascii_packet_data(signature))
        self.assertEqual(len(packets), 1)
        keysig = DetachedSignature.from_packet(packets[0], target=None)

        # Verify values.
        text_message = message.TextMessage(
            expected, filename='', timestamp=datetime.now())
        key.verify(keysig, text_message)

    def test_rsa(self):
        self.check_that_signed_starts_with_expected(
            RSA_SIGNED_EXAMPLE, RSA_EXAMPLE)
        self.verify(self.rsa_keyfile, RSA_SIGNED_EXAMPLE, RSA_EXAMPLE)

    def test_dsa(self):
        self.check_that_signed_starts_with_expected(
            DSA_SIGNED_EXAMPLE, DSA_EXAMPLE)
        self.verify(self.dsa_keyfile, DSA_SIGNED_EXAMPLE, DSA_EXAMPLE)

    def test_invalid_content(self):
        self.assertRaises(
            SignatureVerificationFailed, self.verify,
            self.rsa_keyfile, RSA_SIGNED_EXAMPLE, 'Differing content.')
        self.assertRaises(
            SignatureVerificationFailed, self.verify,
            self.dsa_keyfile, DSA_SIGNED_EXAMPLE, 'Differing content.')
        self.assertRaises(
            SignatureVerificationFailed, self.verify,
            self.rsa_keyfile, RSA_SIGNED_EXAMPLE, RSA_EXAMPLE + '\n')
        self.assertRaises(
            SignatureVerificationFailed, self.verify,
            self.dsa_keyfile, DSA_SIGNED_EXAMPLE, DSA_EXAMPLE + '\n')

    def test_wrong_key(self):
        self.assertRaises(
            SignatureVerificationFailed, self.verify,
            self.dsa_keyfile, RSA_SIGNED_EXAMPLE, RSA_EXAMPLE)
        self.assertRaises(
            SignatureVerificationFailed, self.verify,
            self.rsa_keyfile, DSA_SIGNED_EXAMPLE, DSA_EXAMPLE)
