import os
import unittest

import datetime
from pgp import armor, message, read_key_file, read_message
from pgp.transferrable_keys import BaseSignature


class EncryptDecryptTest(object):
    MESSAGE = 'This message was encrypted using Python PGP.\n'

    def setUp(self):
        super(EncryptDecryptTest, self).setUp()

        # read_key_file returns a TransferablePublicKey, similar to
        # what you get when doing this:
        # > from pgp.keyserver import get_keyserver
        # > ks = get_keyserver('hkp://pgp.mit.edu/')
        # > results = ks.search('walter@example.com')
        # > self.pubkey = results[0].get()
        self.pubkey = read_key_file(self.pubkey_filename, armored=True)
        self.privkey = read_key_file(self.privkey_filename, armored=True)

        # print('user: {}\nkeyid: {}\nsubkeys: {}'.format(
        #     self.pubkey.user_ids, self.pubkey.key_id, self.pubkey.subkeys))
        self.pubkey_sub = self.pubkey.subkeys[0]
        self.privkey.unlock(self.privkey_password)
        self.privkey_sub = self.privkey.subkeys[0]

        # Create, sign, compress and encrypt.
        my_message = message.TextMessage(
            data=self.MESSAGE, filename='whatever.blob',
            timestamp=datetime.datetime.now())
        # Optional, use main (DSA) key here in case of DSA/ElGamal key
        # combo.
        my_message = my_message.sign(self.privkey)
        # Compression is optional.
        my_message = my_message.compress(2, 6)  # 2 = 'ZLIB - RFC 1950'
        # Encrypt it.
        my_message = my_message.public_key_encrypt(9, self.pubkey_sub)

        # Stream to message.
        message_packets = my_message.to_packets()
        message_data = b''.join(map(bytes, message_packets))
        self.armored_message = str(armor.ASCIIArmor(
            armor.PGP_MESSAGE, message_data))

    def test_recipient_keyid(self):
        my_message = read_message(self.armored_message, armored=True)
        self.assertEqual(
            [i.key_id for i in my_message.session_keys],
            [self.pubkey_sub.key_id])

    def test_recipient_decrypt(self):
        self.assertNotIn(self.MESSAGE, self.armored_message)

        my_message = read_message(self.armored_message, armored=True)
        wrapper = my_message.get_message(self.privkey_sub)

        # Decompress.
        self.assertEqual(wrapper.__class__, message.CompressedMessageWrapper)
        wrapper = wrapper.get_message()

        # Unwrap signature.
        self.assertEqual(wrapper.__class__, message.SignedMessageWrapper)
        signatures = wrapper.signatures
        wrapper = wrapper.get_message()

        # Check message.
        self.assertEqual(wrapper.__class__, message.TextMessage)
        self.assertEqual(wrapper.data, self.MESSAGE)

        # Check signature.
        basesig = BaseSignature.from_packet(
            signatures[0].to_packet(), target=None)
        self.pubkey.verify(basesig, wrapper)


class RsaEncryptDecryptTest(EncryptDecryptTest, unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(RsaEncryptDecryptTest, self).__init__(*args, **kwargs)

        self.pubkey_filename = os.path.join(
            os.path.dirname(__file__),
            'data/key-example-walter-rsa-rsa.pub')
        self.privkey_filename = os.path.join(
            os.path.dirname(__file__),
            'data/key-example-walter-rsa-rsa.priv')
        self.privkey_password = 'walter2'


class ElGamalEncryptDecryptTest(EncryptDecryptTest, unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(ElGamalEncryptDecryptTest, self).__init__(*args, **kwargs)

        self.pubkey_filename = os.path.join(
            os.path.dirname(__file__),
            'data/key-example-walter-dsa-elgamal.pub')
        self.privkey_filename = os.path.join(
            os.path.dirname(__file__),
            'data/key-example-walter-dsa-elgamal.priv')
        self.privkey_password = 'walter2'
