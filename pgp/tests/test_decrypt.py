import os.path
import unittest

from pgp import read_message, read_key_file


RSA_ENCRYPTED_EXAMPLE = '''
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1

hIwD5Bvqd+L4q4IBA/0Yq+/GYtcpXmYF279thz3+LJwrP0mITBTjztzOpCGScd7v
/VOAEAUUzqrevcEb30VZq+PhKHJP1r/w6Vj8mRXPsKaLEovzY/lXUIjbfn/H+qY+
2UQejwAEbyJJr69lawTjw8GHp3hrgZtJ7mFzoTlSecDKNbbSrY4TFHnC6aOsHNJW
AaEb+Bl+KIlTpIRIkKCYxWLyyLO9TfWlbhWAjueoTmp+lJ6jt107AK3GNXq6yghX
NpshKpyTqNbD6C6U3fUeJUfOxu+YvlATy84YsOz6uay4Z0X7NVo=
=QwRw
-----END PGP MESSAGE-----
'''
RSA_EXAMPLE = 'RSA-key encrypted example.\n'

ELG_ENCRYPTED_EXAMPLE = '''
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1

hQEOAyE05e0pooDMEAQApQP7dJdoxY3McPt0MLKiEimgjpLjmVK7Hq9hD/U9/Jjj
sTjLrdeKzTSjbgiSmCUEWRM6bytGwyZavaNsT5RaA/E+/sv2UJHZy6XhIwi6jOVU
/AawsLt/ggm430UiM5+M00ZjDDDu2t5fn6cL631LHN2X97gOkzNWmA1CYLfaeT0E
ALIZ+WnOmcmFrbETh2HXtJCSB85Yks5Kn9y36RK7m4g8cRjzefrEh1u9fkOdK6XZ
qJhKAUhTsXwW0yw/GE2DnfaBuMIyE1e+AE27xX6rT0YLbbeFIZw87qU5Vn6to4/3
HBH8/veEMNekcsiMHpvSqy1Sy6qy8ex/WrrEcsgSC1+d0lYBxAKTQZn7aDN8HY0h
Fjffx9zaFyZzo0ODXjePBVREHo5V1VlVFqAL7E/DVB3XeRLnIkS35WuMpTCTtaJx
JA0rCBomJ4yXjOALr23lOnxXiJNahYqOdw==
=rr2+
-----END PGP MESSAGE-----
'''
ELG_EXAMPLE = 'ELG-key encrypted example.\n'


class DecryptTest(unittest.TestCase):
    def decrypt(self, keyfile, password, encrypted, expected):
        key = read_key_file(keyfile, armored=True)
        key.unlock(password)
        subkey = key.subkeys[0]

        my_message = read_message(encrypted, armored=True)
        wrapper = my_message.get_message(subkey)
        while hasattr(wrapper, 'get_message'):  # compressedmessagewrapper?
            wrapper = wrapper.get_message()
        my_message = wrapper.data

        self.assertEqual(my_message.decode('utf-8'), expected)

    def test_rsa(self):
        self.decrypt(
            os.path.join(
                os.path.dirname(__file__),
                'data/key-example-walter-rsa-rsa.priv'),
            'walter2',
            RSA_ENCRYPTED_EXAMPLE,
            RSA_EXAMPLE)

    def test_elg(self):
        self.decrypt(
            os.path.join(
                os.path.dirname(__file__),
                'data/key-example-walter-dsa-elgamal.priv'),
            'walter2',
            ELG_ENCRYPTED_EXAMPLE,
            ELG_EXAMPLE)
