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


# Simple tool for verifying test data with openssl
def verify_openssl(cipher):
    import binascii
    import importlib
    import os
    import subprocess
    import tempfile

    module = importlib.import_module('.test_{0}'.format(cipher),
                                     'pgp.cipher.tests')
    test_data = module.test_data

    for item in test_data:
        plaintext = binascii.unhexlify(item[0])
        expected_ciphertext = binascii.unhexlify(item[1])
        key = item[2]
        test_name = item[3]
        if len(item) != 5:
            extra = {}
        else:
            extra = item[4]
        mode = extra.get('mode', 'ecb').lower()
        key_size = len(key) * 4
        _fd, ptfn = tempfile.mkstemp()
        try:
            f = open(ptfn, 'wb')
            f.write(plaintext)
            f.close()
            command = [
                'openssl',
                'enc',
                '-{cipher}-{key_size}-{mode}'.format(
                        cipher=cipher, key_size=key_size, mode=mode),
                '-in',
                ptfn,
                '-e',
                '-nosalt',
                '-K',
                key
                ]
            if 'iv' in extra:
                command.extend(['-iv', extra['iv']])
            try:
                ciphertext = subprocess.check_output(command)
            except subprocess.CalledProcessError as e:
                print('{n} errored.'.format(n=test_name))
                print(' '.join(command))
                print(e.output)
                continue
            if ciphertext[:len(expected_ciphertext)] != expected_ciphertext:
                print('{n} failed.'.format(n=test_name))
                print('{c} !='.format(c=binascii.hexlify(ciphertext)))
                print('{ec}'.format(ec=binascii.hexlify(expected_ciphertext)))
            else:
                print('{n} succeeded.'.format(n=test_name))
        except:
            os.unlink(ptfn)
            raise


if __name__ == '__main__':
    import sys

    cipher = sys.argv[1]
    verify_openssl(cipher)
