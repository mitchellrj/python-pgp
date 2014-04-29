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

import random

from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
from Crypto.Cipher import CAST
from Crypto.Cipher import DES3
try:
    from Crypto.Cipher import AIDEA
except ImportError:
    # PyCrypto < 2.7
    AIDEA = None
from Crypto.Hash import MD5
from Crypto.Hash import SHA
from pgpdump.packet import SecretKeyPacket

from pgp import utils
from pgp.cipher import camellia
from pgp.cipher import twofish
from pgp.tests.test_keys import make_public_key_packet
from pgp.tests.test_keys import public_key_to_bytes


def make_secret_key_packet(version, creation_time, expiration_days,
                           secret_key, pub_algorithm_type, s2k_id,
                           s2k_specifier=None, s2k_cipher=None,
                           s2k_hash_algorithm_type=None, s2k_salt=None,
                           s2k_iterations=None, s2k_iv=None):
    seckey = SecretKeyPacket(5, 'Secret Key Packet', version >= 4,
                             bytearray(), bytearray())
    public_key = secret_key.publickey()
    result = make_public_key_packet(version, creation_time, expiration_days,
                                    public_key, pub_algorithm_type,
                                    instance=seckey)
    result.s2k_id = s2k_id
    setattr(result, 'raw_s2k_cipher', s2k_cipher)
    result.s2k_cipher = result.lookup_sym_algorithm(s2k_cipher)
    result.s2k_iv = s2k_iv
    setattr(result, 'raw_s2k_type', s2k_specifier)
    result.s2k_type = result.lookup_s2k(s2k_specifier)
    setattr(result, 'raw_s2k_hash', s2k_hash_algorithm_type)
    result.s2k_hash = result.lookup_hash_algorithm(s2k_hash_algorithm_type)
    setattr(result, 's2k_salt', s2k_salt)
    setattr(result, 's2k_iterations', s2k_iterations)
    if pub_algorithm_type in (1, 2, 3):
        result.exponent_d = secret_key.keydata['d']
        result.prime_p = secret_key.keydata['p']
        result.prime_q = secret_key.keydata['q']
        result.multiplicative_inverse = secret_key.keydata['u']
    elif pub_algorithm_type == 17:
        result.exponent_x = secret_key.keydata['x']
    elif pub_algorithm_type in (16, 20):
        result.exponent_x = secret_key.keydata['x']

    return result


s2k_type_lookup = dict([(v[0], k)
                        for k, v in SecretKeyPacket.s2k_types.items()])
s2k_cipher_lookup = dict([(v, k)
                          for k, v in SecretKeyPacket.pub_algorithms.items()])
s2k_hash_lookup = dict([(v, k)
                        for k, v in SecretKeyPacket.hash_algorithms.items()])


def make_salt(length):
    return bytearray([random.randrange(256) for _ in range(length)])


def encode_with_cipher(sym_algorithm_type, iv, secret, data):
    # TODO: V3 encryption support.
    #
    # "With V3 keys, the MPI bit count prefix (i.e., the first two octets) is
    #  not encrypted. Only the MPI non-prefix data is encrypted. Furthermore,
    #  the CFB state is resynchronized at the beginning of each new MPI value,
    #  so that the CFB block boundary is aligned with the start of the MPI
    #  data."
    #
    # What the hell, guys?

    if sym_algorithm_type == 0:
        return data
    elif sym_algorithm_type == 1 and AIDEA is not None:
        cipher = AIDEA.new(secret, mode=AIDEA.MODE_OPENPGP, IV=iv)
        iv_length = 8
    elif sym_algorithm_type == 2:
        cipher = DES3.new(secret, mode=DES3.MODE_OPENPGP, IV=iv)
        iv_length = 8
    elif sym_algorithm_type == 3:
        cipher = CAST.new(secret, mode=CAST.MODE_OPENPGP, IV=iv)
        iv_length = 8
    elif sym_algorithm_type == 4:
        cipher = Blowfish.new(secret, mode=Blowfish.MODE_OPENPGP, IV=iv)
        iv_length = 8
    elif sym_algorithm_type in (7, 8, 9):
        cipher = AES.new(secret, mode=AES.MODE_OPENPGP, IV=iv)
        iv_length = 16
    else:
        # TODO: Add twofish & camellia
        raise NotImplemented

    if len(iv) != iv_length:
        raise ValueError('Invalid IV length, {0}. Expected {1}'.format(
                            len(iv), iv_length
                            ))

    return cipher.encrypt(data)


    # TODO: S2k encoding
def s2k0_encode(sym_algorithm_type, iv, passphrase, data):
    secret = passphrase
    return encode_with_cipher(sym_algorithm_type, iv, secret, data)


def s2k1_encode(sym_algorithm_type, iv, passphrase, data):
    secret = passphrase
    return encode_with_cipher(sym_algorithm_type, iv, secret, data)


def s2k3_encode(sym_algorithm_type, iv, passphrase, data):
    secret = passphrase
    return encode_with_cipher(sym_algorithm_type, iv, secret, data)


def cipher_encode(sym_algorithm_type, iv, passphrase, data):
    secret = MD5.new(passphrase).digest()
    return encode_with_cipher(sym_algorithm_type, iv, secret, data)


def secret_key_to_bytes(packet, passphrase):
    result = public_key_to_bytes(packet)

    unencrypted_data = bytearray()
    pub_algorithm_type = packet.raw_pub_algorithm
    if pub_algorithm_type in (1, 2, 3):
        unencrypted_data.extend(utils.int_to_mpi(result.exponent_d))
        unencrypted_data.extend(utils.int_to_mpi(result.prime_p))
        unencrypted_data.extend(utils.int_to_mpi(result.prime_q))
        unencrypted_data.extend(
                    utils.int_to_mpi(result.multiplicative_inverse)
                    )
    elif pub_algorithm_type in (16, 17, 20):
        unencrypted_data.extend(utils.int_to_mpi(result.exponent_x))

    result.append(packet.s2k_id)
    iv = packet.s2k_iv
    if packet.s2k_id == 0:
        encrypt = lambda x: x
    elif packet.s2k_id in (254, 255):
        s2k_cipher = getattr(packet, 'raw_s2k_cipher', None)
        if s2k_cipher is None:
            s2k_cipher = s2k_cipher_lookup.get(packet.s2k_cipher)
        result.append(s2k_cipher)

        s2k_type = getattr(packet, 'raw_s2k_type', None)
        if s2k_type is None:
            s2k_type = s2k_type_lookup.get(packet.s2k_type)
        result.append(s2k_type)

        if s2k_type in (0, 1, 3):
            s2k_hash = getattr(packet, 'raw_s2k_hash', None)
            if s2k_hash is None:
                s2k_hash = s2k_hash_lookup.get(packet.s2k_hash)
            result.append(s2k_hash)
        if s2k_type == 0:
            encrypt = lambda x: s2k0_encode(s2k_cipher, iv, passphrase, x)
        elif s2k_type == 1:
            s2k_salt = getattr(packet, 'raw_s2k_salt', None)
            if s2k_salt is None:
                s2k_salt = make_salt(8)
            result.extend(s2k_salt)

            encrypt = lambda x: s2k1_encode(s2k_cipher, iv, passphrase, x)
        elif s2k_type == 3:
            s2k_salt = getattr(packet, 's2k_salt', None)
            if s2k_salt is None:
                s2k_salt = make_salt(8)
            result.extend(s2k_salt)

            s2k_iterations = getattr(packet, 's2k_iterations', None)
            if s2k_iterations is None:
                s2k_iterations = 65536
            coded_s2k_iterations = utils.int_to_s2k_count(s2k_iterations)
            result.append(coded_s2k_iterations)

            encrypt = lambda x: s2k3_encode(s2k_cipher, iv, passphrase, x)

    elif packet.s2k_id != 0:
        encrypt = lambda x: cipher_encode(packet.s2k_id, iv, passphrase, x)

    if packet.s2k_id != 0:
        result.extend(packet.s2k_iv)

    if packet.s2k_id in (0, 255):
        checksum = utils.int_to_2byte(sum(unencrypted_data) % 65536)
    elif packet.s2k_id == 254:
        checksum = SHA.new(unencrypted_data).digest()

    if packet.pubkey_version >= 4:
        unencrypted_data.extend(checksum)

    if packet.s2k_id == 0:
        encrypted_data = encrypt(unencrypted_data)

    result.extend(encrypted_data)

    if packet.pubkey_version in (2, 3):
        result.extend(checksum)

    return result
