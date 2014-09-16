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

import bz2
import math
import zlib

from Crypto.Cipher import blockalgo
from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
from Crypto.Cipher import DES3
from Crypto.Cipher import CAST
from Crypto.Hash import MD5
from Crypto.Hash import RIPEMD
from Crypto.Hash import SHA
from Crypto.Hash import SHA224
from Crypto.Hash import SHA256
from Crypto.Hash import SHA384
from Crypto.Hash import SHA512
from Crypto.PublicKey import DSA
from Crypto.PublicKey import ElGamal
from Crypto.PublicKey import RSA
from Crypto.Random import random
from Crypto.Signature import PKCS1_v1_5
from Crypto.Util.number import bytes_to_long
from Crypto.Util.number import GCD
from Crypto.Util.number import long_to_bytes

from pgp.cipher import aidea
from pgp.cipher import camellia
from pgp.cipher import twofish
from pgp.cipher import wrapper as syncable_cipher_wrapper
from pgp.exceptions import PublicKeyAlgorithmCannotSign
from pgp.exceptions import UnsupportedDigestAlgorithm
from pgp.exceptions import UnsupportedPublicKeyAlgorithm


hash_lengths = {
    1: 16,  # MD5
    2: 20,  # SHA1
    3: 20,  # RIPE-MD/160
    8: 32,  # SHA256
    9: 48,  # SHA384
    10: 64,  # SHA512
    11: 28,  # SHA224
    }


symmetric_cipher_block_lengths = {
    0: 0,  # Plaintext
    1: 8,  # IDEA
    2: 8,  # Triple-DES
    3: 8,  # CAST5
    4: 8,  # Blowfish
    7: 16,  # AES-128
    8: 16,  # AES-192
    9: 16,  # AES-256
    10: 16,  # Twofish-256
    11: 16,  # Camellia-128
    12: 16,  # Camellia-192
    13: 16,  # Camellia-256
    }


symmetric_cipher_key_lengths = {
    0: 0,  # Plaintext
    1: 16,  # IDEA
    2: 24,  # Triple-DES
    3: 16,  # CAST5
    4: 16,  # Blowfish
    7: 16,  # AES-128
    8: 24,  # AES-192
    9: 32,  # AES-256
    10: 16,  # Twofish-256
    11: 16,  # Camellia-128
    12: 24,  # Camellia-192
    13: 32,  # Camellia-256
    }


def sign_hash(pub_algorithm_type, secret_key, hash_, k=None):
    if pub_algorithm_type in (1, 3):
        # RSA
        sig_string = PKCS1_v1_5.new(secret_key).sign(hash_)
        return (bytes_to_long(sig_string),)
    elif pub_algorithm_type == 20:
        # ELG
        # TODO: Should only be allowed for test purposes
        if k is None:
            while 1:
                # This can be pretty darn slow
                k = random.StrongRandom().randint(1, secret_key.p - 1)
                if GCD(k, secret_key.p - 1) == 1:
                    break
            print(k)
        # TODO: Remove dependence on undocumented method
        sig_string = PKCS1_v1_5.EMSA_PKCS1_V1_5_ENCODE(
                            hash_, secret_key.size())
        return secret_key.sign(sig_string, k)
    elif pub_algorithm_type == 17:
        q = secret_key.q
        qbits = int(math.floor(float(math.log(q, 2)))) + 1
        qbytes = int(math.ceil(qbits / 8.0))
        if k is None:
            k = random.StrongRandom().randint(1, q - 1)

        digest = hash_.digest()[:qbytes]
        return secret_key.sign(bytes_to_long(digest), k)
    else:
        # TODO: complete
        raise ValueError


def verify_hash(pub_algorithm_type, public_key, hash_, values):
    if pub_algorithm_type in (1, 3):
        # RSA
        s = long_to_bytes(values[0])
        return PKCS1_v1_5.new(public_key).verify(hash_, s)
    elif pub_algorithm_type == 20:
        # ELG
        # TODO: Remove dependence on undocumented method
        sig_string = PKCS1_v1_5.EMSA_PKCS1_V1_5_ENCODE(
                            hash_, public_key.size())
        return public_key.verify(sig_string, values)
    elif pub_algorithm_type == 17:
        # DSA
        q = public_key.q
        qbits = int(math.floor(float(math.log(q, 2)))) + 1
        qbytes = int(math.ceil(qbits / 8.0))

        digest = hash_.digest()
        # Discard empty leading bytes
        start = 0
        while digest[start] == b'\x00':
            start += 1
        digest = digest[start:start + qbytes]
        return public_key.verify(bytes_to_long(digest), values)
    else:
        # TODO: complete this
        raise ValueError


def get_hash_instance(type_):
    """Given a hash type code, returns a new hash instance for that
    type.
    """

    if type_ == 1:
        return MD5.new()
    elif type_ == 2:
        return SHA.new()
    elif type_ == 3:
        return RIPEMD.new()
    elif type_ == 8:
        return SHA256.new()
    elif type_ == 9:
        return SHA384.new()
    elif type_ == 10:
        return SHA512.new()
    elif type_ == 11:
        return SHA224.new()
    else:
        raise UnsupportedDigestAlgorithm(type_)


def get_public_key_constructor(type_):
    """Given a public key type code, returns a function which may be
    used to construct a new instance of that key.
    """
    if type_ == 1:
        # rsa encrypt or sign
        return RSA.construct
    elif type_ == 2:
        # rsa encrypt only
        # invalid for signing
        raise PublicKeyAlgorithmCannotSign(2)
    elif type_ == 3:
        # rsa sign only
        return RSA.construct
    elif type_ == 16:
        # elgamel encrypt only
        # invalid for signing
        raise PublicKeyAlgorithmCannotSign(16)
    elif type_ == 17:
        # dsa
        return DSA.construct
    elif type_ == 18:
        # ec
        # invalid for signing
        raise PublicKeyAlgorithmCannotSign(18)
    elif type_ == 19:
        # ecdsa
        raise UnsupportedPublicKeyAlgorithm(19)
    elif type_ == 20:
        # elgamel encrypt or sign
        return ElGamal.construct
    elif type_ == 21:
        # diffie-hellman
        # invalid for signing
        raise PublicKeyAlgorithmCannotSign(21)
    elif type_ == 105:
        # EDDSA
        # Experimental
        raise UnsupportedPublicKeyAlgorithm(105)
    else:
        raise UnsupportedPublicKeyAlgorithm(type_)


class NoopCipher():

    def __init__(self, *args, **kwargs):
        pass

    def encrypt(self, block):
        return block

    def decrypt(self, block):
        return block


ECB = blockalgo.MODE_ECB
CBC = blockalgo.MODE_CBC
CFB = blockalgo.MODE_CFB
OFB = blockalgo.MODE_OFB
CTR = blockalgo.MODE_CTR
OPENPGP = blockalgo.MODE_OPENPGP


def get_symmetric_cipher(type_, key, mode, iv=None, segment_size=None,
                         syncable=False):
    """
    """

    if mode == ECB:
        mode = blockalgo.MODE_ECB
    elif mode == CBC:
        mode = blockalgo.MODE_CBC
    elif mode == CFB:
        mode = blockalgo.MODE_CFB
    elif mode == OFB:
        mode = blockalgo.MODE_OFB
    elif mode == CTR:
        mode = blockalgo.MODE_CTR
    elif mode == OPENPGP:
        mode = blockalgo.MODE_OPENPGP

    cipher = {
        0: NoopCipher,
        1: aidea,
        2: DES3,
        3: CAST,
        4: Blowfish,
        7: AES,
        8: AES,
        9: AES,
        10: twofish,
        # RFC 5581
        11: camellia,
        12: camellia,
        13: camellia,
        }.get(type_, None)

    if segment_size is None and mode == blockalgo.MODE_CFB:
        segment_size = cipher.block_size * 8

    if syncable and cipher not in (aidea, twofish, camellia):
        # We need to wrap the PyCrypto implementation so we can re-sync
        # for OpenPGP's weird CFB mode.
        return syncable_cipher_wrapper.new(cipher, bytes(key), mode,
                                           IV=bytes(iv),
                                           segment_size=segment_size)

    return cipher.new(bytes(key), mode, IV=bytes(iv), segment_size=segment_size)


class NoopCompression(object):

    def compress(self, data):
        return data

    def decompress(self, data):
        return data

    def flush(self):
        return b''


class ZlibCompression(object):

    def __init__(self):
        self._obj = None
        self._compress = None
        self._result = b''

    def compress(self, data):
        if self._result is None:
            # already flushed
            raise ValueError
        if self._compress is False:
            raise ValueError
        if self._obj is None:
            self._compress = True
            self._obj = zlib.compressobj()
            self._result += self._obj.compress(data)
        return b''

    def decompress(self, data):
        if self._result is None:
            # already flushed
            raise ValueError
        if self._compress is True:
            raise ValueError
        if self._obj is None:
            self._compress = False
            self._obj = zlib.decompressobj()
        self._result += self._obj.decompress(data)
        return b''

    def flush(self):
        if self._result is None:
            # already flushed
            raise ValueError
        result = self._result
        result += self._obj.flush()
        self._result = None
        return result


_CompressionObj = zlib.compressobj().__class__
_DecompressionObj = zlib.decompressobj().__class__


class DeflateCompression(object):

    def __init__(self):
        self._obj = None
        self._compress = None
        self._result = b''

    def compress(self, data):
        if self._result is None:
            # already flushed
            raise ValueError
        if self._compress is False:
            raise ValueError
        if self._obj is None:
            self._compress = True
            self._obj = zlib.compressobj()
        self._result += self._obj.compress(data)
        return b''

    def decompress(self, data):
        if self._result is None:
            # already flushed
            raise ValueError
        if self._compress is True:
            raise ValueError
        if self._obj is None:
            self._compress = False
            self._obj = zlib.decompressobj()
            # Fake header
            self._obj.decompress(b'\x78\x9c')
        self._result += self._obj.decompress(data)
        return b''

    def flush(self):
        if self._result is None:
            # already flushed
            raise ValueError
        result = self._result
        result += self._obj.flush()
        self._result = None
        if self._compress:
            # Discard header and checksum
            result = result[2:-4]
        return result


def get_compression_instance(type_):

    instance = None
    if type_ == 0:
        instance = NoopCompression()
    elif type_ == 1:
        # DEFLATE - RFC 1951
        instance = DeflateCompression()
    elif type_ == 2:
        # ZLIB - RFC 1950
        raise ZlibCompression()
    elif type_ == 3:
        instance = bz2.BZ2Compressor()

    return instance


def hash_key(data_to_hash, key_packet_data):
    """Adds key data to a hash for signature comparison."""

    key_length = len(key_packet_data)
    data_to_hash.append(0x99)
    data_to_hash.extend(int_to_2byte(key_length))
    data_to_hash.extend(key_packet_data)


def packet_type_from_first_byte(byte_):
    if byte_ & 0x7f:
        return byte_ & 0x3f
    return (byte_ & 0x3f) >> 2


def hash_user_data(data_to_hash, target_type, target_packet_data, signature_version):
    """Adds user attribute & user id packets to a hash for signature
    comparison.
    """

    if target_type == 13:
        if signature_version >= 4:
            data_to_hash.append(0xb4)
            data_to_hash.extend(int_to_4byte(len(target_packet_data)))
        data_to_hash.extend(target_packet_data)
    elif target_type == 17:
        if signature_version >= 4:
            data_to_hash.extend(bytearray([0xd1]))
            data_to_hash.extend(int_to_4byte(len(target_packet_data)))
        data_to_hash.extend(target_packet_data)


def hash_packet_for_signature(packet_for_hash,
                              signature_type, signature_version,
                              hash_algorithm_type, signature_creation_time,
                              pub_algorithm_type, public_key_packet=None,
                              hashed_subpacket_data=None):

    data_to_hash = bytearray()
    public_key_packet_data = None
    if public_key_packet is not None:
        public_key_packet_data = public_key_packet.content
    packet_data_for_hash = packet_for_hash.content
    if signature_type in (0x1f, 0x20):
        assert public_key_packet_data is not None
        hash_key(data_to_hash, public_key_packet_data)
    elif signature_type in (0x18, 0x19, 0x28):
        assert public_key_packet_data is not None
        hash_key(data_to_hash, public_key_packet_data)
        hash_key(data_to_hash, packet_data_for_hash)
    elif signature_type == 0x50:
        data_to_hash.append(0x88)
        data_to_hash.append(len(packet_data_for_hash))
        data_to_hash.extend(packet_data_for_hash)
    elif signature_type in (0x00, 0x01):
        data_to_hash.extend(packet_data_for_hash)
    elif signature_type == 0x02:
        pass
    elif signature_type in (0x10, 0x11, 0x12, 0x13, 0x30):
        assert public_key_packet_data is not None
        hash_key(data_to_hash, public_key_packet_data)
        hash_user_data(data_to_hash, packet_for_hash.type, packet_data_for_hash,
                       signature_version)
    elif signature_type == 0x40:
        # Timestamp signatures are poorly defined and semi-deprecated.
        #
        # RFC 1991 defines it as "a signature of a signature, as a notary seal
        # on a signed document." We'll just treat it the same as 0x50 for now.
        #
        # https://tools.ietf.org/html/rfc1991
        # http://www.imc.org/ietf-openpgp/mail-archive/msg04966.html
        # http://www.imc.org/ietf-openpgp/mail-archive/msg04970.html
        data_to_hash.append(0x88)
        data_to_hash.append(len(packet_data_for_hash))
        data_to_hash.extend(packet_data_for_hash)

    if signature_version >= 4:
        data_to_hash.append(signature_version)
    data_to_hash.append(signature_type)
    if signature_version < 4:
        data_to_hash.extend(int_to_4byte(signature_creation_time))
    else:
        data_to_hash.append(pub_algorithm_type)
        data_to_hash.append(hash_algorithm_type)
        hashed_subpacket_length = len(hashed_subpacket_data)
        data_to_hash.extend(int_to_2byte(hashed_subpacket_length))
        data_to_hash.extend(hashed_subpacket_data)
        data_to_hash.append(signature_version)
        data_to_hash.append(255)
        data_to_hash.extend(int_to_4byte(hashed_subpacket_length + 6))

    hash_ = get_hash_instance(hash_algorithm_type)
    hash_.update(data_to_hash)
    return hash_


def bytes_to_int(bytes_, offset, length):
    result = 0
    for i in range(length):
        shift = 8 * (length - i - 1)
        result += bytes_[offset + i] << shift
    return result


def byte_to_int(bytes_, offset):
    return bytes_to_int(bytes_, offset, 1)


def short_to_int(bytes_, offset):
    return bytes_to_int(bytes_, offset, 2)


def long_to_int(bytes_, offset):
    return bytes_to_int(bytes_, offset, 4)


def mpi_length(bytes_, offset):
    mpi_bit_length = short_to_int(bytes_, offset)
    return int(math.ceil(mpi_bit_length / 8.0))


def mpi_to_int(bytes_, offset):
    mpi_byte_length = mpi_length(bytes_, offset)
    offset += 2
    result = bytes_to_int(bytes_, offset, mpi_byte_length)
    offset += mpi_byte_length
    return result, offset


def int_to_bytes(i):
    bits_required = int(math.floor(float(math.log(i, 2)))) + 1
    bytes_required = int(math.ceil(bits_required / 8.0))
    result = bytearray(
        [(i >> (j * 8)) & 0xff
         for j in range(bytes_required, 0, -1)
         ])
    return result


def int_to_2byte(i):
    """Given an integer, return a bytearray of its short, unsigned
    representation, big-endian.
    """

    return bytearray([
            (i >> 8) & 0xff,
            i & 0xff
        ])


def int_to_4byte(i):
    """Given an integer, return a bytearray of its unsigned integer
    representation, big-endian.
    """

    return bytearray([
            (i >> 24) & 0xff,
            (i >> 16) & 0xff,
            (i >> 8) & 0xff,
            i & 0xff
        ])


def int_to_8byte(i):
    """Given an integer, return a bytearray of its unsigned integer
    representation, big-endian.
    """

    return bytearray([
            (i >> 56) & 0xff,
            (i >> 48) & 0xff,
            (i >> 40) & 0xff,
            (i >> 32) & 0xff,
            (i >> 24) & 0xff,
            (i >> 16) & 0xff,
            (i >> 8) & 0xff,
            i & 0xff
        ])


EXPBIAS = 6


def s2k_count_to_int(byte, offset=0):
    return (16 + (byte & 15)) << ((byte >> 4) + EXPBIAS)


def int_to_s2k_count(i):
    if i < 1024:
        raise ValueError(i)
    if i > 65011712:
        raise ValueError(i)
    shift = int(math.floor(math.log(i, 2))) - 4
    if i & ((1 << shift) - 1):
        raise ValueError(i)
    bits = (i >> shift) & 15
    return ((shift - EXPBIAS) << 4) + bits


def int_to_hex(i, expected_size=None):
    fmt = '{:X}'
    if expected_size is not None:
        fmt = '{{:0{size}X}}'.format(size=expected_size)
    result = fmt.format(i)
    if expected_size is not None:
        result = result[-expected_size:]
    return result


def int_to_mpi(i):
    if i < 0:
        raise ValueError(i)
    elif i == 0:
        return bytearray([0, 0])
    bits_required = int(math.floor(float(math.log(i, 2)))) + 1
    bytes_required = int(math.ceil(bits_required / 8.0))
    result = bytearray() + int_to_2byte(bits_required)
    for b in range(bytes_required - 1, -1, -1):
        result.append((i >> (b * 8)) & 0xff)
    return result


MAX_PACKET_LENGTH = 4294967295


def old_packet_length_from_stream(fh):
    length_type = ord(fh.read(1)) & 0x03
    if length_type == 0:
        length = ord(fh.read(1))
    elif length_type == 1:
        length = short_to_int(bytearray(fh.read(2)), 0)
    elif length_type == 2:
        length = long_to_int(bytearray(fh.read(4)), 0)
    else:
        # with & 3 and the other cases, this has to be 3.
        raise ValueError
    return length


def old_packet_length(data, offset):
    length_type = int(data[offset]) & 0x03
    offset += 1
    if length_type == 0:
        length = int(data[offset])
        offset += 1
    elif length_type == 1:
        length = short_to_int(data, offset)
        offset += 2
    elif length_type == 2:
        length = long_to_int(data, offset)
        offset += 4
    else:
        # with & 3 and the other cases, this has to be 3.
        length = len(data) - offset
    return offset, length


def new_packet_length_from_stream(fh):
    length = ord(fh.read(1))
    partial = False
    if length < 192:
        pass
    elif length < 224:
        length = ((length - 192) << 8) + ord(fh.read(1)) + 192
    elif length == 255:
        length = long_to_int(bytearray(fh.read(4)), 0)
    else:
        partial = True
        length = 1 << (length & 0x1f)
    return length, partial


def new_packet_length(data, offset):
    length = int(data[offset])
    partial = False
    offset += 1
    if length < 192:
        pass
    elif length < 224:
        length = ((length - 192) << 8) + data[offset] + 192
        offset += 1
    elif length == 255:
        length = long_to_int(data, offset)
        offset += 4
    else:
        partial = True
        length = 1 << (length & 0x1f)
    return offset, length, partial


def new_packet_length_to_bytes(data_length, allow_partial):
    result = bytearray()
    remaining = 0
    if data_length < 192:
        # one-octet body length
        result.append(data_length)
    elif data_length < 8384:
        # two-octet body length
        stored_length = data_length - 192
        result.append((stored_length >> 8) + 192)
        result.append(stored_length & 0xff)
    elif data_length <= MAX_PACKET_LENGTH:
        # five-octet body length
        result.append(0xff)
        result.append((data_length >> 24) & 0xff)
        result.append((data_length >> 16) & 0xff)
        result.append((data_length >> 8) & 0xff)
        result.append(data_length & 0xff)
    elif allow_partial:
        # 0x1e is the maximum length: 0x1f + 0xe0 = 0xff which is the same as
        # the five-octet length marker.
        result.append(
            0xe0 +  # Partial marker
            0x1e    # log(partial length, 2)
            )
        remaining = data_length - (2 ** 0x1e)
    else:
        raise ValueError((
                'Cannot store data longer than {0} for subpackets or non-data '
                'packets.').format(
                    MAX_PACKET_LENGTH
                ))

    return result, remaining


def old_packet_length_to_bytes(data_length):
    length_type = 0
    if data_length < 256:
        length_type = 0
        length_bytes = [data_length]
    elif data_length < 65536:
        length_type = 1
        length_bytes = [data_length >> 8,
                        data_length & 0xff]
    elif data_length < 16777216:
        length_type = 2
        length_bytes = [data_length >> 24,
                        (data_length >> 16) & 0xff,
                        (data_length >> 8) & 0xff,
                        data_length & 0xff]
    else:
        length_type = 3
        length_bytes = []
    return length_type, length_bytes


def hex_to_bytes(hex_val, expected_length=None):
    result = bytearray()
    if expected_length is not None:
        result.extend([0] * expected_length)

    for i in range(int(len(hex_val) / 2)):
        idx = i * 2
        result.append(int(hex_val[idx:idx + 2], 16))

    if expected_length is not None:
        result = result[-expected_length:]
    return result


def bytearray_to_hex(arr, offset=0, expected=None):
    result = ''
    i = offset
    if expected is not None:
        assert not expected % 2, "Must expect an even number of hex digits."
        end = offset + (expected / 2)
    else:
        end = len(arr)
    while i < end:
        result += '{:02X}'.format(arr[i]).upper()
        i += 1
    if expected is not None:
        if len(result) < expected:
            result = ('0' * len(result) - expected) + result
        else:
            result = result[-1 * expected:]
    return result


def compare_packets(packet1, packet2):
    c = (packet1.raw > packet2.raw) - (packet1.raw < packet2.raw)
    if c:
        return c
    return (packet1.data > packet2.data) - (packet1.data < packet2.data)


def sort_key(packets):
    return sorted(packets, cmp=compare_packets)


def concat_key(packets):
    buf = bytearray()
    for packet in packets:
        packet_length = len(packet.data)
        buf.append(packet.raw)
        buf.extend([
            (packet_length >> 24) & 0xff,
            (packet_length >> 16) & 0xff,
            (packet_length >> 8) & 0xff,
            packet_length & 0xff
            ])
        buf.extend(packet.data)
    return buf


def hash_key_data(packets):
    canonical_key_data = concat_key(sort_key(packets))
    if not canonical_key_data:
        return bytes('')
    return bytearray(MD5.new(canonical_key_data).hexdigest())


def get_signature_values(signature_packet_data):
    """Get the actual public key signature values from the signature
    packet data.
    """

    data = signature_packet_data

    sig_version = data[0]
    offset = 1
    if sig_version in (2, 3):
        offset += 1  # marker
        offset += 1  # signature type
        offset += 4  # creation time
        offset += 8  # key id
        offset += 1  # pub algorithm
        offset += 1  # hash algorithm
        offset += 2  # hash2
    elif sig_version >= 4:
        offset += 1  # signature type
        offset += 1  # pub algorithm
        offset += 1  # hash algorithm

        # hashed subpackets
        length = short_to_int(data, offset)
        offset += 2
        offset += length

        # unhashed subpackets
        length = short_to_int(data, offset)
        offset += 2
        offset += length

        # hash2
        offset += 2

    data_len = len(data)
    result = []
    while offset < data_len:
        mpi, offset = mpi_to_int(data, offset)
        result.append(mpi)

    return result


def key_packet_fingerprint(packet):
    if packet.version < 4:
        md5 = MD5.new()
        # Key type must be RSA for v2 and v3 public keys
        if packet.public_key_algorithm in (1, 2, 3):
            md5.update(int_to_bytes(packet.modulus_n))
            md5.update(int_to_bytes(packet.exponent_e))
        elif packet.public_key_algorithm in (16, 20):
            md5.update(int_to_bytes(packet.prime_p))
            md5.update(int_to_bytes(packet.group_generator_g))
        fingerprint = md5.hexdigest().upper()
    elif packet.version >= 4:
        sha1 = SHA.new()
        pubkey_data = packet.public_content
        pubkey_length = len(pubkey_data)
        seed_bytes = (
                0x99,
                (pubkey_length >> 8) & 0xff,
                pubkey_length & 0xff
            )
        sha1.update(bytearray(seed_bytes))
        sha1.update(pubkey_data)
        fingerprint = sha1.hexdigest().upper()
    return fingerprint
