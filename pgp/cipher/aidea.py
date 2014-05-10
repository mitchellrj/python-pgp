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

from Crypto.Cipher import blockalgo

from pgp.cipher.base import _InternalObj


__all__ = [
    'AIDEACipher', 'new', 'MODE_CBC', 'MODE_CFB', 'MODE_CTR', 'MODE_EAX',
    'MODE_ECB', 'MODE_OFB', 'MODE_OPENPGP', 'MODE_PGP',
    ]


def mul(x, y):
    """Multiplication modulo 65537."""
    x = (x - 1) & 0xffff
    t16 = (y - 1) & 0xffff
    t32 = x * t16 + x + t16
    x = t32 & 0xffff
    t16 = t32 >> 16
    x = x - t16 + int(x < t16) + 1
    return x


def mul_inv(x):
    """The multiplicative inverse of x, modulo 65537."""

    x = x & 0xffff
    if x <= 1:
        return x
    t0 = 1
    t1 = 0x10001 // x
    y = (0x10001 % x) & 0xffff
    while y != 1:
        q = x // y
        x = x % y
        t0 = (t0 + (q * t1)) & 0xffff
        if x == 1:
            return t0
        q = y // x
        y = y % x
        t1 = (t1 + (q * t0)) & 0xffff

    return (1 - t1) & 0xffff


class AIDEA(object):

    def _generate_enc_keys(self, key):
        key_shorts = self._bytes_to_shorts(key)
        result = key_shorts + [0] * (52 - len(key_shorts))

        for i in range(8, 52):
            x = i - 7 if ((i + 1) % 8 > 0) else i - 15
            y = i - 14 if ((i + 2) % 8 < 2) else i - 6
            result[i] = ((result[x] << 9) | (result[y] >> 7)) & 0xffff
        return result

    def _generate_dec_keys(self, key, encryption_key_table):
        result = []
        result.insert(0, mul_inv(encryption_key_table[3]))
        result.insert(0, (-encryption_key_table[2]) & 0xffff)
        result.insert(0, (-encryption_key_table[1]) & 0xffff)
        result.insert(0, mul_inv(encryption_key_table[0]))

        offset = 4
        for i in range(42, -1, -6):
            result.insert(0, encryption_key_table[offset + 1] & 0xffff)
            result.insert(0, encryption_key_table[offset] & 0xffff)
            result.insert(0, mul_inv(encryption_key_table[offset + 5]))
            if i == 0:
                result.insert(0, (-encryption_key_table[offset + 4]) & 0xffff)
                result.insert(0, (-encryption_key_table[offset + 3]) & 0xffff)
            else:
                result.insert(0, (-encryption_key_table[offset + 3]) & 0xffff)
                result.insert(0, (-encryption_key_table[offset + 4]) & 0xffff)
            result.insert(0, mul_inv(encryption_key_table[offset + 2]))
            offset += 6

        return result

    def __init__(self, key, dummy=None):
        self.encryption_key_table = ekt = self._generate_enc_keys(key)
        self.decryption_key_table = self._generate_dec_keys(key, ekt)

    def _bytes_to_shorts(self, block):
        block = bytearray(block)
        result = []
        i = 0
        while i < len(block):
            result.append((block[i] << 8) + block[i + 1])
            i += 2
        return result

    def _shorts_to_bytes(self, shorts):
        result = bytearray()
        for s in shorts:
            result.append(s >> 8)
            result.append(s & 0xff)
        return result

    def _cipher(self, block_in, key_table):
        x1, x2, x3, x4 = self._bytes_to_shorts(block_in)
        offset = 0
        for _ in range(8):
            x1 = mul(x1 & 0xffff, key_table[offset])
            x2 += key_table[offset + 1]
            x3 += key_table[offset + 2]
            x4 = mul(x4 & 0xffff, key_table[offset + 3])

            t2 = x1 ^ x3
            t2 = mul(t2 & 0xffff, key_table[offset + 4])
            t1 = t2 + (x2 ^ x4)
            t1 = mul(t1 & 0xffff, key_table[offset + 5])
            t2 += t1

            x1 ^= t1
            x4 ^= t2
            t2 ^= x2
            x2 = x3 ^ t1
            x3 = t2
            offset += 6

        block_out = self._shorts_to_bytes([
            mul(x1 & 0xffff, key_table[offset]) & 0xffff,
            (x3 + key_table[offset + 1]) & 0xffff,
            (x2 + key_table[offset + 2]) & 0xffff,
            mul(x4 & 0xffff, key_table[offset + 3]) & 0xffff,
            ])
        return bytes(block_out)

    def encrypt(self, block_in):
        return self._cipher(block_in, self.encryption_key_table)

    def decrypt(self, block_in):
        return self._cipher(block_in, self.decryption_key_table)


class _AIDEAObj(_InternalObj):

    @classmethod
    def _create_impl(cls, key):
        impl = AIDEA(key)
        return impl

    block_size = 8
    key_size = (16,)


# Mock out a PyCrypt style cipher using camcrypt underneath
class AIDEACipher(blockalgo.BlockAlgo):

    def __init__(self, key, *args, **kwargs):
        blockalgo.BlockAlgo.__init__(self, _AIDEAObj, key, *args, **kwargs)


def new(key, *args, **kwargs):
    """Create a new Alleged IDEA cipher

    :Parameters:
      key : byte string
        The secret key to use in the symmetric cipher.
        Its length may vary from 5 to 16 bytes.
    :Keywords:
      mode : a *MODE_** constant
        The chaining mode to use for encryption or decryption.
        Default is `MODE_ECB`.
      IV : byte string
        (*Only* `MODE_CBC`, `MODE_CFB`, `MODE_OFB`, `MODE_OPENPGP`).

        The initialization vector to use for encryption or decryption.

        It is ignored for `MODE_ECB` and `MODE_CTR`.

        For `MODE_OPENPGP`, IV must be `block_size` bytes long for
        encryption and `block_size` +2 bytes for decryption (in the
        latter case, it is actually the *encrypted* IV which was
        prefixed to the ciphertext). It is mandatory.

        For all other modes, it must be 8 bytes long.
      nonce : byte string
        (*Only* `MODE_EAX`).
        A mandatory value that must never be reused for any other
        encryption. There are no restrictions on its length, but it is
        recommended to use at least 16 bytes.
      counter : callable
        (*Only* `MODE_CTR`). A stateful function that returns the next
        *counter block*, which is a byte string of `block_size` bytes.
        For better performance, use `Crypto.Util.Counter`.
      mac_len : integer
        (*Only* `MODE_EAX`). Length of the MAC, in bytes.
        It must be no larger than 8 (which is the default).
      segment_size : integer
        (*Only* `MODE_CFB`).The number of bits the plaintext and
        ciphertext are segmented in.
        It must be a multiple of 8. If 0 or not specified, it will be
        assumed to be 8.

    :Return: an `AIDEACipher` object
    """
    return AIDEACipher(key, *args, **kwargs)


#: Electronic Code Book (ECB). See `blockalgo.MODE_ECB`.
MODE_ECB = 1
#: Cipher-Block Chaining (CBC). See `blockalgo.MODE_CBC`.
MODE_CBC = 2
#: Cipher FeedBack (CFB). See `blockalgo.MODE_CFB`.
MODE_CFB = 3
#: This mode should not be used.
MODE_PGP = 4
#: Output FeedBack (OFB). See `blockalgo.MODE_OFB`.
MODE_OFB = 5
#: CounTer Mode (CTR). See `blockalgo.MODE_CTR`.
MODE_CTR = 6
#: OpenPGP Mode. See `blockalgo.MODE_OPENPGP`.
MODE_OPENPGP = 7
#: EAX Mode. See `blockalgo.MODE_EAX`.
MODE_EAX = 9
#: Size of a data block (in bytes)
block_size = _AIDEAObj.block_size
#: Size of a key (in bytes)
key_size = _AIDEAObj.key_size
