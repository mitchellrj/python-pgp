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

from __future__ import absolute_import

from Crypto.Cipher import blockalgo
import twofish as twofish_impl

from pgp.cipher.base import _InternalObj


__all__ = [
    'TwofishCipher', 'new', 'MODE_CBC', 'MODE_CFB', 'MODE_CTR', 'MODE_EAX',
    'MODE_ECB', 'MODE_OFB', 'MODE_OPENPGP', 'MODE_PGP',
    ]


class _TwofishObj(_InternalObj):

    @classmethod
    def _create_impl(cls, key):
        return twofish_impl.Twofish(bytes(key))

    block_size = 16
    key_size = (16, 24, 32)


# Mock out a PyCrypt style cipher using camcrypt underneath
class TwofishCipher(blockalgo.BlockAlgo):

    def __init__(self, key, *args, **kwargs):
        blockalgo.BlockAlgo.__init__(self, _TwofishObj, key, *args, **kwargs)


def new(key, *args, **kwargs):
    """Create a new Twofish cipher

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

    :Return: an `TwofishCipher` object
    """
    return TwofishCipher(key, *args, **kwargs)


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
block_size = _TwofishObj.block_size
#: Size of a key (in bytes)
key_size = _TwofishObj.key_size
