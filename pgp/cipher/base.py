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

__all__ = [
    '_InternalObj', 'MODE_CBC', 'MODE_CFB', 'MODE_CTR', 'MODE_EAX',
    'MODE_ECB', 'MODE_OFB', 'MODE_OPENPGP', 'MODE_PGP',
    ]


try:
    unicode
except NameError:
    unicode = str


class _InternalObj(object):

    # Must be implemented by inheriting classes
    block_size = None
    key_size = None

    # Instance attributes
    segment_size = None
    counter = None
    _impl = None
    old_cipher = None
    IV = None
    mode = None
    count = None

    @classmethod
    def _create_impl(self, key):
        raise NotImplemented  # pragma: no cover

    def _encrypt(self, bytes_):
        return self._impl.encrypt(bytes_)

    def _decrypt(self, bytes_):
        return self._impl.decrypt(bytes_)

    @classmethod
    def new(cls, key, mode=None, IV=None, counter=None, segment_size=0, *args,
            **kwargs):
        if mode is None:
            mode = MODE_ECB

        if mode < MODE_ECB or mode > MODE_CTR:
            raise ValueError('Unknown cipher feedback mode {0}'.format(mode))
        if mode == MODE_PGP:
            raise ValueError('MODE_PGP is not supported anymore')
        if len(key) not in cls.key_size:
            raise ValueError(
                    'Key must be 16, 24 or 32 bytes long, not {0}'.format(
                        len(key)))
        if mode == MODE_ECB and IV:
            # Ignore for now
            pass
            # raise ValueError('ECB mode does not use IV')
        if mode == MODE_CTR and IV:
            raise ValueError('CTR mode needs counter parameter, not IV')
        if ((IV is None
             or len(IV) != cls.block_size)
            and mode not in (MODE_ECB, MODE_CTR)):

            raise ValueError('IV must be {0} bytes long'.format(
                                    cls.block_size))
        if mode == MODE_CFB:
            if segment_size == 0:
                segment_size = 8
            if (segment_size < 1
                or segment_size > cls.block_size * 8
                or (segment_size & 7) != 0):

                raise ValueError('Segment_size must be multiple of 8 (bits) '
                                 'between 1 and {0}. Got {1}.'.format(
                                    cls.block_size * 8, segment_size))
        if mode == MODE_CTR:
            if counter is None:
                raise TypeError("'counter' keyword parameter is required "
                                "with CTR mode")
            if not callable(counter):
                raise ValueError("'counter' parameter must be a callable "
                                 "object")
        elif counter is not None:
            raise ValueError("'counter' parameter only useful with CTR mode")

        obj = cls()
        obj.segment_size = segment_size
        obj.counter = counter
        obj._impl = cls._create_impl(key)
        obj.key_size = len(key)
        obj.old_cipher = bytearray([0] * cls.block_size)
        obj.IV = IV
        if obj.IV is not None:
            if isinstance(IV, unicode):
                IV = IV.encode('ascii')
            obj.IV = bytearray(IV)
        obj.mode = mode
        obj.count = cls.block_size
        return obj

    def encrypt(self, plaintext):
        length = len(plaintext)
        plaintext = bytearray(plaintext)
        temp = bytearray([0] * self.block_size)
        result = bytearray([0] * length)
        i = 0
        if (length % self.block_size
            and self.mode not in (MODE_CFB, MODE_OFB, MODE_CTR)):

            raise ValueError(("Input strings must be a multiple of {0} in "
                              "length").format(self.block_size))
        if self.mode == MODE_CFB and length % (self.segment_size // 8):
            raise ValueError(("Input strings must be a multiple of the "
                              "segment size {0} in length").format(
                                self.segment_size // 8
                            ))

        if self.mode == MODE_ECB:
            while i < length:
                result[i:i + self.block_size] = self._encrypt(
                                bytes(plaintext[i:i + self.block_size])
                                )
                i += self.block_size
        elif self.mode == MODE_CBC:
            while i < length:
                for j in range(self.block_size):
                    temp[j] = plaintext[i + j] ^ self.IV[j]
                result[i:i + self.block_size] = bytearray(
                                    self._encrypt(bytes(temp))
                                    )
                self.IV = result[i:i + self.block_size]
                i += self.block_size
        elif self.mode == MODE_CFB:
            while i < length:
                temp = bytearray(self._encrypt(bytes(self.IV)))
                for j in range(0, self.segment_size // 8):
                    result[i + j] = temp[j] ^ plaintext[i + j]

                if self.segment_size == self.block_size * 8:
                    self.IV = result[i:i + self.block_size]
                elif self.segment_size % 8 == 0:
                    # Shift the IV left by 'size' and append the latest 'size'
                    # bytes from the result
                    size = self.segment_size // 8
                    self.IV = self.IV[size:]
                    self.IV.extend(result[i:i + size])
                    assert len(self.IV) == self.block_size
                else:
                    # segment_size is not a multiple of 8;
                    # currently this can't happen
                    raise ValueError
                i += self.segment_size // 8

            self.count = abs(self.count - (length % self.block_size))
        elif self.mode == MODE_OFB:
            # OFB mode is a stream cipher whose keystream is generated by
            # encrypting the previous ciphered output.
            # - self.IV stores the current keystream block
            # - self.count indicates the current offset within the current
            #   keystream block
            # - plaintext stores the input bytearray
            # - result stores the output bytearray
            # - length indicates the length of the input and output strings
            # - i indicates the current offset within the input and output
            #   strings
            # (length - i) is the number of bytes remaining to encrypt
            # (block_size - self.count) is the number of bytes remaining in
            # the current keystream block
            while i < length:
                # If we don't need more than what remains of the current
                # keystream block, then just XOR it in
                if length - i <= self.block_size - self.count:
                    for j in range(0, length - i):
                        result[i + j] = \
                            self.IV[self.count + j] ^ plaintext[i + j]
                    self.count += length - i
                    i = length
                    continue

                # Use up the current keystream block
                for j in range(0, self.block_size - self.count):
                    result[i + j] = self.IV[self.count + j] ^ plaintext[i + j]
                i += self.block_size - self.count
                self.count = self.block_size

                self.IV = bytearray(self._encrypt(bytes(self.IV)))
                self.count = 0
        elif self.mode == MODE_CTR:
            # CTR mode is a stream cipher whose keystream is generated by
            # encrypting unique counter values.
            # - self.counter points to the Counter callable, which is
            #   responsible for generating keystream blocks
            # - self.count indicates the current offset within the current
            #   keystream block
            # - self.IV stores the current keystream block
            # - plaintext stores the input bytearray
            # - result stores the output bytearray
            # - length indicates the length of the input and output strings
            # - i indicates the current offset within the input and output
            #   strings
            # - (length - i) is the number of bytes remaining to encrypt
            # - (block_size - self.count) is the number of bytes remaining in
            #   the current keystream block
            while i < length:
                # If we don't need more than what remains of the current
                # keystream block, then just XOR it in
                if length - i <= self.block_size - self.count:
                    for j in range(0, length - i):
                        self.IV[self.count + j] ^= plaintext[i + j]
                        result[i + j] = self.IV[self.count + j]
                    self.count += length - i
                    i = length
                    continue

                # Use up the current keystream block
                for j in range(0, self.block_size - self.count):
                    self.IV[self.count + j] ^= plaintext[i + j]
                    result[i + j] = self.IV[self.count + j]
                i += self.block_size - self.count
                self.count = self.block_size

                # Generate a new keystream block
                ctr = self.counter()
                if not isinstance(ctr, (str, bytes, bytearray)):
                    raise TypeError("CTR counter function didn't return a "
                                    "bytestring")
                if len(ctr) != self.block_size:
                    raise TypeError("CTR counter function returned "
                                    "bytestring not of length {0}".format(
                                    self.block_size))
                self.IV = bytearray(self._encrypt(bytes(ctr)))
                self.count = 0
        else:
            raise RuntimeError(("Unknown ciphertext feedback mode {0}; "
                                "this shouldn't happen").format(self.mode))

        return bytes(result)

    def decrypt(self, ciphertext):
        ciphertext = bytearray(ciphertext)
        length = len(ciphertext)
        result = bytearray([0] * length)
        temp = bytearray([0] * self.block_size)
        i = 0
        if self.mode in (MODE_CTR, MODE_OFB):
            return self.encrypt(ciphertext)

        if length % self.block_size and self.mode != MODE_CFB:
            raise ValueError("Input strings must be "
                             "a multiple of {0} in length".format(
                                    self.block_size))

        if (self.mode == MODE_CFB
            and length % (self.segment_size // 8)):
            raise ValueError("Input strings must be a multiple of "
                             "the segment size {0} in length".format(
                            self.segment_size // 8))

        if self.mode == MODE_ECB:
            while i < length:
                result[i:i + self.block_size] = bytearray(self._decrypt(
                            bytes(ciphertext[i:i + self.block_size])
                        )
                    )
                i += self.block_size
        elif self.mode == MODE_CBC:
            while i < length:
                self.old_cipher = self.IV[:]
                temp = bytearray(self._decrypt(bytes(
                        ciphertext[i:i + self.block_size]
                        )))
                for j in range(0, self.block_size):
                    result[i + j] = temp[j] ^ self.IV[j]
                    self.IV[j] = ciphertext[i + j]
                i += self.block_size
        elif self.mode == MODE_CFB:
            while i < length:
                temp = bytearray(self._encrypt(bytes(self.IV)))

                for j in range(0, self.segment_size // 8):
                    result[i + j] = temp[j] ^ ciphertext[i + j]

                if self.segment_size == self.block_size * 8:
                    self.IV[:self.block_size] = \
                        ciphertext[i:i + self.block_size]
                elif self.segment_size % 8 == 0:
                    # Shift the IV left by 'size' and append the latest 'size'
                    # bytes from the ciphertext
                    size = self.segment_size // 8
                    self.IV = self.IV[size:]
                    self.IV.extend(ciphertext[i:i + size])
                    assert len(self.IV) == self.block_size
                else:
                    # segment_size is not a multiple of 8;
                    # currently this can't happen
                    raise ValueError

                i += self.segment_size // 8

            self.count = abs(self.count - (length % self.block_size))
        elif self.mode == MODE_OFB:
            # OFB mode is a stream cipher whose keystream is generated by

                i += self.segment_size // 8
        else:
            raise RuntimeError(("Unknown ciphertext feedback mode {0}; "
                                "this shouldn't happen").format(self.mode))

        return bytes(result)

    def sync(self):
        if self.mode == MODE_CFB:
            # Shift the IV left by 'size' and append the latest 'size'
            # bytes from the ciphertext
            unused = self.block_size - self.count
            if unused == 0:
                return
            self.IV[unused:] = self.IV[:self.block_size - unused]
            self.IV[:unused] = self.old_cipher[self.block_size - unused:]
            assert len(self.IV) == self.block_size
        else:
            pass


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
