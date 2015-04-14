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

import math
import os
import time
import warnings

from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA

from pgp.packets import constants
from pgp.packets.signature_subpackets import signature_subpacket_from_data
from pgp.packets.signature_subpackets import EmbeddedSignatureSubpacket
from pgp.packets.user_attribute_subpackets import \
    user_attribute_subpacket_from_data
from pgp import s2k
from pgp import utils


SYM_ENC_ID_PROTECTED_DATA_PACKET_TYPE = \
    constants.SYMMETRICALLY_ENCRYPTED_AND_INTEGRITY_PROTECTED_DATA_PACKET_TYPE


class Packet(object):

    @classmethod
    def from_packet_content(cls, header_format, type_, content):
        """Parse a packet from the given packet content. This method
        assumes that the packet header has already been parsed and the
        contents of any partial packets has been concatenated to form
        the data argument.
        """
        return cls(header_format, type_, content)

    def __init__(self, header_format, type_, content=None):
        self.header_format = header_format
        self.type = type_
        self._content = content or bytearray()

    def __eq__(self, other):
        return (
            self.__class__ == other.__class__
            and self.header_format == other.header_format
            and self.type == other.type
            )

    def __repr__(self):
        return '<{0} at 0x{1:x}>'.format(self.__class__.__name__,
                                         id(self))

    @property
    def content(self):
        return bytearray(self._content)

    def get_content_for_signature_hash(self, signature_version):
        return self.content

    def __bytes__(self):
        data = self.content
        data_length = len(data)
        packet_type = self.type
        tag = 0x80
        result = bytearray()
        if self.header_format == constants.NEW_PACKET_HEADER_TYPE:
            remaining = data_length
            offset = 0
            tag += 0x40 + packet_type
            result = bytearray([tag])
            while remaining:
                # "An implementation MAY use Partial Body Lengths for data
                #  packets, be they literal, compressed, or encrypted."
                allow_partial = self.type in constants.DATA_TYPES
                packet_length_bytes, remaining = \
                    utils.new_packet_length_to_bytes(
                            data_length,
                            allow_partial)
                result.extend(packet_length_bytes)
                result.extend(data[offset:data_length - remaining])
                offset = data_length - remaining

        else:
            tag += (packet_type << 2)
            length_type, length_bytes = \
                utils.old_packet_length_to_bytes(data_length)
            tag += length_type
            result = bytearray([tag])
            result.extend(length_bytes)
            result.extend(data)

        return bytes(result)


class PublicKeyEncryptedSessionKeyPacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        offset = 0
        version = int(data[offset])
        offset += 1
        key_id = utils.bytearray_to_hex(data, offset, 16)
        # "An implementation MAY accept or use a Key ID of zero as a "wild
        #  card" or "speculative" Key ID.  In this case, the receiving
        #  implementation would try all available private keys, checking for a
        #  valid decrypted session key."
        if key_id == b'0' * 16:
            key_id = None
        offset += 8
        public_key_algorithm = int(data[offset])
        offset += 1
        encrypted_session_key = data[offset:]
        result = cls(header_format, version, key_id, public_key_algorithm,
                     encrypted_session_key)
        result._content = data
        return result

    def __init__(self, header_format, version, key_id, public_key_algorithm,
                 encrypted_session_key):
        Packet.__init__(self, header_format,
                    constants.PUBLIC_KEY_ENCRYPTED_SESSION_KEY_PACKET_TYPE)
        self.version = version
        self.key_id = key_id
        self.public_key_algorithm = public_key_algorithm
        self.encrypted_session_key = encrypted_session_key

    def __eq__(self, other):
        return (
            super(PublicKeyEncryptedSessionKeyPacket, self).__eq__(other)
            and self.version == other.version
            and self.key_id == other.key_id
            and self.public_key_algorithm == other.public_key_algorithm
            and self.encrypted_session_key == other.encrypted_session_key
            )

    @classmethod
    def _get_key_and_cipher_algo(cls, public_key_algorithm, secret_key_obj,
                                 encrypted_session_key):
        if public_key_algorithm in (1, 2, 3):
            cipher = PKCS1_v1_5.new(secret_key_obj)
        else:
            cipher = secret_key_obj
        sentinel = Random.new().read((secret_key_obj.size() + 1) // 8)
        encrypted_session_key_length = len(encrypted_session_key)
        decrypted_values = []
        offset = 0
        while offset < (encrypted_session_key_length - 2):
            mpilen = utils.mpi_length(encrypted_session_key, offset)
            offset += 2
            em = encrypted_session_key[offset:offset + mpilen]
            offset += mpilen
            em = b'\00' * (len(sentinel) - len(em)) + em
            m = cipher.decrypt(em, sentinel)
            if m == sentinel:
                raise ValueError()
            decrypted_values.append(m)
        if public_key_algorithm in (1, 2, 3):
            # RSA
            m = decrypted_values[0]
        elif public_key_algorithm in (17, 19):
            m = decrypted_values[1]

        symmetric_algorithm = int(m[0])
        expected_checksum = (
                (m[-2] << 8) +
                m[-1]
                )
        actual_checksum = sum(m[1:-2]) % 65536
        if expected_checksum != actual_checksum:
            raise ValueError

        return symmetric_algorithm, m[1:-2]

    @classmethod
    def _get_encrypted_key(cls, public_key_algorithm, key_obj,
                           symmetric_algorithm, session_key):
        if public_key_algorithm in (1, 2, 3):
            cipher = PKCS1_v1_5.new(key_obj)
        else:
            cipher = key_obj
        encrypted_key = bytearray()
        session_key = bytearray(session_key)
        checksum = sum(session_key) % 65536
        session_key.insert(0, symmetric_algorithm)
        session_key.extend(bytearray([
            checksum >> 8,
            checksum & 0xff
            ]))
        if public_key_algorithm in (1, 2, 3):
            values = cipher.encrypt(session_key)
        else:
            k = Random.random.randint(1, cipher.p - 2)
            values = cipher.encrypt(utils.bytes_to_int(session_key, 0,
                                                       len(session_key)), k)
            values = map(utils.int_to_bytes, values)
        if isinstance(values, bytes):
            values = (values,)
        for v in values:
            encrypted_key.extend(utils.int_to_mpi(
                utils.bytes_to_int(v, 0, len(v))))

        return encrypted_key

    @property
    def content(self):
        key_id = self.key_id
        if key_id is None:
            key_id = '0' * 16
        data = bytearray([self.version])
        data.extend(utils.hex_to_bytes(key_id, 8))
        data.append(self.public_key_algorithm)
        data.extend(self.encrypted_session_key)

        return data


class SignaturePacket(Packet):

    def to_embedded_subpacket(self, critical=False):
        return EmbeddedSignatureSubpacket(critical, self)

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        assert type_ == constants.SIGNATURE_PACKET_TYPE
        version = data[0]
        offset = 1
        if version in (2, 3):
            # 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
            # |  |  [  ctime  ] [ key_id                 ] |
            # |  |-type                           pub_algo-|
            # |-hash material
            # 10 11 12
            # |  [hash2]
            # |-hash_algo
            hashed_subpackets = None
            unhashed_subpackets = None

            # "hash material" byte must be 0x05
            if data[offset] != 0x05:
                # TODO: message
                raise ValueError("Invalid v3 signature packet")
            offset += 1

            signature_type = data[offset]
            offset += 1

            creation_time = utils.long_to_int(data, offset)
            offset += 4

            key_id = utils.bytearray_to_hex(data, offset, 8)
            offset += 8

            public_key_algorithm = data[offset]
            offset += 1

            hash_algorithm = data[offset]
            offset += 1

            hash2 = data[offset:offset + 2]
            offset += 2

        elif version == 4:
            # 00 01 02 03 ... <hashedsubpackets..> <subpackets..> [hash2]
            # |  |  |-hash_algo
            # |  |-pub_algo
            # |-type
            creation_time = None
            key_id = None

            signature_type = data[offset]
            offset += 1

            public_key_algorithm = data[offset]
            offset += 1

            hash_algorithm = data[offset]
            offset += 1

            # next is hashed subpackets
            length = utils.short_to_int(data, offset)
            offset += 2
            subpacket_end = offset + length
            hashed_subpackets = []
            while offset < subpacket_end:
                hashed_subpacket, offset = \
                    signature_subpacket_from_data(data, offset)
                hashed_subpackets.append(hashed_subpacket)

            # followed by subpackets
            length = utils.short_to_int(data, offset)
            offset += 2
            subpacket_end = offset + length
            unhashed_subpackets = []
            while offset < subpacket_end:
                unhashed_subpacket, offset = \
                    signature_subpacket_from_data(data, offset)
                unhashed_subpackets.append(unhashed_subpacket)

            hash2 = data[offset:offset + 2]
            offset += 2
        else:
            # TODO: message
            raise ValueError("Unsupported signature packet, version %d" %
                    version)

        signature_values = []
        data_len = len(data)
        while offset < data_len:
            mpi, offset = utils.mpi_to_int(data, offset)
            signature_values.append(mpi)

        result = cls(header_format, version, signature_type,
                     public_key_algorithm, hash_algorithm, hash2,
                     signature_values, creation_time, key_id,
                     hashed_subpackets, unhashed_subpackets)
        result._content = data
        return result

    @property
    def human_signature_type(self):
        return constants.human_signature_types.get(self.signature_type,
                                                   'Unknown')

    def __repr__(self):
        return '<{0} 0x{1:02x} ({2}) at 0x{3:x}>'.format(
            self.__class__.__name__,
            self.signature_type,
            self.human_signature_type,
            id(self))

    def __init__(self, header_format, version, signature_type,
                 public_key_algorithm, hash_algorithm, hash2,
                 signature_values, creation_time=None, key_id=None,
                 hashed_subpackets=None,
                 unhashed_subpackets=None):
        Packet.__init__(self, header_format, constants.SIGNATURE_PACKET_TYPE)
        self.version = version
        self.signature_type = signature_type
        self.public_key_algorithm = public_key_algorithm
        self.hash_algorithm = hash_algorithm
        self.hash2 = hash2
        self.signature_values = signature_values
        if version in (2, 3):
            self.creation_time = creation_time
            self.key_id = key_id
        elif version >= 4:
            if hashed_subpackets is None:
                hashed_subpackets = []
            if unhashed_subpackets is None:
                unhashed_subpackets = []
            self.hashed_subpackets = hashed_subpackets
            self.unhashed_subpackets = unhashed_subpackets
        else:
            # TODO: message
            raise ValueError()

    def __eq__(self, other):
        return (
            super(SignaturePacket, self).__eq__(other)
            and self.version == other.version
            and self.signature_type == other.signature_type
            and self.public_key_algorithm == other.public_key_algorithm
            and self.hash_algorithm == other.hash_algorithm
            and self.hash2 == other.hash2
            and self.signature_values == other.signature_values
            and set(self.hashed_subpackets) == set(other.hashed_subpackets)
            and set(self.unhashed_subpackets) == set(other.unhashed_subpackets)
            )

    @property
    def content(self):
        data = bytearray()
        sig_version = self.version
        data.append(sig_version)
        if sig_version >= 4:
            data.append(self.signature_type)
            data.append(self.public_key_algorithm)
            data.append(self.hash_algorithm)
            hashed_subpacket_data = bytearray()
            unhashed_subpacket_data = bytearray()
            for sp in self.hashed_subpackets:
                hashed_subpacket_data.extend(bytes(sp))
            for sp in self.unhashed_subpackets:
                unhashed_subpacket_data.extend(bytes(sp))

            data.extend(utils.int_to_2byte(len(hashed_subpacket_data)))
            data.extend(hashed_subpacket_data)
            data.extend(utils.int_to_2byte(len(unhashed_subpacket_data)))
            data.extend(unhashed_subpacket_data)

        elif sig_version in (2, 3):
            data.append(0x05)
            data.append(self.signature_type)
            data.extend(utils.int_to_4byte(self.creation_time))
            data.extend(self.key_id)
            data.append(self.public_key_algorithm)
            data.append(self.hash_algorithm)
        else:
            # TODO: message
            raise ValueError

        data.extend(self.hash2)
        for value in self.signature_values:
            if value is None:
                continue
            data.extend(utils.int_to_mpi(value))

        return data

    def get_signature_hash_trailer(self):
        result = bytearray()
        if self.version >= 4:
            result.append(self.version)
        result.append(self.signature_type)
        if self.version < 4:
            result.extend(utils.int_to_4byte(self.creation_time))
        else:
            result.append(self.public_key_algorithm)
            result.append(self.hash_algorithm)
            hashed_subpacket_data = bytearray()
            for sp in self.subpackets:
                if not sp.hashed:
                    continue
                hashed_subpacket_data.extend(bytes(sp))

            hashed_subpacket_length = len(hashed_subpacket_data)
            result.extend(utils.int_to_2byte(hashed_subpacket_length))
            result.extend(hashed_subpacket_data)
            result.append(self.version)
            result.append(255)
            result.extend(utils.int_to_4byte(hashed_subpacket_length + 6))

        return result

    def get_content_for_signature_hash(self, signature_version):
        result = bytearray([0x88])
        sig_hash_data = self.get_signature_hash_trailer()
        result.extend(utils.int_to_2byte(len(sig_hash_data)))
        result.extend(sig_hash_data)
        return result


class SymmetricKeyEncryptedSessionKeyPacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        offset = 0
        version = int(data[offset])
        offset += 1
        symmetric_algorithm = int(data[offset])
        offset += 1
        s2k_specification, offset = s2k.parse_s2k_bytes(symmetric_algorithm,
                                                        data,
                                                        offset)
        encrypted_session_key_length = \
            utils.symmetric_cipher_key_lengths.get(symmetric_algorithm)
        # + 1 for the symmetric algorithm
        encrypted_session_key = \
            data[offset:offset + encrypted_session_key_length + 1]
        result = cls(header_format, version, symmetric_algorithm,
                     s2k_specification, encrypted_session_key)
        result._content = data
        return result

    def __init__(self, header_format, version, symmetric_algorithm,
                 s2k_specification, encrypted_session_key=None):
        Packet.__init__(self, header_format,
                    constants.SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY_PACKET_TYPE)
        self.version = version
        self.symmetric_algorithm = symmetric_algorithm
        self.s2k_specification = s2k_specification
        self.encrypted_session_key = encrypted_session_key

    def __eq__(self, other):
        return (
            super(SymmetricKeyEncryptedSessionKeyPacket, self).__eq__(other)
            and self.version == other.version
            and self.symmetric_algorithm == other.symmetric_algorithm
            and self.s2k_specification == other.s2k_specification
            and self.encrypted_session_key == other.encrypted_session_key
            )

    def get_key_and_cipher_algo(self, passphrase):
        return self._get_key_and_cipher_algo(self.s2k_specification,
                                             self.symmetric_algorithm,
                                             passphrase,
                                             self.encrypted_session_key)

    @classmethod
    def _get_key_and_cipher_algo(cls, s2k_specification, symmetric_algorithm,
                                 passphrase, encrypted_session_key=None):
        # "If the encrypted session key is not present (which can be detected
        #  on the basis of packet length and S2K specifier size), then the S2K
        #  algorithm applied to the passphrase produces the session key for
        #  decrypting the file, using the symmetric cipher algorithm from the
        #  Symmetric-Key Encrypted Session Key packet."
        key = s2k_specification.to_key(passphrase)
        symmetric_algorithm = symmetric_algorithm

        # "If the encrypted session key is present, the result of applying the
        #  S2K algorithm to the passphrase is used to decrypt just that
        #  encrypted session key field, using CFB mode with an IV of all
        #  zeros. The decryption result consists of a one-octet algorithm
        #  identifier that specifies the symmetric-key encryption algorithm
        #  used to encrypt the following Symmetrically Encrypted Data packet,
        #  followed by the session key octets themselves."
        if encrypted_session_key:
            block_size = utils.symmetric_cipher_block_lengths.get(
                                symmetric_algorithm)
            iv = bytearray([0] * block_size)
            cipher = utils.get_symmetric_cipher(
                        symmetric_algorithm, key, utils.CFB, iv)
            encrypted_data = bytearray(encrypted_session_key)
            padding = block_size - (len(encrypted_data) % block_size)
            encrypted_data.extend([0] * padding)
            decrypted_data = bytearray(
                cipher.decrypt(bytes(encrypted_data))[:-padding])
            symmetric_algorithm = decrypted_data[0]
            key = bytes(decrypted_data[1:])

        return symmetric_algorithm, key

    @classmethod
    def _get_encrypted_key(cls, s2k_specification, symmetric_algo, passphrase,
                           session_key):
        s2k_sym_algo = s2k_specification.symmetric_algorithm
        key = s2k_specification.to_key(passphrase)
        block_size = utils.symmetric_cipher_block_lengths.get(
                            s2k_sym_algo)
        iv = bytearray([0] * block_size)
        cipher = utils.get_symmetric_cipher(
                    s2k_sym_algo, key, utils.CFB, iv)
        data = bytearray([symmetric_algo])
        data.extend(session_key)
        padding = block_size - len(data) % block_size
        data.extend([0] * padding)
        return bytearray(cipher.encrypt(bytes(data))[:-padding])

    @property
    def content(self):
        data = bytearray([self.version, self.symmetric_algorithm])
        data.extend(bytes(self.s2k_specification))
        if self.encrypted_session_key is not None:
            data.extend(self.encrypted_session_key)

        return data


class OnePassSignaturePacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        offset = 0
        version = int(data[offset])
        offset += 1
        signature_type = int(data[offset])
        offset += 1
        hash_algorithm = int(data[offset])
        offset += 1
        public_key_algorithm = int(data[offset])
        offset += 1
        key_id = utils.bytearray_to_hex(data, offset, 8)
        offset += 8
        nested = data[offset]
        offset += 1
        result = cls(header_format, version, signature_type, hash_algorithm,
                     public_key_algorithm, key_id, nested)
        result._content = data
        return result

    def __init__(self, header_format, version, signature_type, hash_algorithm,
                 public_key_algorithm, key_id, nested):
        Packet.__init__(self, header_format,
                        constants.ONE_PASS_SIGNATURE_PACKET_TYPE)
        self.version = version
        self.signature_type = signature_type
        self.hash_algorithm = hash_algorithm
        self.public_key_algorithm = public_key_algorithm
        self.key_id = key_id
        self.nested = nested

    def __eq__(self, other):
        return (
            super(OnePassSignaturePacket, self).__eq__(other)
            and self.signature_type == other.signature_type
            and self.hash_algorithm == other.hash_algorithm
            and self.public_key_algorithm == other.public_key_algorithm
            and self.key_id == other.key_id
            and self.nested == other.nested
            )

    @property
    def content(self):
        data = bytearray([
                    self.version,
                    self.signature_type,
                    self.hash_algorithm,
                    self.public_key_algorithm,
                    ])
        data.extend(utils.hex_to_bytes(self.key_id, 8))
        data.append(self.nested)
        return data


class PublicKeyPacket(Packet):

    @classmethod
    def _values_from_packet_contents(cls, data):
        offset = 0
        version = int(data[offset])
        offset += 1
        creation_time = utils.long_to_int(data, offset)
        offset += 4

        if version in (2, 3):
            expiration_days = utils.short_to_int(data, offset)
            offset += 2
        elif version >= 4:
            expiration_days = None
        else:
            raise ValueError

        public_key_algorithm = int(data[offset])
        offset += 1
        modulus = None
        exponent = None
        prime = None
        group_generator = None
        group_order = None
        key_value = None
        if public_key_algorithm in (1, 2, 3):
            modulus, offset = utils.mpi_to_int(data, offset)
            exponent, offset = utils.mpi_to_int(data, offset)
        elif public_key_algorithm in (16, 20):
            prime, offset = utils.mpi_to_int(data, offset)
            group_generator, offset = utils.mpi_to_int(data, offset)
            key_value, offset = utils.mpi_to_int(data, offset)
        elif public_key_algorithm == 17:
            prime, offset = utils.mpi_to_int(data, offset)
            group_order, offset = utils.mpi_to_int(data, offset)
            group_generator, offset = utils.mpi_to_int(data, offset)
            key_value, offset = utils.mpi_to_int(data, offset)
        else:
            raise NotImplementedError((
                'Unknown public key algorithm {0}'
                ).format(public_key_algorithm))

        return offset, (
                version, creation_time, public_key_algorithm, expiration_days,
                modulus, exponent, prime, group_order, group_generator,
                key_value)

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        _offset, values = cls._values_from_packet_contents(data)

        result = cls(header_format, *values)
        result._content = data
        return result

    def __init__(self, header_type, version, creation_time,
                 public_key_algorithm, expiration_days=None, modulus=None,
                 exponent=None, prime=None, group_order=None,
                 group_generator=None, key_value=None):
        Packet.__init__(self, header_type, constants.PUBLIC_KEY_PACKET_TYPE)
        self.version = version
        self.creation_time = creation_time
        self.public_key_algorithm = public_key_algorithm
        self.expiration_days = expiration_days
        self.modulus = modulus
        self.exponent = exponent
        self.prime = prime
        self.group_order = group_order
        self.group_generator = group_generator
        self.key_value = key_value

    def __eq__(self, other):
        return (
            super(PublicKeyPacket, self).__eq__(other)
            and self.version == other.version
            and self.creation_time == other.creation_time
            and self.public_key_algorithm == other.public_key_algorithm
            and self.expiration_days == other.expiration_days
            and self.modulus == other.modulus
            and self.exponent == other.exponent
            and self.prime == other.prime
            and self.group_generator == other.group_generator
            and self.group_order == other.group_order
            and self.key_value == other.key_value
            )

    @property
    def public_content(self):
        data = bytearray([self.version])
        data.extend(utils.int_to_4byte(self.creation_time))
        if self.version in (2, 3):
            data.extend(utils.int_to_2byte(self.expiration_days))
        data.append(self.public_key_algorithm)
        if self.public_key_algorithm in (1, 2, 3):
            data.extend(utils.int_to_mpi(self.modulus))
            data.extend(utils.int_to_mpi(self.exponent))
        elif self.public_key_algorithm in (16, 20):
            if self.public_key_algorithm == 20:
                warnings.warn(
                    "These are no longer permitted. An implementation MUST "
                    "NOT generate such keys. An implementation MUST NOT "
                    "generate Elgamal signatures. These must only be used "
                    "for test purposes.")
            data.extend(utils.int_to_mpi(self.prime))
            data.extend(utils.int_to_mpi(self.group_generator))
            data.extend(utils.int_to_mpi(self.key_value))
        elif self.public_key_algorithm == 17:
            data.extend(utils.int_to_mpi(self.prime))
            data.extend(utils.int_to_mpi(self.group_order))
            data.extend(utils.int_to_mpi(self.group_generator))
            data.extend(utils.int_to_mpi(self.key_value))
        else:
            raise NotImplemented

        return data

    @property
    def content(self):
        return self.public_content

    def get_content_for_signature_hash(self, signature_version):
        key_data = self.content
        result = bytearray([0x99])
        result.extend(utils.int_to_2byte(len(key_data)))
        result.extend(key_data)
        return result

    @property
    def key_id(self):
        return self.fingerprint[-16:]

    @property
    def fingerprint(self):
        return utils.key_packet_fingerprint(self)


class PublicSubkeyPacket(PublicKeyPacket):

    def __init__(self, header_type, version, creation_time,
                 public_key_algorithm, expiration_days=None, modulus=None,
                 exponent=None, prime=None, group_order=None,
                 group_generator=None, key_value=None):
        Packet.__init__(self, header_type,
                        constants.PUBLIC_SUBKEY_PACKET_TYPE)
        self.version = version
        self.creation_time = creation_time
        self.public_key_algorithm = public_key_algorithm
        self.expiration_days = expiration_days
        self.modulus = modulus
        self.exponent = exponent
        self.prime = prime
        self.group_generator = group_generator
        self.group_order = group_order
        self.key_value = key_value


class SecretKeyPacket(PublicKeyPacket):

    @classmethod
    def _values_from_packet_contents(cls, data):
        offset, values = PublicKeyPacket._values_from_packet_contents(data)
        s2k_usage = int(data[offset])
        offset += 1
        s2k_specification = None
        if s2k_usage == 0:
            # not encrypted
            symmetric_algorithm = 0
        elif s2k_usage in (254, 255):
            symmetric_algorithm = data[offset]
            offset += 1
            s2k_specification, offset = \
                s2k.parse_s2k_bytes(symmetric_algorithm, data, offset)
        else:
            symmetric_algorithm = s2k_usage

        # 101 is GnuPG's dummy & smartcard mode
        if s2k_usage not in (0, 101):
            block_length = utils.symmetric_cipher_block_lengths.get(
                                symmetric_algorithm, None)
            if block_length is None:
                raise ValueError
            iv = data[offset:offset + block_length]
            offset += block_length

        encrypted_portion = data[offset:]
        if s2k_usage in (0, 255):
            checksum = True
            hash_ = False
        elif s2k_usage == 254:
            hash_ = True
            checksum = False
        else:
            checksum = False
            hash_ = False

        values += (s2k_specification, symmetric_algorithm, iv,
                   encrypted_portion, checksum, hash_)
        return offset, values

    def __init__(self, header_type, version, creation_time,
                 public_key_algorithm, expiration_days=None, modulus=None,
                 exponent=None, prime=None, group_order=None,
                 group_generator=None, key_value=None, s2k_specification=None,
                 symmetric_algorithm=None, iv=None, encrypted_portion=None,
                 checksum=None, hash_=None, passphrase=None, exponent_d=None,
                 prime_p=None, prime_q=None, multiplicative_inverse_u=None,
                 exponent_x=None):

        if None in (s2k_specification, iv, encrypted_portion):
            raise ValueError
        Packet.__init__(self, header_type, constants.SECRET_KEY_PACKET_TYPE)
        self.version = version
        self.creation_time = creation_time
        self.public_key_algorithm = public_key_algorithm
        self.expiration_days = expiration_days
        self.modulus = modulus
        self.exponent = exponent
        self.prime = prime
        self.group_generator = group_generator
        self.group_order = group_order
        self.key_value = key_value
        self.s2k_specification = s2k_specification
        self.symmetric_algorithm = symmetric_algorithm
        self.iv = iv
        self.encrypted_portion = encrypted_portion
        self.checksum = checksum
        self.hash = hash_
        self.passphrase = passphrase
        self.exponent_d = exponent_d
        self.prime_p = prime_p
        self.prime_q = prime_q
        self.multiplicative_inverse_u = multiplicative_inverse_u
        self.exponent_x = exponent_x

    def __eq__(self, other):
        return (
            super(SecretKeyPacket, self).__eq__(other)
            and self.s2k_specification == other.s2k_specification
            and self.symmetric_algorithm == other.symmetric_algorithm
            and self.iv == other.iv
            and self.encrypted_portion == other.encrypted_portion
            and self.checksum == other.checksum
            and self.hash == other.hash
            )

    def decrypt(self, passphrase):
        if self.s2k_specification is not None:
            key = self.s2k_specification.to_key(passphrase)
        else:
            key = passphrase
        values = self.decrypt_encrypted_key_portion(
                    self.version, key, self.symmetric_algorithm, self.iv,
                    self.encrypted_portion, self.checksum, self.hash)

        if self.public_key_algorithm in (1, 2, 3):
            # RSA
            self.exponent_d = values[0]
            self.prime_p = values[1]
            self.prime_q = values[2]
            self.multiplicative_inverse_u = values[3]
        elif self.public_key_algorithm in (16, 17, 20):
            # DSA & Elg
            self.exponent_x = values[0]
        else:
            raise ValueError

    @classmethod
    def encrypt_key_values(cls, version, values, key, symmetric_algorithm,
                           iv, checksum=False, hash_=False):

        cipher = utils.get_symmetric_cipher(
                    symmetric_algorithm, key, utils.OPENPGP, iv,
                    syncable=True)

        unencrypted_data = bytearray()
        for value in values:
            unencrypted_data.extend(utils.int_to_mpi(value))

        if version >= 4:
            encrypted_data = cipher.encrypt(unencrypted_data)
        elif version in (2, 3):
            encrypted_data = bytearray()
            for i in values:
                bits_required = int(math.floor(float(math.log(i, 2)))) + 1
                bytes_required = int(math.ceil(bits_required / 8.0))
                encrypted_data.extend(utils.int_to_2byte(bytes_required))
                cipher.sync()
                mpi_value_bytes = utils.int_to_bytes(i)
                if len(mpi_value_bytes) < bytes_required:
                    mpi_value_bytes = bytearray(
                            [0] * (bytes_required - len(mpi_value_bytes))
                        ) + mpi_value_bytes
                encrypted_data.extend(cipher.encrypt(mpi_value_bytes))

        if checksum:
            checksum = utils.int_to_2byte(sum(unencrypted_data) & 0xffff)
            if version >= 4:
                encrypted_data.extend(cipher.encrypt(checksum))
            else:
                encrypted_data.extend(checksum)

        if hash_:
            hash_ = SHA.new(unencrypted_data).digest()
            encrypted_data.extend(cipher.encrypt(hash_))
        return encrypted_data

    @classmethod
    def decrypt_encrypted_key_portion(cls, version, key, symmetric_algorithm,
                                      iv, encrypted_data, checksum=False,
                                      hash_=False):

        sym_block_size = utils.symmetric_cipher_block_lengths.get(
            symmetric_algorithm, 8)
        if version >= 4:
            cipher = utils.get_symmetric_cipher(
                        symmetric_algorithm, key, utils.CFB, iv)
            padding = bytearray(
                [0x00] * (len(encrypted_data) % sym_block_size))
            decrypted_data = cipher.decrypt(
                bytes(encrypted_data + padding)
                )[:-len(padding)]
        elif version in (2, 3):
            # "With V3 keys, the MPI bit count prefix (i.e., the first two
            #  octets) is not encrypted.  Only the MPI non-prefix data is
            #  encrypted.  Furthermore, the CFB state is resynchronized at the
            #  beginning of each new MPI value, so that the CFB block boundary
            #  is aligned with the start of the MPI data."

            cipher = utils.get_symmetric_cipher(
                        symmetric_algorithm, key, utils.CFB, iv,
                        syncable=True)
            offset = 0
            decrypted_data = bytearray()
            while offset < len(encrypted_data):
                cipher.sync()
                decrypted_data.extend(
                        encrypted_data[offset:offset + 2])
                mpi_length = utils.mpi_length(encrypted_data, offset)
                offset += 2
                encrypted_mpi_content = \
                    encrypted_data[offset:offset + mpi_length]
                offset += mpi_length
                mpi_content = cipher.decrypt(encrypted_mpi_content)
                decrypted_data.extend(mpi_content)
        else:
            raise ValueError

        data_length = len(decrypted_data)
        if checksum:
            data_length -= 2
            if version >= 4:
                # With V4 keys, the checksum is encrypted like the
                # algorithm-specific data.
                expected_checksum = utils.short_to_int(
                        cipher.decrypt(utils.int_to_2byte(decrypted_data[-2:]))
                    )
            actual_checksum = sum(decrypted_data[:-2]) & 0xffff
            if actual_checksum != expected_checksum:
                raise ValueError

        if hash_:
            data_length -= 20
            expected_hash = decrypted_data[-20:]
            actual_hash = SHA.new(decrypted_data[:-20]).digest()
            if bytes(expected_hash) != actual_hash:
                raise ValueError

        values = []
        offset = 0
        while offset < data_length:
            mpi, offset = utils.mpi_to_int(decrypted_data, offset)
            values.append(mpi)

        return values

    @property
    def content(self):
        data = PublicKeyPacket.content.__get__(self)
        if self.s2k_specification is not None:
            if self.checksum:
                s2k_usage = 255
            else:
                s2k_usage = 254
            data.append(s2k_usage)
        data.append(self.symmetric_algorithm)
        if self.s2k_specification is not None:
            data.extend(bytes(self.s2k_specification))
        if self.symmetric_algorithm != 0:
            data.extend(self.iv)
        if self.encrypted_portion:
            data.extend(self.encrypted_portion)
        else:
            if self.public_key_algorithm in (1, 2, 3):
                values = [
                    self.exponent_d,
                    self.prime_p,
                    self.prime_q,
                    self.multiplicative_inverse_u
                    ]
            elif self.public_key_algorithm in (16, 17, 20):
                values = [self.exponent_x]
            else:
                raise ValueError

            if self.s2k_specification is not None:
                key = self.s2k_specification.to_key(self.passphrase)
            else:
                key = self.passphrase
            encrypted_data = self.encrypt_key_values(
                        self.version, values, key, self.symmetric_algorithm,
                        self.iv, s2k_usage in (0, 255), s2k_usage == 254)
            data.extend(encrypted_data)

        return data


class SecretSubkeyPacket(SecretKeyPacket):

    def __init__(self, header_type, version, creation_time,
                 public_key_algorithm, expiration_days=None, modulus=None,
                 exponent=None, prime=None, group_order=None,
                 group_generator=None, key_value=None, s2k_specification=None,
                 symmetric_algorithm=None, iv=None, encrypted_portion=None,
                 checksum=False, hash_=False, passphrase=None, exponent_d=None,
                 prime_p=None, prime_q=None, multiplicative_inverse_u=None,
                 exponent_x=None):

        if None in (s2k_specification, iv, encrypted_portion):
            raise ValueError
        Packet.__init__(self, header_type,
                        constants.SECRET_SUBKEY_PACKET_TYPE)
        self.version = version
        self.creation_time = creation_time
        self.public_key_algorithm = public_key_algorithm
        self.expiration_days = expiration_days
        self.modulus = modulus
        self.exponent = exponent
        self.prime = prime
        self.group_generator = group_generator
        self.group_order = group_order
        self.key_value = key_value
        self.s2k_specification = s2k_specification
        self.symmetric_algorithm = symmetric_algorithm
        self.iv = iv
        self.encrypted_portion = encrypted_portion
        self.checksum = checksum
        self.hash = hash_


class CompressedDataPacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        compression_algorithm = int(data[0])
        compressed_data = data[1:]
        result = cls(header_format, compression_algorithm, compressed_data)
        result._content = data
        return result

    def __init__(self, header_format, compression_algorithm, compressed_data):
        super(CompressedDataPacket, self).__init__(
            header_format, constants.COMPRESSED_DATA_PACKET_TYPE)
        self.compression_algorithm = compression_algorithm
        self.compressed_data = compressed_data

    @classmethod
    def compress_packets(cls, algorithm, level, packets):
        algo = utils.get_compression_instance(algorithm, level)
        packet_data = b''.join(map(bytes, packets))
        data = algo.compress(packet_data)
        data += algo.flush()
        return data

    @classmethod
    def decompress_data(cls, algorithm, data):
        algo = utils.get_compression_instance(algorithm)
        packet_data = algo.decompress(data)
        packet_data += algo.flush()
        packets = []
        offset = 0
        length = len(packet_data)
        while offset < length:
            offset, packet = packet_from_packet_data(packet_data, offset)
            packets.append(packet)
        return packets

    def __eq__(self, other):
        return (
            super(CompressedDataPacket, self).__eq__(other)
            and self.compression_algorithm == other.compression_algorithm
            and self.compressed_data == other.compressed_data
            )

    @property
    def content(self):
        data = bytearray([self.compression_algorithm])
        data.extend(self.compressed_data)
        return data


class SymmetricallyEncryptedDataPacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        result = cls(header_format, data)
        result._content = data
        return result

    def __init__(self, header_format, data):
        Packet.__init__(self, header_format,
                        constants.SYMMETRICALLY_ENCRYPTED_DATA_PACKET_TYPE)
        self.data = data

    def __eq__(self, other):
        return (
            super(SymmetricallyEncryptedDataPacket, self).__eq__(other)
            and self.data == other.data
            )

    @property
    def content(self):
        return self.data


class MarkerPacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        old_literal = data != b'PGP'

        result = cls(header_format, data, old_literal)
        result._content = data
        return result

    def __init__(self, header_format, content, old_literal=False):
        Packet.__init__(self, header_format, constants.MARKER_PACKET_TYPE)
        self.old_literal = old_literal
        self.content = content

    def __eq__(self, other):
        return (
            super(MarkerPacket, self).__eq__(other)
            and self.old_literal == other.old_literal
            and self.content == other.content
            )


class LiteralDataPacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        offset = 0
        data_format = bytes([data[offset]])
        offset += 1
        filename_length = int(data[offset])
        offset += 1
        filename = data[offset:offset + filename_length]
        # "Unless otherwise specified, the character set for text is the
        #  UTF-8"
        filename = filename.decode('utf8', 'replace')
        offset += filename_length
        time = utils.long_to_int(data, offset)
        offset += 4
        content = data[offset:]
        encoding = None
        if b't' == data_format:
            # TODO: Unknown encoding
            encoding = 'latin-1'
        elif b'u' == data_format:
            encoding = 'utf8'
        elif b'b' == data_format:
            pass
        elif data_format in (b'l', b'1'):
            # RFC 1991 ncorrectly stated this local mode flag as '1'
            # (ASCII numeral one).
            pass
        if encoding:
            content = content.decode(encoding)
        if data_format in (b't', b'u'):
            content.replace('\r\n', os.linesep)

        result = cls(header_format, data_format, filename, time, content)
        result._content = data
        return result

    def __init__(self, header_format, data_format, filename, time, data):
        Packet.__init__(self, header_format,
                        constants.LITERAL_DATA_PACKET_TYPE)
        self.data_format = data_format
        self.filename = filename
        self.time = time
        self.data = data

    def __eq__(self, other):
        return (
            super(LiteralDataPacket, self).__eq__(other)
            and self.data_format == other.data_format
            and self.filename == other.filename
            and self.time == other.time
            and self.data == other.data
            )

    @property
    def content(self):
        if self.data_format in (b'l', b'1'):
            warnings.warn('Local mode for data is deprecated.')
        elif self.data_format not in (b'b', b't', b'u'):
            raise ValueError
        data = bytearray(self.data_format)
        data.append(int(len(self.filename)))
        # "Unless otherwise specified, the character set for text is the
        #  UTF-8"
        data.extend(self.filename.encode('utf8', 'replace'))
        timestamp = int(time.mktime(self.time.timetuple()))
        data.extend(utils.int_to_4byte(timestamp))
        content = self.data
        if self.data_format in (b't', b'u'):
            content.replace(os.linesep, '\r\n')
        if self.data_format == b't':
            content = content.encode('latin-1', 'replace')
        elif self.data_format == b'u':
            content = content.encode('utf8', 'replace')
        data.extend(content)
        return data


class TrustPacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        # Implementation-specific

        # GnuPG
        trust_value = int(data[0])
        sig_cache = None
        if not trust_value and len(data) == 2:
            sig_cache = int(data[1])
            if sig_cache & 0x80:
                raise ValueError

        result = cls(header_format, trust_value, sig_cache)
        result._content = data
        return result

    def __init__(self, header_format, trust_value, sig_cache=None):
        Packet.__init__(self, header_format, constants.TRUST_PACKET_TYPE)
        self.trust_value = trust_value
        self.sig_cache = sig_cache

    def __eq__(self, other):
        return (
            super(TrustPacket, self).__eq__(other)
            and self.trust_value == other.trust_value
            and self.sig_cache == other.sig_cache
            )

    @property
    def checked(self):
        return bool(self.sig_cache & 1)

    @property
    def valid(self):
        return bool(self.sig_cache & 2)

    @property
    def content(self):
        data = bytearray([self.trust_value])
        if self.sig_cache is not None:
            data.append(self.sig_cache)
        return data


class UserIDPacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        result = cls(header_format, data.decode('utf8', 'replace'))
        result._content = data
        return result

    def __init__(self, header_format, user_id):
        Packet.__init__(self, header_format, constants.USER_ID_PACKET_TYPE)
        self.user_id = user_id

    def __repr__(self):
        return '<{0} {1} at 0x{2:x}>'.format(self.__class__.__name__,
                                             repr(self.user_id),
                                             id(self))

    def __eq__(self, other):
        return (
            super(UserIDPacket, self).__eq__(other)
            and self.user_id == other.user_id
            )

    @property
    def content(self):
        return self.user_id.encode('utf8', 'replace')

    def get_content_for_signature_hash(self, signature_version):
        result = bytearray()
        packet_data = self.content
        if signature_version >= 4:
            result.append(0xb4)
            result.extend(utils.int_to_4byte(len(packet_data)))
        result.extend(packet_data)
        return result


class OldCommentPacket(Packet):
    """From first draft of RFC 2440

        "A Comment packet is used for holding data that is not relevant
        to software.  Comment packets should be ignored."
    """

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        comment = data.decode('utf8')
        result = cls(header_format, comment)
        result._content = data
        return result

    def __init__(self, header_format, comment):
        Packet.__init__(self, header_format,
                        constants.OLD_COMMENT_PACKET_TYPE)
        self.comment = comment

    def __eq__(self, other):
        return (
            super(OldCommentPacket, self).__eq__(other)
            and self.comment == other.comment
            )

    @property
    def content(self):
        warnings.warn("The comment packet type, 16, only appears in an "
                      "OpenPGP draft.")
        return self.comment.encode('utf8')


class UserAttributePacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        offset = 0
        data_len = len(data)
        subpackets = []
        while offset < data_len:
            sp, offset = user_attribute_subpacket_from_data(
                            data, offset
                        )
            subpackets.append(sp)

        result = cls(header_format, subpackets)
        result._content = data
        return result

    def __init__(self, header_format, subpackets):
        Packet.__init__(self, header_format,
                        constants.USER_ATTRIBUTE_PACKET_TYPE)
        self.subpackets = subpackets

    def __eq__(self, other):
        return (
            super(UserAttributePacket, self).__eq__(other)
            and self.subpackets == other.subpackets
            )

    @property
    def content(self):
        result = bytearray()
        for sp in self.subpackets:
            result.extend(bytes(sp))
        return result

    def get_content_for_signature_hash(self, signature_version):
        result = bytearray()
        packet_data = self.content
        if signature_version >= 4:
            result.append(0xd1)
            result.extend(utils.int_to_4byte(len(packet_data)))
        result.extend(packet_data)
        return result


class SymmetricallyEncryptedAndIntegrityProtectedDataPacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        version = int(data[0])
        encrypted_data = data[1:]
        result = cls(header_format, version, encrypted_data)
        result._content = data
        return result

    def __init__(self, header_format, version, encrypted_data):
        Packet.__init__(self, header_format,
                        SYM_ENC_ID_PROTECTED_DATA_PACKET_TYPE)
        self.version = version
        self.encrypted_data = encrypted_data

    def __eq__(self, other):
        return (
            super(self.__class__, self).__eq__(other)
            and self.version == other.version
            and self.encrypted_data == encrypted_data
            )

    @property
    def content(self):
        result = bytearray([self.version])
        result.extend(self.encrypted_data)
        return result


class ModificationDetectionCodePacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        assert len(data) == 20
        result = cls(header_format, data)
        result._content = data
        return result

    def __init__(self, header_format, data):
        Packet.__init__(self, header_format,
                        constants.MODIFICATION_DETECTION_CODE_PACKET_TYPE)
        self.data = data

    def __eq__(self, other):
        return (
            super(ModificationDetectionCodePacket, self).__eq__(other)
            and self.data == other.data
            )

    @property
    def content(self):
        return self.data


class GpgCommentPacket(OldCommentPacket):

    def __init__(self, header_format, comment):
        Packet.__init__(self, header_format,
                        constants.GPG_COMMENT_PACKET_TYPE)
        self.comment = comment

    @property
    def content(self):
        return self.comment.encode('utf8')


class GpgControlPacket(Packet):

    CLEARSIGN_START = 1
    PIPEMODE = 2
    PLAINTEXT_MARK = 3

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        offset = 0
        # 2 unsigned longs
        sizeof_session_marker = 8
        session_marker = data[offset:offset + sizeof_session_marker]
        offset += sizeof_session_marker
        control = data[offset]
        offset += 1
        content_data = data[offset:]
        result = cls(header_format, session_marker, control, content_data)
        result._content = data
        return result

    def __init__(self, header_format, session_marker, control, content_data):
        Packet.__init__(self, header_format,
                        constants.GPG_CONTROL_PACKET_TYPE)
        self.session_marker = session_marker
        self.control = control
        self.content_data = content_data

    def __eq__(self, other):
        return (
            super(GpgControlPacket, self).__eq__(other)
            and self.session_marker == other.session_marker
            and self.control == other.control
            and self.content_data == other.content_data
            )

    @property
    def content(self):
        data = bytearray(self.session_marker)
        data.append(self.control)
        data.extend(self.content_data)
        return data


PACKET_TYPES = {
    constants.PUBLIC_KEY_ENCRYPTED_SESSION_KEY_PACKET_TYPE:
        PublicKeyEncryptedSessionKeyPacket,
    constants.SIGNATURE_PACKET_TYPE: SignaturePacket,
    constants.SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY_PACKET_TYPE:
        SymmetricKeyEncryptedSessionKeyPacket,
    constants.ONE_PASS_SIGNATURE_PACKET_TYPE: OnePassSignaturePacket,
    constants.SECRET_KEY_PACKET_TYPE: SecretKeyPacket,
    constants.PUBLIC_KEY_PACKET_TYPE: PublicKeyPacket,
    constants.SECRET_SUBKEY_PACKET_TYPE: SecretSubkeyPacket,
    constants.COMPRESSED_DATA_PACKET_TYPE: CompressedDataPacket,
    constants.SYMMETRICALLY_ENCRYPTED_DATA_PACKET_TYPE:
        SymmetricallyEncryptedDataPacket,
    constants.MARKER_PACKET_TYPE: MarkerPacket,
    constants.LITERAL_DATA_PACKET_TYPE: LiteralDataPacket,
    constants.TRUST_PACKET_TYPE: TrustPacket,
    constants.USER_ID_PACKET_TYPE: UserIDPacket,
    constants.PUBLIC_SUBKEY_PACKET_TYPE: PublicSubkeyPacket,
    constants.USER_ATTRIBUTE_PACKET_TYPE: UserAttributePacket,
    SYM_ENC_ID_PROTECTED_DATA_PACKET_TYPE:
        SymmetricallyEncryptedAndIntegrityProtectedDataPacket,
    constants.MODIFICATION_DETECTION_CODE_PACKET_TYPE:
        ModificationDetectionCodePacket,

    # Deprecated
    constants.OLD_COMMENT_PACKET_TYPE: OldCommentPacket,

    # Unofficial
    constants.GPG_COMMENT_PACKET_TYPE: GpgCommentPacket,
    constants.GPG_CONTROL_PACKET_TYPE: GpgControlPacket,
    }


def packet_from_packet_stream(fh):
    """Parse a packet from the given data starting at the offset
    and return a tuple of the length of data consumed and a packet
    object.
    """

    packet_data = bytearray()
    incomplete = True
    previous_tag = None
    previous_header_type = None
    while incomplete:
        first = ord(fh.read(1))
        tag = first & 0x3f
        if previous_tag is not None:
            if tag != previous_tag:
                # TODO: complete message
                raise ValueError()
        previous_tag = tag
        header_type = (
                constants.NEW_PACKET_HEADER_TYPE
                if bool(first & 0x40)
                else constants.OLD_PACKET_HEADER_TYPE
            )
        if previous_header_type is not None:
            if header_type != previous_header_type:
                # TODO: complete message
                raise ValueError()
        if header_type == constants.NEW_PACKET_HEADER_TYPE:
            data_length, incomplete = \
                utils.new_packet_length_from_stream(fh)
        else:
            tag >>= 2
            fh.seek(fh.tell() - 1)
            data_length = utils.old_packet_length_from_stream(fh)
            incomplete = False

        packet_data.extend(fh.read(data_length))

    cls = PACKET_TYPES.get(tag, Packet)

    packet = cls.from_packet_content(header_type, tag, packet_data)
    return packet


def packet_from_packet_data(data, offset=0):
    """Parse a packet from the given data starting at the offset
    and return a tuple of the length of data consumed and a packet
    object.
    """

    packet_data = bytearray()
    incomplete = True
    tag = None
    previous_header_type = None
    while incomplete:
        if not tag:
            tag = data[offset] & 0x3f
            header_type = (
                    constants.NEW_PACKET_HEADER_TYPE
                    if bool(data[offset] & 0x40)
                    else constants.OLD_PACKET_HEADER_TYPE
                )
            if header_type == constants.NEW_PACKET_HEADER_TYPE:
                offset += 1
            else:
                tag >>= 2

        if header_type == constants.NEW_PACKET_HEADER_TYPE:
            offset, data_length, incomplete = utils.new_packet_length(
                    data, offset)
        else:
            offset, data_length = utils.old_packet_length(data, offset)
            incomplete = False

        packet_data.extend(data[offset:offset + data_length])
        offset += data_length

    cls = PACKET_TYPES.get(tag, Packet)

    packet = cls.from_packet_content(header_type, tag, packet_data)
    return offset, packet
