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

import os
import warnings

from pgp.packets import constants
from pgp.packets.signature_subpackets import signature_subpacket_from_data
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

    def __init__(self, header_format, type_):
        self.header_format = header_format
        self.type_ = type_

    @property
    def content(self):
        return bytearray()

    def __bytes__(self):
        data = self.content
        data_length = len(data)
        packet_type = self.type_
        tag = 0x80
        result = bytearray()
        if self.header_format == constants.NEW_PACKET_HEADER_TYPE:
            remaining = data_length
            offset = 0
            while remaining:
                # "An implementation MAY use Partial Body Lengths for data
                #  packets, be they literal, compressed, or encrypted."
                allow_partial = self.type_ in constants.DATA_TYPES
                tag += 0x40 + packet_type
                result = bytearray([tag])
                packet_length_bytes, remaining = \
                    utils.new_packet_length_to_bytes(
                            data_length,
                            allow_partial)
                result.extend(packet_length_bytes)
                result.extend(data[offset:-remaining])
                offset = data_length - remaining

        else:
            tag += (packet_type << 2)
            result = bytearray([tag])
            result.extend(utils.old_packet_length_to_bytes(data_length))
            result.extend(data)

        return bytes(result)


class PublicKeyEncryptedSessionKeyPacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        offset = 0
        version = int(data[offset])
        offset += 1
        key_id = utils.bytearray_to_hex(data, offset, 8)
        offset += 8
        public_key_algorithm = int(data[offset])
        offset += 1
        data_len = len(data)
        session_key_values = []
        while offset < data_len:
            mpi, offset = utils.mpi_to_int(data, offset)
            session_key_values.append(mpi)
        return cls(header_format, version, key_id, public_key_algorithm,
                   session_key_values)

    def __init__(self, header_format, version, key_id, public_key_algorithm,
                 session_key_values):
        Packet.__init__(self, header_format,
                    constants.PUBLIC_KEY_ENCRYPTED_SESSION_KEY_PACKET_TYPE)
        self.version = version
        self.key_id = key_id,
        self.public_key_algorithm = public_key_algorithm
        self.session_key_values = session_key_values

    @property
    def content(self):
        data = bytearray(
                        [self.version] +
                        utils.hex_to_bytes(self.key_id, 8) +
                        [self.public_key_algorithm]
                    )
        for value in self.session_key_values:
            data.extend(utils.int_to_mpi(value))

        return data


class SignaturePacket(Packet):

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

        return cls(header_format, version, signature_type,
                   public_key_algorithm, hash_algorithm, hash2,
                   signature_values, creation_time, key_id, hashed_subpackets,
                   unhashed_subpackets)

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
            self.hashed_subpackets = hashed_subpackets
            self.unhashed_subpackets = unhashed_subpackets
        else:
            # TODO: message
            raise ValueError()

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
            for sp in self.subpackets:
                subpacket_data = bytes(sp)
                if sp.hashed:
                    hashed_subpacket_data.extend(subpacket_data)
                else:
                    unhashed_subpacket_data.extend(subpacket_data)

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


class SymmetricKeyEncryptedSessionKeyPacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        offset = 0
        version = int(data[offset])
        offset += 1
        symmetric_algorithm = int(data[offset])
        offset += 1
        s2k_specifier, offset = s2k.parse_s2k_bytes(symmetric_algorithm, data,
                                              offset)
        encrypted_session_key_length = \
            utils.symmetric_cipher_block_lengths.get(symmetric_algorithm)
        encrypted_session_key = \
            data[offset:offset + encrypted_session_key_length]
        return cls(header_format, version, symmetric_algorithm, s2k_specifier,
                   encrypted_session_key)

    def __init__(self, header_format, version, symmetric_algorithm,
                 s2k_specifier, encrypted_session_key=None):
        Packet.__init__(self, header_format,
                    constants.PUBLIC_KEY_ENCRYPTED_SESSION_KEY_PACKET_TYPE)
        self.version = version
        self.symmetric_algorithm = symmetric_algorithm,
        self.s2k_specifier = s2k_specifier
        self.encrypted_session_key = encrypted_session_key

    @property
    def content(self):
        data = bytearray(
                        [self.version, self.symmetric_algorithm] +
                        bytes(self.s2k_specifier)
                    )
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
        return cls(header_format, version, signature_type, hash_algorithm,
                   public_key_algorithm, key_id, nested)

    def __init__(self, header_format, version, signature_type, hash_algorithm,
                 public_key_algorithm, key_id, nested):
        Packet.__init__(self, header_format,
                        constants.ONE_PASS_SIGNATURE_PACKET_TYPE)
        self.signature_type = signature_type
        self.hash_algorithm = hash_algorithm
        self.public_key_algorithm = public_key_algorithm
        self.key_id = key_id
        self.nested = nested

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
        group_gen = None
        group_order = None
        key_value = None
        if public_key_algorithm in (1, 2, 3):
            modulus, offset = utils.mpi_to_int(data, offset)
            exponent, offset = utils.mpi_to_int(data, offset)
        elif public_key_algorithm in (16, 20):
            prime, offset = utils.mpi_to_int(data, offset)
            group_gen, offset = utils.mpi_to_int(data, offset)
            key_value, offset = utils.mpi_to_int(data, offset)
        elif public_key_algorithm == 17:
            prime, offset = utils.mpi_to_int(data, offset)
            group_order, offset = utils.mpi_to_int(data, offset)
            group_gen, offset = utils.mpi_to_int(data, offset)
            key_value, offset = utils.mpi_to_int(data, offset)
        else:
            raise NotImplemented

        return offset, (
                version, creation_time, public_key_algorithm, expiration_days,
                modulus, exponent, prime, group_gen, group_order, key_value)

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        _offset, values = cls._values_from_packet_contents(data)

        return cls(header_format, *values)

    def __init__(self, header_type, version, creation_time,
                 public_key_algorithm, expiration_days=None, modulus=None,
                 exponent=None, prime=None, group_gen=None, group_order=None,
                 key_value=None):
        Packet.__init__(self, header_type, constants.PUBLIC_KEY_PACKET_TYPE)
        self.version = version
        self.creation_time = creation_time
        self.public_key_algorithm = public_key_algorithm
        self.expiration_days = expiration_days
        self.modulus = modulus
        self.exponent = exponent
        self.prime = prime
        self.group_gen = group_gen
        self.group_order = group_order
        self.key_value = key_value

    @property
    def content(self):
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
            data.extend(utils.int_to_mpi(self.group_gen))
            data.extend(utils.int_to_mpi(self.key_value))
        elif self.public_key_algorithm == 17:
            data.extend(utils.int_to_mpi(self.prime))
            data.extend(utils.int_to_mpi(self.group_order))
            data.extend(utils.int_to_mpi(self.group_gen))
            data.extend(utils.int_to_mpi(self.key_value))
        else:
            raise NotImplemented


class PublicSubkeyPacket(PublicKeyPacket):

    def __init__(self, header_type, version, creation_time,
                 public_key_algorithm, expiration_days=None, modulus=None,
                 exponent=None, prime=None, group_gen=None, group_order=None,
                 key_value=None):
        Packet.__init__(self, header_type,
                        constants.PUBLIC_SUBKEY_PACKET_TYPE)
        self.version = version
        self.creation_time = creation_time
        self.public_key_algorithm = public_key_algorithm
        self.expiration_days = expiration_days
        self.modulus = modulus
        self.exponent = exponent
        self.prime = prime
        self.group_gen = group_gen
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

        if s2k_usage in (0, 255):
            encrypted_portion = data[offset:-2]
            checksum = data[-2:]
        else:
            encrypted_portion = data[offset:]
            checksum = None

        values += (s2k_specification, symmetric_algorithm, iv,
                   encrypted_portion, checksum)
        return offset, values

    def __init__(self, header_type, version, creation_time,
                 public_key_algorithm, expiration_days=None, modulus=None,
                 exponent=None, prime=None, group_gen=None, group_order=None,
                 key_value=None, s2k_specification=None,
                 symmetric_algorithm=None, iv=None, encrypted_portion=None,
                 checksum=None):

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
        self.group_gen = group_gen
        self.group_order = group_order
        self.key_value = key_value
        self.s2k_specification = s2k_specification
        self.symmetric_algorithm = symmetric_algorithm
        self.iv = iv
        self.encrypted_portion = encrypted_portion
        self.checksum = checksum

    @property
    def content(self):
        data = PublicKeyPacket.content
        if self.s2k_specification is not None:
            if self.checksum is not None:
                s2k_usage = 255
            else:
                s2k_usage = 254
            data.append(s2k_usage)
        data.append(self.symmetric_algorithm)
        if self.s2k_specification is not None:
            data.extend(bytes(self.s2k_specification))
        if self.symmetric_algorithm != 0:
            data.extend(self.iv)
        data.extend(self.encrypted_portion)
        if self.checksum is not None:
            data.extend(self.checksum)
        return data


class SecretSubkeyPacket(SecretKeyPacket):

    def __init__(self, header_type, version, creation_time,
                 public_key_algorithm, expiration_days=None, modulus=None,
                 exponent=None, prime=None, group_gen=None, group_order=None,
                 key_value=None, s2k_specification=None,
                 symmetric_algorithm=None, iv=None, encrypted_portion=None,
                 checksum=None):

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
        self.group_gen = group_gen
        self.group_order = group_order
        self.key_value = key_value
        self.s2k_specification = s2k_specification
        self.symmetric_algorithm = symmetric_algorithm
        self.iv = iv
        self.encrypted_portion = encrypted_portion
        self.checksum = checksum


class CompressedDataPacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        compression_algorithm = int(data[0])
        compressed_data = data[1:]
        return cls(header_format, compression_algorithm, compressed_data)

    def __init__(self, header_format, compression_algorithm, compressed_data):
        Packet.__init__(header_format, constants.COMPRESSED_DATA_PACKET_TYPE)
        self.compression_algorithm = compression_algorithm
        self.compressed_data = compressed_data

    @property
    def content(self):
        data = bytearray([self.compression_algorithm])
        data.extend(self.compressed_data)
        return data


class SymmetricallyEncryptedDataPacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        cls(header_format, data)

    def __init__(self, header_format, data):
        Packet.__init__(self, header_format,
                        constants.SYMMETRICALLY_ENCRYPTED_DATA_PACKET_TYPE)
        self.data = data

    @property
    def content(self):
        return self.data


class MarkerPacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        old_literal = data.decode('utf8', 'replace') != u'PGP'

        return cls(header_format, data, old_literal)

    def __init__(self, header_format, content, old_literal=False):
        Packet.__init__(self, header_format, constants.MARKER_PACKET_TYPE)
        self.old_literal = old_literal
        self.content = content


class LiteralDataPacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        offset = 0
        data_format = bytes(data[offset])
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
            encoding = 'ascii'
        elif b'u' == data_format:
            encoding = 'utf8'
        elif b'b' == data_format:
            pass
        elif data_format in (b'l', b'1'):
            # RFC 1991 ncorrectly stated this local mode flag as '1'
            # (ASCII numeral one).
            pass
        content = content.decode(encoding)
        if data_format in (b't', b'u'):
            content.replace('\r\n', os.linesep)

        return cls(header_format, data_format, filename, time, content)

    def __init__(self, header_format, data_format, filename, time, data):
        Packet.__init__(self, header_format,
                        constants.LITERAL_DATA_PACKET_TYPE)
        self.data_format = data_format
        self.filename = self.filename
        self.time = time
        self.data = data

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
        data.extend(utils.int_to_4byte(self.time))
        content = self.data
        if self.data_format in (b't', b'u'):
            content.replace(os.linesep, '\r\n')
        if self.data_format == b't':
            content = content.encode('ascii', 'replace')
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

        return cls(header_format, trust_value, sig_cache)

    def __init__(self, header_format, trust_value, sig_cache=None):
        Packet.__init__(self, header_format, constants.TRUST_PACKET_TYPE)
        self.trust_value = trust_value
        self.sig_cache = sig_cache

    @property
    def content(self):
        data = bytearray([self.trust_value])
        if self.sig_cache is not None:
            data.append(self.sig_cache)
        return data


class UserIDPacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        return cls(header_format, data.decode('utf8', 'replace'))

    def __init__(self, header_format, user_id):
        Packet.__init__(self, header_format, constants.USER_ID_PACKET_TYPE)
        self.user_id = user_id

    @property
    def content(self):
        return self.user_id.encode('utf8', 'replace')


class OldCommentPacket(Packet):
    """From first draft of RFC 2440

        "A Comment packet is used for holding data that is not relevant
        to software.  Comment packets should be ignored."
    """

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        comment = data.decode('utf8')
        return cls(header_format, comment)

    def __init__(self, header_format, comment):
        Packet.__init__(self, header_format,
                        constants.OLD_COMMENT_PACKET_TYPE)
        self.comment = comment

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

        return cls(header_format, subpackets)

    def __init__(self, header_format, subpackets):
        Packet.__init__(self, header_format,
                        constants.USER_ATTRIBUTE_PACKET_TYPE)
        self.subpackets = subpackets

    @property
    def content(self):
        result = bytearray()
        for sp in self.subpackets:
            result.extend(bytes(sp))
        return result


class SymmetricallyEncryptedAndIntegrityProtectedDataPacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        version = int(data[0])
        encrypted_data = data[1:]
        return cls(header_format, version, encrypted_data)

    def __init__(self, header_format, version, encrypted_data):
        Packet.__init__(self, header_format,
                        SYM_ENC_ID_PROTECTED_DATA_PACKET_TYPE)
        self.version = version
        self.encrypted_data = encrypted_data

    @property
    def content(self):
        result = bytearray([self.version])
        result.extend(self.encrypted_data)
        return result


class ModificationDetectionCodePacket(Packet):

    @classmethod
    def from_packet_content(cls, header_format, type_, data):
        assert len(data) == 20
        return cls(header_format, data)

    def __init__(self, header_format, data):
        Packet.__init__(self, header_format,
                        constants.MODIFICATION_DETECTION_CODE_PACKET_TYPE)
        self.data = data

    @property
    def content(self):
        return self.data


class GpgCommentPacket(OldCommentPacket):

    def __init__(self, header_format, comment):
        Packet.__init__(self, header_format,
                        constants.GPG_COMMENT_PACKET_TYPE)

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
        return cls(header_format, session_marker, control, content_data)

    def __init__(self, header_format, session_marker, control, content_data):
        Packet.__init__(self, header_format,
                        constants.GPG_CONTROL_PACKET_TYPE)
        self.session_marker = session_marker
        self.control = control
        self.content_data = content_data

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


def packet_from_packet_data(data, offset=0):
    """Parse a packet from the given data starting at the offset
    and return a tuple of the length of data consumed and a packet
    object.
    """

    packet_data = bytearray()
    incomplete = True
    previous_tag = None
    previous_header_type = None
    while incomplete:
        tag = data[offset] & 0x3f
        if previous_tag is not None:
            if tag != previous_tag:
                # TODO: complete message
                raise ValueError()
        previous_tag = tag
        header_type = (
                constants.NEW_PACKET_HEADER_TYPE
                if bool(data[offset] & 0x40)
                else constants.OLD_PACKET_HEADER_TYPE
            )
        if previous_header_type is not None:
            if header_type != previous_header_type:
                # TODO: complete message
                raise ValueError()
        if header_type == constants.NEW_PACKET_HEADER_TYPE:
            offset += 1
            offset, data_length, incomplete = utils.new_packet_length(
                    data, offset)
        else:
            tag >>= 2
            offset, data_length = utils.old_packet_length(data, offset)
            incomplete = False

        packet_data.extend(data[offset:offset + data_length])
        offset += data_length

    cls = PACKET_TYPES.get(tag, Packet)

    packet = cls.from_packet_content(header_type, tag, packet_data)
    return offset, packet
