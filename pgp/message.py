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

import abc
import collections
import datetime

from zope.interface import implementer
from zope.interface import provider

from pgp.packets import constants as C
from pgp.packets import packets
from pgp.signature import BaseSignature
from pgp import utils


class MessageSignature(BaseSignature):

    one_pass = None


# https://tools.ietf.org/html/rfc4880#section-11.3
class LiteralMessage(object):
    # A literal data packet

    __metaclass__ = abc.ABCMeta

    @classmethod
    def from_packet(cls, packet):
        data_format = packet.data_format
        if data_format in ('u', 't'):
            class_ = TextMessage
        else:
            class_ = BinaryMessage
        filename = packet.filename
        timestamp = datetime.datetime.fromtimestamp(packet.time)
        data = packet.data
        return class_(data, filename, timestamp)

    @abc.abstractmethod
    def __init__(self, message, filename, timestamp):
        self.message = message
        self.filename = filename
        self.timestamp = timestamp

    @abc.abstractmethod
    def to_packet(self, header_format):
        raise NotImplemented

    def to_packets(self, header_format):
        return [self.to_packet(header_format)]


class TextMessage(object):

    def to_packet(self, header_format):
        return packets.LiteralDataPacket(
                    header_format, 'u', self.filename, self.timestamp,
                    self.message)


LiteralMessage.register(TextMessage)


class BinaryMessage(object):

    def to_packet(self, header_format):
        return packets.LiteralDataPacket(
                    header_format, 'b', self.filename, self.timestamp,
                    self.message)


LiteralMessage.register(BinaryMessage)


encrypted_message_data_packet_types = (
    # DATA
    C.SYMMETRICALLY_ENCRYPTED_DATA_PACKET_TYPE,
    C.SYMMETRICALLY_ENCRYPTED_AND_INTEGRITY_PROTECTED_DATA_PACKET_TYPE,
    )


encrypted_message_session_key_packet_types = (
    # ESK
    C.SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY_PACKET_TYPE,
    C.PUBLIC_KEY_ENCRYPTED_SESSION_KEY_PACKET_TYPE,
    )


encrypted_message_packet_types = (
    encrypted_message_data_packet_types +
    encrypted_message_session_key_packet_types
    )


class EncryptedSessionKey(object):

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def encrypt(self, passphrase, data):
        pass

    @abc.abstractmethod
    def decrypt(self, passphrase, data):
        pass


class SymmetricSessionKey(object):

    symmetric_algorithm = None
    s2k_specification = None
    session_key = None

    @classmethod
    def from_packet(cls, packet):
        return cls(packet.symmetric_algorithm, packet.s2k_specification,
                   packet.encrypted_session_key)

    def __init__(self, symmetric_algorithm, s2k_specification,
                 encrypted_session_key=None):
        self.symmetric_algorithm = symmetric_algorithm
        self.s2k_specification = s2k_specification
        self.encrypted_session_key = encrypted_session_key

    def decrypt(self, passphrase, data):
        PacketCls = packets.SymmetricKeyEncryptedSessionKeyPacket

        key, symmetric_algorithm = PacketCls._get_key_and_cipher_algo(
                    self.s2k_specification, self.symmetric_algorithm,
                    passphrase, self.encrypted_session_key)

        pkts = PacketCls._decrypt_packet_data(key, symmetric_algorithm, data)

        return open_pgp_message_from_packets(pkts)

    def encrypt(self, passphrase, data):
        # TODO: encrypt
        pass


EncryptedSessionKey.register(SymmetricSessionKey)


class PublicKeySessionKey(object):

    symmetric_algorithm = 1  # IDEA
    key_hash_algorithm = 1  # MD5

    @classmethod
    def from_packet(cls, packet):
        pass

    def decrypt(self, passphrase, data):
        pass


EncryptedSessionKey.register(PublicKeySessionKey)


class DefaultSessionKey(object):

    symmetric_algorithm = 1  # IDEA
    key_hash_algorithm = 1  # MD5

    def decrypt(self, passphrase, data):
        hash_ = utils.get_hash_instance(self.key_hash_algorithm)
        hash_.update(passphrase)
        key = hash_.digest()


EncryptedSessionKey.register(DefaultSessionKey)


class EncryptedMessageWrapper(object):

    @classmethod
    def from_packets(cls, packets):
        session_keys = []
        packet = packets.popleft()
        message_data = bytearray()
        if packet.type in encrypted_message_data_packet_types:
            # No session key
            session_keys = [DefaultSessionKey()]
        else:
            while packet.type in encrypted_message_session_key_packet_types:
                session_keys.append(parse_session_key_packet(packet))
                packet = packets.popleft()

        if not session_keys:
            raise ValueError

        while packet.type in encrypted_message_packet_types:
            message_data.extend(parse_encrypted_message_packet(packet))
            packet = packets.popleft()

    def __init__(self, message_data):
        pass

    def get_message(self):
        # "In addition, decrypting a Symmetrically Encrypted Data packet or a
        #  Symmetrically Encrypted Integrity Protected Data packet as well as
        #  decompressing a Compressed Data packet must yield a valid OpenPGP
        #  Message."
        pass

    def to_packet(self):
        pass

    def to_packets(self, header_format):
        return [self.to_packet(header_format)]


class SignedMessageWrapper(object):
    # A signature packet followed by any other message type, or a
    # one-pass signature packet followed by a message type, followed by a
    # matching signature packet

    @classmethod
    def from_packets(cls, packets):
        one_pass = False
        packet = packets.popleft()
        if packet.type == C.ONE_PASS_SIGNATURE_PACKET_TYPE:
            one_pass = True
        elif packet.type != C.SIGNATURE_PACKET_TYPE:
            signature = None

    def __init__(self, message):
        self.message = message

    def to_packets(self):
        pass


class CompressedMessageWrapper(object):
    # A compressed data packet

    @classmethod
    def from_packet(cls, packet):
        return cls(packet.compression_algorithm,
                   open_pgp_message_from_packets(packet.packets))

    def __init__(self, compression_algorithm, message):
        self.compression_algorithm = compression_algorithm
        self.message = message

    def to_packet(self, header_format):
        pkts = self.message.to_packets(header_format)
        packets.CompressedDataPacket(
                header_format, self.compression_algorithm, pkts)

    def to_packets(self, header_format):
        return [self.to_packet(header_format)]


def open_pgp_message_from_packets(packets):
    packets = collections.deque(packets)
    packet = packets.popleft()
    if packet.type in encrypted_message_packet_types:
        packets.insert(0, packet)
        result = EncryptedMessageWrapper.from_packets(packets)
    elif packet.type in (C.ONE_PASS_SIGNATURE_PACKET_TYPE,
                         C.SIGNATURE_PACKET_TYPE):
        result = SignedMessageWrapper.from_packets(packets)
    elif packet.type == C.COMPRESSED_DATA_PACKET_TYPE:
        result = CompressedMessageWrapper.from_packet(packet)
    elif packet.type == C.LITERAL_DATA_PACKET_TYPE:
        result = LiteralMessage.from_packet(packet)

    return result


# https://tools.ietf.org/html/rfc4880#section-11.4
class DetachedSignature(object):
    # A single signature packet

    @classmethod
    def from_packets(cls, packets):
        pass

    def __init__(self, message):
        self.message = message

    def to_packets(self):
        pass
