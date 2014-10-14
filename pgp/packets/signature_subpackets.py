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

import warnings

from pgp import crc24
from pgp import utils
from pgp.packets import constants


class SignatureSubpacket(object):

    @classmethod
    def from_subpacket_content(cls, type_, critical, sub_data):
        return cls(type_, critical)

    def __init__(self, type_, critical):
        self.type = type_
        self.critical = critical

    def __eq__(self, other):
        return (
            self.__class__ == other.__class__
            and bytes(self) == bytes(other)
            )

    def __hash__(self):
        return crc24.crc24(bytes(self))

    @property
    def content(self):
        return bytearray()

    def __bytes__(self):
        data = self.content
        data_len = len(data) + 1  # For the type
        result = bytearray()
        packet_length_bytes, _ = \
                utils.new_packet_length_to_bytes(data_len, False)
        result.extend(packet_length_bytes)
        raw = self.type + (0x80 if self.critical else 0x00)
        result.append(raw)
        result.extend(data)
        return bytes(result)


class CreationTimeSubpacket(SignatureSubpacket):

    @classmethod
    def from_subpacket_content(cls, type_, critical, sub_data):
        assert len(sub_data) == 4
        time = utils.long_to_int(sub_data, 0)
        return cls(critical, time)

    def __init__(self, critical, time):
        SignatureSubpacket.__init__(
                self, constants.CREATION_TIME_SUBPACKET_TYPE, critical)
        self.time = time

    @property
    def content(self):
        return utils.int_to_4byte(self.time)


class ExpirationSecondsSubpacket(CreationTimeSubpacket):

    def __init__(self, critical, time):
        SignatureSubpacket.__init__(
                self, constants.EXPIRATION_SECONDS_SUBPACKET_TYPE, critical)
        self.time = time


class ExportableSubpacket(SignatureSubpacket):

    @classmethod
    def from_subpacket_content(cls, type_, critical, sub_data):
        assert len(sub_data) == 1
        assert not sub_data[0] & 0xfe
        exportable = bool(sub_data[0])
        return cls(critical, exportable)

    def __init__(self, critical, exportable):
        SignatureSubpacket.__init__(
                self, constants.EXPORTABLE_SUBPACKET_TYPE, critical)
        self.exportable = exportable

    @property
    def content(self):
        # ensure self.exportable is bool before getting an int value
        return bytearray([int(bool(self.exportable))])


class TrustSubpacket(SignatureSubpacket):

    @classmethod
    def from_subpacket_content(cls, type_, critical, sub_data):
        assert len(sub_data) == 2
        depth = int(sub_data[0])
        amount = int(sub_data[1])
        return cls(critical, depth, amount)

    def __init__(self, critical, depth=0, amount=0):
        assert depth < 256 and depth >= 0
        assert amount < 256 and depth >= 0
        SignatureSubpacket.__init__(
                self, constants.TRUST_SUBPACKET_TYPE, critical)
        self.depth = depth
        self.amount = amount

    @property
    def content(self):
        return bytearray([int(self.depth), int(self.amount)])


class RegularExpressionSubpacket(SignatureSubpacket):

    @classmethod
    def from_subpacket_content(cls, type_, critical, sub_data):
        assert len(sub_data) > 0
        assert sub_data[-1] == 0
        pattern = sub_data[:-1].decode('ascii', 'replace')
        return cls(critical, pattern)

    def __init__(self, critical, pattern):
        SignatureSubpacket.__init__(
                self, constants.REGULAR_EXPRESSION_SUBPACKET_TYPE, critical)
        self.pattern = pattern

    @property
    def content(self):
        return bytearray(self.pattern.encode('ascii', 'replace'))


class RevocableSubpacket(SignatureSubpacket):

    @classmethod
    def from_subpacket_content(cls, type_, critical, sub_data):
        assert len(sub_data) == 1
        assert not sub_data[0] & 0xfe
        revocable = bool(sub_data[0])
        return cls(critical, revocable)

    def __init__(self, critical, revocable):
        SignatureSubpacket.__init__(
                self, constants.REVOCABLE_SUBPACKET_TYPE, critical)
        self.revocable = revocable

    @property
    def content(self):
        # ensure self.revocable is bool before getting an int value
        return bytearray([int(bool(self.revocable))])


class KeyExpirationTimeSubpacket(CreationTimeSubpacket):

    def __init__(self, critical, time):
        SignatureSubpacket.__init__(
                self, constants.KEY_EXPIRATION_TIME_SUBPACKET_TYPE, critical)
        self.time = time


class AdditionalRecipientRequestSubpacket(SignatureSubpacket):
    """From first draft of RFC 2440.

        "Key holder requests encryption to additional recipient when
        data is encrypted to this username.  If the class octet
        contains 0x80, then the key holder strongly requests that the
        additional recipient be added to an encryption.  Implementing
        software may treat this subpacket in any way it sees fit. This
        is found only on a self-signature."
    """

    @classmethod
    def from_subpacket_content(cls, type_, critical, sub_data):
        strong_request = bool(sub_data[0] & 0x80)
        public_key_algorithm = sub_data[1]
        fingerprint = utils.bytearray_to_hex(sub_data, 2, 20)
        return cls(critical, strong_request, public_key_algorithm,
                   fingerprint)

    def __init__(self, critical, strong_request, public_key_algorithm,
                 fingerprint):
        SignatureSubpacket.__init__(
                self, constants.ADDITIONAL_RECIPIENT_REQUEST_SUBPACKET_TYPE,
                critical)
        self.strong_request = strong_request
        self.public_key_algorithm = public_key_algorithm
        self.fingerprint = fingerprint

    @property
    def content(self):
        warnings.warn("The additional recipients request signature subpacket "
                      "type is deprecated.")
        data = bytearray([
                    0x80 if self.strong_request else 0x00,
                    self.public_key_algorithm,
                ])
        data.extend(utils.hex_to_bytes(self.fingerprint, 20))
        return data


class PreferredSymmetricAlgorithmsSubpacket(SignatureSubpacket):

    @classmethod
    def from_subpacket_content(cls, type_, critical, sub_data):
        # Spec doesn't forbid an empty list
        preferred_algorithms = list(map(int, sub_data))
        return cls(critical, preferred_algorithms)

    def __init__(self, critical, preferred_algorithms):
        for alg in preferred_algorithms:
            assert alg < 256
        SignatureSubpacket.__init__(self,
                constants.PREFERRED_SYMMETRIC_ALGORITHMS_SUBPACKET_TYPE,
                critical)
        self.preferred_algorithms = preferred_algorithms

    @property
    def content(self):
        return bytearray(map(int, self.preferred_algorithms))


class RevocationKeySubpacket(SignatureSubpacket):

    @classmethod
    def from_subpacket_content(cls, type_, critical, sub_data):
        assert len(sub_data) == 22
        tag = sub_data
        assert tag & 0x80
        sensitive = bool(tag & 0x40)
        public_key_algorithm = int(sub_data[1])
        fingerprint = utils.bytearray_to_hex(sub_data, 2, 20)
        return cls(critical, fingerprint, public_key_algorithm,
                   sensitive=sensitive)

    def __init__(self, critical, fingerprint, public_key_algorithm,
                 sensitive=False):

        if isinstance(fingerprint, (bytes, bytearray)):
            assert len(fingerprint) == 20
            fingerprint = utils.bytearray_to_hex(fingerprint, 0, 20)
        else:
            assert len(fingerprint) == 40
        SignatureSubpacket.__init__(
                self, constants.REVOCATION_KEY_SUBPACKET_TYPE, critical)
        self.fingerprint = fingerprint
        self.public_key_algorithm = public_key_algorithm
        self.sensitive = sensitive

    @property
    def content(self):
        tag = 0x80 + (0x40 if self.sensitive else 0x00)
        data = bytearray(
                        [tag, int(self.public_key_algorithm)] +
                        utils.bytearray_to_hex(self.fingerprint, 20)
                    )
        return data


class IssuerSubpacket(SignatureSubpacket):

    @classmethod
    def from_subpacket_content(cls, type_, critical, sub_data):
        assert len(sub_data) == 8
        key_id = utils.bytearray_to_hex(sub_data, 0, 16)
        return cls(critical, key_id)

    def __init__(self, critical, key_id):
        SignatureSubpacket.__init__(
                self, constants.ISSUER_KEY_ID_SUBPACKET_TYPE, critical)
        self.key_id = key_id

    @property
    def content(self):
        data = bytearray(
                utils.hex_to_bytes(self.key_id, 8)
            )
        return data


class NotationSubpacket(SignatureSubpacket):

    @classmethod
    def from_subpacket_content(cls, type_, critical, sub_data):
        assert len(sub_data) >= 8
        offset = 0
        flags = sub_data[:4]
        offset += 4
        assert not any(flags[1:])
        assert not flags[0] & 0x7f
        human_readable = 0x80
        name_length = utils.short_to_int(sub_data, offset)
        offset += 2
        value_length = utils.short_to_int(sub_data, offset)
        offset += 2
        raw_name = sub_data[offset:offset + name_length]
        offset += name_length
        value = sub_data[offset:offset + value_length]
        offset += value_length
        assert offset == len(sub_data)

        name_and_namespace = raw_name.decode('utf8', 'replace')
        name, namespace = (name_and_namespace.split('@', 1) + [None])[:2]

        if human_readable:
            value = value.decode('utf8', 'replace')

        return cls(critical, name, namespace, human_readable, value)

    def __init__(self, critical, name, namespace, human_readable, value):
        SignatureSubpacket.__init__(
                self, constants.NOTATION_SUBPACKET_TYPE, critical)
        self.name = name
        self.namespace = namespace
        self.human_readable = human_readable
        self.value = value

    @property
    def content(self):
        raw_name = self.name.encode('utf8', 'replace')
        if self.namespace:
            raw_name += b'@' + self.namespace.encode('utf8', 'replace')
        raw_value = self.value
        if self.human_readable:
            raw_value = raw_value.encode('utf8', 'replace')
        data = bytearray([0x80 if self.human_readable else 0, 0, 0, 0])
        data.extend(utils.int_to_2byte(len(raw_name)))
        data.extend(utils.int_to_2byte(len(raw_value)))
        data.extend(raw_name)
        data.extend(raw_value)
        return data


class PreferredHashAlgorithmsSubpacket(PreferredSymmetricAlgorithmsSubpacket):

    def __init__(self, critical, preferred_algorithms):
        for alg in preferred_algorithms:
            assert alg < 256
        SignatureSubpacket.__init__(self,
                constants.PREFERRED_HASH_ALGORITHMS_SUBPACKET_TYPE, critical)
        self.preferred_algorithms = preferred_algorithms


class PreferredCompressionAlgorithmsSubpacket(
                PreferredSymmetricAlgorithmsSubpacket
            ):

    def __init__(self, critical, preferred_algorithms):
        for alg in preferred_algorithms:
            assert alg < 256
        SignatureSubpacket.__init__(self,
                constants.PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET_TYPE,
                critical)
        self.preferred_algorithms = preferred_algorithms


class KeyServerPreferencesSubpacket(SignatureSubpacket):

    @classmethod
    def from_subpacket_content(cls, type_, critical, sub_data):
        assert len(sub_data) > 0
        no_modify = bool(sub_data[0] & 0x80)
        return cls(critical, no_modify)

    def __init__(self, critical, no_modify):
        SignatureSubpacket.__init__(self,
                constants.KEY_SERVER_PREFERENCES_SUBPACKET_TYPE, critical)
        self.no_modify = no_modify

    @property
    def content(self):
        return bytearray([0x80 if self.no_modify else 0x00])


class PreferredKeyServerSubpacket(SignatureSubpacket):

    @classmethod
    def from_subpacket_content(cls, type_, critical, sub_data):
        assert len(sub_data) > 0
        uri = sub_data.decode('utf8', 'replace')
        return cls(critical, uri)

    def __init__(self, critical, uri):
        SignatureSubpacket.__init__(
                self, constants.PREFERRED_KEY_SERVER_SUBPACKET_TYPE, critical)
        self.uri = uri

    @property
    def content(self):
        return bytearray(self.uri.encode('utf8', 'replace'))


class PrimaryUserIDSubpacket(SignatureSubpacket):

    @classmethod
    def from_subpacket_content(cls, type_, critical, sub_data):
        assert len(sub_data) == 1
        assert not sub_data[0] & 0xfe
        primary = bool(sub_data[0])
        return cls(critical, primary)

    def __init__(self, critical, primary):
        SignatureSubpacket.__init__(self, 25, critical)
        self.primary = primary

    @property
    def content(self):
        # ensure self.primary is bool before getting an int value
        return bytearray([int(bool(self.primary))])


class PolicyURISubpacket(PreferredKeyServerSubpacket):

    def __init__(self, critical, uri):
        SignatureSubpacket.__init__(self, 26, critical)
        self.uri = uri


class KeyFlagsSubpacket(SignatureSubpacket):

    @classmethod
    def from_subpacket_content(cls, type_, critical, sub_data):
        assert len(sub_data) > 0
        known_flags = sub_data[0]
        may_certify_others = bool(known_flags & 0x01)
        may_sign_data = bool(known_flags & 0x02)
        may_encrypt_comms = bool(known_flags & 0x04)
        may_encrypt_storage = bool(known_flags & 0x08)
        may_be_used_for_auth = bool(known_flags & 0x20)
        may_have_been_split = bool(known_flags & 0x10)
        may_have_multiple_owners = bool(known_flags & 0x80)
        return cls(critical, may_certify_others, may_sign_data,
                   may_encrypt_comms, may_encrypt_storage,
                   may_be_used_for_auth, may_have_been_split,
                   may_have_multiple_owners)

    def __init__(self, critical, may_certify_others=True, may_sign_data=True,
                 may_encrypt_comms=True, may_encrypt_storage=True,
                 may_be_used_for_auth=True, may_have_been_split=True,
                 may_have_multiple_owners=True):
        SignatureSubpacket.__init__(self, constants.KEY_FLAGS_SUBPACKET_TYPE,
                                    critical)
        self.may_certify_others = may_certify_others
        self.may_sign_data = may_sign_data
        self.may_encrypt_comms = may_encrypt_comms
        self.may_encrypt_storage = may_encrypt_storage
        self.may_be_used_for_auth = may_be_used_for_auth
        self.may_have_been_split = may_have_been_split
        self.may_have_multiple_owners = may_have_multiple_owners

    @property
    def content(self):
        data = bytearray([
            (0x01 if self.may_certify_others else 0x00) +
            (0x02 if self.may_sign_data else 0x00) +
            (0x04 if self.may_encrypt_comms else 0x00) +
            (0x08 if self.may_encrypt_storage else 0x00) +
            (0x10 if self.may_have_been_split else 0x00) +
            (0x20 if self.may_be_used_for_auth else 0x00) +
            (0x80 if self.may_have_multiple_owners else 0x00)
            ])
        return data


class UserIDSubpacket(SignatureSubpacket):

    @classmethod
    def from_subpacket_content(cls, type_, critical, sub_data):
        user_id = sub_data.decode('utf8')
        return cls(critical, user_id)

    def __init__(self, critical, user_id):
        SignatureSubpacket.__init__(
                self, constants.ISSUERS_USER_ID_SUBPACKET_TYPE, critical)
        self.user_id = user_id

    @property
    def content(self):
        return bytearray(self.user_id.encode('utf8', 'replace'))


class RevocationReasonSubpacket(SignatureSubpacket):

    @classmethod
    def from_subpacket_content(cls, type_, critical, sub_data):
        revocation_code = sub_data[0]
        revocation_reason = sub_data[1:].decode('utf8', 'replace')
        return cls(critical, revocation_code, revocation_reason)

    def __init__(self, critical, revocation_code, revocation_reason):
        SignatureSubpacket.__init__(
                self, constants.REVOCATION_REASON_SUBPACKET_TYPE, critical)
        assert revocation_code < 256
        self.revocation_code = revocation_code
        self.revocation_reason = revocation_reason

    @property
    def content(self):
        data = bytearray([self.revocation_code])
        data += bytearray(
                        self.revocation_reason.encode('utf8', 'replace')
                    )
        return data


class FeaturesSubpacket(SignatureSubpacket):

    @classmethod
    def from_subpacket_content(cls, type_, critical, sub_data):
        assert len(sub_data) > 0
        supports_modification_detection = sub_data[0] & 0x01
        return cls(critical, supports_modification_detection)

    def __init__(self, critical, supports_modification_detection):
        SignatureSubpacket.__init__(
                self, constants.FEATURES_SUBPACKET_TYPE, critical)
        self.supports_modification_detection = supports_modification_detection

    @property
    def content(self):
        data = bytearray([
                        0x01 if self.supports_modification_detection else 0x00
                        ])
        return data


class TargetSubpacket(SignatureSubpacket):

    @classmethod
    def from_subpacket_content(cls, type_, critical, sub_data):
        assert len(sub_data) > 2
        public_key_algorithm = int(sub_data[0])
        hash_algorithm = int(sub_data[1])
        hash_length = utils.hash_lengths.get(hash_algorithm, None)
        if hash_length is None:
            hash_length = len(sub_data) - 2
        else:
            assert hash_length == len(sub_data) - 2
        hash_ = utils.bytearray_to_hex(sub_data, 2, len(sub_data) - 2)
        return cls(critical, public_key_algorithm, hash_algorithm, hash_,
                   hash_length=hash_length)

    def __init__(self, critical, public_key_algorithm=0, hash_algorithm=0,
                 hash_=None, hash_length=None):
        SignatureSubpacket.__init__(
                self, constants.TARGET_SUBPACKET_TYPE, critical)
        assert public_key_algorithm < 256
        assert hash_algorithm < 256
        if hash_algorithm not in utils.hash_lengths:
            assert hash_length is not None
        self.public_key_algorithm = public_key_algorithm
        self.hash_algorithm = hash_algorithm
        self.hash = hash_ or bytearray()
        self.hash_length = hash_length

    @property
    def content(self):
        hash_length = utils.hash_lengths.get(self.hash_algorithm, None)
        if hash_length is None:
            hash_length = self.hash_length

        return bytearray([
                            int(self.public_key_algorithm),
                            int(self.hash_algorithm),
                        ] + utils.hex_to_bytes(self.hash, hash_length)
                    )


class EmbeddedSignatureSubpacket(SignatureSubpacket):

    @classmethod
    def from_subpacket_content(cls, type_, critical, sub_data):
        from pgp.packets.packets import SignaturePacket

        signature = SignaturePacket.from_packet_content(
                        constants.NEW_PACKET_HEADER_TYPE, 2, sub_data
                    )
        return cls(critical, signature)

    def __init__(self, critical, signature):
        SignatureSubpacket.__init__(
                self, constants.EMBEDDED_SIGNATURE_SUBPACKET_TYPE, critical)
        self.signature = signature

    @property
    def content(self):
        return self.signature.content


SIGNATURE_SUBPACKET_TYPES = {
    constants.CREATION_TIME_SUBPACKET_TYPE: CreationTimeSubpacket,
    constants.EXPIRATION_SECONDS_SUBPACKET_TYPE: ExpirationSecondsSubpacket,
    constants.EXPORTABLE_SUBPACKET_TYPE: ExportableSubpacket,
    constants.TRUST_SUBPACKET_TYPE: TrustSubpacket,
    constants.REGULAR_EXPRESSION_SUBPACKET_TYPE: RegularExpressionSubpacket,
    constants.REVOCABLE_SUBPACKET_TYPE: RevocableSubpacket,
    constants.KEY_EXPIRATION_TIME_SUBPACKET_TYPE: KeyExpirationTimeSubpacket,
    constants.PREFERRED_SYMMETRIC_ALGORITHMS_SUBPACKET_TYPE:
        PreferredSymmetricAlgorithmsSubpacket,
    constants.REVOCATION_KEY_SUBPACKET_TYPE: RevocationKeySubpacket,
    constants.ISSUER_KEY_ID_SUBPACKET_TYPE: IssuerSubpacket,
    constants.NOTATION_SUBPACKET_TYPE: NotationSubpacket,
    constants.PREFERRED_HASH_ALGORITHMS_SUBPACKET_TYPE:
        PreferredHashAlgorithmsSubpacket,
    constants.PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET_TYPE:
        PreferredCompressionAlgorithmsSubpacket,
    constants.KEY_SERVER_PREFERENCES_SUBPACKET_TYPE:
        KeyServerPreferencesSubpacket,
    constants.PREFERRED_KEY_SERVER_SUBPACKET_TYPE:
        PreferredKeyServerSubpacket,
    constants.PRIMARY_USER_ID_SUBPACKET_TYPE: PrimaryUserIDSubpacket,
    constants.POLICY_URI_SUBPACKET_TYPE: PolicyURISubpacket,
    constants.KEY_FLAGS_SUBPACKET_TYPE: KeyFlagsSubpacket,
    constants.ISSUERS_USER_ID_SUBPACKET_TYPE: UserIDSubpacket,
    constants.REVOCATION_REASON_SUBPACKET_TYPE: RevocationReasonSubpacket,
    constants.FEATURES_SUBPACKET_TYPE: FeaturesSubpacket,
    constants.TARGET_SUBPACKET_TYPE: TargetSubpacket,
    constants.EMBEDDED_SIGNATURE_SUBPACKET_TYPE: EmbeddedSignatureSubpacket,

    # Deprecated
    constants.ADDITIONAL_RECIPIENT_REQUEST_SUBPACKET_TYPE:
        AdditionalRecipientRequestSubpacket,

    # Unofficial
    # None
    }


def signature_subpacket_from_data(data, offset=0):
    offset, length, partial = utils.new_packet_length(data, offset)
    # TODO: smarter error
    assert not partial
    tag = data[offset]
    subpacket_type = tag & 0x7f
    critical = bool(tag & 0x80)
    length -= 1  # Since we've parsed the tag from the data
    offset += 1
    sub_data = data[offset:offset + length]
    offset += length
    cls = SIGNATURE_SUBPACKET_TYPES.get(subpacket_type, SignatureSubpacket)
    return (
        cls.from_subpacket_content(subpacket_type, critical, sub_data),
        offset
        )
