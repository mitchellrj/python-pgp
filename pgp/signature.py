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

import datetime
import re
import time
import weakref

from zope.interface import implementer
from zope.interface import provider

from pgp import interfaces
from pgp import exceptions
from pgp.packets import constants as C
from pgp.packets import packets
from pgp.packets import signature_subpackets
from pgp.regex import validate_subpacket_regex
from pgp.user_id import parse_user_id


_marker = object()


@implementer(interfaces.INotation)
class Notation(object):

    namespace = None
    name = None
    value = None

    @classmethod
    def from_subpacket(cls, subpacket):
        if subpacket.critical:
            # We don't understand what any notations mean really.
            raise exceptions.CannotParseCriticalNotation
        return cls(subpacket.namespace, subpacket.name, subpacket.value,
                   subpacket.human_readable)

    def to_subpacket(self):
        return signature_subpackets.NotationSubpacket(
                critical=False,
                name=self.name,
                namespace=self.namespace,
                human_readable=self.is_human_readable(),
                value=self.value,
                )

    def __init__(self, namespace, name, value, human_readable):
        self.namespace = namespace
        self.name = name
        self.value = value
        self.human_readable = human_readable

    def is_human_readable(self):
        return self.human_readable


@implementer(interfaces.IRevocationKeyInfo)
class RevocationKeyInfo(object):

    public_key_algorithm = None
    fingerprint = None
    sensitive = None

    @classmethod
    def from_subpacket(cls, subpacket):
        return cls(subpacket.public_key_algorithm,
                   subpacket.fingerprint,
                   subpacket.sensitive)

    def to_subpacket(self, critical=False):
        return signature_subpackets.RevocationKeySubpacket(
                    critical,
                    self.fingerprint,
                    self.public_key_algorithm,
                    self.sensitive,
                )

    def __init__(self, public_key_algorithm, fingerprint, sensitive=False):
        self.public_key_algorithm = public_key_algorithm
        self.fingerprint = fingerprint
        self.sensitive = sensitive


@implementer(interfaces.ISignature)
class BaseSignature(object):

    NotationClass = Notation
    RevocationKeyInfoClass = RevocationKeyInfo

    version = None
    signature_type = None
    public_key_algorithm = None
    hash_algorithm = None
    hash2 = None
    signature_values = None

    # Information about the signature
    creation_time = None
    issuer_key_ids = None
    expiration_time = None
    exportable = None
    trust_depth = None
    trust_amount = None
    regular_expressions = None
    revocable = None
    notations = None
    issuer_user_id = None
    issuer_user_name = None
    issuer_user_email = None
    issuer_user_comment = None
    revocation_reason = None
    revocation_code = None
    embedded_signatures = None

    # Information about the thing the signature is applied to
    key_expiration_time = None
    preferred_compression_algorithms = None
    preferred_hash_algorithms = None
    preferred_symmetric_algorithms = None
    revocation_keys = None
    key_server_should_not_modify = None
    preferred_key_server = None
    primary_user_id = None
    policy_uri = None
    may_certify_others = None
    may_sign_data = None
    may_encrypt_comms = None
    may_encrypt_storage = None
    may_be_used_for_auth = None
    may_have_been_split = None
    may_have_multiple_owners = None
    supports_modification_detection = None

    @staticmethod
    def _make_regex(subpacket):
        validate_subpacket_regex(subpacket.pattern)
        return re.compile(subpacket.pattern)

    @staticmethod
    def _from_subpackets(packet, type_, attr=None, constructor=None,
                         return_all=False, default=_marker):
        ignore_subpacket_exceptions = (
                exceptions.CannotParseCritical,
                exceptions.RegexValueError
            )
        if return_all:
            result = []
        else:
            result = default
        for subpacket in packet.unhashed_subpackets:
            item = default
            if subpacket.type != type_:
                continue
            if attr is not None:
                item = getattr(subpacket, attr, default)
            else:
                try:
                    item = constructor(subpacket)
                except ignore_subpacket_exceptions:
                    # Handled by "if item is not default" below
                    pass
            if return_all:
                if item is not default:
                    result.append(item)
            else:
                result = item
        for subpacket in packet.hashed_subpackets:
            item = default
            if subpacket.type != type_:
                continue
            if attr is not None:
                item = getattr(subpacket, attr, default)
            else:
                try:
                    item = constructor(subpacket)
                except ignore_subpacket_exceptions:
                    # Handled by "if item is not default" below
                    pass
            if return_all:
                if item is not default:
                    result.append(item)
            else:
                result = item
        if not return_all and result is _marker:
            raise ValueError
        return result

    @classmethod
    def from_packet(cls, packet, target):
        version = packet.version
        signature_type = packet.signature_type
        public_key_algorithm = packet.public_key_algorithm
        hash_algorithm = packet.hash_algorithm,
        hash2 = packet.hash2
        signature_values = packet.signature_values
        if version in (2, 3):
            creation_time = datetime.datetime.fromtimestamp(
                                packet.creation_time)
            issuer_key_ids = [packet.key_id]
            expiration_time = None
            exportable = None
            trust_depth = None
            trust_amount = None
            regular_expressions = []
            revocable = None
            notations = []
            issuer_user_id = None
            revocation_reason = None
            revocation_code = None
            embedded_signatures = []
            key_expiration_time = None
            preferred_compression_algorithms = []
            preferred_hash_algorithms = []
            preferred_symmetric_algorithms = []
            revocation_keys = []
            key_server_should_not_modify = None
            preferred_key_server = None
            primary_user_id = None
            policy_uri = None
            may_certify_others = None
            may_sign_data = None
            may_encrypt_comms = None
            may_encrypt_storage = None
            may_be_used_for_auth = None
            may_have_been_split = None
            may_have_multiple_owners = None
            supports_modification_detection = None
        elif version >= 4:
            creation_time = datetime.datetime.fromtimestamp(
                cls._from_subpackets(
                    packet,
                    C.CREATION_TIME_SUBPACKET_TYPE,
                    'time',
                    default=None
                ))
            expiration_seconds = cls._from_subpackets(
                    packet,
                    C.EXPIRATION_SECONDS_SUBPACKET_TYPE,
                    'time',
                    default=None)
            expiration_time = None
            if expiration_seconds is not None:
                expiration_time = (
                    creation_time +
                    datetime.timedelta(seconds=expiration_seconds)
                    )
            exportable = cls._from_subpackets(
                    packet,
                    C.EXPORTABLE_SUBPACKET_TYPE,
                    'exportable',
                    default=None)
            trust_depth = cls._from_subpackets(
                    packet,
                    C.TRUST_SUBPACKET_TYPE,
                    'depth',
                    default=None)
            trust_amount = cls._from_subpackets(
                    packet,
                    C.TRUST_SUBPACKET_TYPE,
                    'amount',
                    default=None)
            revocable = cls._from_subpackets(
                    packet,
                    C.REVOCABLE_SUBPACKET_TYPE,
                    'revocable',
                    default=None)
            issuer_user_id = cls._from_subpackets(
                    packet,
                    C.ISSUERS_USER_ID_SUBPACKET_TYPE,
                    'user_id',
                    default=None)
            revocation_reason = cls._from_subpackets(
                    packet,
                    C.REVOCATION_REASON_SUBPACKET_TYPE,
                    'revocation_reason',
                    default=None)
            revocation_code = cls._from_subpackets(
                    packet,
                    C.REVOCATION_REASON_SUBPACKET_TYPE,
                    'revocation_code',
                    default=None)
            key_expiration_seconds = cls._from_subpackets(
                    packet,
                    C.KEY_EXPIRATION_TIME_SUBPACKET_TYPE,
                    'time',
                    default=None)
            key_expiration_time = None
            if key_expiration_seconds is not None:
                key_expiration_time = (
                    target.creation_time +
                    datetime.timedelta(seconds=key_expiration_seconds)
                    )
            preferred_compression_algorithms = cls._from_subpackets(
                    packet,
                    C.PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET_TYPE,
                    'preferred_algorithms',
                    default=[])
            preferred_hash_algorithms = cls._from_subpackets(
                    packet,
                    C.PREFERRED_HASH_ALGORITHMS_SUBPACKET_TYPE,
                    'preferred_algorithms',
                    default=[])
            preferred_symmetric_algorithms = cls._from_subpackets(
                    packet,
                    C.PREFERRED_SYMMETRIC_ALGORITHMS_SUBPACKET_TYPE,
                    'preferred_algorithms',
                    default=[])
            key_server_should_not_modify = cls._from_subpackets(
                    packet,
                    C.KEY_SERVER_PREFERENCES_SUBPACKET_TYPE,
                    'no_modify',
                    default=None)
            preferred_key_server = cls._from_subpackets(
                    packet,
                    C.PREFERRED_KEY_SERVER_SUBPACKET_TYPE,
                    'uri',
                    default=None)
            primary_user_id = cls._from_subpackets(
                    packet,
                    C.PRIMARY_USER_ID_SUBPACKET_TYPE,
                    'primary',
                    default=None)
            policy_uri = cls._from_subpackets(
                    packet,
                    C.POLICY_URI_SUBPACKET_TYPE,
                    'uri',
                    default=None)
            may_certify_others = cls._from_subpackets(
                    packet,
                    C.KEY_FLAGS_SUBPACKET_TYPE,
                    'may_certify_others',
                    default=None)
            may_sign_data = cls._from_subpackets(
                    packet,
                    C.KEY_FLAGS_SUBPACKET_TYPE,
                    'may_sign_data',
                    default=None)
            may_encrypt_comms = cls._from_subpackets(
                    packet,
                    C.KEY_FLAGS_SUBPACKET_TYPE,
                    'may_encrypt_comms',
                    default=None)
            may_encrypt_storage = cls._from_subpackets(
                    packet,
                    C.KEY_FLAGS_SUBPACKET_TYPE,
                    'may_encrypt_storage',
                    default=None)
            may_be_used_for_auth = cls._from_subpackets(
                    packet,
                    C.KEY_FLAGS_SUBPACKET_TYPE,
                    'may_be_used_for_auth',
                    default=None)
            may_have_been_split = cls._from_subpackets(
                    packet,
                    C.KEY_FLAGS_SUBPACKET_TYPE,
                    'may_have_been_split',
                    default=None)
            may_have_multiple_owners = cls._from_subpackets(
                    packet,
                    C.KEY_FLAGS_SUBPACKET_TYPE,
                    'may_have_multiple_owners',
                    default=None)
            supports_modification_detection = cls._from_subpackets(
                    packet,
                    C.FEATURES_SUBPACKET_TYPE,
                    'supports_modification_detection',
                    default=None)
            issuer_key_ids = cls._from_subpackets(
                    packet,
                    C.ISSUER_KEY_ID_SUBPACKET_TYPE,
                    'key_id',
                    default=[],
                    return_all=True)
            revocation_keys = cls._from_subpackets(
                    packet,
                    C.REVOCATION_KEY_SUBPACKET_TYPE,
                    constructor=cls.RevocationKeyInfoClass.from_subpacket,
                    return_all=True)
            regular_expressions = cls._from_subpackets(
                    packet,
                    C.REGULAR_EXPRESSION_SUBPACKET_TYPE,
                    constructor=cls._make_regex,
                    return_all=True)
            notations = cls._from_subpackets(
                    packet,
                    C.NOTATION_SUBPACKET_TYPE,
                    constructor=cls.NotationClass.from_subpacket,
                    return_all=True)
            embedded_signatures = cls._from_subpackets(
                    packet,
                    C.EMBEDDED_SIGNATURE_SUBPACKET_TYPE,
                    constructor=cls.from_packet,
                    return_all=True)
        else:
            raise ValueError

        return cls(target, version, signature_type, public_key_algorithm,
                   hash_algorithm, hash2, signature_values, creation_time,
                   issuer_key_ids, expiration_time, exportable, trust_depth,
                   trust_amount, regular_expressions, revocable, notations,
                   issuer_user_id, revocation_reason, revocation_code,
                   embedded_signatures, key_expiration_time,
                   preferred_compression_algorithms,
                   preferred_hash_algorithms, preferred_symmetric_algorithms,
                   revocation_keys, key_server_should_not_modify,
                   preferred_key_server, primary_user_id, policy_uri,
                   may_certify_others, may_sign_data, may_encrypt_comms,
                   may_encrypt_storage, may_be_used_for_auth,
                   may_have_been_split, may_have_multiple_owners,
                   supports_modification_detection)

    def to_packet(self, header_format, hash_subpackets=None,
                  critical_subpackets=None):
        if self.version >= 4:
            # Use subpackets
            if critical_subpackets is None:
                critical_subpackets = []
            hashed_subpackets = []
            unhashed_subpackets = []
            is_critical = lambda subtype: subtype in critical_subpackets
            subpacket_list = lambda subtype: (
                    hashed_subpackets
                    if (
                        hash_subpackets is None or
                        subtype in hash_subpackets
                        )
                    else unhashed_subpackets
                )

            crit = is_critical(C.CREATION_TIME_SUBPACKET_TYPE)
            creation_time = int(time.mktime(self.creation_time.timetuple()))
            hashed_subpackets.append(
                signature_subpackets.CreationTimeSubpacket(crit,
                                                           creation_time)
                )

            if self.expiration_time is not None:
                crit = is_critical(C.EXPIRATION_SECONDS_SUBPACKET_TYPE)
                expiration_seconds = (
                        self.expiration_time - self.creation_time).seconds
                subpacket_list(C.EXPIRATION_SECONDS_SUBPACKET_TYPE).append(
                    signature_subpackets.ExpirationSecondsSubpacket(
                            crit, expiration_seconds)
                    )

            if self.exportable is not None:
                crit = is_critical(C.EXPORTABLE_SUBPACKET_TYPE)
                subpacket_list(C.EXPORTABLE_SUBPACKET_TYPE).append(
                    signature_subpackets.ExportableSubpacket(
                            crit, self.exportable)
                    )

            if self.trust_depth is not None and self.trust_amount is not None:
                crit = is_critical(C.TRUST_SUBPACKET_TYPE)
                subpacket_list(C.TRUST_SUBPACKET_TYPE).append(
                    signature_subpackets.TrustSubpacket(
                            crit, self.trust_depth, self.trust_amount)
                    )

            crit = is_critical(C.REGULAR_EXPRESSION_SUBPACKET_TYPE)
            subpacket_list(C.REGULAR_EXPRESSION_SUBPACKET_TYPE).extend([
                signature_subpackets.RegularExpressionSubpacket(
                        crit, regex.pattern
                    )
                for regex in self.regular_expressions
                ])

            if self.revocable is not None:
                crit = is_critical(C.REVOCABLE_SUBPACKET_TYPE)
                subpacket_list(C.REVOCABLE_SUBPACKET_TYPE).append(
                    signature_subpackets.RevocableSubpacket(
                            crit, self.revocable)
                    )

            if self.key_expiration_time is not None:
                crit = is_critical(C.KEY_EXPIRATION_TIME_SUBPACKET_TYPE)
                key_expiration_time = int(time.mktime(
                            self.key_expiration_time.timetuple()))
                subpacket_list(C.KEY_EXPIRATION_TIME_SUBPACKET_TYPE).append(
                    signature_subpackets.KeyExpirationTimeSubpacket(
                            crit, key_expiration_time)
                    )

            if self.preferred_symmetric_algorithms:
                sub_type = C.PREFERRED_SYMMETRIC_ALGORITHMS_SUBPACKET_TYPE
                crit = is_critical(sub_type)
                subpacket_list(sub_type).append(
                    signature_subpackets.PreferredSymmetricAlgorithmsSubpacket(
                            crit, *self.preferred_symmetric_algorithms)
                    )

            crit = is_critical(C.REVOCATION_KEY_SUBPACKET_TYPE)
            subpacket_list(C.REVOCATION_KEY_SUBPACKET_TYPE).extend([
                revocation_key_info.to_subpacket(crit)
                for revocation_key_info in self.revocation_keys
                ])

            crit = is_critical(C.ISSUER_KEY_ID_SUBPACKET_TYPE)
            subpacket_list(C.ISSUER_KEY_ID_SUBPACKET_TYPE).extend([
                signature_subpackets.IssuerSubpacket(crit, key_id)
                for key_id in self.issuer_key_ids
                ])

            crit = is_critical(C.NOTATION_SUBPACKET_TYPE)
            subpacket_list(C.NOTATION_SUBPACKET_TYPE).extend([
                notation.to_subpacket(crit)
                for notation in self.notations
                ])

            if self.preferred_hash_algorithms:
                sub_type = C.PREFERRED_HASH_ALGORITHMS_SUBPACKET_TYPE
                crit = is_critical(sub_type)
                subpacket_list(sub_type).append(
                    signature_subpackets.PreferredHashAlgorithmsSubpacket(
                            crit, *self.preferred_hash_algorithms)
                    )

            if self.preferred_compression_algorithms:
                sub_type = C.PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET_TYPE
                crit = is_critical(sub_type)
                subpacket_list(sub_type).append(
                    signature_subpackets.PreferredCompressionAlgorithmsSubpacket(
                            crit, *self.preferred_compression_algorithms)
                    )

            if self.key_server_should_not_modify is not None:
                crit = is_critical(C.KEY_SERVER_PREFERENCES_SUBPACKET_TYPE)
                subpacket_list(C.KEY_SERVER_PREFERENCES_SUBPACKET_TYPE).append(
                    signature_subpackets.KeyServerPreferencesSubpacket(
                            crit, self.key_server_should_not_modify)
                    )

            if self.preferred_key_server is not None:
                crit = is_critical(C.PREFERRED_KEY_SERVER_SUBPACKET_TYPE)
                subpacket_list(C.PREFERRED_KEY_SERVER_SUBPACKET_TYPE).append(
                    signature_subpackets.PreferredKeyServerSubpacket(
                            crit, self.preferred_key_server)
                    )

            if self.primary_user_id is not None:
                crit = is_critical(C.PRIMARY_USER_ID_SUBPACKET_TYPE)
                subpacket_list(C.PRIMARY_USER_ID_SUBPACKET_TYPE).append(
                    signature_subpackets.PrimaryUserIDSubpacket(
                            crit, self.primary_user_id)
                    )

            if self.policy_uri is not None:
                crit = is_critical(C.POLICY_URI_SUBPACKET_TYPE)
                subpacket_list(C.POLICY_URI_SUBPACKET_TYPE).append(
                    signature_subpackets.PolicyURISubpacket(
                            crit, self.policy_uri)
                    )

            if (
                    self.may_be_used_for_auth is not None
                    or self.may_certify_others is not None
                    or self.may_encrypt_comms is not None
                    or self.may_encrypt_storage is not None
                    or self.may_have_been_split is not None
                    or self.may_have_multiple_owners is not None
                    or self.may_sign_data is not None
                    ):
                crit = is_critical(C.KEY_FLAGS_SUBPACKET_TYPE)
                subpacket_list(C.KEY_FLAGS_SUBPACKET_TYPE).append(
                    signature_subpackets.KeyFlagsSubpacket(
                            crit,
                            self.may_certify_others,
                            self.may_sign_data,
                            self.may_encrypt_comms,
                            self.may_encrypt_storage,
                            self.may_be_used_for_auth,
                            self.may_have_been_split,
                            self.may_have_multiple_owners,
                            )
                    )

            if self.issuer_user_id is not None:
                crit = is_critical(C.ISSUERS_USER_ID_SUBPACKET_TYPE)
                subpacket_list(C.ISSUERS_USER_ID_SUBPACKET_TYPE).append(
                    signature_subpackets.UserIDSubpacket(
                            crit, self.issuer_user_id)
                    )

            if self.revocation_code is not None:
                crit = is_critical(C.REVOCATION_REASON_SUBPACKET_TYPE)
                subpacket_list(C.REVOCATION_REASON_SUBPACKET_TYPE).append(
                    signature_subpackets.RevocationReasonSubpacket(
                            crit, self.revocation_code, self.revocation_reason)
                    )

            if self.supports_modification_detection is not None:
                crit = is_critical(C.FEATURES_SUBPACKET_TYPE)
                subpacket_list(C.FEATURES_SUBPACKET_TYPE).append(
                    signature_subpackets.FeaturesSubpacket(
                            crit, self.supports_modification_detection)
                    )

            crit = is_critical(C.EMBEDDED_SIGNATURE_SUBPACKET_TYPE)
            subpacket_list(C.EMBEDDED_SIGNATURE_SUBPACKET_TYPE).extend([
                signature_subpackets.EmbeddedSignatureSubpacket(
                        crit,
                        signature.to_packet(
                            header_format,
                            hash_subpackets=hash_subpackets,
                            critical_subpackets=critical_subpackets,
                            )
                        )
                for signature in self.embedded_signatures
                ])
            # Set target hash etc
            packet = packets.SignaturePacket(
                        header_format, self.version, self.signature_type,
                        self.public_key_algorithm, self.hash_algorithm,
                        self.hash2, self.signature_values, hashed_subpackets,
                        unhashed_subpackets)
        elif self.version in (2, 3):
            creation_time = int(time.mktime(self.creation_time.timetuple()))
            packet = packets.SignaturePacket(
                        header_format, self.version, self.signature_type,
                        self.public_key_algorithm, self.hash_algorithm,
                        self.hash2, self.signature_values, creation_time,
                        self.issuer_key_ids[0])
        return packet

    def __repr__(self):
        return '<{0} 0x{1:02x} at 0x{2:x}>'.format(self.__class__.__name__,
                                                   self.signature_type,
                                                   id(self))

    def __init__(self, target, version, signature_type, public_key_algorithm,
                 hash_algorithm, hash2, signature_values, creation_time,
                 issuer_key_ids, expiration_time=None, exportable=None,
                 trust_depth=None, trust_amount=None,
                 regular_expressions=None, revocable=None, notations=None,
                 issuer_user_id=None, revocation_reason=None,
                 revocation_code=None, embedded_signatures=None,
                 key_expiration_time=None,
                 preferred_compression_algorithms=None,
                 preferred_hash_algorithms=None,
                 preferred_symmetric_algorithms=None,
                 revocation_keys=None, key_server_should_not_modify=None,
                 preferred_key_server=None, primary_user_id=None,
                 policy_uri=None, may_certify_others=None, may_sign_data=None,
                 may_encrypt_comms=None, may_encrypt_storage=None,
                 may_be_used_for_auth=None, may_have_been_split=None,
                 may_have_multiple_owners=None,
                 supports_modification_detection=None):

        self._target_ref = weakref.ref(target)
        self.version = version
        self.signature_type = signature_type
        self.public_key_algorithm = public_key_algorithm
        self.hash_algorithm = hash_algorithm
        self.hash2 = hash2
        self.signature_values = signature_values
        self.creation_time = creation_time
        self.issuer_key_ids = issuer_key_ids
        self.expiration_time = expiration_time
        self.exportable = exportable
        self.trust_depth = trust_depth
        self.trust_amount = trust_amount
        self.regular_expressions = regular_expressions
        self.revocable = revocable
        self.notations = notations
        self.issuer_user_id = issuer_user_id
        self.revocation_reason = revocation_reason
        self.revocation_code = revocation_code
        self.embedded_signatures = embedded_signatures
        self.key_expiration_time = key_expiration_time
        self.preferred_compression_algorithms = \
            preferred_compression_algorithms
        self.preferred_hash_algorithms = preferred_hash_algorithms
        self.preferred_symmetric_algorithms = preferred_symmetric_algorithms
        self.revocation_keys = revocation_keys
        self.key_server_should_not_modify = key_server_should_not_modify
        self.preferred_key_server = preferred_key_server
        self.primary_user_id = primary_user_id
        self.policy_uri = policy_uri
        self.may_certify_others = may_certify_others
        self.may_sign_data = may_sign_data
        self.may_encrypt_comms = may_encrypt_comms
        self.may_encrypt_storage = may_encrypt_storage
        self.may_be_used_for_auth = may_be_used_for_auth
        self.may_have_been_split = may_have_been_split
        self.may_have_multiple_owners = may_have_multiple_owners
        self.supports_modification_detection = supports_modification_detection

    @property
    def target(self):
        # Resolve weakref
        return self._target_ref()

    def is_expired(self):
        pass

    def is_revoked(self):
        pass

    def issuer_key_is_expired(self):
        pass

    def issuer_key_is_revoked(self):
        pass

    def signature_target(self):
        pass

    @property
    def issuer_user_name(self):
        if self.issuer_user_id is None:
            return None
        return parse_user_id(self.issuer_user_id)[0]

    @property
    def issuer_user_email(self):
        if self.issuer_user_id is None:
            return None
        return parse_user_id(self.issuer_user_id)[1]

    @property
    def issuer_user_comment(self):
        if self.issuer_user_id is None:
            return None
        return parse_user_id(self.issuer_user_id)[2]
