# Packet types
PUBLIC_KEY_ENCRYPTED_SESSION_KEY_PACKET_TYPE = 1
SIGNATURE_PACKET_TYPE = 2
SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY_PACKET_TYPE = 3
ONE_PASS_SIGNATURE_PACKET_TYPE = 4
SECRET_KEY_PACKET_TYPE = 5
PUBLIC_KEY_PACKET_TYPE = 6
SECRET_SUBKEY_PACKET_TYPE = 7
COMPRESSED_DATA_PACKET_TYPE = 8
SYMMETRICALLY_ENCRYPTED_DATA_PACKET_TYPE = 9
MARKER_PACKET_TYPE = 10
LITERAL_DATA_PACKET_TYPE = 11
TRUST_PACKET_TYPE = 12
USER_ID_PACKET_TYPE = 13
PUBLIC_SUBKEY_PACKET_TYPE = 14
USER_ATTRIBUTE_PACKET_TYPE = 17
SYMMETRICALLY_ENCRYPTED_AND_INTEGRITY_PROTECTED_DATA_PACKET_TYPE = 18
MODIFICATION_DETECTION_CODE_PACKET_TYPE = 19

# Deprecated packet types
OLD_COMMENT_PACKET_TYPE = 16  # From RFC 2440 draft 1

# Non-standard packet types
GPG_COMMENT_PACKET_TYPE = 61
GPG_CONTROL_PACKET_TYPE = 63

# Shorthand for data packet types
DATA_TYPES = (
    COMPRESSED_DATA_PACKET_TYPE,
    SYMMETRICALLY_ENCRYPTED_DATA_PACKET_TYPE,
    LITERAL_DATA_PACKET_TYPE,
    SYMMETRICALLY_ENCRYPTED_AND_INTEGRITY_PROTECTED_DATA_PACKET_TYPE,
    )

# Packet header types
NEW_PACKET_HEADER_TYPE = 1
OLD_PACKET_HEADER_TYPE = 2


# Signature types
SIGNATURE_OF_A_BINARY_DOCUMENT = 0x00
SIGNATURE_OF_A_CANONICAL_TEXT_DOCUMENT = 0x01
STANDALONE_SIGNATURE = 0x02
GENERIC_CERTIFICATION = 0x10
PERSONA_CERTIFICATION = 0x11
CASUAL_CERTIFICATION = 0x12
POSITIVE_CERTIFICATION = 0x13
SUBKEY_BINDING_SIGNATURE = 0x18
PRIMARY_KEY_BINDING_SIGNATURE = 0x19
SIGNATURE_DIRECTLY_ON_A_KEY = 0x1f
KEY_REVOCATION_SIGNATURE = 0x20
SUBKEY_REVOCATION_SIGNATURE = 0x28
CERTIFICATION_REVOCATION_SIGNATURE = 0x30
TIMESTAMP_SIGNATURE = 0x40
THIRD_PARTY_CONFIRMATION_SIGNATURE = 0x50


# Signature subpacket types
CREATION_TIME_SUBPACKET_TYPE = 2
EXPIRATION_SECONDS_SUBPACKET_TYPE = 3
EXPORTABLE_SUBPACKET_TYPE = 4
TRUST_SUBPACKET_TYPE = 5
REGULAR_EXPRESSION_SUBPACKET_TYPE = 6
REVOCABLE_SUBPACKET_TYPE = 7
KEY_EXPIRATION_TIME_SUBPACKET_TYPE = 9
PREFERRED_SYMMETRIC_ALGORITHMS_SUBPACKET_TYPE = 11
REVOCATION_KEY_SUBPACKET_TYPE = 12
ISSUER_KEY_ID_SUBPACKET_TYPE = 16
NOTATION_SUBPACKET_TYPE = 20
PREFERRED_HASH_ALGORITHMS_SUBPACKET_TYPE = 21
PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET_TYPE = 22
KEY_SERVER_PREFERENCES_SUBPACKET_TYPE = 23
PREFERRED_KEY_SERVER_SUBPACKET_TYPE = 24
PRIMARY_USER_ID_SUBPACKET_TYPE = 25
POLICY_URI_SUBPACKET_TYPE = 26
KEY_FLAGS_SUBPACKET_TYPE = 27
ISSUERS_USER_ID_SUBPACKET_TYPE = 28
REVOCATION_REASON_SUBPACKET_TYPE = 29
FEATURES_SUBPACKET_TYPE = 30
TARGET_SUBPACKET_TYPE = 31
EMBEDDED_SIGNATURE_SUBPACKET_TYPE = 32

# Deprecated signature subpacket types
ADDITIONAL_RECIPIENT_REQUEST_SUBPACKET_TYPE = 10  # From RFC 2440 draft 1


# User attribute subpacket types
IMAGE_ATTRIBUTE_SUBPACKET_TYPE = 1


# User attribute image subpacket image formats
JPEG_IMAGE_FORMAT = 1
