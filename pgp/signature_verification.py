# python-pgp A Python OpenPGP implementation                                                                         
# Copyright (C) 2014 Richard Mitchell
#
# Portions of this code are based on code from GnuPG.
# GnuPG is Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003,
#               2004, 2006 Free Software Foundation, Inc.
# GnuPG is licensed under the GNU Public License version 3 or later.
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

"""This module provides methods for the verification and validation of
OpenPGP signatures found in public key data.
"""

from datetime import datetime
from datetime import timedelta
import time

from pgpdump.utils import get_int2

from pgp.compat import raise_with
from pgp.exceptions import CannotValidateSignature
from pgp.exceptions import InvalidBackSignature
from pgp.exceptions import InvalidSignature
from pgp.exceptions import InvalidSubkeyBindingSignature
from pgp.exceptions import MissingBackSignature
from pgp.exceptions import SignatureCreatedInTheFuture
from pgp.exceptions import SignatureCreatedBeforeContent
from pgp.exceptions import SignatureDigestMismatch
from pgp.exceptions import SignatureVerificationFailed
from pgp.exceptions import SignedByRevokedKey
from pgp.exceptions import SignatureHasExpired
from pgp.exceptions import SigningKeyCreatedInTheFuture
from pgp.exceptions import SigningKeyHasBeenRevoked
from pgp.exceptions import SigningKeyHasExpired
from pgp.exceptions import UnexpectedSignatureType
from pgp.exceptions import UnsupportedPublicKeyAlgorithm
from pgp.utils import get_signature_values
from pgp.utils import get_public_key_constructor
from pgp.utils import hash_packet_for_signature
from pgp.utils import verify_hash


def get_revocation_keys(key_data):
    """Returns a list of revocation key IDs for the given public key
    data. Does not return revocation keys for subkeys.
    """

    for s in key_data['signatures']:
        if s['sig_type'] == 0x1f:
            revkey = s.get('revocation_key', None)
            # actually a fingerprint
            if revkey:
                yield revkey[-16:]


def check_back_signatures(key_data, signature_data, strict=False):
    """Validates the backsignature of a subkey binding signature if one
    exists.
    """

    for sig in signature_data.get('embedded_signatures', []):
        if sig['sig_type'] == 0x19:
            hashed_subpacket_data = get_hashed_subpacket_data(
                                        sig['_data']
                                        )
            hash_ = hash_packet_for_signature(
                        signature_data['parent']['_data'],
                        14,
                        key_data['_data'],
                        sig['sig_type'],
                        sig['sig_version'],
                        sig['hash_algorithm_type'],
                        sig['creation_time'],
                        sig['pub_algorithm_type'],
                        hashed_subpacket_data
                        )
            try:
                check_signature(key_data, sig, hash_, strict)
            except InvalidSignature, e:
                raise_with(InvalidBackSignature(key_data['key_id']), e)

    if signature_data.get('may_sign_data', False):
        # "For subkeys that can issue signatures, the subkey binding
        #  signature MUST contain an Embedded Signature subpacket with a
        #  primary key binding signature (0x19) issued by the subkey on
        #  the top-level key."
        raise MissingBackSignature


def check_signature_values(key_data, signature_data, strict=False):
    """Do basic checks on the signature validity including chronology
    validation, expiration and revocation.
    """

    if key_data['creation_time'] > signature_data['creation_time']:
        raise SignatureCreatedBeforeContent()

    sig_expired = False
    key_expired = False
    key_revoked = False
    current_time = time.time()
    key_creation_time = key_data['creation_time']
    sig_creation_time = signature_data['creation_time']

    if key_creation_time > current_time:
        raise SigningKeyCreatedInTheFuture(key_data['key_id'])

    if sig_creation_time > current_time:
        raise SignatureCreatedInTheFuture()

    sig_expires_seconds = signature_data.get('expiration_seconds', 0)
    if sig_expires_seconds:
        if ((sig_creation_time + sig_expires_seconds)
            > current_time):

            if strict:
                raise SignatureHasExpired(sig_creation_time +
                                          sig_expires_seconds)
            sig_expired = True

    key_expiration_time = None
    key_expiration_days = key_data.get('expiration_days', 0)
    if not key_expiration_days:
        # Check signatures for key expiration times
        for sig_data in key_data.get('signatures', []):
            key_expiration_seconds = sig_data.get('key_expiration_seconds', 0)
            if key_expiration_seconds:
                key_expiration_time = \
                    key_creation_time + key_expiration_seconds
                break
    else:
        key_expiration_time = time.mktime((
                datetime.utcfromtimestamp(key_creation_time) +
                timedelta(days=key_expiration_days)
            ).timetuple())

    if key_expiration_time is not None and key_expiration_time < current_time:
        if strict:
            raise SigningKeyHasExpired(key_expiration_time)
        key_expired = True

    if signature_data.get('revocable', None) is not False:
        # "Signatures that are not revocable have any later revocation
        #  signatures ignored. They represent a commitment by the signer that
        #  he cannot revoke his signature for the life of his key. If this
        #  packet is not present, the signature is revocable."
        revocation_key_parent = key_data.get('parent', key_data)
        revocation_key = ''
        for sig_data in key_data['signatures']:
            # first look for separate revocation keys
            if sig_data['sig_type'] in (0x1f, 0x18):
                revocation_key = sig_data.get('revocation_key', '')[-8:]
                if revocation_key:
                    break
        for sig_data in key_data['signatures']:
            if sig_data['sig_type'] in (0x20, 0x28):
                revocation_time = sig_data['creation_time']
                if revocation_time < key_data['creation_time'] and strict:
                    raise SignedByRevokedKey(key_data['key_id'])
                if sig_data['key_id'] == revocation_key_parent['key_id']:
                    if strict:
                        raise SigningKeyHasBeenRevoked(key_data['key_id'])
                    key_revoked = True
                elif (revocation_key and
                      sig_data['key_id'][-8:] == revocation_key):

                    if strict:
                        raise SigningKeyHasBeenRevoked(key_data['key_id'])
                    key_revoked = True

    return sig_expired, key_expired, key_revoked


def get_hashed_subpacket_data(data):
    """Get the hashed subpacket data from a signature packet's data."""

    sig_version = data[0]
    offset = 1
    if sig_version in (2, 3):
        return bytearray()
    elif sig_version >= 4:
        offset += 1
        offset += 1
        offset += 1
        length = get_int2(data, offset)
        offset += 2
        return data[offset:offset + length]


def key_verify(algorithm_type, expected_hash, signature_data, key_data):
    """Verify that the signature data matches the calculated digest of
    the data being signed using the key that made the signature.
    """

    key_constructor = get_public_key_constructor(algorithm_type)
    signature_values = get_signature_values(signature_data['_data'])

    if algorithm_type == 17:
        key_obj = key_constructor((long(key_data['prime']),
                                   long(key_data['group_order']),
                                   long(key_data['group_gen']),
                                   long(key_data['key_value'])
                                   ))
    elif algorithm_type == 20:
        key_obj = key_constructor((long(key_data['prime']),
                                   long(key_data['group_gen']),
                                   long(key_data['key_value'])
                                   ))
    elif algorithm_type in (1, 3):
        key_obj = key_constructor((long(key_data['modulus']),
                                   long(key_data['exponent'])
                                   ))
    else:
        raise UnsupportedPublicKeyAlgorithm(algorithm_type)

    if not verify_hash(algorithm_type, key_obj, expected_hash,
                       signature_values):
        raise SignatureVerificationFailed()


def check_signature(key_data, signature_data, hash_, strict=False):
    """Validate the signature created by this key matches the digest of
    the data it claims to sign.
    """

    sig_expired, key_expired, key_revoked = \
            check_signature_values(key_data, signature_data, strict)

    # Perform the quick check first before busting out the public key
    # algorithms
    digest = hash_.digest()
    if bytearray(digest[:2]) != signature_data['_sig_hash2']:
        raise SignatureDigestMismatch()

    key_verify(key_data['pub_algorithm_type'], hash_, signature_data,
               key_data)

    return sig_expired, key_expired, key_revoked


def validate_key_signature(signature_data, hash_, key_data, strict=False):
    """Validates whether the signature of a key is valid."""

    sig_expired, key_expired, key_revoked = \
            check_signature(key_data, signature_data, hash_, strict)
    if key_data.get('parent'):
        check_back_signatures(key_data, signature_data)

    return sig_expired, key_expired, key_revoked


def check_revocation_keys(key_data, signature_data, hash_, signing_key,
                          strict=False):
    """Validates a revocation signature on a public key, where the key
    being revoked has been signed by another key.
    """

    for rk in get_revocation_keys(key_data):
        if rk[-len(key_data['key_id']):] == key_data['key_id']:
            return validate_key_signature(signature_data, hash_, signing_key,
                                          strict)


def validate_signature(public_key_data, target_type, target_packet,
                       signature_data, signing_key_data, strict=False):
    """Returns a tuple of three booleans, the first indicates whether
    the signature has expired, the second indicates if the signing key
    has expired, the third indicates if the signing key has been
    revoked.

    If the signing_key passed in is a subkey, it must have the 'parent'
    item set to its public key data.
    """

    hashed_subpacket_data = get_hashed_subpacket_data(
                                signature_data['_data']
                                )
    hash_ = hash_packet_for_signature(
                public_key_data['_data'],
                target_type,
                target_packet['_data'],
                signature_data['sig_type'],
                signature_data['sig_version'],
                signature_data['hash_algorithm_type'],
                signature_data['creation_time'],
                signature_data['pub_algorithm_type'],
                hashed_subpacket_data
                )
    sig_type = signature_data['sig_type']
    result = False, False
    if sig_type == 0x20:
        # public key revocation
        if public_key_data['key_id'] != signature_data['key_id']:
            result = check_revocation_keys(public_key_data, signature_data,
                                           hash_, signing_key_data, strict)
        else:
            result = check_signature(public_key_data, signature_data, hash_,
                                     strict)
    elif sig_type == 0x28:
        # subkey revocation
        result = check_signature(public_key_data, signature_data, hash_,
                                 strict)
    elif sig_type == 0x18:
        # key binding
        if public_key_data['key_id'] != signature_data['key_id']:
            raise InvalidSubkeyBindingSignature()
        result = check_signature(public_key_data, signature_data, hash_,
                                 strict)
    elif sig_type == 0x1f:
        # direct key signature
        result = check_signature(public_key_data, signature_data, hash_,
                                 strict)
    elif sig_type in (0x10, 0x11, 0x12, 0x13):
        result = check_signature(signing_key_data, signature_data, hash_,
                                 strict)
    elif sig_type == 0x19:
        # Backsignature, we shouldn't have this here
        raise UnexpectedSignatureType(0x19)
    else:
        # 0x00, 0x01, 0x02, 0x30, 0x40 & 0x50 do not apply to public keys
        raise UnexpectedSignatureType(sig_type)

    return result


def validate_signatures(target_data, db, target_type=6, pk_data=None,
                        strict=False):
    if pk_data is None:
        pk_data = target_data

    for sig in target_data.get('signatures', []):
        if sig['validated']:
            continue
        signing_key_data = None
        i = 0
        while len(i < sig['key_ids']) and not signing_key_data:
            signing_key_data = db.get_key_by_key_id(
                                        sig['key_ids'][i]['key_id']
                                    )
        if not signing_key_data:
            continue
        try:
            validate_signature(pk_data, target_type, target_data,
                               sig, signing_key_data, strict)
        except InvalidSignature:
            sig['validated'] = False
        except CannotValidateSignature:
            sig['validated'] = None
        else:
            sig['validated'] = True

    for uid in target_data.get('user_ids', []):
        validate_signatures(uid, db, target_type=13, pk_data=pk_data,
                            strict=strict)

    for uattr in target_data.get('user_attributes', []):
        validate_signatures(uattr, db, target_type=17, pk_data=pk_data,
                            strict=strict)

    for subkey in target_data.get('subkeys', []):
        validate_signatures(subkey, db, target_type=14, pk_data=pk_data,
                            strict=strict)
