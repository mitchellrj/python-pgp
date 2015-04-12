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

import datetime

from pgp import utils
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
from pgp.exceptions import SigningKeyCreatedInTheFuture
from pgp.exceptions import SigningKeyHasBeenRevoked
from pgp.exceptions import SigningKeyHasExpired
from pgp.exceptions import UnexpectedSignatureType
from pgp.exceptions import UnsupportedPublicKeyAlgorithm
from pgp.packets import constants
from pgp.transferrable_keys import TransferablePublicKey
from pgp.transferrable_keys import TransferableSecretKey

try:
    long
except NameError:
    long = int


def get_revocation_keys(key):
    """Returns a list of revocation key IDs for the given key. Does not
    return revocation keys for subkeys.
    """

    for s in key.signatures:
        if s.signature_type == constants.KEY_REVOCATION_SIGNATURE:
            revkeys = s.revocation_keys
            for revkey_info in revkeys:
                yield revkey_info.fingerprint[-16:]


def check_back_signatures(key, subkey_binding_signature, strict=False,
                          current_time=None):
    """Validates the backsignature of a subkey binding signature if one
    exists.
    """

    for sig in subkey_binding_signature.embedded_signatures:
        if sig.signature_type == constants.PRIMARY_KEY_BINDING_SIGNATURE:
            hashed_subpacket_data = get_hashed_subpacket_data(
                                        subkey_binding_signature
                                        )
            target = subkey_binding_signature.target()
            if not target:
                continue
            hash_ = utils.hash_packet_for_signature(
                        key.to_packet(),
                        sig.signature_type,
                        sig.version,
                        sig.hash_algorithm,
                        sig.creation_time,
                        sig.public_key_algorithm,
                        target.to_packet(),
                        hashed_subpacket_data
                        )
            try:
                check_signature(key, sig, hash_, strict, current_time)
            except InvalidSignature as e:
                raise_with(InvalidBackSignature(target.key_id), e)

    if subkey_binding_signature.may_sign_data:
        # "For subkeys that can issue signatures, the subkey binding
        #  signature MUST contain an Embedded Signature subpacket with a
        #  primary key binding signature (0x19) issued by the subkey on
        #  the top-level key."
        raise MissingBackSignature()


def check_signature_values(key, signature, current_time=None, strict=False):
    """Do basic checks on the signature validity including chronology
    validation, expiration and revocation.
    """

    if key.creation_time > signature.creation_time:
        raise SignatureCreatedBeforeContent()

    key_expired = False
    key_revoked = False
    if current_time is None:
        current_time = datetime.datetime.now()
    key_creation_time = key.creation_time
    sig_creation_time = signature.creation_time

    if key_creation_time > current_time:
        raise SigningKeyCreatedInTheFuture(key.key_id)

    if sig_creation_time > current_time:
        raise SignatureCreatedInTheFuture()

    key_expiration_time = key.expiration_time
    if key_expiration_time is not None and key_expiration_time < current_time:
        if strict:
            raise SigningKeyHasExpired(key_expiration_time)
        key_expired = True

    if signature.revocable is not False:
        # "Signatures that are not revocable have any later revocation
        #  signatures ignored. They represent a commitment by the signer that
        #  he cannot revoke his signature for the life of his key. If this
        #  packet is not present, the signature is revocable."
        revocation_key_parent = key.primary_public_key or key
        revocation_keys = []
        for sig in key.signatures:
            # first look for separate revocation keys
            if sig.signature_type in (constants.SUBKEY_BINDING_SIGNATURE,
                                      constants.SIGNATURE_DIRECTLY_ON_A_KEY):
                revocation_keys.extend([
                    rev_key.fingerprint[-8:]
                    for rev_key
                    in sig.revocation_keys
                    ])
        for sig in key.signatures:
            if sig.signature_type in (constants.SUBKEY_REVOCATION_SIGNATURE,
                                      constants.KEY_REVOCATION_SIGNATURE):
                revocation_time = sig.creation_time
                if revocation_time < key.creation_time and strict:
                    raise SignedByRevokedKey(key.key_id)
                if revocation_key_parent.key_id in sig.issuer_key_ids:
                    if strict:
                        raise SigningKeyHasBeenRevoked(key.key_id)
                    key_revoked = True
                elif (revocation_keys and
                      key.key_id[-8:] in revocation_keys):

                    if strict:
                        raise SigningKeyHasBeenRevoked(key.key_id)
                    key_revoked = True

    return key_expired, key_revoked


def get_hashed_subpacket_data(signature):
    """Get the hashed subpacket data from a signature packet's data."""

    sig_version = signature.version
    if sig_version in (2, 3):
        return bytearray()
    elif sig_version >= 4:
        return b''.join(map(bytes, signature.hashed_subpackets))


def key_verify(expected_hash, signature, key):
    """Verify that the signature data matches the calculated digest of
    the data being signed using the key that made the signature.
    """

    return key.verify(signature, expected_hash)


def check_signature(key, signature, hash_, strict=False, current_time=None):
    """Validate the signature created by this key matches the digest of
    the data it claims to sign.
    """

    key_expired, key_revoked = \
            check_signature_values(key, signature, strict,
                                   current_time=current_time)

    # Perform the quick check first before busting out the public key
    # algorithms
    digest = hash_.digest()
    if bytearray(digest[:2]) != signature.hash2:
        raise SignatureDigestMismatch()

    key_verify(key, hash_, signature)

    return key_expired, key_revoked


def validate_key_signature(signature, hash_, key, strict=False,
                           current_time=None):
    """Validates whether the signature of a key is valid."""

    key_expired, key_revoked = \
            check_signature(key, signature, hash_, strict,
                            current_time=current_time)
    parent = key.public_key_parent
    if parent:
        check_back_signatures(key, signature, strict, current_time)

    return key_expired, key_revoked


def check_revocation_keys(key, signature, hash_, signing_key,
                          strict=False, current_time=None):
    """Validates a revocation signature on a public key, where the key
    being revoked has been signed by another key.
    """

    for rk in get_revocation_keys(key):
        if rk[-len(key.key_id):] == key.key_id:
            return validate_key_signature(signature, hash_, signing_key,
                                          strict, current_time)


def validate_signature(target, signature, signing_key, public_key=None,
                       strict=False, current_time=None):
    """Returns a tuple of three booleans, the first indicates whether
    the signature has expired, the second indicates if the signing key
    has expired, the third indicates if the signing key has been
    revoked.

    If the signing_key passed in is a subkey, it must have the 'parent'
    item set to its public key data.
    """

    hashed_subpacket_data = get_hashed_subpacket_data(
                                signature
                                )
    sig_type = signature.signature_type
    hash_ = utils.hash_packet_for_signature(
                target.to_packet(),
                signature.signature_type,
                signature.version,
                signature.hash_algorithm,
                signature.creation_time,
                signature.public_key_algorithm,
                public_key.to_packet(),
                hashed_subpacket_data
                )
    result = False, False
    if sig_type == constants.KEY_REVOCATION_SIGNATURE:
        # public key revocation
        if public_key.key_id not in signature.issuer_key_ids:
            result = check_revocation_keys(public_key, signature,
                                           hash_, signing_key, strict,
                                           current_time)
        else:
            result = check_signature(public_key, signature, hash_,
                                     strict, current_time)
    elif sig_type == constants.SUBKEY_REVOCATION_SIGNATURE:
        # subkey revocation
        result = check_signature(public_key, signature, hash_,
                                 strict, current_time)
    elif sig_type == constants.SUBKEY_BINDING_SIGNATURE:
        # key binding
        if public_key.key_id not in signature.issuer_key_ids:
            raise InvalidSubkeyBindingSignature()
        result = check_signature(public_key, signature, hash_,
                                 strict, current_time)
    elif sig_type == constants.SIGNATURE_DIRECTLY_ON_A_KEY:
        # direct key signature
        result = check_signature(public_key, signature, hash_,
                                 strict, current_time)
    elif sig_type in (constants.GENERIC_CERTIFICATION,
                      constants.CASUAL_CERTIFICATION,
                      constants.POSITIVE_CERTIFICATION,
                      constants.PERSONA_CERTIFICATION):
        result = check_signature(signing_key, signature, hash_,
                                 strict, current_time)
    elif sig_type == constants.PRIMARY_KEY_BINDING_SIGNATURE:
        # Backsignature, we shouldn't have this here
        raise UnexpectedSignatureType(constants.PRIMARY_KEY_BINDING_SIGNATURE)
    elif sig_type == constants.CERTIFICATION_REVOCATION_SIGNATURE:
        revocation_keys = [
            rev_key.fingerprint[-16:]
            for rev_key
            in signature.parent.revocation_keys
            ]
        if not signature.target:
            pass
        elif (
                signing_key.key_id not in signature.target.issuer_key_ids
                and signing_key.key_id not in revocation_keys
                ):
            raise SignatureVerificationFailed(
                'Signature cannot be revoked by this key')
        elif signature.target.revocable is False:
            raise SignatureVerificationFailed('Signature cannot be revoked')
        elif signature.target.creation_time > signature.creation_time:
            raise SignatureCreatedBeforeContent()
        # TODO: FIX THIS
        # result = check_signature(signing_key, signature, hash_,
        #                          strict)
    else:
        # 0x00, 0x01, 0x02, 0x30, 0x40 & 0x50 do not apply to public keys
        raise UnexpectedSignatureType(sig_type)

    return result


def get_target_type(item):
    return item.to_packet().type


def validate_signatures(target, db, strict=False):
    pk = getattr(target, 'primary_public_key', None)
    if pk is None:
        pk = target

    for sig in target.signatures:
        if sig.validated is not None:
            continue
        for signing_key_id in sig.issuer_key_ids:
            if pk.key_id == signing_key_id:
                # Shortcut for selfsig
                signing_keys = [pk]
            else:
                signing_keys = list(db.search(key_id=signing_key_id))
            if signing_keys:
                signing_key = signing_keys[0]
                try:
                    key_expired, key_revoked = \
                        validate_signature(target, sig, signing_key, pk,
                                           strict)
                except InvalidSignature:
                    sig.validated = False
                    break
                except CannotValidateSignature:
                    sig.validated = None
                else:
                    sig.validated = True
                    break
                sig.issuer_key_expired = key_expired
                sig.issuer_key_revoked = key_revoked

    if isinstance(target, (TransferablePublicKey, TransferableSecretKey)):
        for uid in target.user_ids:
            validate_signatures(uid, db, strict=strict)

        for uattr in target.user_attributes:
            validate_signatures(uattr, db, strict=strict)

        for subkey in target.subkeys:
            validate_signatures(subkey, db, strict=strict)
