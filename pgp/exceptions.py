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


class CannotParseCritical(RuntimeError):
    """This signature subpacket cannot be parsed by this implementation
    and is marked as critical. It must be discarded.
    """


class CannotParseCriticalNotation(CannotParseCritical):
    """This notation subpacket cannot be parsed by this implementation
    and is marked as critical. It must be discarded.
    """


class SensitiveSignature(ValueError):
    """This signature is marked as being a senstive revocation key. We
    should not have received it.
    """


class InvalidKey(ValueError):
    """This public key contains some invalid data."""


class InvalidKeyPacketOrder(InvalidKey):
    """The packets that make up this public key are ordered in an
    invalid way.
    """


class InvalidKeyPacketType(InvalidKey):
    """This packet is not valid for a transferable public key."""


class InvalidUserAttribute(InvalidKey):
    """This user attribute contains some invalid data."""


class InvalidUserAttributeImageFormat(InvalidUserAttribute):
    """The image format provided by this user attribute is not valid."""


class InvalidUserAttributeImage(InvalidUserAttribute):
    """The image data provided by this user attribute is not valid for
    the image format specified.
    """


class UnsupportedPacketType(InvalidKey):
    """This packet type is unsupported in public key data."""


class UnsupportedPacketVersion(UnsupportedPacketType):
    """The version of this packet is not supported by this
    implementation.
    """


class UnsupportedSignatureVersion(UnsupportedPacketVersion):
    """The version of this signature is not supported by this
    implementation.
    """


# You might think these should inherit from InvalidSignature, but no
# TODO: explain this better
class ReservedSignatureSubpacket(InvalidKey):
    """This signature contains a subpacket type which is reserved."""


class InvalidSignatureSubpacket(InvalidKey):
    """This signature contains a subpacket type which is invalid."""


class LocalCertificationSignature(InvalidKey):
    """This signature is a local certification. We should not have
    received it and should discard it."""


class RegexValueError(InvalidSignatureSubpacket):
    """This regular expression signature subpacket contains an invalid
    expression.
    """

    def __init__(self, position, string, unterminated=False):
        if unterminated:
            position -= 1
        self.position = position
        self.string = string

    def __str__(self):
        return 'Invalid character at position {0}\n{1}\n{2}^'.format(
                    self.position, self.string, ' ' * self.position
                    )


class CannotValidateSignature(TypeError):
    """The implementation cannot validate this signature. It may or may
    not be valid.
    """


class UnexpectedSignatureType(CannotValidateSignature):
    """The implementation cannot validate this type of signature of
    this data.
    """


class UnsupportedPublicKeyAlgorithm(CannotValidateSignature):
    """The public key algorithm used by this signature is not supported
    by this implementation.
    """


class PublicKeyAlgorithmCannotSign(CannotValidateSignature):
    """The public key algorithm used by this signature cannot be used
    to sign data.
    """


class UnsupportedDigestAlgorithm(CannotValidateSignature):
    """The digest algorithm used by this signature is not supported by
    this implementation.
    """


class InvalidSignature(ValueError):
    """This signature is invalid."""


class SignatureDigestMismatch(InvalidSignature):
    """The signature check-bytes do not match the digest of the data it
    claims to sign.
    """


class SignatureVerificationFailed(InvalidSignature):
    """The signature does not match the data which it claims to sign.
    """


class InvalidSubkeyBindingSignature(InvalidSignature):
    """The signature binding this subkey to the primary key was not
    created by the primary key it claims to be bound to.
    """


class MissingBackSignature(InvalidSubkeyBindingSignature):
    """The subkey binding signature indicates that this subkey may be
    used to sign data. A backsignature is required for signing subkeys
    and one was not embedded in this binding signature.
    """


class InvalidBackSignature(InvalidSubkeyBindingSignature):
    """This subkey binding signature provided a backsignature, but did
    the backsignature is invalid.
    """


class SignatureTimeConflict(InvalidSignature):
    """Some kind of time conflict exists between the signature and the
    key that made it.
    """


class SigningKeyCreatedInTheFuture(SignatureTimeConflict):
    """The key used to create this signature claims to have been
    created in the future.
    """


class SignatureCreatedInTheFuture(SignatureTimeConflict):
    """This signature claims to have been created in the future."""


class SignatureCreatedBeforeContent(SignatureTimeConflict):
    """This signature was created before the content it signs purports
    to have been.
    """


class SignatureWarning(UserWarning):
    """Something is amiss with this signature, but it is not
    necessarily invalid.
    """


class SignatureHasExpired(SignatureWarning):
    """The signature has expired."""


class SigningKeyHasExpired(SignatureWarning):
    """The key used to make this signature has expired since the
    signature was created.
    """


class SignedByRevokedKey(SignatureWarning):
    """The key used to make this signature had already been revoked
    when the signature was created.
    """


class SigningKeyHasBeenRevoked(SignatureWarning):
    """The key used to make this signature has been revoked since the
    signature was created.
    """
