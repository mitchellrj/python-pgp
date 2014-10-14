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

from pgp.packets import constants
from pgp import utils


class UserAttributeSubpacket(object):

    @classmethod
    def from_subpacket_content(cls, sub_type, sub_data):
        return cls(sub_type)

    def __init__(self, sub_type):
        self.sub_type = sub_type

    def __eq__(self, other):
        return (
            self.__class__ == other.__class__
            and self.sub_type == other.sub_type
            )

    @property
    def content(self):
        return bytearray()

    def __bytes__(self):
        data = self.content
        result = bytearray()
        # +1 for sub type
        result.extend(utils.new_packet_length_to_bytes(
            len(data) + 1, False)[0])
        result.append(self.sub_type)
        result.extend(data)
        return bytes(result)


class ImageAttributeSubpacket(UserAttributeSubpacket):

    @classmethod
    def from_subpacket_content(cls, sub_type, sub_data, parse_unknown=False):
        # "The only currently defined subpacket type is 1, signifying
        #  an image."

        # "The first two octets of the image header contain the length of
        #  the image header.  Note that unlike other multi-octet numerical
        #  values in this document, due to a historical accident this
        #  value is encoded as a little-endian number."
        header_length = sub_data[0] + (sub_data[1] << 8)
        header_version = sub_data[2]
        image_format = None
        if header_version == 1:
            if not header_length == 16:
                raise ValueError
            image_format = sub_data[3]
            if any(sub_data[4:16]):
                # Incorrect
                raise ValueError
            content_data = sub_data[header_length:]
        elif parse_unknown:
            # If we want to parse unknown, non-image data
            content_data = sub_data[header_length:]
        else:
            raise ValueError

        return cls(header_version, header_length, image_format, content_data)

    def __init__(self, header_version, header_length, image_format,
                 content_data):
        UserAttributeSubpacket.__init__(
                self, constants.IMAGE_ATTRIBUTE_SUBPACKET_TYPE)
        self.header_version = header_version
        self.header_length = header_length
        self.image_format = image_format
        self.data = content_data

    def __eq__(self, other):
        return (
            super(ImageAttributeSubpacket, self).__eq__(other)
            and self.header_version == other.header_version
            and self.header_length == other.header_length
            and self.image_format == other.image_format
            and self.data == other.data
            )

    @property
    def content(self):
        result = bytearray([
                    self.header_length & 0xff,
                    (self.header_length >> 8) & 0xff,
                    self.header_version,
                ])
        if self.image_format is not None:
            result.append(self.image_format)
            result.extend([0] * (self.header_length - 4))
        else:
            result.extend([0] * (self.header_length - 3))
        result.extend(self.data)
        return result


USER_ATTRIBUTE_SUBPACKET_TYPES = {
    constants.IMAGE_ATTRIBUTE_SUBPACKET_TYPE: ImageAttributeSubpacket,
    }


def user_attribute_subpacket_from_data(data, offset=0):
    sub_data = bytearray()
    offset, sub_len, sub_partial = utils.new_packet_length(data, offset)
    if sub_partial:
        # "An implementation MAY use Partial Body Lengths for data
        #  packets, be they literal, compressed, or encrypted.  [...]
        #  Partial Body Lengths MUST NOT be used for any other packet
        #  types."
        raise ValueError
    sub_type = int(data[offset])
    # + 1 for sub type
    sub_data_start = offset + 1
    sub_data_end = sub_data_start + sub_len - 1
    sub_data.extend(data[sub_data_start:sub_data_end])
    offset = sub_data_end
    cls = USER_ATTRIBUTE_SUBPACKET_TYPES.get(sub_type, UserAttributeSubpacket)
    return cls.from_subpacket_content(sub_type, sub_data), offset
