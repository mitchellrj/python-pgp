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


from pgp.armor import ASCIIArmor
from pgp.packets.packets import packet_from_packet_data
from pgp.packets.packets import packet_from_packet_stream


def parse_binary_packet_stream(fh):
    while 1:
        pos = fh.tell()
        if len(fh.read(1)) != 1:
            return
        else:
            fh.seek(pos)
        packet = packet_from_packet_stream(fh)
        yield packet


def parse_binary_packet_data(data):
    offset = 0
    length = len(data)
    while offset < length:
        offset, packet = packet_from_packet_data(data, offset)
        yield packet


def parse_ascii_packet_data(data):
    armor = ASCIIArmor.from_ascii(data)
    return parse_binary_packet_data(bytes(armor))
