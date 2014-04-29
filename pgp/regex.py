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

"""OpenPGP regular expression syntax is not the same, nor as complex as
Python's regular expression syntax. This module provides methods for
validating that a regular expression is valid according to the
specification provided by RFC 4880.

http://tools.ietf.org/html/rfc4880#section-8
"""

import re

from pgp.exceptions import RegexValueError


re_tokenizer = re.compile(r'(\\.|[\]|*?+()\[]|[^\\])')


class Regex(object):

    complete = True

    def __init__(self):
        self.branches = []

    def __str__(self):
        return '|'.join(map(str, self.branches))


class Branch(object):

    complete = True

    def __init__(self, regex):
        self.regex = regex
        self.pieces = []

    def __str__(self):
        return ''.join(map(str, self.pieces))


class Piece(object):

    complete = False

    def __init__(self, branch):
        self.branch = branch
        self.atom = None
        self.terminator = ''

    def __str__(self):
        return '{0}{1}'.format(self.atom, self.terminator)


class Atom(object):

    complete = True
    start = ''
    end = ''

    def __init__(self, piece):
        self.piece = piece
        self.content = ''

    def __str__(self):
        return '{0}{1}{2}'.format(self.start, self.content,
                                  self.end if self.complete else '')


class Group(Atom):

    complete = False
    start = '('
    end = ')'


class Range(Atom):

    complete = False
    start = '['
    end = ']'


def validate_partial_subpacket_regex(tokens):
    root = Regex()
    current = Branch(root)
    root.branches.append(current)
    valid = True
    unterminated = False
    while valid and tokens:
        tok = tokens.pop(0)
        if tok == '|':
            piece = None
            if isinstance(current, Range) and not current.complete:
                current.content += tok
                continue
            if isinstance(current, Atom):
                if not current.complete:
                    valid = False
                    continue
                else:
                    piece = current.piece
                    regex = current.piece.branch.regex
            elif isinstance(current, Piece):
                piece = current
                regex = current.branch.regex
            elif isinstance(current, Branch):
                regex = current.regex
            if piece:
                piece.complete = True
            current = Branch(regex)
            regex.branches.append(current)
        elif tok in '*+?':
            if isinstance(current, Range) and not current.complete:
                current.content += tok
                continue
            if isinstance(current, Atom):
                if not current.complete:
                    valid = False
                    continue
                else:
                    piece = current.piece
            elif isinstance(current, Piece):
                if piece.complete:
                    valid = False
                piece = current
            else:
                valid = False
                continue
            piece.terminator = tok
            piece.complete = True
            current = piece.branch
        elif tok == '(':
            if isinstance(current, Range) and not current.complete:
                current.content += tok
                continue
            if isinstance(current, Atom):
                if not current.complete:
                    valid = False
                    continue
                current.piece.complete = True
                branch = current.piece.branch
            elif isinstance(current, Branch):
                branch = current
            piece = Piece(branch)
            branch.pieces.append(piece)
            current = Group(piece)
            piece.atom = current
            # We don't care about the validity of the sub expression, really,
            # just so long as we've parsed as much terminated data as we can.
            unterminated, _valid, sub_expr = validate_partial_subpacket_regex(
                                        tokens
                                    )
            current.content = sub_expr
        elif tok == ')':
            if isinstance(current, Range) and not current.complete:
                current.content += tok
                continue
            if not isinstance(current, Group):
                valid = False
                continue
            current.complete = True
            current = current.piece
        elif tok == '[':
            if isinstance(current, Range):
                current.content += tok
                continue
            elif isinstance(current, Atom):
                if not current.complete:
                    valid = False
                    continue
                current.piece.complete = True
                branch = current.piece.branch
            elif isinstance(current, Branch):
                branch = current
            piece = Piece(branch)
            branch.pieces.append(piece)
            current = Range(piece)
            piece.atom = current
        elif tok == ']':
            if isinstance(current, Range):
                if current.content in ('', '^'):
                    current.content += tok
                    continue
                if not current.complete:
                    current.complete = True
                    current = current.piece
                else:
                    valid = False
                    continue
            else:
                valid = False
                continue
        else:  # .^$ \\
            # anything
            if isinstance(current, Branch):
                branch = current
                piece = Piece(branch)
                branch.pieces.append(piece)
                current = Atom(piece)
                piece.atom = current
            elif isinstance(current, Piece):
                if not current.complete:
                    # Should always be false
                    current.complete = True
                branch = current.branch
                piece = Piece(branch)
                branch.pieces.append(piece)
                current = Atom(piece)
                piece.atom = current
            elif isinstance(current, Atom):
                if current.complete:
                    current.piece.complete = True
                    branch = current.piece.branch
                    piece = Piece(branch)
                    branch.pieces.append(piece)
                    current = Atom(piece)
                    piece.atom = current

            current.content += (tok)

    if (
            valid and
            (isinstance(current, Range) or isinstance(current, Group))
            and not current.complete
        ):

        unterminated = True

    if not valid:
        tokens.insert(0, tok)
    return unterminated, valid, str(root)


def validate_subpacket_regex(re_str):
    tokens = re_tokenizer.findall(re_str)
    unterminated, valid, valid_portion = \
        validate_partial_subpacket_regex(tokens)
    if unterminated:
        raise RegexValueError(len(valid_portion), re_str, unterminated=True)
    if not valid:
        raise RegexValueError(len(valid_portion), re_str)
