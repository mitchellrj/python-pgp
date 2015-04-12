from argparse import ArgumentError
import re


VALID_LIST_OPTIONS = set([
    u'show-photos',
    u'show-policy-urls',
    u'show-notations',
    u'show-std-notations',
    u'show-user-notations',
    u'show-keyserver-urls',
    u'show-uid-validity',
    u'show-unusable-uids',
    u'show-unusable-subkeys',
    u'show-keyring',
    u'show-sig-expire',
    u'show-sig-subpackets',
    ])


class ListCommand(object):

    def __init__(self, list_options):
        self.list_options = dict([
            ((
                 sub_option
                 if not sub_option.startswith('no-')
                 else sub_option[2:]
            ),
            sub_option.startswith('no-')
            )
            for sub_option
            in [
                re.split(r'[, ]', option)
                for option
                in list_options
            ]])
        invalid_list_options = (
            set(self.list_options.keys()) - VALID_LIST_OPTIONS
            )
        if invalid_list_options:
            raise ArgumentError(
                u'--list-options', u'Invalid list options: {0}'.format(
                u', '.join(list(map(repr, invalid_list_options)))))
