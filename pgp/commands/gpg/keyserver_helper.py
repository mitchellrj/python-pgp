from argparse import ArgumentError
import re


VALID_KEYSERVER_OPTIONS = set([
    u'include-revoked',
    u'include-disabled',
    u'auto-key-retrieve',
    u'honor-keyserver-url',
    u'honor-pka-record',
    u'include-subkeys',
    u'timeout',
    u'http-proxy',
    u'max-cert-size',
    u'debug',
    u'check-cert',
    u'ca-cert-file',
    ])


class KeyServerHelper(object):

    def __init__(self, keyserver, keyserver_options):
        self.keyserver = keyserver
        self.keyserver_options = dict([
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
                in keyserver_options
            ]])
        invalid_keyserver_options = (
            set(self.list_options.keys()) - VALID_KEYSERVER_OPTIONS
            )
        if invalid_keyserver_options:
            raise ArgumentError(
                u'--list-options', u'Invalid list options: {0}'.format(
                u', '.join(list(map(repr, invalid_keyserver_options)))))
