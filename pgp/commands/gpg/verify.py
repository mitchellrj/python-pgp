import re


VALID_VERIFY_OPTIONS = set([
    u'show-photos',
    u'show-policy-urls',
    u'show-notations',
    u'show-std-notations',
    u'show-user-notations',
    u'show-keyserver-urls',
    u'show-uid-validity',
    u'show-unusable-uids',
    u'show-primary-uid-only',
    u'pka-lookups',
    u'pka-trust-increase',
    ])


class Command(object):

    multifile = True

    def __init__(self, verify_options):
        self.verify_options = dict([
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
                in verify_options
            ]])
        invalid_verify_options = (
            set(self.verify_options.keys()) - VALID_VERIFY_OPTIONS
            )
        if invalid_verify_options:
            raise ValueError(u'Invalid verify options: {0}'.format(
                u', '.join(list(map(repr, invalid_verify_options)))))
