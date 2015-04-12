import re


VALID_IMPORT_OPTIONS = set([
    u'import-local-sigs',
    u'repair-pks-subkey-bug',
    u'merge-only',
    u'import-clean',
    u'import-minimal',
    ])


class Command(object):

    def __init__(self, import_options):
        self.import_options = set([
            sub_option
            for sub_option
            in [
                re.split(r'[, ]', option)
                for option
                in import_options
            ]])
        invalid_import_options = self.import_options - VALID_IMPORT_OPTIONS
        if invalid_import_options:
            raise ValueError(u'Invalid import options: {0}'.format(
                u', '.join(list(map(repr, invalid_import_options)))))
