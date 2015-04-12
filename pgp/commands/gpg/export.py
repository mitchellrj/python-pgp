import re


VALID_EXPORT_OPTIONS = set([
    u'export-local-sigs',
    u'export-attributes',
    u'export-sensitive-revkeys',
    u'export-reset-subkey-passwd',
    u'export-clean',
    u'export-minimal',
    ])


class Command(object):

    def __init__(self, export_options):
        self.export_options = set([
            sub_option
            for sub_option
            in [
                re.split(r'[, ]', option)
                for option
                in export_options
            ]])
        invalid_export_options = self.export_options - VALID_EXPORT_OPTIONS
        if invalid_export_options:
            raise ValueError(u'Invalid export options: {0}'.format(
                u', '.join(list(map(repr, invalid_export_options)))))
