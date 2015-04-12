try:
    from collections import UserString  # @UndefinedVariable
except ImportError:
    UserString = unicode  # @UndefinedVariable


class FormattedString(UserString):

    forced_encoding = None

    def __init__(self, *args, **kwargs):
        self.forced_encoding = kwargs.pop('force_encoding', None)
        UserString.__init__(self, *args, **kwargs)

    def encode(self, encoding=None, errors=None):
        if self.forced_encoding is not None:
            encoding = self.forced_encoding
        return UserString.encode(self, encoding=encoding, errors=errors)


class Formatter(object):
    """Formats strings or objects. Functions """

    def __init__(self, armor_output, armor_input, keyid_format, batch,
                 with_colons, fixed_list_mode, comments, emit_version,
                 not_dash_escaped, with_key_data, fast_list_mode,
                 no_literal):
        self.armor_output = armor_output
        self.armor_input = armor_input
        self.keyid_format = keyid_format
        self.batch = batch
        self.with_colons = with_colons
        self.fixed_list_mode = fixed_list_mode
        self.with_key_data = with_key_data
        self.fast_list_mode = fast_list_mode

    def format_key(self, key):
        fields = key
        if self.fixed_list_mode:
            pass
        if self.with_fingerprint:
            pass
        if self.with_colons:
            FormattedString(u':'.join(fields), force_encoding='utf-8')
