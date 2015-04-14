import re

import chardet

from pgp import message


class MessageCommand(object):

    def __init__(self, io_helper, message_filename, set_filesize,
                 escape_from_lines, for_your_eyes_only):
        self.io_helper = io_helper
        if for_your_eyes_only:
            message_filename = u'_CONSOLE'
        self.message_filename = message_filename
        # TODO: set_filesize
        self.set_filesize = set_filesize
        self.escape_from_lines = escape_from_lines

    def file_to_literal_message(self, filename, binary=True, encoding=None):
        timestamp = self.io_helper.get_timestamp(filename)
        if filename is None:
            file_ = self.io_helper.open_stdin()
        else:
            file_ = self.io_helper.open_file(filename)
        if self.message_filename:
            filename = self.message_filename
        if binary:
            msg = message.BinaryMessage(file_.read(), filename, timestamp)
        else:
            data = file_.read()
            if encoding:
                data = data.decode(encoding)
            else:
                encoding = chardet.detect(data).get('encoding', 'utf8')
                data = data.decode()

            if self.escape_from_lines:
                data = re.sub(r'^From ', u'- From ', data)
            msg = message.TextMessage(data, filename, timestamp)
        return msg

    def run(self, filename=None):
        msg = self.file_to_literal_message(filename)
        msg = self.process_message(msg)
        msg = self.postprocess_message(msg)
        self.output(msg, filename)

    def output(self, message, filename):
        output_filename = self.formatter.make_output_filename(filename)
        self.io_helper.write_output(
            self.formatter.format_message(message),
            output_filename=output_filename
            )
