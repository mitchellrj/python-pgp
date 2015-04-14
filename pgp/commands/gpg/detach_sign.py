from pgp.commands.gpg.sign import Command as SignCommand


class Command(SignCommand):

    def output(self, message, filename):
        output_filename = self.formatter.make_output_filename(filename)
        signature = message.signatures[0]
        self.io_helper.write_output(
            self.formatter.format_signature(signature),
            output_filename=output_filename
            )
