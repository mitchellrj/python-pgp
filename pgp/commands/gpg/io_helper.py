import datetime
from io import BytesIO
import os
import re
import shlex
import subprocess
import sys
import tempfile

from six import text_type

from pgp.commands.gpg.exceptions import FatalException


class IOHelper(object):

    def __init__(self, stdin, stdout, stderr, output, max_output, status_fd,
                 display_charset, verbosity, quiet, no_tty, yes, photo_viewer,
                 exec_path, ask_cert_level, default_cert_level,
                 default_recipient, default_recipient_self,
                 no_default_recipent, use_agent, exit_on_status_write_error,
                 exit, no_greeting, no_permission_warning, local_user,
                 interactive, debug_level, progress_filter,
                 status_file, logger_fd, logger_file, attribute_fd,
                 attribute_file, passphrase_repeat, passphrase_fd,
                 passphrase_file, passphrase, command_fd, command_file,
                 ask_sig_expire, default_sig_expire, ask_cert_expire,
                 default_cert_expire, enable_special_filenames
                 ):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        if output == u'-':
            # Just treat as stdout
            output = None
        self.output_file = output
        self.max_output = max_output
        self.status_fd = status_fd
        self.status_file = status_file
        self.display_charset = display_charset
        self.verbosity = verbosity
        self.quiet = quiet
        self.no_tty = no_tty
        # Can be True, False or None
        self.yes = yes
        self.photo_viewer = photo_viewer
        self.exec_path = exec_path
        self.ask_cert_level = ask_cert_level
        self.default_cert_level = default_cert_level
        self.default_recipient = default_recipient
        self.default_recipient_self = default_recipient_self
        self.no_default_recipient = no_default_recipent
        self.local_user = local_user
        self.use_agent = use_agent
        self.exit_on_status_write_error = exit_on_status_write_error
        self.exit = exit
        self.no_permission_warning = no_permission_warning
        self.interactive = interactive
        self.debug_level = debug_level
        self.progress_filter = progress_filter
        self.logger_fd = logger_fd
        self.logger_file = logger_file
        self.attribute_fd = attribute_fd
        self.attribute_file = attribute_file
        self.passphrase_repeat = passphrase_repeat
        self.passphrase_fd = passphrase_fd
        self.passphrase_file = passphrase_file
        self.passphrase = passphrase
        self.command_fd = command_fd
        self.command_file = command_file
        self.ask_sig_expire = ask_sig_expire
        self.default_sig_expire = default_sig_expire
        self.ask_cert_expire = ask_cert_expire
        self.default_cert_expire = default_cert_expire
        self.enable_special_filenames = enable_special_filenames

        if not no_greeting:
            print('Welcome!', file=self.stdout)

    def open_filename(self, filename, mode='r'):
        if self.enable_special_filenames:
            match = re.match(r'^-&([0-9]+)$', filename)
            if match:
                return os.fdopen(match.groups(1), mode)
        return open(filename, mode)

    def permissions_warning(self, filename, mode, expected_mode):
        if self.no_permission_warning:
            return

    def overwrite_file(self):
        if self.interactive:
            pass

    def error(self):
        pass

    def warning(self):
        pass

    def info(self):
        pass

    def debug(self):
        pass

    def read_pgp_content(self):
        pass

    def get_passphrase(self):
        pass

    def get_timestamp(self, filename):
        if filename is None:
            timestamp = datetime.datetime.now()
            if self.self.faked_system_time:
                if u'T' in self.faked_system_time:
                    timestamp = datetime.datetime.strptime(
                        '%Y%m%dT%H%M%s')
                else:
                    timestamp = datetime.datetime.fromtimestamp(
                        self.faked_system_time)
        else:
            timestamp = datetime.datetime.fromtimestamp(
                os.path.getmtime(filename))
        return timestamp

    def get_current_time(self):
        if self.faked_system_time:
            if 'T' in self.faked_system_time:
                return datetime.datetime.strptime(
                    self.faked_system_time,
                    '%Y%m%dT%H%M%S'
                    )
            return datetime.datetime.fromtimestamp(self.faked_system_time)
        return datetime.datetime.now()

    def get_cert_level(self):
        if self.ask_cert_level:
            pass
        return self.default_cert_level

    def get_default_recipient(self):
        if self.local_user:
            return self.local_user
        if self.no_default_recipient:
            return None
        if self.default_recipient_self:
            return 'self'
        if self.default_recipient:
            return self.default_recipient
        return None

    def view_photo(self, photo_data, key_id, long_key_id, fingerprint,
                   extension, mime_type, validity, full_validity,
                   user_id_base32):
        if not hasattr(photo_data, 'read'):
            photo_data = BytesIO(photo_data)
        unlink_after = True
        use_file = True
        filename = None
        stdin = None
        env = None
        command = self.photo_viewer.replace(
            u'%k', key_id).replace(
            u'%K', long_key_id).replace(
            u'%f', fingerprint).replace(
            u'%t', extension).replace(
            u'%T', mime_type).replace(
            u'%v', validity).replace(
            u'%V', full_validity).replace(
            u'%U', user_id_base32).replace(
            u'%%', u'%')
        if u'%I' in command:
            unlink_after = False
        elif u'%i' not in command:
            use_file = False
        else:
            stdin = photo_data

        if use_file:
            fd, filename = tempfile.mkstemp(extension)
            with os.fdopen(fd) as fh:
                fh.write(photo_data)

            command = command.replace(u'%i', filename)
            command = command.replace(u'%I', filename)

        if self.exec_path:
            env = {}
            env.update(os.environ)
            env['PATH'] = self.exec_path

        # Execute command
        with subprocess.Popen(
                shlex.split(command),
                bufsize=4096,
                stdin=stdin,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env
                ) as proc:
            proc.wait()

        if unlink_after and filename:
            os.unlink(filename)

    def write_status(self, status):
        stdout = self.stdout
        close = False
        try:
            if self.status_fd:
                stdout = os.fdopen(self.status_fd, 'wb')
                close = True
            if self.status_file:
                stdout = self.open_filename(self.status_file, 'wb')
                close = True
            stdout.write(status.encode(self.display_charset))
        except (IOError, OSError, TypeError, ValueError):
            if self.exit_on_status_write_error:
                self.exit(1)
        finally:
            if close:
                stdout.close()

    def write_log(self, logmessage):
        stdout = self.stdout
        close = False
        try:
            if self.status_fd:
                stdout = os.fdopen(self.logger_fd, 'wb')
                close = True
            if self.status_file:
                stdout = self.open_filename(self.logger_file, 'wb')
                close = True
            stdout.write(logmessage.encode(self.display_charset))
        except (IOError, OSError, TypeError, ValueError):
            if self.exit_on_status_write_error:
                self.exit(1)
        finally:
            if close:
                stdout.close()

    def write_attribute(self, attribute):
        stdout = self.stdout
        close = False
        try:
            if self.status_fd:
                stdout = os.fdopen(self.attribute_fd, 'wb')
                close = True
            if self.status_file:
                stdout = self.open_filename(self.attribute_file, 'wb')
                close = True
            stdout.write(attribute.encode(self.display_charset))
        except (IOError, OSError, TypeError, ValueError):
            if self.exit_on_status_write_error:
                self.exit(1)
        finally:
            if close:
                stdout.close()

    def write_output(self, output, stdout=None, output_filename=None):
        if self.max_output:
            limit = self.max_output
        if output_filename is None:
            output_filename = self.output_file
        if output_filename:
            stdout = self.open_file(output_filename, 'wb')
        if stdout is None:
            stdout = self.stdout
        written_bytes = 1
        total_bytes = 0
        while written_bytes:
            written_bytes = stdout.write(output.read(1024))
            total_bytes += written_bytes
            if limit and total_bytes > limit:
                raise FatalException(1)
        return total_bytes


    def open_file(self, filename, mode='rb'):
        if isinstance(filename, text_type):
            filename = filename.encode(sys.getfilesystemencoding())
        return open(filename, mode)

    def open_stdin(self):
        return self.stdin
