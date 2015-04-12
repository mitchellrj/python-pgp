from argparse import ArgumentError
import importlib
import inspect
import os
import sys

from pgp import NAME
from pgp.commands.gpg.algorithm_helper import AlgorithmHelper
from pgp.commands.gpg.arguments import make_argparser
from pgp.commands.gpg.formatter import Formatter
from pgp.commands.gpg.io_helper import IOHelper
from pgp.commands.gpg.keyring_helper import KeyringHelper
from pgp.commands.gpg.keyserver_helper import KeyServerHelper
from pgp.commands.gpg.multifile import MultifileCommand
from pgp.commands.gpg.trustdb_helper import TrustDBHelper


def make_it_so(cls, **params):
    argspec = inspect.getargspec(cls.__init__)
    args = []
    kwargs = {}
    if argspec.varargs:
        args = params['args']
    if argspec.keywords:
        kwargs = params
    else:
        for k, v in params.items():
            if k in argspec.args:
                kwargs[k] = v
    return cls(*args, **kwargs)


def main(argv=None,
         environ=None,
         prog=None,
         exit=sys.exit,  # @ReservedAssignment
         stdin=sys.stdin,
         stdout=sys.stdout,
         stderr=sys.stderr,
         formatter_class=Formatter,
         io_helper_class=IOHelper,
         algorithm_helper_class=AlgorithmHelper,
         trustdb_helper_class=TrustDBHelper,
         keyring_helper_class=KeyringHelper,
         keyserver_helper_class=KeyServerHelper,
         argparser_factory=make_argparser,
         ):
    if argv is None:
        if prog is None:
            prog = sys.argv[0]
        argv = sys.argv[1:]
    if environ is None:
        environ = os.environ
    if prog is None:
        prog = NAME

    if hasattr(stdin, 'encoding'):
        default_arg_encoding = stdin.encoding
    else:
        default_arg_encoding = sys.getdefaultencoding()

    argparser = argparser_factory(
        prog=prog, default_arg_encoding=default_arg_encoding, exit=exit,
        stdout=stdout, stderr=stderr)
    args = argparser.parse_args(*argv)
    commands = args.command
    if not commands:
        # TODO: make some kind of assumption
        argparser.error(u'No command specified.')
    if len(commands) > 1:
        argparser.error(u'Cannot specify more than one command.')

    if args.keyring and '/' in args.keyring:
        args.keyring = os.path.join(args.homedir, args.keyring)

    # TODO: dry_run
    # TODO: list_only

    params = vars(args)
    algorithm_helper = make_it_so(algorithm_helper_class, **params)
    params['algorithm_helper'] = algorithm_helper
    formatter = make_it_so(formatter_class, **params)
    params['formatter'] = formatter
    io_helper = make_it_so(io_helper_class, stdin=stdin, stdout=stdout,
                           stderr=stderr, exit=exit, **params)
    params['io_helper'] = io_helper
    keyserver_helper = make_it_so(keyserver_helper_class, **params)
    params['keyserver_helper'] = keyserver_helper
    keyring_helper = make_it_so(keyring_helper_class, **params)
    params['keyring_helper'] = keyring_helper
    trustdb_helper = make_it_so(trustdb_helper_class, **params)
    params['trustdb_helper'] = trustdb_helper

    command_mod = importlib.import_module('.{0}'.format(commands[0]),
                                          __package__.rsplit('.', 1)[0])
    try:
        command = make_it_so(command_mod.Command, **params)
    except ArgumentError as e:
        argparser.error(str(e))

    if args.multifile:
        if commands[0] not in ('verify', 'decrypt', 'encrypt'):
            argparser.error(u'Cannot combine --multifile with this command.')
        command = MultifileCommand(command)

    exit_code = command.run(*args.args)
    return exit(exit_code)
