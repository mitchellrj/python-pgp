from argparse import ArgumentError
import importlib
import inspect
import os
import sys

from pgp import NAME
from pgp.commands.gpg import combinations
from pgp.commands.gpg import exceptions
from pgp.commands.gpg.algorithm_helper import AlgorithmHelper
from pgp.commands.gpg.arguments import Commands
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


COMMAND_COMBINATIONS = {
    set([Commands.Encrypt, Commands.Symmetric, Commands.Sign]):
        combinations.EncryptSymmetricAndSign,
    set([Commands.Encrypt, Commands.Sign]):
        combinations.EncryptAndSign,
    set([Commands.Symmetric, Commands.Sign]):
        combinations.SymmetricAndSign,
    set([Commands.Fingerprint, Commands.CheckSigs]):
        combinations.FingerprintCheckSigs,
    set([Commands.Fingerprint, Commands.ListSigs]):
        combinations.FingerprintListSigs,
    }


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
    params = vars(args)

    # TODO: dry_run
    # TODO: list_only

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

    command_options = args.command
    params['show_fingerprints'] = 0

    if not command_options:
        # TODO: make some kind of assumption
        argparser.error(u'No command specified.')

    for command_option in command_options:
        if command_option == Commands.Fingerprint:
            params['show_fingerprints'] += 1

    if len(command_options) > 1:
        combination_key = set(command_options)
        if combination_key not in COMMAND_COMBINATIONS:
            argparser.error(u'Cannot specify more than one command.')
        command_class = COMMAND_COMBINATIONS[combination_key]
    else:
        command_mod = importlib.import_module(
            '.{0}'.format(command_options[0]),
            __package__.rsplit('.', 1)[0])
        command_class = command_mod.Command

    try:
        command = make_it_so(command_class, **params)
    except ArgumentError as e:
        argparser.error(str(e))

    if args.multifile:
        if getattr(command, 'multifile', False):
            argparser.error(u'Cannot combine --multifile with this command.')
        command = MultifileCommand(command)

    if args.keyring and '/' in args.keyring:
        args.keyring = os.path.join(args.homedir, args.keyring)

    exit_code = 0
    try:
        command.run(*args.args)
    except exceptions.FatalException as e:
        exit_code = e.exit_code
    return exit(exit_code)
