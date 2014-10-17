import argparse
import os
import sys


VERSION = 'x.x.x'


class Compliance:

    GnuPG = 1
    OpenPGP = 2
    RFC4880 = 3
    RFC2440 = 4
    RFC1991 = 5
    PGP2 = 6
    PGP6 = 7
    PGP7 = 8
    PGP8 = 9


class Commands:

    Sign = 1
    Clearsign = 2
    DetachSign = 3
    Encrypt = 4
    Symmetric = 5
    Store = 6
    Encrypt = 7
    Decrypt = 8
    Verify = 9
    VerifyMulti = 10
    EncryptMulti = 11
    DecryptMulti = 12
    ListKeys = 13
    ListSecretKeys = 14
    ListSigs = 15
    CheckSigs = 16
    Fingerprint = 17
    ListPackets = 18
    CardEdit = 19
    CardStatus = 20
    ChangePin = 21
    DeleteKey = 22
    DeleteSecretKey = 23
    DeleteSecretAndPublicKey = 24
    Export = 25
    SendKeys = 26
    ExportSecretKeys = 27
    ExportSecretSubkeys = 28
    Import = 29
    RecvKeys = 30
    RefreshKeys = 31
    SearchKeys = 32
    FetchKeys = 33
    UpdateTrustDB = 34
    CheckTrustDB = 35
    ExportOwnerTrust = 36
    ImportOwnerTrust = 37
    RebuildKeyDBCaches = 38
    PrintMD = 39
    PrintMDs = 40
    GenRandom = 41
    GenPrime = 42
    EnArmor = 43
    DeArmor = 44
    GenKey = 45
    GenRevoke = 46
    DesigRevoke = 47
    EditKey = 48
    SignKey = 49
    LocalSignKey = 50


_export_secret_help = (
    'Same as --export, but exports the secret keys  instead. This is '
    'normally not very useful and a security risk. The second form of the '
    'command has the special property to render the secret part of the '
    'primary key useless; this is a GNU extension to OpenPGP and other '
    'implementations can not be expected to successfully import such a key. '
    'See the option --simple-sk-checksum if you want to import such an '
    'exported key with an older OpenPGP implementation.'
    )


class TextmodeAction(argparse.Action):

    def __init__(self, *args, **kwargs):
        self.tdest = kwargs.pop('tdest', kwargs['dest'])
        super(TextmodeAction, self).__init__(*args, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, self.const)
        if option_string == '-t':
            setattr(namespace, self.tdest, self.const)


argparser = argparse.ArgumentParser(
    usage="%(prog)s [--homedir dir] [--options file] [options] command [args]",
    description="OpenPGP encryption and signing tool",
    add_help=False
    )
argparser.add_argument(
    '--homedir', metavar='dir', help='Set the name of the home directory to '
    '[dir]. If this option is not used, the home directory defaults to '
    '\'~{sep}.gnupg\'.'.format(sep=os.path.sep)
    )
argparser.add_argument(
    '--options', metavar='file', help='Read options from [file] and do not '
    'try to read them from the default options in the homedir.'
    )
# options
options = argparser.add_argument_group('Options')
options.add_argument(
    '--default-key', metavar='name', dest='default_key',
    help='Use name as the default key to sign with. If this option is not '
    'used, the default key is the first key found in the secret keyring. '
    'Note that -u or --local-user overrides this option.'
    )
options.add_argument(
    '--default-recipient', metavar='name', dest='default_recipient',
    help='Use name as default recipient if option --recipient is not used '
    'and don\'t ask if this is a valid one. name must be non-empty.'
    )
options.add_argument(
    '--default-recipient-self', action='store_true',
    dest='default_recipient_self',
    help='Use the default key as default recipient if option --recipient is '
    'not used and don\'t ask if this is a valid one. The default key is the '
    'first one from the secret keyring or the one set with --default-key.'
    )
options.add_argument(
    '--no-default-recipient', action='store_true', dest='no_default_recipent',
    help='Reset --default-recipient and --default-recipient-self.'
    )
options.add_argument(
    '--verbose, -v', action='count', dest='verbosity',
    help='Give more information during processing. If used twice, the input '
    'data is listed in detail.'
    )
options.add_argument(
    '--no-verbose', action='store_const', dest='verbosity', const=0,
    help='Reset verbosity level to 0.'
    )
options.add_argument(
    '--quiet, -q', action='store_true', dest='quiet',
    help='Try to be as quiet as possible.'
    )
options.add_argument(
    '--batch', action='store_true', dest='batch',
    help='Use batch mode. Never ask, do not allow interactive commands.'
    )
options.add_argument(
    '--no-batch', action='store_false', dest='batch',
    help='Disables batch mode.'
    )
options.add_argument(
    '--no-tty', action='store_true', dest='no_tty',
    help='Make sure that the TTY (terminal) is never used for any output. '
    'This option is needed in some cases because %(prog)s sometimes prints '
    'warnings to the TTY even if --batch is used.'
    )
options.add_argument(
    '--yes', action='store_true', dest='yes',
    help='Assume "yes" on most questions.'
    )
options.add_argument(
    '--no', action='store_false', dest='yes',
    help='Assume "no" on most questions.'
    )
options.add_argument(
    '--list-options', metavar='opt', action='append', dest='list_options',
    help='This is a space or comma delimited string that gives options used '
    'when listing keys and signatures (that is, --list-keys, --list-sigs, '
    '--list-public-keys, --list-secret-keys, and the --edit-key functions). '
    'Options can be prepended with a \'no-\' (after the two dashes) to give '
    'the opposite meaning.'
    )
options.add_argument(
    '--verify-options', metavar='opt', action='append', dest='verify_options',
    help='This is a space or comma delimited string that gives options used '
    'when verifying signatures. Options can be prepended with a \'no-\' to '
    'give the opposite meaning.'
    )
options.add_argument(
    '--enable-dsa2', action='store_true', dest='enable_dsa2',
    help='Enable hash truncation for all DSA keys even for old DSA Keys up '
    'to 1024 bit. This is also the default with --openpgp.'
    )
options.add_argument(
    '--disable-dsa2', action='store_false', dest='enable_dsa2',
    help='Disable hash truncation for all DSA keys even for old DSA Keys up '
    'to 1024 bit.'
    )
options.add_argument(
    '--photo-viewer', metavar='command', dest='photo_viewer',
    help='This is the command line that should be run to view a photo ID. '
    '"%%i" will be expanded to a filename containing the photo. "%%I" does '
    'the same, except the file will not be deleted once the viewer exits. '
    'Other flags are "%%k" for the key ID, "%%K" for the long key ID, "%%f" '
    'for the key fingerprint, "%%t" for the extension of the image type '
    '(e.g. "jpg"), "%%T" for the MIME type of the image (e.g. "image/jpeg"), '
    '"%%v" for the single-character calculated validity of the image being '
    'viewed (e.g. "f"), "%%V" for the calculated validity as a string (e.g. '
    '"full"), "%%U" for a base32 encoded hash of the user ID, and "%%%%" for '
    'an actual percent sign. If neither %%i or %%I are present, then the '
    'photo will be supplied to the viewer on standard input.'
    )
options.add_argument(
    '--exec-path', metavar='path', dest='exec_path',
    help='Sets a list of directories to search for photo viewers. If not '
    'provided photo viewers use the $PATH environment variable.'
    )
options.add_argument(
    '--keyring', metavar='file', action='append', dest='keyrings',
    help=('Add file to the current list of keyrings. If file begins with a '
    'tilde and a slash, these are replaced by the $HOME directory. If the '
    'filename does  not contain a slash, it is assumed to be in the %(prog)s '
    'home directory ("~{sep}.gnupg" if --homedir or $GNUPGHOME is not used).'
    '\n\n'
    'Note that this adds a keyring to the current list. If the intent is to '
    'use the specified keyring alone, use --keyring along with '
    '--no-default-keyring.').format(sep=os.path.sep)
    )
options.add_argument(
    '--secret-keyring', metavar='file', action='append',
    dest='secret_keyrings',
    help='Same as --keyring but for secret keyrings.'
    )
options.add_argument(
    '--primary-keyring', metavar='file', dest='primary_keyring',
    help='Designate file a  the primary public keyring. This means that '
    'newly imported keys (via --import or keyserver --recv-from) will go to '
    'this keyring.'
    )
options.add_argument(
    '--trustdb-name', metavar='file', dest='trustdb_file',
    help=('Use file instead of the default trustdb. If file begins with a'
    'tilde and a slash, these are replaced by the $HOME directory. If the '
    'filename does  not contain a slash, it is assumed to be in the %(prog)s '
    'home directory (\'~{sep}.gnupg\' if --homedir or $GNUPGHOME is not '
    'used).').format(sep=os.path.sep)
    )
options.add_argument(
    '--compress-level', metavar='n', type=int, dest='z_compress_level',
    help='Set compression level to n for the ZIP and ZLIB  compression '
    'algorithms. The default is to use the default compression level of zlib '
    '(normally 6). A value of 0  for  n  disables compression.'
    )
options.add_argument(
    '--bzip2-compress-level', metavar='n', type=int, dest='bz_compress_level',
    help='Set the compression  level for the BZIP2 compression algorithm '
    '(defaulting to 6). This is a different option from --compress-level '
    'since BZIP2  uses  a  significant amount of memory for each additional '
    'compression level.'
    )
options.add_argument(
    '-z', metavar='n', type=int, dest='compress_level',
    help='-z sets both BZIP2 and ZLIB / ZIP compression levels. A value of 0 '
    'for n disables compression.'
    )
options.add_argument(
    '--ask-cert-level', action='store_true', dest='ask_cert_level',
    default=False,
    help='When making a key signature, prompt for a certification level. If '
    'this option is not specified, the certification level used is set via '
    '--default-cert-level. See --default-cert-level for information on the '
    'specific levels and how they are used. This option defaults to no.'
    )
options.add_argument(
    '--no-ask-cert-level', action='store_false', dest='ask_cert_level',
    default=False,
    help='Disables --ask-cert-level.'
    )
options.add_argument(
    '--default-cert-level', metavar='n', type=int, dest='default_cert_level',
    default=0,
    help='The default to use for the check level when signing a key.\n\n'
    '0 means you make no particular claim as to how carefully you verified '
    'the key.\n\n'
    '1 means you believe the key is owned by the person who claims to own it '
    'but you could not, or did not verify the key at all. This is useful for '
    'a "persona" verification, where you sign the key of a pseudonymous user.'
    '\n\n'
    '2 means you did casual verification of the key. For example, this could '
    'mean that you verified the key fingerprint and checked the user ID on '
    'the key against a photo ID.\n\n'
    '3 means you did extensive verification of the key. For example, this '
    'could mean that you verified the key fingerprint with the owner of the '
    'key in person, and that you checked, by means of a hard to forge '
    'document with a photo ID (such as a passport) that the name of the key '
    'owner matches the name in the user ID on the key, and finally that you '
    'verified (by exchange of email) that the email address on the key '
    'belongs to the key owner.\n\n'
    'Note that the examples given above for levels 2 and 3 are just that: '
    'examples. In the end, it is up to you to decide just what "casual" and '
    '"extensive" mean to you.\n\n'
    'This option defaults to 0 (no particular claim).'
    )
options.add_argument(
    '--min-cert-level', metavar='n', type=int, dest='min_cert_level',
    default=2,
    help='When building the trust database, treat any signatures with a'
    'certification level below this as invalid. Defaults to 2, which '
    'disregards level 1 signatures. Note that level 0 "no particular claim" '
    'signatures are always accepted.'
    )
options.add_argument(
    '--trusted-key', metavar='long key ID', action='append',
    dest='trusted_keys',
    help='Assume that the specified key (which must be given as a full 8 '
    'byte key ID) is as trustworthy as one of your own secret keys. This '
    'option is useful if you don\'t want to keep your secret keys (or one of '
    'them) online but still want to be able to check the validity of a given '
    'recipient or signatory\'s key.'
    )
options.add_argument(
    '--trust-model', choices=['pgp', 'classic', 'direct', 'always', 'auto'],
    action='store', dest='trust_model',
    help='Set what trust model %(prog)s should follow. The models are:\n\n'
    'pgp: This is the Web of Trust combined with trust signatures as used in '
    'PGP 5.x and later. This is the default trust model when creating a new '
    'trust database.\n\n'
    'classic: This is the standard Web of Trust as used in PGP 2.x and '
    'earlier.\n\n'
    'direct: Key validity is set directly by the user and not calculated via '
    'the Web of Trust.\n\n'
    'always: Skip key validation and assume that used keys are always fully '
    'trusted. You generally won\'t use this unless you are using some '
    'external validation scheme. This option also suppresses the '
    '"[uncertain]" tag printed with signature checks when there is no '
    'evidence that the user ID is bound to the key. Note that this trust '
    'model still does not allow the use of expired, revoked, or disabled '
    'keys.\n\n'
    'auto: Select the trust model depending on whatever the internal trust '
    'database says. This is the default model if such a database already '
    'exists.'
    )
options.add_argument(
    '--auto-key-locate', action='append', choices=['cert', 'pka', 'ldap',
    'keyserver', 'keyserver-URL', 'local', 'nodefault', 'clear'],
    dest='auto_key_locate',
    help='%(prog)s can automatically locate and retrieve keys as needed '
    'using this option. This happens when encrypting to an email address (in '
    'the "user@example.com" form), and there are no user@example.com keys on '
    'the local keyring. This option takes any number of the following '
    'mechanisms, in the order they are to be tried:\n\n'
    'cert: Locate a key using DNS CERT, as specified in RFC4398.\n\n'
    'pka: Locate a key using DNS PKA.\n\n'
    'ldap: Using DNS Service Discovery, check the domain in question for any '
    'LDAP keyservers to use. If this fails, attempt to locate the key using '
    'the PGP Universal method of checking "ldap://keys.(thedomain)".\n\n'
    'keyserver: Locate a key using whatever keyserver is defined using the '
    '--keyserver option.\n\n'
    'keyserver-URL: In addition, a keyserver URL as used in the --keyserver '
    'option may be used here to query that particular keyserver.\n\n'
    'local: Locate the key using the local keyrings. This mechanism allows '
    'to select the order a local key lookup is done. Thus using '
    '"--auto-key-locate local" is identical to --no-auto-key-locate.\n\n'
    'nodefault: This flag disables the standard local key lookup, done '
    'before any of the mechanisms defined by the --auto-key-locate are '
    'tried. The position of this mechanism in the list does not matter. It '
    'is not required if local is also used.\n\n'
    'clear: Clear all defined mechanisms. This is useful to override '
    'mechanisms given in a config file.'
    )
options.add_argument(
    '--no-auto-key-locate', action='store_const', const=[],
    dest='auto_key_locate',
    help='Equivalent to "--auto-key-locate local".'
    )
options.add_argument(
    '--keyid-format', choices=['short', '0xshort', 'long', '0xlong'],
    dest='keyid_format',
    help='Select how to display key IDs. "short" is the traditional '
    '8-character key ID. "long" is the more accurate (but less convenient) '
    '16-character key ID. Add an "0x" to either to include an "0x" at the '
    'beginning of the key ID, as in 0x99242560. Note that this option is '
    'ignored if the option --with-colons is used.'
    )
options.add_argument(
    '--keyserver', metavar='name', action='append', dest='keyserver',
    help='Use name as your keyserver. This is the server that --recv-keys, '
    '--send-keys, and --search-keys will communicate with to receive keys '
    'from, send keys to, and search for keys on. The format of the name is a '
    'URI: `scheme:[//]keyservername[:port]\' The scheme is the type of '
    'keyserver: "hkp" for the HTTP (or compatible) keyservers, "ldap" for '
    'the LDAP keyservers, or "mailto" for the Graff email keyserver. Note '
    'that your particular installation of %(prog)s may have other keyserver '
    'types available as well. Keyserver schemes are case-insensitive. After '
    'the keyserver name, optional keyserver configuration options may be '
    'provided. These are the same as the global --keyserver-options from '
    'below, but apply only to this particular keyserver.\n\n'
    'Most keyservers synchronize with each other, so there is  generally no '
    'need to send keys to more than one server. The keyserver '
    'hkp://keys.gnupg.net uses round robin DNS to give a different keyserver '
    'each time you use it.'
    )
options.add_argument(
    '--keyserver-options', metavar='name=value1', nargs='+', action='append',
    dest='keyserver_options',
    help='This is a space or comma delimited string that gives options for '
    'the keyserver. Options can be prefixed with a `no-\' to give the '
    'opposite meaning. Valid import-options or export-options may be used '
    'here as well to apply to importing (--recv-key) or exporting '
    '(--send-key) a key from a keyserver. While not all options are '
    'available for all keyserver types, some common options are:\n\n'
    'include-revoked: When searching for a key with --search-keys, include '
    'keys that are marked on the keyserver as revoked. Note that not all '
    'keyservers differentiate between revoked and unrevoked keys, and for '
    'such keyservers this option is meaningless. Note also that most '
    'keyservers do not have cryptographic verification of key revocations, '
    'and so turning this option off may result in skipping keys that are '
    'incorrectly marked as revoked.\n\n'
    'include-disabled: When searching for a key with --search-keys, include '
    'keys that are marked on the keyserver as disabled. Note that this '
    'option is not used with HKP keyservers.\n\n'
    'auto-key-retrieve: This option enables the automatic retrieving of keys '
    'from a keyserver when verifying signatures made by keys that are not on '
    'the local keyring.\n\n'
    'Note that this option makes a "web bug" like behavior possible. '
    'Keyserver operators can see which keys you request, so by sending you a '
    'message signed by a brand new key (which you naturally will not have on '
    'your local keyring), the operator can tell both your IP address and the '
    'time when you verified the signature.\n\n'
    'honor-keyserver-url: When using --refresh-keys, if the key in question '
    'has a preferred keyserver URL, then use that preferred keyserver to '
    'refresh the key from. In addition, if auto-key-retrieve is set, and the '
    'signature being verified has a preferred keyserver URL, then use that '
    'preferred key-server to fetch the key from. Defaults to yes.\n\n'
    'honor-pka-record: If auto-key-retrieve is set, and the signature being '
    'verified has a PKA record, then use the PKA information to fetch the '
    'key. Defaults to yes.\n\n'
    'include-subkeys: When receiving a key, include subkeys as potential '
    'targets. Note that this option is not used with HKP keyservers, as they '
    'do not support retrieving keys by subkey id.\n\n'
    'verbose: Tell the keyserver helper program to be more verbose. This '
    'option can be repeated multiple times to increase the verbosity level.'
    '\n\n'
    'timeout: Tell the keyserver helper program how long (in seconds) to try '
    'to perform a keyserver action before giving up. Note that performing '
    'multiple actions at the same time uses this timeout value per action. '
    'For example, when retrieving multiple keys via --recv-keys, the timeout '
    'applies separately to each key retrieval, and not to the --recv-keys '
    'command as a whole. Defaults to 30 seconds.\n\n'
    'http-proxy: Set the proxy to use for HTTP and HKP keyservers. This '
    'overrides the "http_proxy" environment variable, if any.\n\n'
    'max-cert-size: When retrieving a key via DNS CERT, only accept keys up '
    'to this size. Defaults to 16384 bytes.\n\n'
    'debug: Turn on debug output in the keyserver helper program. Note that '
    'the details of debug output depends on which keyserver helper program '
    'is being used, and in turn, on any libraries that the keyserver helper '
    'program uses internally (libcurl, openldap, etc).\n\n'
    'check-cert: Enable certificate checking if the keyserver presents one '
    '(for hkps or ldaps). Defaults to on.\n\n'
    'ca-cert-file: Provide a certificate store to override the system '
    'default. Only necessary if check-cert is enabled, and the keyserver is '
    'using a certificate that is not present in a system default certificate '
    'list.\n\nNote that depending on the SSL library that the keyserver '
    'helper is built with, this may actually be a directory or a file.'
    )
options.add_argument(
    '--completes-needed', metavar='n', type=int, default=1,
    dest='completes_needed',
    help='Number of completely trusted users to introduce a new key signer '
    '(defaults to 1).'
    )
options.add_argument(
    '--marginals-needed', metavar='n', type=int, default=3,
    dest='marginals_needed',
    help='Number of marginally trusted users to introduce a new key signer '
    '(defaults to 3)'
    )
options.add_argument(
    '--max-cert-depth', metavar='n', type=int, default=5,
    dest='max_cert_depth',
    help='Maximum depth of a certification chain (default is 5).'
    )
options.add_argument(
    '--simple-sk-checksum', action='store_true', default=False,
    dest='simple_sk_checksum',
    help='Secret keys are integrity protected by using a SHA-1 checksum. '
    'This method is part of the OpenPGP specification. Old applications '
    'don\'t understand this new format, so this option may be used to switch '
    'back to the old behaviour. Using this option bears a security risk. '
    'Note that using this option only takes effect when the secret key is '
    'encrypted - the simplest way to make this happen is to change the '
    'passphrase on the key (even changing it to the same value is '
    'acceptable).'
    )
options.add_argument(
    '--no-sig-cache', action='store_true', default=False, dest='no_sig_cache',
    help='Do not cache the verification status of key signatures. Caching '
    'gives a much better performance in key listings. However, if you '
    'suspect that your public keyring is not save against write '
    'modifications, you can use this option to disable the caching. It '
    'probably does not make sense to disable it because all kind of damage '
    'can be done if someone else has write access to your public keyring.'
    )
options.add_argument(
    '--no-sig-create-check', action='store_true', default=False,
    dest='no_sig_create_check',
    help='%(prog)s normally verifies each signature right after creation to '
    'protect against bugs and hardware malfunctions which could leak out '
    'bits from the secret key. This extra verification needs some time '
    '(about 115% for DSA keys), and so this option can be used to disable '
    'it. However, due to the fact that the signature creation needs manual '
    'interaction, this performance penalty does not matter in most settings.'
    )
options.add_argument(
    '--auto-check-trustdb', action='store_true', default=True,
    dest='auto_check_trustdb',
    help='If %(prog)s feels that its information about the Web of Trust has '
    'to be updated, it automatically  runs  the  --check-trustdb command '
    'internally.'
    )
options.add_argument(
    '--no-auto-check-trustdb', action='store_false', default=True,
    dest='auto_check_trustdb',
    help='If %(prog)s feels that its information about the Web of Trust has '
    'to be updated, it automatically  runs  the  --check-trustdb command '
    'internally. --no-auto-check-trustdb disables this option.'
    )
options.add_argument(
    '--use-agent', action='store_true', default=True,
    dest='use_agent',
    help='Try to use the GnuPG-Agent. With this option, %(prog)s first tries '
    'to connect to the agent before it asks for a passphrase.'
    )
options.add_argument(
    '--no-use-agent', action='store_false', default=True,
    dest='use_agent',
    help='Try to use the GnuPG-Agent. With this option, %(prog)s first tries '
    'to connect to the agent before it asks for a passphrase. '
    '--no-use-agent disables this option.'
    )
# options.add_argument(
#     '--gpg-agent-info'
#     )
options.add_argument(
    '--lock-once', action='store_const', const=1, default=2,
    dest='lock_count',
    help='Lock the databases the first time a lock is requested and do not '
    'release the lock until the process terminates.'
    )
options.add_argument(
    '--lock-multiple', action='store_const', const=2, default=2,
    dest='lock_count',
    help='Release the locks every time a lock is no longer needed. Use this '
    'to override a previous --lock-once from a config file.'
    )
options.add_argument(
    '--lock-never', action='store_const', const=0, default=2,
    dest='lock_count',
    help='Disable locking entirely. This option should be used only in very '
    'special environments, where it can be assured that only one process is '
    'accessing those files. A bootable floppy with a stand-alone encryption '
    'system will probably use this. Improper usage of this option may lead '
    'to data and key corruption.'
    )
options.add_argument(
    '--exit-on-status-write-error', action='store_true', default=False,
    dest='exit_on_status_write_error',
    help='This option will cause write errors on the status FD to '
    'immediately terminate the process. That should in fact be the default '
    'but it never worked this way and thus we need an option to enable this, '
    'so that the change won\'t break applications which close their end of a '
    'status FD connected pipe too early. Using this option along with '
    '--enable-progress-filter may be used to cleanly cancel long running '
    '%(prog)s operations.'
    )
# options.add_argument(
#     '--limit-card-insert-tries'
#     )
# options.add_argument(
#     '--no-random-seed-file'
#     )
options.add_argument(
    '--no-greeting', action='store_true', default=False, dest='no_greeting',
    help='Suppress the initial copyright message.'
    )
# options.add_argument(
#     '--no-secmem-warning'
#     )
options.add_argument(
    '--no-permission-warning', action='store_true', default=False,
    dest='no_permission_warning',
    help='Suppress the warning about unsafe file and home directory '
    '(--homedir) permissions. Note that the permission checks that %(prog)s '
    'performs are not intended to be authoritative, but rather they simply '
    'warn about certain common permission problems. Do not assume that the '
    'lack of a warning means that your system is secure.\n\n'
    'Note that the warning for unsafe --homedir permissions cannot be '
    'suppressed in the configuration file, as this would allow an attacker '
    'to place an unsafe configuration file in place, and use this file to '
    'suppress warnings about itself. The --homedir permissions warning may '
    'only be suppressed on the command line.'
    )
options.add_argument(
    '--no-mdc-warning', action='store_true', default=False,
    dest='no_mdc_warning',
    help='Suppress the warning about missing MDC integrity protection.'
    )
options.add_argument(
    '--require-secmem', action='store_true', default=False,
    dest='require_secmem',
    help='Refuse to run if %(prog)s cannot get secure memory. Defaults to no.'
    )
options.add_argument(
    '--no-require-secmem', action='store_false', default=False,
    dest='require_secmem',
    help='Allow %(prog)s to run even if it cannot get secure memory '
    '(default).'
    )
options.add_argument(
    '--require-cross-certification', action='store_true', default=True,
    dest='require_cross_certification',
    help='When verifying a signature made from a subkey, ensure that the '
    'cross certification "back signature" on the subkey is present and valid '
    '(default).'
    )
options.add_argument(
    '--no-require-cross-certification', action='store_false', default=True,
    dest='require_cross_certification',
    help='When verifying a signature made from a subkey, do not require that '
    'the cross certification "back signature" on the subkey is present and '
    'valid.'
    )
options.add_argument(
    '--expert', action='store_true', default=False, dest='expert',
    help='Allow the user to do certain nonsensical or "silly" things like '
    'signing an expired or revoked key, or certain potentially incompatible '
    'things like generating unusual key types. This also disables certain '
    'warning messages about potentially incompatible actions. As the name '
    'implies, this option is for experts only. If you don\'t fully '
    'understand the implications of what it allows you to do, leave this off.'
    )
options.add_argument(
    '--no-expert', action='store_false', default=False, dest='expert',
    help='Prevent the user from doing certain nonsensical or "silly" things '
    'like signing an expired or revoked key, or certain potentially '
    'incompatible things like generating unusual key types. This also '
    'enables certain warning messages about potentially incompatible '
    'actions (default).'
    )
key_options = options.add_argument_group('Key related options')
key_options.add_argument(
    '--recipient, -r', metavar='name', action='append', dest='recipients',
    help='Encrypt for user id "name". If this option or --hidden-recipient '
    'is not specified, %(prog)s asks for the user-id unless '
    '--default-recipient is given.'
    )
key_options.add_argument(
    '--hidden-recipient, -R', metavar='name', action='append',
    dest='hidden_recipients',
    help='Encrypt for user ID "name", but hide the key ID of this user\'s '
    'key. This option helps to hide the receiver of the message and is a '
    'limited countermeasure against traffic analysis. If this option or '
    '--recipient is not specified, %(prog)s asks for the user ID unless '
    '--default-recipient is given.'
    )
key_options.add_argument(
    '--encrypt-to', metavar='name', action='append', dest='encrypt_to',
    help='Same as --recipient but this one is intended for use in the '
    'options file and may be used with your own user-id as an '
    '"encrypt-to-self". These keys are only used when there are other '
    'recipients given either by use of --recipient or by the asked user id. '
    'No trust checking is performed for these user ids and even disabled '
    'keys can be used.'
    )
key_options.add_argument(
    '--hidden-encrypt-to', metavar='name', action='append',
    dest='hidden_encrypt_to',
    help='Same as --hidden-recipient but this one is intended for use in the '
    'options file and may be used with your own user-id as an '
    '"encrypt-to-self". These keys are only used when there are other '
    'recipients given either by use of --recipient or by the asked user id. '
    'No trust checking is performed for these user ids and even disabled '
    'keys can be used.'
    )
key_options.add_argument(
    '--no-encrypt-to', action='store_true', dest='no_encrypt_to',
    help='Disable the use of all --encrypt-to and --hidden-encrypt-to keys.'
    )
key_options.add_argument(
    '--group', metavar='name=value1', action='append', dest='groups',
    help='Sets up a named group, which is similar to aliases in email '
    'programs. Any time the group name is a recipient (-r or --recipient), '
    'it will be expanded to the values specified. Multiple groups with the '
    'same name are automatically merged into a single group.\n\n'
    'The values are key IDs or fingerprints, but any key description is '
    'accepted. Note that a value with spaces in it will be treated as two '
    'different values. Note also there is only one level of expansion --- '
    'you cannot make a group that points to another group. When used from '
    'the command line, it may be necessary to quote the argument to this '
    'option to prevent the shell from treating it as multiple arguments.'
    )
key_options.add_argument(
    '--ungroup', metavar='name', action='append', dest='ungroups',
    help='Remove a given entry from the --group list.'
    )
key_options.add_argument(
    '--no-groups', action='store_true', default=False, dest='no_groups',
    help='Remove all entries from the --group list.'
    )
key_options.add_argument(
    '--local-user, -u', metavar='name', dest='local_user',
    help='Use "name" as the key to sign with. Note that this option '
    'overrides --default-key.'
    )
key_options.add_argument(
    '--try-all-secrets', action='store_true', default=False,
    dest='try_all_secrets',
    help='Don\'t look at the key ID as stored in the message but try all '
    'secret keys in turn to find the right decryption key. This option '
    'forces the behaviour as used by anonymous recipients (created by using '
    '--throw-keyids or --hidden-recipient) and might come handy in case '
    'where an encrypted message contains a bogus key ID.'
    )
key_options.add_argument(
    '--skip-hidden-recipients', action='store_true', default=False,
    dest='skip_hidden_recipients',
    help='During decryption skip all anonymous recipients. This option helps '
    'in the case that people use the hidden recipients feature to hide their '
    'own encrypt-to key from others. If one has many secret keys this may '
    'lead to a major annoyance because all keys are tried in turn to decrypt '
    'something which was not really intended for it. The drawback of this '
    'option is that it is currently not possible to decrypt a message which '
    'includes real anonymous recipients.'
    )
key_options.add_argument(
    '--no-skip-hidden-recipients', action='store_false', default=False,
    dest='skip_hidden_recipients',
    help='During decryption not not skip anonymous recipients (default).'
    )
io_options = options.add_argument_group('Input and Output')
io_options.add_argument(
    '--armor, -a', action='store_true', default=False, dest='armor_output',
    help='Create ASCII-armored output. The default is to create the binary '
    'OpenPGP format.'
    )
io_options.add_argument(
    '--no-armor', action='store_false', default=False, dest='armor_input',
    help='Assume the input data is not in ASCII armored format.'
    )
io_options.add_argument(
    '--output, -o', metavar='file', dest='output',
    help='Write output to "file".'
    )
io_options.add_argument(
    '--max-output', metavar='n', type=int, default=0, dest='max_output',
    'This option sets a limit on the number of bytes that will be generated '
    'when processing a file. Since OpenPGP supports various levels of '
    'compression, it is possible that the plaintext of a given message may '
    'be significantly larger than the original OpenPGP message. While '
    '%(prog)s works properly with such messages, there is often a desire to '
    'set a maximum file size that will be generated before processing is '
    'forced to stop by the OS limits. Defaults to 0, which means "no limit".'
    )
io_options.add_argument(
    '--import-options', metavar='parameters', action='append',
    dest='import_options',
    help='This is a space or comma delimited string that gives options for '
    'importing keys. Options can be prepended with a "no-" to give the '
    'opposite meaning. The options are:\n\n'
    'import-local-sigs\n'
    'Allow importing key signatures marked as '
    '"local". This is not generally useful unless a shared keyring scheme is '
    'being used. Defaults to no.\n\n'
    'repair-pks-subkey-bug\n'
    'During import, attempt to repair the damage caused by the PKS keyserver '
    'bug (pre version 0.9.6) that mangles keys with multiple subkeys. Note '
    'that this cannot completely repair the damaged key as some crucial data '
    'is removed by the keyserver, but it does at least give you back one '
    'subkey. Defaults to no for regular --import and to yes for keyserver '
    '--recv-keys.\n\n'
    'merge-only\n'
    'During import, allow key updates to existing keys, but do not allow any '
    'new keys to be imported. Defaults to no.\n\n'
    'import-clean\n'
    'After import, compact (remove all signatures except the self-signature) '
    'any user IDs from the new key that are not usable. Then, remove any '
    'signatures from the new key that are not usable. This includes '
    'signatures that were issued by keys that are not present on the '
    'keyring. This option is the same as running the --edit-key command '
    '"clean" after import. Defaults to no.\n\n'
    'import-minimal\n'
    'Import the smallest key possible. This removes all signatures except '
    'the most recent self-signature on each user ID. This option is the same '
    'as running the --edit-key command "minimize" after import. Defaults to '
    'no.'
    )
io_options.add_argument(
    '--export-options', metavar='parameters', action='append',
    dest='export_options',
    help='This is a space or comma delimited string that gives options for '
    'exporting keys. Options can be prepended with a "no-" to give the '
    'opposite meaning. The options are:\n\n'
    'export-local-sigs\n'
    'Allow exporting key signatures marked as "local". This is not generally '
    'useful unless a shared keyring scheme is being used. Defaults to no.\n\n'
    'export-attributes\n'
    'Include attribute user IDs (photo IDs) while exporting. This is useful '
    'to export keys if they are going to be used by an OpenPGP program that '
    'does not accept attribute user IDs. Defaults to yes.\n\n'
    'export-sensitive-revkeys\n'
    'Include designated revoker information that was marked as "sensitive". '
    'Defaults to no.\n\n'
    'export-reset-subkey-passwd\n'
    'When using the --export-secret-subkeys command, this option resets the '
    'passphrases for all exported subkeys to empty. This is useful when the '
    'exported subkey is to be used on an unattended machine where a '
    'passphrase doesn\'t necessarily make sense. Defaults to no.\n\n'
    'export-clean\n'
    'Compact (remove all signatures from) user IDs on the key being exported '
    'if the user IDs are not usable. Also, do not export any signatures that '
    'are not usable. This includes signatures that were issued by keys that '
    'are not present on the keyring. This option is the same as running the '
    '--edit-key command "clean" before export except that the local copy of '
    'the key is not modified. Defaults to no.\n\n'
    'export-minimal\n'
    'Export the smallest key possible. This removes all signatures except '
    'the most recent self-signature on each user ID. This option is the same '
    'as running the --edit-key command "minimize" before export except that '
    'the local copy of the key is not modified. Defaults to no.'
    )
io_options.add_argument(
    '--with-colons', action='store_true', default=False, dest='with_colons',
    help='Print key listings delimited by colons. Note that the output will '
    'be encoded in UTF-8 regardless of any --display-charset setting. This '
    'format is useful when %(prog)s is called from scripts and other '
    'programs as it is easily machine parsed.'
    )
io_options.add_argument(
    '--fixed-list-mode', action='store_true', default=False,
    dest='fixed_list_mode',
    help='Do not merge primary user ID and primary key in --with-colon '
    'listing mode and print all timestamps as seconds since 1970-01-01.'
    )
io_options.add_argument(
    '--with-fingerprint', action='store_true', default=False,
    dest='with_fingerprint',
    help='Same as the command --fingerprint but changes only the format of '
    'the output and may be used together with another command.'
    )
openpgp_options = options.add_argument_group(
    'OpenPGP protocol specific options')
openpgp_options.add_argument(
    '-t, --textmode', action=TextmodeAction, default=False, dest='text_mode',
    tdest='clearsign',
    help='Treat input files as text and store them in the OpenPGP canonical '
    'text form with standard "CRLF" line endings. This also sets the '
    'necessary flags to inform the recipient that the encrypted or signed '
    'data is text and may need its line endings converted back to whatever '
    'the local system uses. This option is useful when communicating between '
    'two platforms that have different line ending conventions (UNIX-like to '
    'Mac, Mac to Windows, etc).\n\n'
    'If -t (but not --textmode) is used together with armoring and signing, '
    'this enables clearsigned messages. This kludge is needed for '
    'command-line compatibility with command-line versions of PGP; normally '
    'you would use --sign or --clearsign to select the type of the signature.'
    )
openpgp_options.add_argument(
    '--force-v3-sigs', action='store_true', default=False,
    dest='force_v3_sigs',
    help='OpenPGP states that an implementation should generate v4 '
    'signatures but PGP versions 5 through 7 only recognize v4 signatures on '
    'key material. This option forces v3 signatures for signatures on data. '
    'Note that this option implies --no-ask-sig-expire, and unsets '
    '--sig-policy-url, --sig-notation, and --sig-keyserver-url, as these '
    'features cannot be used with v3 signatures. --no-force-v3-sigs disables '
    'this option. Defaults to no.'
    )
openpgp_options.add_argument(
    '--no-force-v3-sigs', action='store_false', default=False,
    dest='force_v3_sigs',
    help='Disables --force-v3-sigs (default).'
    )
openpgp_options.add_argument(
    '--force-v4-certs', action='store_true', default=False,
    dest='force_v4_certs',
    help='Always use v4 key signatures even on v3 keys. This option also '
    'changes the default hash algorithm for v3 RSA keys from MD5 to SHA-1.'
    )
openpgp_options.add_argument(
    '--no-force-v4-certs', action='store_false', default=False,
    dest='force_v4_certs',
    help='Disables --force-v4-certs (default).'
    )
openpgp_options.add_argument(
    '--force-mdc', action='store_true', default=False, dest='force_mdc',
    help='Force the use of encryption with a modification detection code. '
    'This is always used with the newer ciphers (those with a blocksize '
    'greater than 64 bits), or if all of the recipient keys indicate MDC '
    'support in their feature flags.'
    )
openpgp_options.add_argument(
    '--disable-mdc', action='store_true', default=False, dest='disable_mdc',
    help='Disable the use of the modification detection code. Note that by '
    'using this option, the encrypted message becomes vulnerable to a '
    'message modification attack.'
    )
openpgp_options.add_argument(
    '--personal-cipher-preferences', metavar='string',
    dest='personal_cipher_preferences',
    help='Set the list of personal cipher preferences to "string". Use '
    '%(prog)s --version to get a list of available algorithms, and use none '
    'to set no preference at all. This allows the user to safely override '
    'the algorithm chosen by the recipient key preferences, as %(prog)s will '
    'only select an algorithm that is usable by all recipients. The most '
    'highly ranked cipher in this list is also used for the --symmetric '
    'encryption command.'
    )
openpgp_options.add_argument(
    '--personal-digest-preferences', metavar='string',
    dest='personal_digest_preferences',
    help='Set the list of personal digest preferences to "string". Use '
    '%(prog)s --version to get a list of available algorithms, and use none '
    'to set no preference at all. This allows the user to safely override '
    'the algorithm chosen by the recipient key preferences, as %(prog)s will '
    'only select an algorithm that is usable by all recipients. The most '
    'highly ranked digest algorithm in this list is also used when signing '
    'without encryption (e.g. --clearsign or --sign).'
    )

openpgp_options.add_argument(
    '--personal-compress-preferences', metavar='string',
    dest='personal_compress_preferences',
    help='Set the list of personal compression preferences to "string". Use '
    '%(prog)s --version to get a list of available algorithms, and use none '
    'to set no preference at all. This allows the user to safely override '
    'the algorithm chosen by the recipient key preferences, as %(prog)s will '
    'only select an algorithm that is usable by all recipients. The most '
    'highly ranked compression algorithm in this list is also used when '
    'there are no recipient keys to consider (e.g. --symmetric).'
    )
openpgp_options.add_argument(
    '--s2k-cipher-algo', metavar='name', dest='s2k_cipher_algo',
    help='Use "name" as the cipher algorithm used to protect secret keys. '
    'The default cipher is CAST5. This cipher is also used for conventional '
    'encryption if  --personal-cipher-preferences and --cipher-algo is not '
    'given.'
    )
openpgp_options.add_argument(
    '--s2k-digest-algo', metavar='name', dest='s2k_digest_algo',
    help='Use name as the digest algorithm used to mangle the passphrases. '
    'The default algorithm is SHA-1.'
    )
openpgp_options.add_argument(
    '--s2k-mode', metavar='n', type=int, choices=(0, 1, 3), default=3,
    dest='s2k_mode',
    help='Selects how passphrases are mangled. If n is 0 a plain passphrase '
    '(which is not recommended) will be used, a 1 adds a salt to the '
    'passphrase and a 3 (the default) iterates the whole process a number of '
    'times (see --s2k-count). Unless --rfc1991 is used, this mode is also '
    'used for conventional encryption.'
    )
openpgp_options.add_argument(
    '--s2k-count', metavar='n', type=int, dest='s2k_count', default=65536,
    # TODO: not really - it's the number of bytes hashed
    help='Specify how many times the passphrase mangling is repeated. This '
    'value may range between 1024 and 65011712 inclusive. The default is '
    '65536. Note that not all values in the 1024-65011712 range are legal '
    'and if an illegal value is selected, %(prog)s will round up to the '
    'nearest legal value. This option is only meaningful if --s2k-mode is 3.'
    )
compliance_options = options.add_argument_group('Compliance options')
compliance_options.add_argument(
    '--gnupg', action='store_const', const=Compliance.GnuPG,
    dest='compliance', default=Compliance.GnuPG,
    help='Use standard GnuPG behavior. This is essentially OpenPGP behavior '
    '(see --openpgp), but with some additional workarounds for common '
    'compatibility problems in different versions of PGP. This is the '
    'default option, so it is not generally needed, but it may be useful to '
    'override a different compliance option in the configuration file.'
    )
compliance_options.add_argument(
    '--openpgp', action='store_const', const=Compliance.OpenPGP,
    dest='compliance', default=Compliance.GnuPG,
    help='Reset all packet, cipher and digest options to strict OpenPGP '
    'behavior. Use this option to reset all previous options like --s2k-*, '
    '--cipher-algo, --digest-algo and --compress-algo to OpenPGP compliant '
    'values. All PGP workarounds are disabled.'
    )
compliance_options.add_argument(
    '--rfc4880', action='store_const', const=Compliance.RFC4880,
    dest='compliance', default=Compliance.GnuPG,
    help='Reset all packet, cipher and digest options to strict RFC-4880 '
    'behavior. Note that this is currently the same thing as --openpgp.'
    )
compliance_options.add_argument(
    '--rfc2440', action='store_const', const=Compliance.RFC2440,
    dest='compliance', default=Compliance.GnuPG,
    help='Reset all packet, cipher and digest options to strict RFC-2440 '
    'behavior.'
    )
compliance_options.add_argument(
    '--rfc1991', action='store_const', const=Compliance.RFC1991,
    dest='compliance', default=Compliance.GnuPG,
    help='Try to be more RFC-1991 (PGP 2.x) compliant.'
    )
compliance_options.add_argument(
    '--pgp2', action='store_const', const=Compliance.PGP2,
    dest='compliance', default=Compliance.GnuPG,
    help='Set up all options to be as PGP 2.x compliant as possible, and '
    'warn if an action is taken (e.g. encrypting to a non-RSA key) that will '
    'create a message that PGP 2.x will not be able to handle. Note that '
    '"PGP 2.x" here means "MIT PGP 2.6.2". There are other versions of PGP '
    '2.x available, but the MIT release is a good common baseline.\n\n'
    'This option implies --rfc1991 --disable-mdc --no-force-v4-certs '
    '--escape-from-lines --force-v3-sigs --cipher-algo IDEA '
    '--digest-algo MD5 --compress-algo ZIP. It also disables --textmode when '
    'encrypting.'
    )
compliance_options.add_argument(
    '--pgp6', action='store_const', const=Compliance.PGP6,
    dest='compliance', default=Compliance.GnuPG,
    help='Set up all options to be as PGP 6 compliant as possible. This '
    'restricts you to the ciphers IDEA (if the IDEA plugin is installed), '
    '3DES, and CAST5, the hashes MD5, SHA1 and RIPEMD160, and the '
    'compression algorithms none and ZIP. This also disables --throw-keyids, '
    'and making signatures with signing subkeys as PGP 6 does not understand '
    'signatures made by signing subkeys.\n\n'
    'This option implies --disable-mdc --escape-from-lines --force-v3-sigs.'
    )
compliance_options.add_argument(
    '--pgp7', action='store_const', const=Compliance.PGP7,
    dest='compliance', default=Compliance.GnuPG,
    help='Set up all options to be as PGP 7 compliant as possible. This is '
    'identical to --pgp6 except that MDCs are not disabled, and the list of '
    'allowable ciphers is expanded to add AES128, AES192, AES256, and '
    'TWOFISH.'
    )
compliance_options.add_argument(
    '--pgp8', action='store_const', const=Compliance.PGP8,
    dest='compliance', default=Compliance.GnuPG,
    help='Set up all options to be as PGP 8 compliant as possible. PGP 8 is '
    'a lot closer to the OpenPGP standard than previous versions of PGP, so '
    'all this does is disable --throw-keyids and set --escape-from-lines. '
    'All algorithms are allowed except for the SHA224, SHA384, and SHA512 '
    'digests.'
    )
# commands
commands = argparser.add_argument_group('Commands')
commands.add_argument(
    '--version', action='version',
    version='%(prog)s {version}'.format(version=VERSION),
    help='Print the program version'
    )
commands.add_argument(
    '--help, -h', action='help', help='Print a usage '
    'message summarizing the most useful command line options. Note that you '
    'cannot abbreviate this command.'
    )
commands.add_argument(
    '--sign, -s', dest='command', action='append_const', const=Commands.Sign,
    help='Make a signature. This command may be combined with --encrypt (for '
    'a signed and encrypted message), --symmetric (for a signed and '
    'symmetrically encrypted message), or --encrypt and --symmetric together '
    '(for a signed message that may be decrypted via a secret  key or a '
    'passphrase). The key to be used for signing is chosen by default or can '
    'be set with the --local-user and --default-key options.'
    )
commands.add_argument(
    '--clearsign', dest='command', action='append_const',
    const=Commands.Clearsign,
    help='Make a clear text signature. The content in a clear text signature '
    'is readable without any special software. OpenPGP software is only '
    'needed to verify the signature. Clear text signatures may modify '
    'end-of-line whitespace for platform independence and are not intended '
    'to be reversible. The key to be used for signing is chosen by default '
    'or can be set with the --local-user and --default-key options.'
    )
commands.add_argument(
    '--detach-sign, -b', dest='command', action='append_const',
    const=Commands.DetachSign, help='Make a detached signature.'
    )
commands.add_argument(
    '--encrypt, -e', dest='command', action='append_const',
    const=Commands.Encrypt,
    help='Encrypt data. This option may be combined with --sign (for a '
    'signed and encrypted message), --symmetric (for a message that may be '
    'decrypted via a secret key or a passphrase), or --sign and --symmetric '
    'together (for a signed message that may be decrypted via a secret key '
    'or a passphrase).'
    )
commands.add_argument(
    '--symmetric, -c', dest='command', action='append_const',
    const=Commands.Symmetric,
    help='Encrypt with a symmetric cipher using a passphrase. The default '
    'symmetric cipher used is CAST5, but may be chosen with the '
    '--cipher-algo option. This option may be combined with --sign (for a '
    'signed and symmetrically encrypted message), --encrypt (for a message '
    'that may be decrypted via a secret key or a passphrase), or --sign and '
    '--encrypt together (for a signed message that may be decrypted via a '
    'secret key or a passphrase).'
    )
commands.add_argument(
    '--store', dest='command', action='append_const', const=Commands.Store,
    help='Store only (make a simple RFC1991 literal data packet).'
    )
commands.add_argument(
    '--decrypt, -d', dest='command', action='append_const',
    const=Commands.Decrypt,
    help='Decrypt  the file given on the command line (or STDIN if no file '
    'is specified) and write it to STDOUT (or the file specified with '
    '--output). If the decrypted file is signed, the signature is also '
    'verified. This command differs from the default operation, as it never '
    'writes to the filename which is included in the file and it rejects '
    'files which don\'t begin with an encrypted message.'
    )
commands.add_argument(
    '--verify', dest='command', action='append_const', const=Commands.Verify,
    help='Assume that the first argument is a signed file or a detached '
    'signature and verify it without generating any output. With no '
    'arguments, the signature packet is read from STDIN. If only a sigfile '
    'is given, it may be a complete signature or a detached signature, in '
    'which case the signed stuff is expected in a file without the ".sig" or '
    '".asc" extension. With more than 1 argument, the first should be a '
    'detached signature and the remaining files are the signed stuff. To '
    'read the signed stuff from STDIN, use \'-\' as the second filename. For '
    'security reasons a detached signature cannot read the signed material '
    'from STDIN without denoting it in the above way.\n\n'
    'Note: When verifying a cleartext signature, %(prog)s verifies only what '
    'makes up the cleartext signed data and not any extra data outside of '
    'the cleartext signature or header lines following directly the dash '
    'marker line. The option --output may be used to write out the actual '
    'signed data; but there are other pitfalls with this format as well. It '
    'is suggested to avoid cleartext signatures in favor of detached '
    'signatures.'
    )
commands.add_argument(
    '--multifile', dest='multifile', action='store_true',
    help='This modifies certain other commands to accept multiple files for '
    'processing on the command line or read from STDIN with each filename on '
    'a separate line. This allows for many files to be processed at once. '
    '--multifile may currently be used along with --verify, --encrypt, and '
    '--decrypt. Note that --multifile --verify may not be used with detached '
    'signatures.'
    )
commands.add_argument(
    '--verify-files', dest='command', action='append_const',
    const=Commands.VerifyMulti,
    help='Identical to --multifile --verify.'
    )
commands.add_argument(
    '--encrypt-files', dest='command', action='append_const',
    const=Commands.EncryptMulti,
    help='Identical to --multifile --encrypt.'
    )
commands.add_argument(
    '--decrypt-files', dest='command', action='store_const',
    const=Commands.DecryptMulti,
    help='Identical to --multifile --decrypt.'
    )
commands.add_argument(
    '--list-keys, -k, --list-public-keys', dest='command',
    action='append_const', const=Commands.ListKeys,
    help='List all keys from the public keyrings, or just the keys given on '
    'the command line.'
    )
commands.add_argument(
    '--list-secret-keys, -K', dest='command', action='append_const',
    const=Commands.ListSecretKeys,
    help='List all keys from the secret keyrings, or just the ones given on '
    'the command line. A # after the letters sec means that the secret key '
    'is not usable (for example, if it was created via '
    '--export-secret-subkeys).'
    )
commands.add_argument(
    '--list-sigs', dest='command', action='append_const',
    const=Commands.ListSigs,
    help='Same as --list-keys, but the signatures are listed too.\n\nFor '
    'each signature listed, there are several flags in between the "sig" tag '
    'and keyid. These flags give additional information about each '
    'signature. From left to right, they are the numbers 1-3 for certificate '
    'check level (see --ask-cert-level), "L" for a local or non-exportable '
    'signature (see --lsign-key), "R" for a nonRevocable signature (see the '
    '--edit-key command "nrsign"), "P" for a signature that contains a '
    'policy URL (see --cert-policy-url), "N" for a signature that contains a '
    'notation (see --cert-notation), "X" for an eXpired signature (see '
    '--ask-cert-expire), and the numbers 1-9 or "T" for 10 and above to '
    'indicate trust signature levels (see the --edit-key command "tsign").'
    )
commands.add_argument(
    '--check-sigs', dest='command', action='append_const',
    const=Commands.CheckSigs,
    help='Same as --list-sigs, but the signatures are verified. Note that '
    'for performance reasons the revocation status of a signing key is not '
    'shown.\n\nThe status of the verification is indicated by a flag '
    'directly following the "sig" tag (and thus before the flags described '
    'above for --list-sigs). A "!" indicates that the signature has been '
    'successfully verified, a "-" denotes a bad signature and a "%" is used '
    'if an error occurred while checking the signature (e.g. a non supported '
    'algorithm).'
    )
commands.add_argument(
    '--fingerprint', dest='command', action='append_const',
    const=Commands.Fingerprint,
    help='List all keys (or the specified ones) along with their '
    'fingerprints. This is the same output as --list-keys but with the '
    'additional output of a line with the fingerprint. May also be combined '
    'with --list-sigs or --check-sigs. If this command is given twice, the '
    'fingerprints of all secondary keys are listed too.'
    )
commands.add_argument(
    '--list-packets', dest='command', action='append_const',
    const=Commands.ListPackets,
    help='List only the sequence of packets. This is mainly useful for '
    'debugging.'
    )
commands.add_argument(
    '--delete-key', dest='command', action='append_const',
    const=Commands.DeleteKey,
    help='Remove key from the public keyring. In batch mode either --yes is '
    'required or the key must be specified by fingerprint. This is a '
    'safeguard against accidental deletion of multiple keys.'
    )
commands.add_argument(
    '--delete-secret-key', dest='command', action='append_const',
    const=Commands.DeleteSecretKey,
    help='Remove key from the secret keyring. In batch mode the key must be '
    'specified by fingerprint.'
    )
commands.add_argument(
    '--delete-secret-and-public-key', dest='command', action='append_const',
    const=Commands.DeleteSecretAndPublicKey,
    help='Same as --delete-key, but if a secret key exists, it will be '
    'removed first. In batch mode the key must be specified by fingerprint.'
    )
commands.add_argument(
    '--export', dest='command', action='append_const', const=Commands.Export,
    help='Either export all keys from all keyrings (default keyrings and '
    'those registered via option --keyring), or if at least one name is '
    'given, those of the given name. The new keyring is written to STDOUT '
    'or to the file given with option --output. Use together with --armor to '
    'mail those keys.'
    )
commands.add_argument(
    '--send-keys', dest='command', action='append_const',
    const=Commands.SendKeys,
    help='Similar to --export but sends the keys to a keyserver. '
    'Fingerprints may be used instead of key IDs. Option --keyserver must be '
    'used to give the name of this keyserver. Don\'t send your complete '
    'keyring to a keyserver --- select only those keys which are new or '
    'changed by you. If no key IDs are given, %(prog)s does nothing.'
    )
commands.add_argument(
    '--export-secret-keys', dest='command', action='append_const',
    const=Commands.ExportSecretKeys,
    help=_export_secret_help
    )
commands.add_argument(
    '--export-secret-subkeys', dest='command', action='append_const',
    const=Commands.ExportSecretKeys,
    help=_export_secret_help
    )
commands.add_argument(
    '--import', dest='command', action='append_const', const=Commands.Import,
    help='Import/merge keys. This adds the given keys to the keyring.\n\n'
    'There are a few other options which control how this command works. '
    'Most notable here is the --import-options merge-only option which does '
    'not insert new keys but does only the merging of new signatures, '
    'user-IDs and subkeys.'
    )
commands.add_argument(
    '--recv-keys', dest='command', action='append_const',
    const=Commands.RecvKeys,
    help='Import the keys with the given key IDs from a keyserver. Option '
    '--keyserver must be used to give the name of this keyserver.'
    )
commands.add_argument(
    '--refresh-keys', dest='command', action='append_const',
    const=Commands.RefreshKeys,
    help='Request updates from a keyserver for keys that already exist on '
    'the local keyring. This is useful for updating a key with the latest '
    'signatures, user IDs, etc. Calling this with no arguments will refresh '
    'the entire keyring. Option --keyserver must be used to give the name of '
    'the keyserver for all keys that do not have preferred keyservers set '
    '(see --keyserver-options honor-key-server-url).'
    )
commands.add_argument(
    '--search-keys', dest='command', action='append_const',
    const=Commands.SearchKeys,
    help='Search the keyserver for the given names. Multiple names given '
    'here will be joined together to create the search string for the '
    'keyserver. Option --keyserver must be used to give the name of this '
    'keyserver. Keyservers that support different search methods allow using '
    'the syntax specified in "How to specify a user ID" below. Note that '
    'different keyserver types support different search methods. Currently '
    'only LDAP supports them all.'
    )
commands.add_argument(
    '--fetch-keys', dest='command', action='append_const',
    const=Commands.FetchKeys,
    help='Retrieve keys located at the specified URIs. Note that different '
    'installations of GnuPG may support different protocols (HTTP, FTP, '
    'LDAP, etc.)'
    )
commands.add_argument(
    '--update-trustdb', dest='command', action='append_const',
    const=Commands.UpdateTrustDB,
    help='Do trust database maintenance. This command iterates over all keys '
    'and builds the Web of Trust. This is an interactive command because it '
    'may have to ask for the "ownertrust" values for keys. The user has to '
    'give an estimation of how far she trusts the owner of the displayed key '
    'to correctly certify (sign) other keys. %(prog)s only asks for the '
    'ownertrust value if it has not yet been assigned to a key. Using the '
    '--edit-key menu, the assigned value can be changed at any time.'
    )
commands.add_argument(
    '--check-trustdb', dest='command', action='append_const',
    const=Commands.CheckTrustDB,
    help='Do trust database maintenance without user interaction. From time '
    'to time the trust database must be updated so that expired keys or '
    'signatures and the resulting changes in the Web of Trust can be '
    'tracked. Normally, GnuPG will calculate when this is required and do it '
    'automatically unless --no-auto-check-trustdb is set. This command can '
    'be used to force a trust database check at any time. The processing is '
    'identical to that of --update-trustdb but it skips keys with a not yet '
    'defined "ownertrust".\n\nFor use with cron jobs, this command can be '
    'used together with --batch in which case the trust database check is '
    'done only if a check is needed. To force a run even in batch mode add '
    'the option --yes.'
    )
commands.add_argument(
    '--export-ownertrust', dest='command', action='append_const',
    const=Commands.ExportOwnerTrust,
    help='Send the ownertrust values to STDOUT. This is useful for backup '
    'purposes as these values are the only ones which can\'t be re-created '
    'from a corrupted trustdb. Example:\n    %(prog)s --export-ownertrust > '
    'otrust.txt'
    )
commands.add_argument(
    '--import-ownertrust', dest='command', action='append_const',
    const=Commands.ImportOwnerTrust,
    help='Update the trustdb with the ownertrust values stored in files (or '
    'STDIN if not given); existing values will be overwritten. In case of a '
    'severely damaged trustdb and if you have a recent backup of the '
    'ownertrust values (e.g. in the file \'otrust.txt\', you may re-create '
    'the trustdb using these commands:\n    cd ~/.gnupg\n     rm trustdb.gpg'
    '\n    gpg --import-ownertrust < otrust.txt'
    )
commands.add_argument(
    '--enarmor', dest='command', action='append_const',
    const=Commands.EnArmor,
    help='Pack an arbitrary input into an OpenPGP ASCII armor.'
    )
commands.add_argument(
    '--dearmor', dest='command', action='append_const',
    const=Commands.DeArmor,
    help='Unpack an arbitrary input from an OpenPGP ASCII armor.'
    )
commands.add_argument(
    '--gen-key', dest='command', action='append_const',
    const=Commands.GenKey,
    help='Generate a new key pair. This command is normally only used '
    'interactively.'
    )
commands.add_argument(
    '--gen-revoke', dest='command', action='append_const',
    const=Commands.GenRevoke,
    help='Generate a revocation certificate for the complete key. To revoke '
    'a subkey or a signature, use the --edit command.'
    )
commands.add_argument(
    '--desig-revoke', dest='command', action='append_const',
    const=Commands.DesigRevoke,
    help='Generate a designated revocation certificate for a key. This '
    'allows a user (with the permission of the keyholder) to revoke someone '
    'else\'s key.'
    )
commands.add_argument(
    '--edit-key', dest='command', action='append_const',
    const=Commands.EditKey,
    help='Present a menu which enables you to do most of the key management '
    'related tasks. It expects the specification of a key on the command '
    'line.'
    )
commands.add_argument(
    '--sign-key', dest='command', action='append_const',
    const=Commands.SignKey,
    help='Signs a public key with your secret key. This is a shortcut '
    'version of the subcommand "sign" from --edit-key.'
    )
commands.add_argument(
    '--lsign-key', dest='command', action='append_const',
    const=Commands.LocalSignKey,
    help='Signs a public key with your secret key but marks it as '
    'non-exportable. This is a shortcut version of the subcommand "lsign" '
    'from --edit-key.'
    )
# args


def main():
    pass


if __name__ == '__main__':
    main()
