import argparse
import os
import sys


VERSION = 'x.x.x'


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
