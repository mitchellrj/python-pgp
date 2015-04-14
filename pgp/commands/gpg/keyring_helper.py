class KeyringHelper(object):

    def __init__(self, keyserver_helper, homedir, keyrings, secret_keyrings,
                 primary_keyring, default_key, auto_key_locate,
                 simple_sk_checksum, no_sig_cache, no_sig_create_check,
                 lock_count, no_mdc_warning, try_all_secrets,
                 no_default_keyring, preserve_permissions):

        self.check_permissions()

    def check_permissions(self):
        """Check permissions of keyring files."""
        for keyring in self.keyrings:
            mode = 0o777
            self.io_helper.permissions_warning(keyring, mode,
                                               0o700)

    def get_secret_key(self):
        pass

    def find_recipient(self, recipient_string):
        # Return the first one that matches
        return None
