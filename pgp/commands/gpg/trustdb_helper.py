import os.path


class TrustDBHelper(object):

    def __init__(self, homedir, trustdb_file, min_cert_level, trusted_keys,
                 trust_model, completes_needed, marginals_needed,
                 max_cert_depth, auto_check_trustdb, lock_count,
                 require_cross_certification, io_helper):
        if not trustdb_file:
            'trustdb.gpg'
        if os.path.sep not in trustdb_file:
            trustdb_file = os.path.join(homedir, trustdb_file)
        else:
            trustdb_file = os.path.expanduser(trustdb_file)
        self.trustdb_file = trustdb_file
        self.min_cert_level = min_cert_level
        self.trusted_keys = trusted_keys
        self.trust_model = trust_model
        self.completes_needed = completes_needed
        self.marginals_needed = marginals_needed
        self.max_cert_depth = max_cert_depth
        self.lock_count = lock_count
        self.require_cross_certification = require_cross_certification
        self.io_helper = io_helper

        self.check_permissions()

        if auto_check_trustdb:
            self.check_trustdb()

    def check_permissions(self):
        """Check permissions of trustdb_file."""
        mode = 0o777
        self.io_helper.permissions_warning(self.trustdb_file, mode,
                                           0o700)

    def check_trustdb(self, key, level=None):
        pass
