==========
python-pgp
==========

.. image:: https://travis-ci.org/mitchellrj/python-pgp.svg?branch=master
   :target: https://travis-ci.org/mitchellrj/python-pgp

.. image:: https://coveralls.io/repos/mitchellrj/python-pgp/badge.png
   :target: https://coveralls.io/r/mitchellrj/python-pgp

Summary
-------

python-pgp aims to reproduce the full functionality of GnuPG in Python.
It may also be used for creating raw OpenPGP packets and packet streams
for test purposes. This may be a bit of a heavyweight solution for some
purposes.

Alternatives
============

Other Python packages which provide related functionality:

* `pyassuan <https://pypi.python.org/pypi/pyassuan/>`_ - communicate
  with GnuPG using its socket protocol.
* `pgpdump <https://pypi.python.org/pypi/pgpdump>`_ - a pure python
  library for parsing OpenPGP packets.
* `gnupg <https://pypi.python.org/pypi/gnupg>`_ - a wrapper around the
  GnuPG executable.
* `python-gnupg <https://pypi.python.org/pypi/python-gnupg>`_ - another
  wrapper around the GnuPG executable.
* `gpgkeys <https://pypi.python.org/pypi/gpgkeys>`_ - another wrapper
  around the GnuPG executable.
* `gpglib <https://pypi.python.org/pypi/gpglib>`_ - a pure python
  library for parsing OpenPGP packets and decrypting messages.
* `OpenPGP <https://pypi.python.org/pypi/OpenPGP>`_ - an unmaintained
  pure python library with much of the functionality of old versions
  of GnuPG.
* `encryptedfile <https://pypi.python.org/pypi/encryptedfile>`_ - a
  pure python library for symmetrically encrypting files in an
  OpenPGP-compatible way.
* `PGPy <https://pypi.python.org/pypi/PGPy>`_ - a pure python
  library with basic parsing and signing of OpenPGP packets.
* `OpenPGP-Python <https://github.com/singpolyma/OpenPGP-Python>`_ - a
  pure python port of
  `openpgp-php <https://github.com/bendiken/openpgp-php>`_. It can
  parse OpenPGP packets and verify & create signatures.

System requirements
-------------------

* build-essential

For Twofish support
===================

* libtwofish-dev

Recommended
===========

* libgmp10-dev (for fastmath extension of pycrypto)

Installation
------------
::

    pip install pgp

with Twofish support::

    pip install pgp[twofish]

with Camellia support::

    pip install pgp[camellia]


with Twofish & Camellia support::

    pip install pgp[camellia,twofish]

Usage
-----

High level
==========

Parsing a message
`````````````````
::

    from pgp import read_message
    message = read_message(data)

Parsing a transferrable key
```````````````````````````
::

    from pgp import read_key
    key = read_key(data)

Loading the GnuPG database
``````````````````````````
::

    from pgp import get_gnupg_db
    db = get_gnupg_db()
    key = db.search(user_id='Joe')[0]

Retrieving a key from a keyserver and creating a message for it
```````````````````````````````````````````````````````````````
::

    >>> import datetime
    >>> from pgp import *
    >>> from pgp.keyserver import get_keyserver
    >>> ks = get_keyserver('hkp://pgp.mit.edu/')
    >>> results = ks.search('Joe Bloggs')
    >>> recipient_key = results[0].get()
    >>> recipient_subkey = recipient_key.subkeys[0]
    >>> message = message.TextMessage(
    ...     u"This message was encrypted using Python PGP\n",
    ...     u"somefilename.txt",
    ...     datetime.datetime.now())
    >>> my_secret_key = read_key_file('secret_key.gpg')
    >>> my_secret_key.unlock('My passphrase')
    >>> message = message.sign(my_secret_key)
    >>> message = message.compress(2, 6)  # 2=ZLIB, 6=default-level
    >>> message = message.public_key_encrypt(9, recipient_subkey)
    >>> message_packets = message.to_packets()
    >>> message_data = b''.join(map(bytes, message_packets))
    >>> armored_message = armor.ASCIIArmor(
    ...     armor.PGP_MESSAGE, message_data)
    >>> with open('message.asc', 'w') as file_handle:
    ...     file_handle.write(str(armored_message))

Low level
=========

Parsing a packet stream
```````````````````````
::

    from pgp.packets import parsers
    parsers.parse_binary_packet_data(packet_data)

Serializing a packet
````````````````````
::

    from pgp.packets import parsers
    packets = parsers.parse_binary_packet_data(packet_data)
    b''.join(map(bytes, packets))

Security
--------

If you are using this package to handle private key data and
decryption, please note that there is no (reasonable) way currently in
Python to securely erase memory and that copies of things are made often
and in non-obvious ways. If you are concerned about key data being
compromised by a memory leak, do not use this package for handling
secret key data. On the other hand, "if your memory is constantly being
compromised, I would re-think your security setup."

OpenPGP uses compression algorithms. Beware when feeding untrusted data
into this library of
`Zip bomb <http://en.wikipedia.org/wiki/Zip_bomb>`_ or similar denial
of service attacks.

Development
-----------

The main repository for this package is `on GitHub
<https://github.com/mitchellrj/python-pgp>`_. To develop on the package
and install development dependencies, clone the repository and install
the 'dev' extras.::

    git clone git@github.com:mitchellrj/python-pgp.git
    cd python-pgp
    virtualenv .
    bin/pip install -e ".[dev]"

Running tests
=============
::

    bin/python setup.py nosetests

Building documentation
======================
::

    bin/python setup.py build_sphinx

