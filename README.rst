.. image:: https://travis-ci.org/mitchellrj/python-pgp.svg?branch=master
   :target: https://travis-ci.org/mitchellrj/python-pgp

.. image:: https://coveralls.io/repos/mitchellrj/python-pgp/badge.png
   :target: https://coveralls.io/r/mitchellrj/python-pgp

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

Parsing a packet stream
=======================
::
    
    from pgp.packets import parsers
    parsers.parse_binary_packet_data(packet_data)

Serializing a packet
====================
::
    
    from pgp.packets import parsers
    packets = parsers.parse_binary_packet_data(packet_data)
    bytes(next(packets))

Parsing a transferable public key
=================================
::
    
    from pgp import models
    from pgp.packets import parsers
    packets = list(parsers.parse_binary_packet_data(packet_data))
    models.TransferablePublicKey.from_packets(packets)

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

