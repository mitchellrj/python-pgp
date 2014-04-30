.. image:: https://travis-ci.org/mitchellrj/python-pgp.svg?branch=master
   :target: https://travis-ci.org/mitchellrj/python-pgp

.. image:: https://coveralls.io/repos/mitchellrj/python-pgp/badge.png
   :target: https://coveralls.io/r/mitchellrj/python-pgp

System requirements
===================

* build-essential

For Twofish support
-------------------

* libtwofish-dev

Recommended
-----------

* libgmp10-dev (for fastmath extension of pycrypto)

Installation
============
::

    pip install pgp

with Twofish support::

    pip install pgp[twofish]

with Camellia support::

    pip install pgp[camellia]


with Twofish & Camellia support::

    pip install pgp[camellia,twofish]


Development
===========

To install development dependencies, install the 'dev' extras.::

    pip install -e ".[dev]"

Running tests
-------------
::

    python setup.py nosetests

Building documentation
----------------------
::

    python setup.py build_sphinx

