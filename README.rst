TODO: travis
//.. image:: https://travis-ci.org/thomdixon/pysha2.svg?branch=master
//    :target: https://travis-ci.org/thomdixon/pysha2

======
pysha3
======

License
=======

This software is distributed under the 
`MIT License <https://choosealicense.com/licenses/mit/>`_.

About
=====

pysha3 is a pure Python3 implementation of the `FIPS 180-2 <https://csrc.nist.gov/publications/detail/fips/180/2/archive/2004-02-25>`_ secure hash
standard. `Thomas Dixon <https://github.com/thomdixon>`_ originally `wrote and published pysha2 <https://github.com/thomdixon/pysha2>`_ on the web prior to
the inclusion of `hashlib <https://docs.python.org/3/library/hashlib.html>`_ into the Python standard
library. Unfortunately, the original source was lost due to a hard
drive failure. Fortunately, the library proved useful to some at the
time (due to the prevalence of Python 2.3 and 2.4), and so he was able
to recover all but the unit tests (which he later rewrote).

`This fork <https://github.com/correabuscar/pysha3>`_ is modified by Emanuel Czirai to work for Python 3.10 and for my own uses.

You should probably use hashlib or if you're into learning more about how it works, see this one instead: https://github.com/pdoms/SHA256-PYTHON

Usage
=====

The library supports both the "old" hash interface of ``md5`` and
``sha``, as well as the "new" hash interface introduced by
``hashlib``. This permits you to use pysha3 as a drop-in replacement
for either interface.

A quick example of hashing a string::

    import sha2

    print(sha2.sha256('Can you keep a secret?').hexdigest())

Testing
=======

To run the included unit tests, execute::

    python3 test.py

in the current directory or run with ``nosetests``.

