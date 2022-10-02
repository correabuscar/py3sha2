#!/usr/bin/python3

from __future__ import annotations #needed for return type to be the same class type ie. -> sha256
#^ SyntaxError: from __future__ imports must occur at the beginning of the file

__author__ = 'Thomas Dixon'
__license__ = 'MIT'
#NOTE: the sha* implementations are originally from src: https://github.com/thomdixon/pysha2
#and only the code modifications/additions (and not the sha* implementations) are by Emanuel Czirai
__authors__ = "Thomas Dixon, Emanuel Czirai"
__maintainer__ = "Emanuel Czirai"
__version__ = "0.0.2"
__status__ = "Development"
#^ technically production-ready, but you should use hashlib instead!
#header info src: https://stackoverflow.com/a/1523456/19999437 and https://epydoc.sourceforge.net/manual-fields.html#module-metadata-variables

import copy, struct, sys
from sha2.sha256 import shaBase

def new(m=None, encoding=None):
    return sha512(m, encoding)

class sha512(shaBase):
    _h = (0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
          0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179)
    _output_size = 8

    #blocksize = 1
    block_size = 128
    #digest_size = 64
    element_size_bytes=8
    s0_bit_ops1=[1,8,7]
    s1_bit_ops1=[19,61,6]
    s0_bit_ops2=[28,34,39]
    s1_bit_ops2=[14,18,41]




