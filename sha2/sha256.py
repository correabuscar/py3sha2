#!/usr/bin/python3

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

import copy
import struct
import sys
#from sha2 import shaBase #what's this? recursion?
from sha2.shaBase import shaBase


def new(m=None, encoding:str=None):
    return sha256(m, encoding)


class sha256(shaBase):
    _k = (0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
          0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
          0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
          0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
          0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
          0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
          0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
          0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
          0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
          0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
          0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
          0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
          0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
          0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
          0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
          0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)
    _h = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
    _output_size = 8 #because 8 elements in _h are used for sha256, but only 7(of 8) for sha224

    block_size = 64 #this is bytes not bits!

    element_size_bytes = 4 #added by me, size in bytes of one element of _k or _h


    #def __init__(self, m=None, encoding='utf8'):
    #    super().__init__() #mandatory, doneFIXME: how to ensure it's not missed? well, else it will error anyway. Okay not defining it at all it is then!

    def dummy(self):
        pass


