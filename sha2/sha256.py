#!/usr/bin/python3

from __future__ import annotations #needed for return type to be the same class type ie. -> sha256
#^ SyntaxError: from __future__ imports must occur at the beginning of the file

__author__ = 'Thomas Dixon'
__license__ = 'MIT'
#NOTE: the sha* implementations are originally from ie. src: https://github.com/thomdixon/pysha2
#and only the code modifications/additions (and not the sha* implementations) are by Emanuel Czirai
__authors__ = "Thomas Dixon, Emanuel Czirai"
__maintainer__ = "Emanuel Czirai"
__version__ = "0.0.1"
__status__ = "Development"
#^ technically production-ready, but you should use hashlib instead!
#header info src: https://stackoverflow.com/a/1523456/19999437 and https://epydoc.sourceforge.net/manual-fields.html#module-metadata-variables

import copy
import struct
import sys


def new(m=None):
    return sha256(m)

class sha256(object):
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

    #these 3 aren't used, apparently, ok we're gonna make them be used:
    blocksize = 1
    block_size = 64
    element_size_bytes = 4 #added by me, size in bytes of one element of _k or _h
    element_size_bits=element_size_bytes*8
    block_size_minus_1 = block_size-1 #ie. 63
    digest_size = _output_size * element_size_bytes #==32bytes (8*4) for sha256, 28=(7*4) for sha224

    debug:bool=False #set to true to print stuff

    def __init__(self, m=None, encoding='utf8'):
        assert self.block_size-1 == self.block_size_minus_1
        assert self.block_size_minus_1+1 == self.block_size
        assert self._output_size*4 == self.digest_size #32 for sha256, 28 for sha224
        #print(sys.getsizeof(self._k[0])) # this is in bits!
        assert sys.getsizeof(self._k[0]) == sys.getsizeof(self._h[0])
        assert sys.getsizeof(self._k[0]) == self.element_size_bytes * 8
        assert sys.getsizeof(self._k[0]) == self.element_size_bits

        self._buffer = bytes()
        self._counter = 0

        if m is not None:
            if type(m) is str:
                m = bytes(m, encoding=encoding)
            if type(m) is not bytes:
                raise TypeError('%s() argument 1 must be bytes, not %s' % (self.__class__.__name__, type(m).__name__))
            self.update(m)

    def _rotr(self, x, y):
        return ((x >> y) | (x << (self.element_size_bits - y))) & 0xFFFFFFFF

    def _sha256_process(self, c):
        wtw_this_is=64 #it's 80 for sha512/384! 64 for sha256/224
        w = [0]*wtw_this_is
        w[0:16] = struct.unpack('!16L', c)
        #^ The form '!' represents the network byte order which is always big-endian as defined in IETF RFC 1700 https://tools.ietf.org/html/rfc1700
        # ^ L is unsigned long, integer, std size 4
        #src: https://docs.python.org/3/library/struct.html#struct.calcsize
        if self.debug:
            print(w)

        for i in range(16, wtw_this_is):
            s0 = self._rotr(w[i-15], 7) ^ self._rotr(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = self._rotr(w[i-2], 17) ^ self._rotr(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF

        a,b,c,d,e,f,g,h = self._h

        for i in range(wtw_this_is):
            s0 = self._rotr(a, 2) ^ self._rotr(a, 13) ^ self._rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = s0 + maj
            s1 = self._rotr(e, 6) ^ self._rotr(e, 11) ^ self._rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            t1 = h + s1 + ch + self._k[i] + w[i]

            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF

        self._h = [(x+y) & 0xFFFFFFFF for x,y in zip(self._h, [a,b,c,d,e,f,g,h])]

    def update(self, m, encoding='utf-8') -> sha256:
        if not m:
            return self
        if type(m) is str:
            m = bytes(m, encoding=encoding)
        if type(m) is not bytes:
            raise TypeError('%s() argument 1 must be bytes, not %s' % (sys._getframe().f_code.co_name, type(m).__name__))

        self._buffer += m
        self._counter += len(m)

        while len(self._buffer) >= self.block_size:
            self._sha256_process(self._buffer[:self.block_size])
            self._buffer = self._buffer[self.block_size:]
        return self

    def digest(self):
        if self.debug:
            print(f"{self._counter=} {0x3F=} {self._counter<<3=} {self.block_size_minus_1=}")
        mdi = self._counter & self.block_size_minus_1 #0x3F #that's 63 or 111111 but 11111 is 31; so this is mod 64
        #^ so mdi is the remainder of the size of buffer div 64, aka size mod 64
        if self.debug:
            print(f"{mdi=}")
        bit_shift_left_by_3 = self._counter<<3 #that's eg. 0b1 << 3 = 0b1000 aka 8
        if self.debug:
            print(f"{bit_shift_left_by_3=}")
        length = struct.pack('!Q', bit_shift_left_by_3)
        #^ Q is unsigned long long, integer, std size 8
        if self.debug:
            print(f"{length=}")

        if mdi < 56:
            #55 because 64-8-1=55 (length is 8 bytes, the first \x80 is 1 byte)
            padlen = 55-mdi
        else:
            #119 because 128-8-1=119 (length is 8 bytes, the first \x80 is 1 byte; see termination below)
            padlen = 119-mdi

        if self.debug:
            print(f"{padlen=}")

        r = self.copy()
        termination=b'\x80'+(b'\x00'*padlen)+length
        if self.debug:
            print(f"{termination=}")
        r.update(termination)
        return b''.join([struct.pack('!L', i) for i in r._h[:self._output_size]])

    def hexdigest(self):
        return self.digest().hex()

    def copy(self):
        return copy.deepcopy(self)
