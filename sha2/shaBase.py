#!/usr/bin/python3

from __future__ import annotations #needed for return type to be the same class type ie. -> sha256
#^ SyntaxError: from __future__ imports must occur at the beginning of the file

__author__ = 'Thomas Dixon'
__license__ = 'MIT'
#NOTE: the sha* implementations are originally from src: https://github.com/thomdixon/pysha2
#and only the code modifications/additions (and not the sha* implementations) are by Emanuel Czirai
__authors__ = "Thomas Dixon, Emanuel Czirai"
__maintainer__ = "Emanuel Czirai"
__version__ = "0.0.4"
__status__ = "Development"
#^ technically production-ready, but you should use hashlib instead!
#header info src: https://stackoverflow.com/a/1523456/19999437 and https://epydoc.sourceforge.net/manual-fields.html#module-metadata-variables

import copy
import struct
import sys
#import abc #abstract base class
from abc import ABC, abstractmethod


class shaBase(ABC): #metaclass=abc.ABCMeta):
    #blocksize = 1 #don't know what this is! and it's not used
    debug:bool=False #set to true to print stuff
    default_string_encoding = 'utf8' #or 'utf-8' same thing

    #------

    #using tricks from src: https://stackoverflow.com/a/53417582/19999437
    @property
    @abstractmethod
    def element_size_bytes(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def block_size(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def _h(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def _output_size(self):
        raise NotImplementedError


    #@abstractmethod #this prevents instantiating shaBase! and subclasses must override this to be instantiable themselves! ugly hack if you ask me. Ok, don't need this anymore due to the above ones!
    #def dummy(self):
    #    pass

    #------

    #Computed in subclass at __init__ time:
    element_size_bits:int=0
    _k = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
          0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
          0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
          0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
          0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
          0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
          0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
          0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
          0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
          0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
          0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
          0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
          0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
          0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
          0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
          0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
          0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
          0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
          0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
          0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]

    #readonly: TODO: how?
    _big_endian_char='!' #in struck.pack/unpack, that's network ordering which is BE aka big endian
    _big_endian_Q_struct_str=_big_endian_char+'Q' #aka '!Q' aka BE 8 bytes or 64 bits


    #TODO: actually read the pdf, rather than try to understand things from this code.

    def __init__(self, m=None, encoding:str=None):
        super().__init__()

        if encoding is None:
            encoding=self.default_string_encoding

        if self.__class__ != shaBase: #this 'if' isn't needed now due to ABC not allowing shaBase to be instantiated!
            #recompute static fields, well, actually, define them for the first time
            self.block_size_minus_1 = self.block_size-1 #ie. 63
            self.element_size_bits = self.element_size_bytes*8 #ie. 32 bits
            self.element_size_mask = 2**self.element_size_bits-1 #eg. 2^32-1==0xFFFFFFFF for sha256; a bit mask that's the size of the element of _k or _h
            match self.element_size_bytes:
                case 4: self.element_size_char = 'L' #aka 4*8=32 bits
                case 8: self.element_size_char = 'Q' #aka 8*8=64 bits
                case _: raise Exception(f"unexpected {self.element_size_bytes=} (should be 4 or 8)")
            self.digest_size = self._output_size * self.element_size_bytes #==32bytes (8*4) for sha256, 28=(7*4) for sha224, and for sha384 and sha512 is 6*8=48 respectively 8*8=64
            #doneFIXME: find proper name for this:

            if self.block_size == 64:
                #print(f"{len(self._k)=}")
                self._k=self._k[:64] #only first 64 of _k are used for sha224 and sha256, else all 80 for sha384 and sha512
                #^ the above two 64s are unrelated!
                #print(f"{len(self._k)=}")
                #for each in self._k:
                #    each=each & self.element_size_mask
                for idx,elem in enumerate(self._k):
                    #print(f"{self._k[idx]=:X} {idx=} {elem=:X} {elem >> self.element_size_bytes=:X} {self.element_size_mask=:x} {self.element_size_bytes=}")
                    self._k[idx]=elem >> self.element_size_bits  #self.element_size_mask
                #assert self._k == list(self._kactual)
            #print(f"{len(self._k)=}") #this is 80 for sha512 and 64 for sha256
            self._len_of_k=len(self._k)


        self.check_invariants()

        self._buffer = bytes()
        self._counter = 0

        if m is not None: #eg. not empty string, then
            if type(m) is str:
                assert encoding is not None
                m = bytes(m, encoding=encoding)
            if type(m) is not bytes:
                raise TypeError('%s() argument 1 must be bytes or str, not %s' % (self.__class__.__name__, type(m).__name__))
            self.update(m)

    def check_invariants(self):
        assert len(self._k) == self._len_of_k
        match self.__class__.__name__:
            case 'sha384' | 'sha512': assert 80 == self._len_of_k
            case 'sha224' | 'sha256': assert 64 == self._len_of_k
            #self._len_of_k = 64 #it's 80 for sha512/384! 64 for sha256/224
            case _: raise Exception(f"Unexpected {self.__class__.__name__=}")
        for each in self._k:
            assert each & self.element_size_mask == each

        assert self.block_size in [64,128]
        assert self.block_size - 1 == self.block_size_minus_1
        assert self.block_size_minus_1 + 1 == self.block_size
        assert self.element_size_bytes * 16==self.block_size #TODO: should I derrive it from this? maybe read PDF to see if any relation!
        assert self._output_size * self.element_size_bytes == self.digest_size #32 for sha256, 28 for sha224
        #print(sys.getsizeof(self._k[0])) # this is in bits!
        #assert sys.getsizeof(self._k[0]) == sys.getsizeof(self._h[0])
        #for i in self._k:
            #    print(f"{sys.getsizeof(i)=} {i=}")
        #print(f"{sys.getsizeof(self._k[0])=} {self.__class__=}") #FIXME: this is 36 for sha384 /:)
        #well that getsizeof() is no good https://stackoverflow.com/a/10365639/19999437
        #assert sys.getsizeof(self._k[0]) == self.element_size_bytes * 8 #8 bits per byte
        #assert sys.getsizeof(self._k[0]) == self.element_size_bits
        assert self.element_size_bytes * 8 == self.element_size_bits

        #TODO: rename mask to bitmask
        match self.element_size_bytes:
            case 4: actual_mask=0xFFFFFFFF
            case 8: actual_mask=0xFFFFFFFFFFFFFFFF
            case _: raise Exception(f"unexpected {self.element_size=} (should be 4 or 8)")
        assert (2 ** self.element_size_bits) - 1 == actual_mask
        assert 2 ** self.element_size_bits - 1 == self.element_size_mask

        #
        #print(f"{self.element_size_mask ^ self._k[0]=:b}")
        assert (self._k[0] & self.element_size_mask) == self._k[0]
        assert (self._k[0] & self.element_size_mask) ^ self._k[0] == 0
        assert (self.element_size_mask ^ self._k[0]) == (self._k[0] & self.element_size_mask) ^ self.element_size_mask
        #

        #
        for jlist in [self.s0_bit_ops1,
                  self.s1_bit_ops1,
                  self.s0_bit_ops2,
                  self.s1_bit_ops2]:
            assert len(jlist)==3
            for i in jlist:
                assert i<64
                assert i>0
        #

        if self.__class__.__name__ in ['sha384', 'sha512']:
            assert 80 == self._len_of_k
        elif self.__class__.__name__ in ['sha224', 'sha256']:
            assert 64 == self._len_of_k
        else:
            raise Exception(f"unexpected {self.__class__.__name__=}")

    def _rotr(self, x, y):
        return ((x >> y) | (x << (self.element_size_bits - y))) & self.element_size_mask

    def _process(self, c):
        w = [0]*self._len_of_k
        w[0:16] = struct.unpack(self._big_endian_char+'16'+self.element_size_char, c)
        #^ The form '!' represents the network byte order which is always big-endian as defined in IETF RFC 1700 https://tools.ietf.org/html/rfc1700
        # ^ L is unsigned long, integer, std size 4
        #src: https://docs.python.org/3/library/struct.html#struct.calcsize
        if self.debug:
            print("w=[")
            print(", ".join(f"0x{num:0{self.element_size_bytes*2}X}" for num in w))
            #print(", ".join(f"0x{num:0{self.element_size_bytes*2}X}" for num in w if num!=0))
            print("]")

        for i in range(16, self._len_of_k):
            s0 = self._rotr(w[i-15], self.s0_bit_ops1[0]) ^ self._rotr(w[i-15], self.s0_bit_ops1[1]) ^ (w[i-15] >> self.s0_bit_ops1[2])
            s1 = self._rotr(w[i-2], self.s1_bit_ops1[0]) ^ self._rotr(w[i-2], self.s1_bit_ops1[1]) ^ (w[i-2] >> self.s1_bit_ops1[2])
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & self.element_size_mask

        a,b,c,d,e,f,g,h = self._h

        for i in range(self._len_of_k):
            s0 = self._rotr(a, self.s0_bit_ops2[0]) ^ self._rotr(a, self.s0_bit_ops2[1]) ^ self._rotr(a, self.s0_bit_ops2[2])
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = s0 + maj
            s1 = self._rotr(e, self.s1_bit_ops2[0]) ^ self._rotr(e, self.s1_bit_ops2[1]) ^ self._rotr(e, self.s1_bit_ops2[2])
            ch = (e & f) ^ ((~e) & g)
            t1 = h + s1 + ch + self._k[i] + w[i]

            h = g
            g = f
            f = e
            e = (d + t1) & self.element_size_mask
            d = c
            c = b
            b = a
            a = (t1 + t2) & self.element_size_mask

        self._h = [(x+y) & self.element_size_mask for x,y in zip(self._h, [a,b,c,d,e,f,g,h])]

    def update(self, m, encoding:str=None) -> shaBase:
        if not m:  #hmm, this matches empty string doesn't it? yes!
            return self

        if encoding is None:
            encoding=self.default_string_encoding

        if type(m) is str:
            assert encoding is not None
            m = bytes(m, encoding=encoding)
        if type(m) is not bytes:
            raise TypeError('%s() argument 1 must be bytes or str, not %s' % (sys._getframe().f_code.co_name, type(m).__name__))

        self._buffer += m
        self._counter += len(m)

        #doneFIXME: get rid of the compile errors whilst in vim like below: (because these are private fields inited only from subclass!)
        while len(self._buffer) >= self.block_size:
            self._process(self._buffer[:self.block_size])
            self._buffer = self._buffer[self.block_size:]
        return self

    def digest(self):
        if self.debug:
            print(f"{self._counter=} {0x3F=} {self._counter<<3=} {self.block_size_minus_1=}")
        mdi = self._counter & self.block_size_minus_1 #0x3F #that's 63 or 111111 but 11111 is 31; so this is mod 64
        #^ so mdi is the remainder of the size of buffer div 64, aka size mod 64; ie. bytes
        if self.debug:
            print(f"{mdi=}")
        bit_shift_left_by_3 = self._counter<<3 #that's eg. 0b1 << 3 = 0b1000 aka 8
        if self.debug:
            print(f"{bit_shift_left_by_3=}")
        length = struct.pack(self._big_endian_Q_struct_str, bit_shift_left_by_3)
        #^ Q is unsigned long long, integer, std size 8 (it's always 8 here, even for sha512)

        len_length=len(length)
        assert 8 == len_length

        if self.debug:
            print(f"{length=} {len(length)=}")

        if self.__class__.__name__ in ['sha384', 'sha512']:
            times=2
        else:
            times=1

        #if mdi < 56: # < 112 for sha512
        if mdi < self.block_size - (times * len_length): # -8 bytes of 'length' for sha256, -16 for sha512 !
            #55 because 64-8-1=55 (length is 8 bytes for sha256, the first \x80 is 1 byte)
            padlen = (self.block_size -len_length -1) -mdi # so 55-mdi for sha256, and 111-mdi for sha512
        else:
            #119 because 2*64-8-1=119 (length is 8 bytes for sha256(twice for sha512), the first \x80 is 1 byte; see termination below)
            padlen = (2*self.block_size -len_length -1) -mdi #so 119-mdi for sha256, 239-mdi for sha512

        if self.debug:
            print(f"{padlen=}")

        r = self.copy()
        termination=b'\x80'+(b'\x00'*padlen)+length
        if self.debug:
            print(f"{termination=}")
        r.update(termination)
        return b''.join([struct.pack(self._big_endian_char+self.element_size_char, i) for i in r._h[:self._output_size]])

    def hexdigest(self):
        return self.digest().hex()

    def copy(self):
        return copy.deepcopy(self)


#TODO: make this a test:
#a=shaBase() #doneFIXME: oh goodie, can still instantiate this, then why use abc. Must use @abstractmethod, done!

