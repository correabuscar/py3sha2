#!/usr/bin/python3

from sha2 import *

sha256.debug=True
print(sha256("a").hexdigest())
#print(sha256("0123456789abcdefgh❧i").hexdigest())
#sha512.debug=True
#print(sha512("A").hexdigest())

