#!/usr/bin/python3

from sha2 import *

sha256.debug=True
print(sha256("Hello World!").hexdigest())
#sha512.debug=True
#print(sha512("A").hexdigest())

