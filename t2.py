#!/usr/bin/python3

from sha2 import *

sha256.debug=True
print(sha256("A").hexdigest())
