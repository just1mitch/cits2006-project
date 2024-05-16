# Generate a key of chosen length containing ascii printable characters
#
# Author: Mitchell Otley (23475725)
#
# Key is usable in any of the provided ciphers:
#   Quagmire3 cipher (rba_quagmire.py)
#   XOR cipher (rba_xor.py)
#   vigenere cipher (rba_vigenere.py)
#
from secrets import choice
from string import printable

# Generates a key of length 'length' from a random choice of
# ascii letters and digits and returns the key
def generate_key(length):
    key = ''.join(choice(printable) for i in range(length))
    return key