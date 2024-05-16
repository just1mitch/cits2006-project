# XOR Cipher
#
# Author: Mitchell Otley (23475725)
#
# Usage: 
# ciphertext = xor_encrypt(message, key)
# plaintext = xor_decrypt(ciphertext, key)
# Where message is a string, and key is a string
# of any length that contains ascii-printable characters
#
from base64 import b64encode, b64decode

# Applies the xor function between each character of the string and key
# If the string is longer than the key, a modulo operator is used to loop
# over the character used to do the xor operation
# Returns a characterwise xor'd string from the two provided strings
def apply_xor(string1, string2):
    result = ""
    for i in range(len(string1)):
        result += chr(ord(string1[i]) ^ ord(string2[i % len(string2)]))
    return result

# Encrypts the plaintext with the key via an xor cipher
# Returns the ciphertext as ascii encoded, then base64 encoded
def xor_encrypt(plaintext, key):
    ciphertext = apply_xor(plaintext, key)
    return b64encode(ciphertext.encode("ascii"))

# Decodes a base 64, ascii encoded ciphertext and decrypts it
# by calling the apply_xor function
# Returns the plaintext string
def xor_decrypt(ciphertext, key):
    ciphertext = b64decode(ciphertext).decode("ascii")
    plaintext = apply_xor(ciphertext, key)
    return plaintext