from secrets import choice
from string import ascii_letters, digits
from base64 import b64encode, b64decode

# Applies the xor function between each character of the string and key
# If the string is longer than the key, a modulo operator is used to loop
# over which character is xor'd
# Returns an ascii encoded 
def apply_xor(string, key):
    result = ""
    for i in range(len(string)):
        result += chr(ord(string[i]) ^ ord(key[i % len(key)]))
    return result

# Encrypts the plaintext with the key via an xor cipher
# Returns the encrypted message as ascii encoded, then base64 encoded
# This is used because it allows for the message to be stored without
# losing data
def xor_encrypt(plaintext, key):
    ciphertext = apply_xor(plaintext, key)
    return b64encode(ciphertext.encode("ascii"))

# Decrypts a base 64, ascii encoded ciphertext 
def xor_decrypt(ciphertext, key):
    ciphertext = b64decode(ciphertext).decode("ascii")
    plaintext = apply_xor(ciphertext, key)
    return plaintext