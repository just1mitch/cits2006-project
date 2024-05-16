# A vignere cipher on the ASCII printable alphabet
from string import printable
from base64 import b64encode, b64decode


# Adapted from https://gist.github.com/flipperbw/8c93cc6c24db1a6c72953c38c385ab36
# and https://www.geeksforgeeks.org/vigenere-cipher/
def vig_encrypt(message, key):
    ciphertext = ""
    for i, char in enumerate(message):
        # Get the index of the current plaintext character
        plaintext_index = printable.index(char)
        # Get the index of the current key character
        key_index = printable.index(key[i % len(key)])

        ciphertext += printable[(plaintext_index + key_index) % len(printable)]
    # ASCII and Base64 encode
    return b64encode(ciphertext.encode("ascii"))
        
def vig_decrypt(ciphertext, key):
    ciphertext = b64decode(ciphertext).decode("ascii")
    plaintext = ""
    for i, char in enumerate(ciphertext):
        ciphertext_index = printable.index(char)
        key_index = printable.index(key[i % len(key)])

        plaintext += printable[(ciphertext_index - key_index) % len(printable)]
    
    return plaintext
