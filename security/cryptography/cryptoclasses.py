from cryptography.include import (
    encrypt as encrypt_lib, 
    decrypt, 
    hash_file
)

from cryptography.include.ciphers.util import generate_key

# Cipher class to allow MTD to interact with cipher algorithms
# Performs encryption and decryption, as well as key generation if needed
class Cipher:

    # Create instance of Cipher with one of the following attributes
    # assignkey - If you have a key that you want to be able to encrypt/decrypt a file with
    # newkeysize - Instance will generate its own new key for you to use
    # Assigns the key (generated or assigned) to self.key
    def __init__(self, assignkey=None, newkeysize=None):
        if assignkey is not None:
            self.key = assignkey
        elif newkeysize is not None:
            self.key = generate_key(newkeysize)
        else:
            raise ValueError("Either a keysize or key must be provided.")

    # Encrypt file with given cipher
    # Cipher is one of the following: 
    # 'xor': XOR Cipher
    # 'vigenere': Vignere Cipher
    # 'quagmire': Quagmire 3 Cipher
    def encrypt(self, file, cipher: encrypt_lib.Ciphers):
        encrypt_lib.encrypt(file, cipher, self.key)

    # Decrypt file with given cipher
    # Cipher is one of the following: 
    # 'xor': XOR Cipher
    # 'vigenere': Vignere Cipher
    # 'quagmire': Quagmire 3 Cipher
    def decrypt(self, file, cipher: encrypt_lib.Ciphers):
        decrypt.decrypt(file, cipher, self.key)

# Hash class to allow MTD to interact with hashing algorithms
class Hash:

    # Hashes the input file and stores
    def hash(input, output, format):
        return hash_file(input, output, format)
    