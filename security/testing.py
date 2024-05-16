from cryptography.cryptoclasses import Cipher
import os

# Generates new key of size 50 (i.e. for encrypting)
cipher = Cipher(newkeysize=50)
keystore = cipher.key
path = os.path.abspath('./security/testencrypt.txt')

# Encrypt file with new key
cipher.encrypt(path, 'xor')

print('encrypted')

# Some time later...

newcipher = Cipher(assignkey=keystore)

# Decrypt file with assigned key
cipher.decrypt(path, 'xor')
print('decrypted')