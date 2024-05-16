import math
import random
from security.cryptography.cryptoclasses import Cipher
from security.cryptography.include.encrypt import Ciphers


class Encryptor:
    def __init__(self, quarantiner_dir):
        self.key_file = quarantiner_dir + '/.encryption'
        with open(self.key_file, 'r') as f:
            contents = f.read().strip()
            if contents:
                self.stored_cipher, stored_key = contents.split(' ', maxsplit=1)
            else:
                self.stored_cipher, stored_key = random.choice(list(Ciphers)), None

        self.cipher_handler = Cipher(newkeysize=50) if stored_key is None else Cipher(assignkey=stored_key)
        self.stored_key = self.cipher_handler.key

        with open(self.key_file, 'w') as f:
            f.write(f"{self.stored_cipher} {self.stored_key}")

    def encrypt(self, file_path):
        return self.cipher_handler.encrypt(file_path, self.stored_cipher)

    def decrypt(self, file_path):
        return self.cipher_handler.decrypt(file_path, self.stored_cipher)