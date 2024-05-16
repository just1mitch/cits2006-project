import math
import random
from cryptography.cryptoclasses import Cipher
from cryptography.include.encrypt import Ciphers


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
        #Check if file is already encrypted
        with open(self.key_file, 'r') as f:
            lines = f.readlines()
        for line in lines:
            if file_path in line:
                return
        self.cipher_handler.encrypt(file_path, self.stored_cipher)
        self.mark_file_as_encrypted(file_path)

    def decrypt(self, file_path):
        #Check if file is already decrypted
        can_decrypt = False
        with open(self.key_file, 'r') as f:
            lines = f.readlines()
        for line in lines:
            if file_path in line:
                can_decrypt = True
                break
        if not can_decrypt:
            return
        
        self.cipher_handler.decrypt(file_path, self.stored_cipher)
        self.unmark_file_as_encrypted(file_path)
    
    def mark_file_as_encrypted(self, file_path):
        with open(self.key_file, 'a') as f:
            f.write(f"{file_path}\n")

    def unmark_file_as_encrypted(self, file_path):
        with open(self.key_file, 'r') as f:
            lines = f.readlines()
        with open(self.key_file, 'w') as f:
            for line in lines:
                if file_path not in line:
                    f.write(line)
    
    def shuffle_encryption(self):
        #Decrypt all files
        with open(self.key_file, 'r') as f:
            lines = f.readlines()
        for line in lines[1:]:
            self.decrypt(line.strip())
        #Change the encryption key
        self.cipher_handler = Cipher(newkeysize=50)
        self.stored_key = self.cipher_handler.key
        self.stored_cipher = random.choice(list(Ciphers))

        with open(self.key_file, 'w') as f:
            f.write(f"{self.stored_cipher} {self.stored_key}")
