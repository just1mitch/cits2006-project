import base64
import math
import os
import random
from cryptography.cryptoclasses import Cipher
from cryptography.include.encrypt import Ciphers


class Encryptor:
    def __init__(self, quarantiner_dir: str, sensitive_dirs: list[str]):
        self.key_file = quarantiner_dir + '/.encryption'
        self.sensitive_dirs = sensitive_dirs
        with open(self.key_file, 'r') as f:
            contents = f.read().strip()
            if contents:
                self.stored_cipher, stored_key = contents.split(' ', maxsplit=1)
            else:
                self.stored_cipher = None
                stored_key = None

        print(f"Stored cipher: {self.stored_cipher}")
        print(f"Stored key: {stored_key}")
        if stored_key:
            print("Using stored cipher key...")
            self.cipher_handler = Cipher(assignkey=base64.b64decode(stored_key.encode('ascii')).decode('ascii'))
            self.stored_cipher = Ciphers[self.stored_cipher]
        else:
            print("Generating new cipher key and choosing new cipher...")
            self.cipher_handler = Cipher(newkeysize=50)
            self.stored_cipher = random.choice(list(Ciphers))
        self.stored_key = self.cipher_handler.key

        if not contents:
            with open(self.key_file, 'w') as f:
                f.write(f"{self.stored_cipher.name} {base64.b64encode(self.stored_key.encode('ascii')).decode('ascii')}\n")

    def encrypt(self, file_path):
        #Check if file is already encrypted
        with open(self.key_file, 'r') as f:
            lines = f.readlines()
        for line in lines:
            if file_path in line:
                return
        self.cipher_handler.encrypt(file_path, cipher=self.stored_cipher)
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
            print(f"File {file_path} is not encrypted!")
            return
        else:
            print(f"Decrypting {file_path}")
            self.cipher_handler.decrypt(file_path, cipher=self.stored_cipher)
            self.unmark_file_as_encrypted(file_path)

    def encrypt_unencrypted(self):
        for sensitive_dir in self.sensitive_dirs:
            for root, dirs, files in os.walk(sensitive_dir):
                for file in files:
                    print(f"Encrypting {os.path.join(root, file)}")
                    self.encrypt(os.path.join(root, file))
    
    def decrypt_encrypted(self):
        for sensitive_dir in self.sensitive_dirs:
            for root, dirs, files in os.walk(sensitive_dir):
                for file in files:
                    self.decrypt(os.path.join(root, file))
    
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
        self.decrypt_encrypted()
        #Change the encryption key
        self.cipher_handler = Cipher(newkeysize=50)
        self.stored_key = self.cipher_handler.key
        self.stored_cipher = random.choice(list(Ciphers))

        with open(self.key_file, 'w') as f:
            f.write(f"{self.stored_cipher.name} {base64.b64encode(self.stored_key.encode('ascii')).decode('ascii')}\n")
        
        #Reencrypt the files
        self.encrypt_unencrypted()