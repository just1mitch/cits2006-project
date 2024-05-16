from security.cryptography.cryptoclasses import Cipher


class Encryptor:
    def __init__(self, key):
        if key:
            self.cipher = Cipher(assignkey=key)
        else:
            self.cipher = Cipher(newkeysize=50)

    def encrypt(self, file_path):
        return self.cipher.encrypt(file_path, 'xor')

    def decrypt(self, file_path):
        return self.cipher.decrypt(file_path, 'xor')