from enum import Enum

from cryptography.include.ciphers import (
    rba_vigenere,
    rba_xor,
    rba_quagmire,
)

class Ciphers(Enum):
    VIGENERE = 'vigenere'
    XOR = 'xor'
    QUAGMIRE = 'quagmire'

def encrypt(file, format: Ciphers, key):
    file_content: str = ""
    with open(file, "r") as fd:
        file_content = fd.read()
    
    match (format):
        case Ciphers.VIGENERE:
            file_content = rba_vigenere.vig_encrypt(file_content, key)
        case Ciphers.XOR:
            file_content = rba_xor.xor_encrypt(file_content, key)
        case Ciphers.QUAGMIRE:
            file_content = rba_quagmire.q3_encrypt(file_content, key)
        case _:
            return -1
    
    with open(file, "wb") as fd:
        fd.write(file_content)
    
    return 0
