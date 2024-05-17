from cryptography.include.ciphers import (
    rba_vigenere,
    rba_xor,
    rba_quagmire,
)
from cryptography.include.encrypt import Ciphers

def decrypt(file, format, key):
    file_content: str = ""
    with open(file, "r") as fd:
        file_content = fd.read()
    
    match (format):
        case Ciphers.VIGENERE:
            file_content = rba_vigenere.vig_decrypt(file_content, key)
        case Ciphers.XOR:
            file_content = rba_xor.xor_decrypt(file_content, key)
        case Ciphers.QUAGMIRE:
            file_content = rba_quagmire.q3_decrypt(file_content, key)
        case _:
            return -1
    
    with open(file, "w") as fd:
        fd.write(file_content)
    
    return 0