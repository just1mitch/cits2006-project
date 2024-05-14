from include.ciphers import (
    rba_vigenere,
    rba_xorcipher,
    rba_quagmire,
)

def encrypt(file, format, key):
    file_content: str = ""
    with open(file, "r") as fd:
        file_content = fd.read()
    
    match (format):
        case 'vigenere':
            file_content = rba_vigenere.vig_encrypt(file_content, key)
        case 'xor':
            file_content = rba_xorcipher.xor_encrypt(file_content, key)
        case 'quagmire.py':
            file_content = rba_quagmire.q3_encrypt(file_content, key)
        case _:
            return -1
    
    with open(file, "wb") as fd:
        fd.write(file_content)
    
    return 0