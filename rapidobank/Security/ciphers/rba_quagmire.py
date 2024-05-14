from encrypt import generate_key
from string import ascii_letters, digits

# In a quagmire cipher, the keyword is made from
# the first appearance of each alphanumeric character
# in the key
def generate_keyed_alphabet(key):
    keyed_alphabet = ""
    for char in key:
        if char not in keyed_alphabet:
            keyed_alphabet += char
    # Add remaining unused alphanumeric characters to keyword
    for char in ascii_letters + digits:
        if char not in keyed_alphabet:
            keyed_alphabet += char
    return keyed_alphabet

def q3_encrypt(plaintext, keyed_alphabet):
    return

if __name__ == "__main__":
    key = generate_key(50)
    keyed_alphabet = generate_keyed_alphabet(key)
    print(len(keyed_alphabet))