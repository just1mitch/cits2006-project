# Quagmire3 Cipher based on the explanation given in
# https://sites.google.com/site/cryptocrackprogram/user-guide/cipher-types/substitution/quagmire
#
# Author: Mitchell Otley (23475725)
#
# Usage: 
# ciphertext = q3_encrypt(message, key)
# plaintext = q3_decrypt(ciphertext, key)
# Where message is a string, and key is a string 
# of any length that contains ascii-printable characters
#
from string import printable
from base64 import b64encode, b64decode
from util import generate_key

# The keyword length determines the number of keyed alphabets used
# and therefore the size of the groups the plaintext is split into
# the characters of the keyword also decide how much each iteration
# of the keyed alphabet is rotated
# The Keyword can include any ascii printable character
KEYWORD = "CIPHER" 

# The indicator is character that determines the period and alignment
# of the keyed alphabets generated usig the KEYWORD
INDICATOR = "A"

# In a quagmire cipher, the keyed alphabet is made from
# the first appearance of each alphanumeric character
# in the key (any unseen key is appended to the end)
def generate_keyed_alphabet(key):
    keyed_alphabet = ""
    for char in key:
        if char not in keyed_alphabet:
            keyed_alphabet += char
    # Add remaining unused alphanumeric characters to keyword
    for char in printable:
        if char not in keyed_alphabet:
            keyed_alphabet += char
    return keyed_alphabet

def generate_keyed_alphabet_table(keyed_alphabet):
    # For each char in the keyword, a new keyed_alphabet is created
    # where the original keyed_alphabet is rotated such that the char
    # is at the index of where the INDICATOR is in the original keyed_alphabet
    a_index = keyed_alphabet.index(INDICATOR)
    alphabet_table = []
    for letter in KEYWORD:
        l_index = keyed_alphabet.index(letter)
        if l_index > a_index:
            # rotate left by l_index - a_index if letter is after a
            part_alphabet = keyed_alphabet[l_index-a_index:] + keyed_alphabet[0:(l_index-a_index)]
        else:
            # else rotate right
            part_alphabet = keyed_alphabet[(len(keyed_alphabet) - l_index - a_index):] + keyed_alphabet[0:(len(keyed_alphabet) - l_index - a_index)]
        alphabet_table.append(part_alphabet)
    return alphabet_table

def q3_encrypt(plaintext, key):
    # Use the key to generate a keyed alphabet
    keyed_alphabet = generate_keyed_alphabet(key)
    # Create iterations of the keyed alphabet to encrypt with
    alphabet_table = generate_keyed_alphabet_table(keyed_alphabet)

    # Split the plaintext into groups of length 'keyword'
    plaintext_split = [plaintext[i:i+len(KEYWORD)] for i in range(0, len(plaintext), len(KEYWORD))]
    ciphertext = ""
    # Each character in the group is assigned a keyed_alphabet based on its
    # index (e.g. first character assigned to first keyed alphabet)
    for group in plaintext_split:
        for part, char in enumerate(group):
            keyed_alphabet_index = keyed_alphabet.index(char)
            ciphertext += alphabet_table[part][keyed_alphabet_index]
    
    # Return ascii and base64 encoded ciphertext for storage
    return b64encode(ciphertext.encode("ascii"))

def q3_decrypt(ciphertext, key):
    # Decode ciphertext
    decoded = b64decode(ciphertext).decode("ascii")
    # Generate keyed alphabet from key
    keyed_alphabet = generate_keyed_alphabet(key)
    # Generate table of keyed alphabets
    alphabet_table = generate_keyed_alphabet_table(keyed_alphabet)
    ciphertext_split = [decoded[i:i+len(KEYWORD)] for i in range(0, len(decoded), len(KEYWORD))]
    plaintext = ""

    for group in ciphertext_split:
        for part, char in enumerate(group):
            keyed_alphabet_index = alphabet_table[part].index(char)
            plaintext += keyed_alphabet[keyed_alphabet_index]

    return plaintext
