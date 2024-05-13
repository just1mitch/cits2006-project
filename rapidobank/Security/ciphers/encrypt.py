from secrets import choice
from string import printable

# Generates a key of length 'length' from a random choice of
# ascii letters and digits and returns the key
def generate_key(length):
    key = ''.join(choice(printable) for i in range(length))
    return key