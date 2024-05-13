from math import gcd

p = 257 # Prime 1
q = 191 # Prime 2

n = p * q # Modulus

# Euler's Totient Function
euler = (p-1) * (q-1)

# Pick integer relatively prime to e
gcd_list = []
for i in range(2, euler):
    if gcd(i,euler) == 1:
        gcd_list.append(i)

if len(gcd_list) < 1:
    exit()

e = gcd_list[0] # take first relatively prime number
d = pow(e, -1, euler) # calculate d

message = "message"
# Encryption
ciphertext = ""
for i in message:
    ciphertext += str(pow(ord(i),e,n)) + "\t"

print(ciphertext)

# Decryption
plaintext = ""
char_list = ciphertext.split('\t')
for i in char_list[:-1]:
    plaintext += chr(pow(int(i),d, n))

print(plaintext)