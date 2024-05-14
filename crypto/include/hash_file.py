import struct

def hash_file(ifile, ofile, format) -> int:
    hex_digest = ""
    match (format):
        case "md5":
            state = MD5()
            with open(ifile, 'rb') as fd:
                state.hash(fd)
                hex_digest = state.digest_50_char().hex()
        case "xxhash":
            state = XXHASH()
            with open(ifile, 'rb') as fd:
                file_contents = fd.read()
                hex_digest = state.xxhash(file_contents)
        case "murmur":
            state = MURMUR()
            with open(ifile, 'rb') as fd:
                file_contents = fd.read()
                hex_digest = state.murmurhash3(file_contents)
        case "sha256":
            state = SHA256()
            try:
                with open(ifile, 'rb') as fd:
                    file_contents = fd.read()
                    hex_digest = state.sha256(file_contents)
            except:
                if ifile is not None:
                    hex_digest = state.sha256(ifile)
                    print(hex_digest)
        case _:
            return -1

    if (ofile == "&1"):
        print(hex_digest)
    else:
        with open(ofile, "w") as fd:
            fd.write(hex_digest)
    
    return 0

def not_32(uint_32): return 0xffffffff - uint_32

def rotl_32(uint_32, shift): return ((uint_32 << (shift & 31)) | ((uint_32 & 0xffffffff) >> (32 - (shift & 31)))) & 0xffffffff

class MD5:
    block_size = 64
    k = (0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
         0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
         0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
         0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
         0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
         0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
         0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
         0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
         0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
         0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
         0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
         0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
         0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
         0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
         0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
         0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,)
    s = (7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
         5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,)
    g = [i for i in range(16)] + [(5 * i + 1) % 16 for i in range(16)] + [(3 * i + 5) % 16 for i in range(16)] + [(7 * i) % 16 for i in range(16)]

    def __init__(self):
        self.state = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,)
        self.length = 0
    
    def hash(self, bytestream):
        read = False
        while bytes_read := bytestream.read(MD5.block_size):
            read = True
            num_bytes = len(bytes_read)
            self.length += num_bytes
            if num_bytes < MD5.block_size:
                self.final(bytes_read)
                break
            self.handle(bytes_read)
        if not read:
            self.final(b'')

    def handle(self, bytestring):
        m = [int.from_bytes(bytestring[i:i + 4], byteorder='little') for i in range(0, MD5.block_size, 4)]
        funcs = [MD5.F for _ in range(16)] + [MD5.G for _ in range(16)] + [MD5.H for _ in range(16)] + [MD5.I for _ in range(16)]
        a, b, c, d = self.state
        mod = 2 << 31
        for i in range(MD5.block_size):
            a = (funcs[i](b, c, d) + a + MD5.k[i] + m[MD5.g[i]]) % mod
            a = (rotl_32(a, MD5.s[i]) + b) % mod
            a, b, c, d = d, a, b, c
        self.state = ((self.state[0] + a) % mod, (self.state[1] + b) % mod, (self.state[2] + c) % mod, (self.state[3] + d) % mod,)
    
    def final(self, bytestring):
        bytestring += b'\x80'
        size = len(bytestring)
        length_bytes_start = MD5.block_size - 8
        length_bytes = int.to_bytes(((self.length * 8) % (2 << 63)), length=8, byteorder='little')
        if size < length_bytes_start:
            bytestring = (b'\0' * (length_bytes_start - size)) + length_bytes
            self.handle(bytestring)
        elif size == length_bytes_start:
            bytestring += length_bytes
            self.handle(bytestring)
        else:
            bytestring += b'\0' * (MD5.block_size - size)
            self.handle(bytestring)
            self.handle((b'\0' * (length_bytes_start)) + length_bytes)
    
    def digest(self):
        return b''.join(s.to_bytes(length=4, byteorder='little') for s in self.state)

    def digest_50_char(self):
        digest = self.digest()
        digest_25_int = (int.from_bytes(digest, byteorder='little') ** 2) % (2 << 199)
        return digest_25_int.to_bytes(length=25, byteorder='little')
    
    def F(b, c, d): return d ^ (b & (c ^ d))
    
    def G(b, c, d): return c ^ (d & (b ^ c))
    
    def H(b, c, d): return b ^ c ^ d
    
    def I(b, c, d): return c ^ (b | not_32(d))


    def pad(msg):
        block_size = MD5.block_size
        if len (msg) > block_size:
            raise ValueError("msg must be less then or equal to 64 bytes (512 bits)")
        if len(msg) == block_size:
            return msg
        buf = b'\x80' + '\0' * (block_size - len(msg) - 1) 
        buf += msg
        return buf


class XXHASH:

    def xxhash(self, data, seed=123123123):
        """
        Calculate the xxHash of the given data.

        :param data: The data to be hashed.
        :param seed: Optional seed value (default is 0).
        :return: The xxHash of the data (truncated to 128 bits).
        """
        # Define prime numbers for hashing
        PRIME64_1 = 0x9E3779B185EBCA87
        PRIME64_2 = 0xC2B2AE3D27D4EB4F
        PRIME64_3 = 0x165667B19E3779F9
        PRIME64_4 = 0x85EBCA77C2B2AE63
        PRIME64_5 = 0x27D4EB2F165667C5

        # Initialize hash state
        h64 = seed + PRIME64_5

        # Process input in 8-byte chunks
        for i in range(0, len(data) // 8 * 8, 8):
            chunk = data[i:i + 8]
            if len(chunk) < 8:
                chunk += b'\x00' * (8 - len(chunk))  # Pad if chunk size is less than 8 bytes

            # Mix and process chunk
            chunk_val = int.from_bytes(chunk, 'little')
            h64 ^= (chunk_val * PRIME64_2) & 0xFFFFFFFFFFFFFFFF
            h64 = ((h64 << 31) | (h64 >> 33)) & 0xFFFFFFFFFFFFFFFF
            h64 = (h64 * PRIME64_1) & 0xFFFFFFFFFFFFFFFF

        # Process remaining bytes
        for i in range(0, len(data) % 8):
            h64 ^= data[len(data) - 1 - i] * PRIME64_1
            h64 = ((h64 << 25) | (h64 >> 39)) & 0xFFFFFFFFFFFFFFFF
            h64 = (h64 * PRIME64_4) & 0xFFFFFFFFFFFFFFFF

        # Finalize hash
        h64 ^= h64 >> 33
        h64 *= PRIME64_2
        h64 ^= h64 >> 29
        h64 *= PRIME64_3
        h64 ^= h64 >> 32

        # Convert 128-bit hash to hexadecimal string
        hash_str = h64 & ((1 << 256) - 1)
        # Convert the 256-bit hash to bytes (32 bytes)
        hash_bytes = hash_str.to_bytes(length=32, byteorder="little", signed=False)
        # Convert the bytes to hexadecimal string
        return hash_bytes.hex()[:50]
    
class MURMUR:
    def murmurhash2(self, key, seed=0):
        # Constants
        m = 0x5bd1e995
        r = 24
        length = len(key)

        # Initialize hash to seed value
        hash_value = seed ^ length

        # Mix function
        def mix(h, k):
            k *= m
            k ^= k >> r
            k *= m
            h *= m
            h ^= k
            return h

        # Update hash with each 4-byte chunk of the key
        while len(key) >= 4:
            chunk = int.from_bytes(key[:4], byteorder='little', signed=False)
            key = key[4:]
            hash_value = mix(hash_value, chunk)

        # Handle remaining bytes in key
        if len(key) > 0:
            tail = int.from_bytes(key, byteorder='little', signed=False)
            hash_value ^= tail
            hash_value *= m

        # Finalize hash
        hash_value ^= hash_value >> 13
        hash_value *= m
        hash_value ^= hash_value >> 15

        # Ensure hash is at least 50 characters long
        hex_hash = hex(hash_value)[2:]  # Remove '0x' prefix
        hex_hash += hex_hash * (50 // len(hex_hash) + 1)
        return hex_hash[:50]
    
    def murmurhash3(self, key, seed=0):
        ## https://en.wikipedia.org/wiki/MurmurHash
        # Constants
        c1 = 0xcc9e2d51
        c2 = 0x1b873593
        r1 = 15
        r2 = 13
        m = 5
        n = 0xe6546b64

        length = len(key)
        hash_value = seed

        # Process the key in 4-byte chunks
        for i in range(0, length, 4):
            k = key[i:i+4]
            k = k.ljust(4, b'\0')  # Pad key if it's less than 4 bytes
            k = int.from_bytes(k, byteorder='little', signed=False)

            k *= c1
            k &= 0xFFFFFFFF  # To ensure 32-bit integer overflow
            k = (k << r1 | k >> (32 - r1)) & 0xFFFFFFFF  # Rotate left
            k *= c2
            k &= 0xFFFFFFFF  # To ensure 32-bit integer overflow

            hash_value ^= k
            hash_value = ((hash_value << r2) | (hash_value >> (32 - r2))) * m + n
            hash_value &= 0xFFFFFFFF  # To ensure 32-bit integer overflow

        # Handle the remaining bytes
        tail = key[length & ~3:]
        if tail:
            k = int.from_bytes(tail, byteorder='little', signed=False)
            k *= c1
            k &= 0xFFFFFFFF  # To ensure 32-bit integer overflow
            k = (k << r1 | k >> (32 - r1)) & 0xFFFFFFFF  # Rotate left
            k *= c2
            k &= 0xFFFFFFFF  # To ensure 32-bit integer overflow
            hash_value ^= k

        # Finalize hash
        hash_value ^= length
        hash_value ^= hash_value >> 16
        hash_value *= 0x85ebca6b
        hash_value ^= hash_value >> 13
        hash_value *= 0xc2b2ae35
        hash_value ^= hash_value >> 16
    
        # Convert hash value to hexadecimal string
        hex_hash = hex(hash_value & 0xFFFFFFFF)  # Ensure 32-bit hash value
        return hex_hash

        
class SHA256:
    # https://en.wikipedia.org/wiki/SHA-2

    # Constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):

    def right_rotate(self, x, n):
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


    def sha256(self, message):
        h0 = 0x6a09e667
        h1 = 0xbb67ae85
        h2 = 0x3c6ef372
        h3 = 0xa54ff53a
        h4 = 0x510e527f
        h5 = 0x9b05688c
        h6 = 0x1f83d9ab
        h7 = 0x5be0cd19

        k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
         ]
        # Pre-processing:
        original_length = len(message)
        # Add a single '1' bit at the end of the message
        message += b'\x80'
        # Append '0' bits until the length of the message in bits is 448 (mod 512)
        while (len(message) * 8) % 512 != 448:
            message += b'\x00'

        # Append the original length of the message as a 64-bit big-endian integer
        original_length = (len(message) - 1) * 8  # Subtract 1 to exclude the appended '1' bit
        message += original_length.to_bytes(8, 'big')

        print(message)


        # Process the message in successive 512-bit chunks:
        for chunk_start in range(0, len(message), 64):
            # Initialize the eight working variables
            w = [0] * 64
            for i in range(16):
                w[i] = int.from_bytes(message[chunk_start + i * 4: chunk_start + (i + 1) * 4], 'big')
            for i in range(16, 64):
                s0 = self.right_rotate(w[i-15], 7) ^ self.right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
                s1 = self.right_rotate(w[i-2], 17) ^ self.right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)
                w[i] = (w[i-16] + s0 + w[i-7] + s1)

            # Initialize hash value for this chunk
            a = h0
            b = h1
            c = h2
            d = h3
            e = h4
            f = h5
            g = h6
            h = h7

            # Main loop
            for i in range(64):
                s1 = self.right_rotate(e, 6) ^ self.right_rotate(e, 11) ^ self.right_rotate(e, 25)
                ch = (e & f) ^ ((~e) & g)
                temp1 = (h + s1 + ch + k[i] + w[i])
                s0 = self.right_rotate(a, 2) ^ self.right_rotate(a, 13) ^ self.right_rotate(a, 22)
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (s0 + maj)

                h = g
                g = f
                f = e
                e = (d + temp1)
                d = c
                c = b
                b = a
                a = (temp1 + temp2)

            # Add this chunk's hash to result so far:
            h0 = (h0 + a)
            h1 = (h1 + b)
            h2 = (h2 + c)
            h3 = (h3 + d) 
            h4 = (h4 + e)
            h5 = (h5 + f)
            h6 = (h6 + g) 
            h7 = (h7 + h)

        # Produce the final hash value:
        digest = '{:08x}'.format(h0) + '{:08x}'.format(h1) + '{:08x}'.format(h2) + '{:08x}'.format(h3) + '{:08x}'.format(h4) + '{:08x}'.format(h5) + '{:08x}'.format(h6) + '{:08x}'.format(h7)
        return digest