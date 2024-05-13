from io import BytesIO

def hash_file(file, format) -> int:
    match (format):
        case "md5":
            state = MD5()
            with open(file, 'rb') as fd:
                state.hash(fd)
                print(state.digest().hex() == 'd41d8cd98f00b204e9800998ecf8427e')
                print(state.digest().hex())
                return 0
        case _:
            return -1

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

    def digest_char_num(self, num_chars):
        return
    
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
