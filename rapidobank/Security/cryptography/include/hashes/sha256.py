from include.hashes.util import rotr_32

class SHA256:
    # Constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
    def sha256(self, ifile):
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
        
        try:
            with open(ifile, 'rb') as fd:
                message = fd.read()
        except:
            message = ifile

        # Pre-processing:
        original_length = len(message) * 8
        message += b'\x80'  # Append 1 bit by adding a single byte with 0b10000000
        while (len(message) * 8) % 512 != 448:
            message += b'\x00'  # Append 0 bits by adding a single byte with all bits set to 0

        original_length = original_length.to_bytes(8, 'big')
        message += original_length

        # Process the message in successive 512-bit chunks:
        for chunk_start in range(0, len(message), 64):
            # Initialize the eight working variables
            w = [0] * 64
            for i in range(16):
                w[i] = int.from_bytes(message[chunk_start + i * 4: chunk_start + (i + 1) * 4], 'big')
            for i in range(16, 64):
                s0 = rotr_32(w[i-15], 7) ^ rotr_32(w[i-15], 18) ^ (w[i-15] >> 3)
                s1 = rotr_32(w[i-2], 17) ^ rotr_32(w[i-2], 19) ^ (w[i-2] >> 10)
                w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF

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
                s1 = rotr_32(e, 6) ^ rotr_32(e, 11) ^ rotr_32(e, 25)
                ch = (e & f) ^ ((~e) & g)
                temp1 = (h + s1 + ch + k[i] + w[i]) & 0xFFFFFFFF
                s0 = rotr_32(a, 2) ^ rotr_32(a, 13) ^ rotr_32(a, 22)
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (s0 + maj) & 0xFFFFFFFF

                h = g
                g = f
                f = e
                e = (d + temp1) & 0xFFFFFFFF
                d = c
                c = b
                b = a
                a = (temp1 + temp2) & 0xFFFFFFFF

            # Add this chunk's hash to result so far:
            h0 = (h0 + a) & 0xFFFFFFFF
            h1 = (h1 + b) & 0xFFFFFFFF
            h2 = (h2 + c) & 0xFFFFFFFF
            h3 = (h3 + d) & 0xFFFFFFFF
            h4 = (h4 + e) & 0xFFFFFFFF
            h5 = (h5 + f) & 0xFFFFFFFF
            h6 = (h6 + g) & 0xFFFFFFFF
            h7 = (h7 + h) & 0xFFFFFFFF

        # Produce the final hash value:
        digest = '{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}'.format(h0, h1, h2, h3, h4, h5, h6, h7)
        return digest