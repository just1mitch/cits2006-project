class MURMUR:
    def murmurhash2(self, key, seed=0):
        # Constants
        m = 0x5bd1e995
        r = 24
        length = len(key)

        # Initialize hash to seed value
        hash_value = seed ^ length

        # Mix function
        @staticmethod
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