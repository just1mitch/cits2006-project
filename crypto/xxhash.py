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
        hash_str = h64 & int.from_bytes((b'\xff' * 32), byteorder="little") - 1
        # Convert the 256-bit hash to bytes (3372438548945421310400603113032345769924716067099285175102
        hash_bytes = hash_str.to_bytes(length=25, byteorder="little", signed=False)
        # Convert the bytes to hexadecimal string
        return hash_bytes.hex()
    
hasher = XXHASH()
print(hasher.xxhash(data=b"1245678"))