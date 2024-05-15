def not_32(uint_32): return 0xffffffff - uint_32

def rotl_32(uint_32, shift): return ((uint_32 << shift) | (uint_32 >> (32 - shift))) & 0xffffffff

def rotr_32(uint_32, shift): return ((uint_32 >> shift) | (uint_32 << (32 - shift))) & 0xFFFFFFFF