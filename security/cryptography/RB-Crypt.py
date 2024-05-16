#!/usr/bin/env python3

"""
Author 1: Elijah Mullens (23335907)
Purpose: CITS2006 Group Project, UWA
Date: Semester 1, 2024
"""


from sys import argv
from getopt import getopt

from include import (
    encrypt,
    decrypt,
    hash_file,
)

from include.ciphers.util import generate_key


usage = """
A way of encrypting and hashing files, designed for the Rapido Bank file
system.

Usage:
  ./RB-Crypt.py [options] [input file] [output file]

Options:
  --help      : Help
  -e          : Encrypt
  -d          : Decrypt
  -h          : Hash
  -i          : Input File
  -o          : Output File
  -k          : Key
  --key-file  : Key File
  --key-gen   : Generate Key

Behaviour:
  -e          : Expects an encryption format from [ vigenere | xor | quagmire ]
  -d          : Expects the encryption format from [ vigenere | xor | quagmire ]
  -h          : Expects a hash format from [ md5 | xxhash | murmur | sha256 ]
  -i          : The file to be encryped/decrypted/hashed
  -o          : The file hash will be output to
  -k          : The raw key to use in encryption/decryption
  --key-file  : The file that holds the encryption/decryption key
  --key-gen   : Generates a key of length 50. If used in conjuction with -e, a
                file with extension .key is created to store the key, otherwise
                the key will be printed to stdout

Example:
  ./RB-Crypt.py -i infile -e format -k encryption-key -h hformat outfile
"""

if __name__ == "__main__":
    # Get args
    opts, args = getopt(argv[1:], "e:d:h:i:o:k:", ["help", "key-file=", "key-gen"])

    if ("--help", '',) in opts:
        print(usage)
        exit(0)

    # Define option structs
    perform: dict = {}

    ifile: str = None
    ofile: str = None
    key: str = None
    keygen: bool = False

    ciphers = ['vigenere', 'xor', 'quagmire']
    hashes = ['md5', 'xxhash', 'murmur', 'sha256']

    out_message: str = ""

    # Set options
    for opt in opts:
        match (opt[0]):
            case '-i':
                ifile = opt[1]
            case '-o':
                ofile = opt[1]
            case '-e':
                _check = opt[1].lower()
                if _check not in ciphers:
                    out_message += f"avaliable encryption ciphers: {', '.join(ciphers)}\n"
                else:
                    perform["encrypt"] = _check
            case '-d':
                _check = opt[1].lower()
                if _check not in ciphers:
                    out_message += f"avaliable encryption ciphers: {', '.join(ciphers)}\n"
                else:
                    perform["decrypt"] = _check
            case '-h':
                _check = opt[1].lower()
                if _check not in hashes:
                    out_message += f"avaliable encryption ciphers: {', '.join(hashes)}\n"
                else:
                    perform["hash"] = _check
            case '-k':
                key = opt[1]
            case "--key-file":
                if key is None:
                    with open(opt[1], 'r') as fd:
                        key = fd.read()
            case "--key-gen":
                keygen = True
    
    if out_message != "":
        print(out_message)
        exit(1)

    # Ensure proper options
    if "decrypt" in perform and key is None:
        print(f"requires key for decryption\n\n{usage}")
        exit(1)

    grabbed_ifile: bool = False
    if ifile is None:
        if len(args) < 1:
            print(f"requires input file\n\n{usage}")
            exit(1)
        else:
            grabbed_ifile = True
            ifile = args[0]
    
    # if "encrypt" in perform:
    #     if key is None:
    #         if keygen:
    #             key = generate_key(50)
    #             with open(f"{ifile}.key", 'w') as fd:
    #                 fd.write(key)
    #         else:
    #             print(f"requires key for decryption\n\n{usage}")
    #             exit(1)
    if keygen:
        if "encrypt" in perform and key is None:
            key = generate_key(50)
            with open(f"{ifile}.key", "w") as fd:
                fd.write(key)
        else:
            print(generate_key(50))
    
    if "encrypt" in perform and key is None:
        print(f"key required for encryption\n\n{usage}")
        exit(1)

    if "hash" in perform and ofile is None:
        if args == 1 and not grabbed_ifile:
            ofile = args[0]
        elif args == 2:
            ofile = args[1]
        else:
            ofile = ifile + ".hash"

    # Perform operations
    if "encrypt" in perform:
        if encrypt.encrypt(ifile, perform["encrypt"], key) != 0:
            print(f"error occured while encrypting\n{usage}")
            exit(1)
    if "hash" in perform:
        if hash_file.hash_file(ifile, ofile, perform["hash"]) != 0:
            # print(f"error occured while hashing\n{usage}")
            exit(1)
    if "decrypt" in perform:
        if decrypt.decrypt(ifile, perform["decrypt"], key) != 0:
            print(f"error occured while decyrpting\n{usage}")
            exit(1)
