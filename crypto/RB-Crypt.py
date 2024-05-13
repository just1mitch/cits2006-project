#!/bin/python3

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

Behaviour:
  -e          : Expects an encryption format from [ e1 | e2 | ... ]
  -d          : Expects the encryption format from [ e1 | e2 | ... ]
  -h          : Expects a hash format from [ h1 | h2 | ... ]
  -i          : The file to be encryped/decrypted/hashed
  -o          : The file hash will be output to
  -k          : The raw key to use in encryption/decryption
  --key-file  : The file that holds the encryption/decryption key

Example:
  ./RB-Crypt.py -i infile -e format -k encryption-key -h hformat outfile
"""

if __name__ == "__main__":
    # Get args
    opts, args = getopt(argv[1:], "e:d:h:i:o:k:", ["help=", "key-file="])

    if ("--help", '',) in opts:
        print(usage)
        exit(0)

    # Define option structs
    perform: dict = {}

    ifile: str = None
    ofile: str = None
    key: str = None

    # Set options
    for opt in opts:
        match (opt[0]):
            case '-i':
                ifile = opt[1]
            case '-o':
                ofile = opt[1]
            case '-e':
                perform["encrypt"] = opt[1].lower()
            case '-d':
                perform["decrypt"] = opt[1].lower()
            case '-h':
                perform["hash"] = opt[1].lower()
            case '-k':
                key = opt[1]
            case "--key-file":
                if key is None:
                    key = opt[1]

    # Ensure proper options
    if ("encrypt" in perform or "decrypt" in perform) and key is None:
        print(f"requires key for encryption or decryption\n\n{usage}")
        exit(1)

    if ifile is None:
        if len(args) < 1:
            print(f"requires input file\n\n{usage}")
            exit(1)
        else:
            ifile = args[0]

    if "hash" in perform and ofile is None:
        if args == 2:
            ofile = args[1]
        else:
            ofile = ifile + ".hash"

    # Perform operations
    if "encrypt" in perform:
        if encrypt.encrypt(ifile, perform["encrypt"], key) != 0:
            print(f"error occured while encrypting\n{usage}")
            exit(0)
    if "hash" in perform:
        if hash_file.hash_file(ifile, perform["hash"]) != 0:
            # print(f"error occured while hashing\n{usage}")
            exit(0)
    if "decrypt" in perform:
        if decrypt.decrypt(ifile, perform["decrypt"], key) != 0:
            print(f"error occured while decyrpting\n{usage}")
            exit(0)
