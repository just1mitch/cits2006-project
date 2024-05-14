# CITS2006 Group Report
## Authors
- Daniel Jennings (23064976)
- Izzy Scott (23105336)
- Elijah Mullens (23335907)
- Joel Willoughby (23135002)
- Mitchell Otley (23475725)
## Overview
Below is a description of our implementation of the project specification to design security solutions for the RapidoBank Filesystem.

This report is separated into each section of the project specification:

- [Yara Engine](#yara-engine-designed-by-joel-and-mitchell)
- [Cipher system and Hashing Algorithm](#cipher-system-and-hashing-algorithm-designed-by-elijah)
- [MTD System](#mtd-system-designed-by-izzy-and-daniel)
- [Dynamic Security Recommendations](#dynamic-security-recommendations)

## Yara Engine (Designed by Joel and Mitchell)

## Cipher System and Hashing Algorithm (Designed by Elijah)\

### Brief
The RB-Cyrpt.py script is designed to be a diverse command line tool to
encrypt, decrypt, and hash the requested file. The CLI tool utilises a set of
flags to differentiate what is happening. An example of how to use the tool is
as follows; 

Say we have a file <b>testfile</b> that we want to <b>encrypt</b>
and <b>hash</b> simultaneously. The encryption algorithm we wish to use is
<b>Quagmire 3</b> while the hashing algorithm is <b>SHA256</b>. We don't have
a key for the encryption, instead we want one generated. The CLI input for this
will be:
```Shell
Security/cryptography/RB-Crypt.py -i testfile -e quagmire -h sha256 --key-gen
```
This will encrypt the file provided by the `-i` flag, then produce a hash of
that file stored in `testfile.hash`. The key used for the encryption will also
be stored in `testfile.key`.

<b>It should be noted that the above script path is the relative path from the
rapidobank filesystem root, any attempts to run it should modify the relative/
absolute path accordingly</b>

A `--help` flag is available to describe how to use the CLI tool.

### Ciphers
There are 3 ciphers available for the RB-Crypt.py script, which follow the the
`-e` or `-d` flags. The text which follows the flags is case agnostic, however
it must be one of the provided ciphers specified below:
1. <b>Vigenere</b>: called with `vigenere`
2. <b>XOR</b>: called with `xor`
3. <b>Quagmire 3</b>: called with `quagmire`

the `--key-gen` flag is also available to randomly generate a cipher key of
length 50 and store it in a file called `<filename>.key`. Alternatively, if
key-gen is called without any other args it will output the random key to
`stdout`.

### Hashes
The hash function can be called in conjuction with or seperate from the cipher
functionality. When called with in conjuction with a cipher flag, the hashing
will take place either before a decryption or after an encryption has occured
on the file. The <b>output file</b> - specified either by `-o` or the
ordinally second un-flagged text - is where the hash will be output to. This
can be mapped to `stdout` with `\&1` or if not output is provided, the output
file will be `<filename>.hash`.

Four hash algorithms have been implemented for RB-Crypt's `-h` flag, those
being:
1. <b>MD5</b>: called with `md5`
2. <b>xxHash</b>: called with `xxhash`
3. <b>MurmurHash</b>: called with `murmur`
4. <b>SHA256</b>: called with `sha256`

Again the strings are case agnostic and the called with part describes that it
should follow the -h.

### RB-Crypt Format
overall the format for calling RB-Crypt, as specified by the `--help` flag is
```Shell
./RB-Crypt.py [options] [input file] [output file]
```


## MTD System (Designed by Izzy and Daniel)

## Dynamic Security Recommendations
