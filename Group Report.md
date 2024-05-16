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

## Cipher System and Hashing Algorithm (Designed by Elijah)

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
The MTD system we have impliment will run in a continuous loop that scans every 5 seconds once started until the operator stops the program. We believed this was best to achieve a safer filesystem, as it will be constantly scanning for the following dangers and making the changes necessary to maintain integrity within the filesystem.
#### Yara Alert Raised
Files in the monitored directory are presented to the yara engine for scanning. Files which trigger an alert macthing one or mone of the specified yara ruels are hashed, this hash is then queried against VirusTotal's API to find any previously matched file uploads. If any of these files have never been seen before we upload the file present on our system for scanning. The results from either the hash search or the file upload are checked for vulnerability ratings meeting or exceeding the specifications of the operator. Such files are then moved to a quarantine directory that only the MTD has access and is denied permission to execute. Files which trigger a Yara alert but do not return as meeting or excceeding the threshold, have their hashes added to an exempt list (`whitelist`) so further alerts wont trigger a query against VirusTotal's API. 
- should a scan result in one or more q if a q is triggered the sens directed encrypted ...
#### Changes to the Filesystem
Any files that now come under the exempt list will be catergorised as safe. As a files hash will change as it is modifed or a new hash will be created when a file is added these will not be within the `whitelist`, therefore will be included in the next continous scan done by the MTD assessed by the previous criteria of the YARA rules or operator specified threshold.
#### Passing of Time Interval
As per the project brief the MTD system will change the security settings of the filesystem after a predefined period of time. This results in <b>\<insert what happens here></b>
#### Quarantiner Mode
The following command is apart of the mtd model which allows the operator to interact with the files that are moved and held in the quarantine directory.
`python security/mtd.py quarantiner`
When you enter into this mode there are clearly labeled actions that you can perform upon the files within this directory. 
- `List` the contents of the directory
- `Delete` a quarantined file by its hash
- `Restore` a quarantined file by its hash
- `Quit` the quarantine menu (exit you out of this mode)
## Dynamic Security Recommendations
