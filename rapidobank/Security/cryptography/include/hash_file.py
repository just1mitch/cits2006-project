from include.hashes import (
    md5,
    xxhash,
    murmur,
    sha256,
)

def hash_file(ifile, ofile, format) -> int:
    hex_digest = ""
    fd = open(ifile, 'rb')
    close_fd = True

    match (format):
        case "md5":
            state = md5.MD5()
            state.hash(fd)
            hex_digest = state.digest_50_char().hex()
        case "xxhash":
            state = xxhash.XXHASH()
            file_contents = fd.read()
            hex_digest = state.xxhash(file_contents)
        case "murmur":
            state = murmur.MURMUR()
            file_contents = fd.read()
            hex_digest = state.murmurhash3(file_contents)
        case "sha256":
            fd.close()
            close_fd = False

            state = sha256.SHA256()
            hex_digest = state.sha256(ifile)
        case _:
            return -1
    
    if close_fd: fd.close()

    if (ofile == "&1"):
        print(hex_digest)
    else:
        with open(ofile, "w") as fd:
            fd.write(hex_digest)
    
    return 0