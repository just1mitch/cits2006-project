md5_min_block = 64


def hash_file(file, format) -> int:
    match (format):
        case "md5":
            return md5(file)
        case _:
            return -1


def md5(file) -> int:
    """
    Args:
        file (str): file name
    Returns:
        0: on success
        -1: on fail
    """
    with open(file, "r+b") as fd:
        read_file = fd.read(md5_min_block)
        if len(read_file) < md5_min_block:
            read_file += 0b10000000
            while len(read_file) < md5_min_block:
                read_file += bytes('\0' * (md5_min_block - len(read_file)))
