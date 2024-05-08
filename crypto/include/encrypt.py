def encrypt(file, format, key):
    with open(file, "r") as f:
        print(f.read())

    print(format, key)
