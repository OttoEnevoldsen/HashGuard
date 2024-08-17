from random import randint
import os

def hashguard(input_text, salt_file, length):
    with open(salt_file, "rb") as f:
        salt = f.read().decode(errors="ignore")
    output = ""
    input_text += salt
    unique_value = sum(ord(c) for c in input_text)
    for i in range(length):
        unique_value += i
        output += chr(((ord(input_text[i * unique_value % len(input_text)]) * unique_value // (i + 1)) % 95) + 32)
    return output

def generate_salt(filename, length):
    with open(filename, "wb") as f:
        f.write(os.urandom(length))

def main():
    print("""
  _   _           _      ____                     _ 
 | | | | __ _ ___| |__  / ___|_   _  __ _ _ __ __| |
 | |_| |/ _` / __| '_ \| |  _| | | |/ _` | '__/ _` |
 |  _  | (_| \__ \ | | | |_| | |_| | (_| | | | (_| |
 |_| |_|\__,_|___/_| |_|\____|\__,_|\__,_|_|  \__,_| - v1.2""")
    print("-" * 64)
    while True:
        command = input("Hash Plaintext or Salt [-hash, -salt]: ")
        match command:
            case "-hash":
                ui_hash()
            case "-salt":
                ui_salt()
            case _:
                print(f"Invalid command: {command}")

def ui_hash():
    fromfile = input("Get plaintext from file? [y, n]: ")
    match fromfile:
        case "y":
            plaintext_file = input("File (must be .txt file): ")
            if is_valid_file(plaintext_file):
                with open(plaintext_file, "r") as f:
                    txt = f.read()
            else:
                print(f"File {plaintext_file} does not exist")
                return
        case "n":
            txt = input("Plaintext: ")
        case _:
            print("Invalid option")
            return
    
    print("Type filename or type \"-generate\" for new salt file")
    filename = input("Salt file [\"salt.bin\"]: ")
    
    if filename != "-generate":
        if filename.endswith(".bin"):
            if is_valid_file(filename):
                hashing_alg = input("Hashing algorithm [hg64, hg256]: ")
                process_hash(txt, filename, hashing_alg)
            else:
                print(f"File {filename} does not exist")
        else:
            print(f"Invalid filename: {filename}")
    else:
        generate_salt_ui(txt)

def generate_salt_ui(txt):
    filename = input("Enter filename for new salt (must be .bin file): ")
    if filename.endswith(".bin"):
        default = input("Use default settings for generating salt? [y, n]: ")
        salt_length = 8 if default == "y" else int(input("Length of salt in bytes [1 - 32]: "))
        generate_salt(filename, salt_length)
        print(f"Salt generated with size: {salt_length} bytes, at \"{filename}\"")
        hashing_alg = input("Hashing algorithm [hg64, hg256]: ")
        process_hash(txt, filename, hashing_alg)
    else:
        print(f"Invalid filename: {filename}")

def process_hash(txt, filename, hashing_alg):
    length = 64 if hashing_alg == "hg64" else 256
    if hashing_alg in ["hg64", "hg256"]:
        hash_result = hashguard(txt, filename, length)
        print("-" * 64)
        print(hash_result)
        print("-" * 64)
        save = input("Save to file? [y, n]: ")
        if save == "y":
            hash_file = input("Where to save (must be .txt file): ")
            with open(hash_file, "w") as f:
                f.write(hash_result)
            print(f"Successfully saved to {hash_file}")
    else:
        print(f"Invalid option: {hashing_alg}")

def ui_salt():
    filename = input("Enter filename for salt (must be .bin file): ")
    if filename.endswith(".bin"):
        default = input("Use default settings for generating salt? [y, n]: ")
        salt_length = 8 if default == "y" else int(input("Length of salt in bytes [1 - 32]: "))
        generate_salt(filename, salt_length)
        print(f"Salt generated with size: {salt_length} bytes, at \"{filename}\"")
    else:
        print(f"Invalid filename: {filename}")

def is_valid_int(n):
    try:
        int(n)
        return True
    except ValueError:
        return False

def is_valid_file(filename):
    try:
        with open(filename, "rb") as f:
            f.read()
        return True
    except (FileNotFoundError, IOError):
        return False

if __name__ == "__main__":
    main()
