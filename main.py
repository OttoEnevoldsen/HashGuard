import os
from random import randint

# Constants for default values
DEFAULT_SALT_LENGTH = 8
DEFAULT_HASH_LENGTH = 64
MAX_SALT_LENGTH = 32
HASH_ROUNDS = 64

# Exception classes can be added for specific errors if needed
class FileNotFoundError(Exception):
    pass

# Hashing function with type hints and error handling
def hashguard(input_text: str, salt_file: str, length: int) -> str:
    """
    Hash the input text combined with a salt.

    Parameters:
    input_text (str): The text to be hashed.
    salt_file (str): The filename of the salt.
    length (int): The length of the hash output.

    Returns:
    str: The generated hash.
    """
    try:
        with open(salt_file, "rb") as f:
            salt = f.read().decode(errors="ignore")
    except (FileNotFoundError, IOError):
        raise FileNotFoundError(f"Unable to open salt file: {salt_file}")

    input_text += salt
    mixed_input = "".join(
        input_text[i % len(input_text)] + salt[i % len(salt)]
        for i in range(max(len(input_text), len(salt)))
    )
    
    unique_value = sum(ord(c) for c in mixed_input)
    random_factor = sum(ord(c) * i for i, c in enumerate(mixed_input)) % 128
    
    output = ""
    for i in range(length):
        unique_value ^= ord(mixed_input[i * unique_value % len(mixed_input)])
        unique_value = (unique_value << 5 | unique_value >> 27) & 0xFFFFFFFF
        output += chr(((ord(mixed_input[i * unique_value % len(mixed_input)]) * (unique_value + random_factor) // (i + 1)) % 95) + 32)
    
    return iterative_hash(output, HASH_ROUNDS)

# Iterative hashing function with rounds
def iterative_hash(output: str, rounds: int) -> str:
    """
    Apply multiple rounds of hashing.

    Parameters:
    output (str): The initial output to be hashed.
    rounds (int): The number of rounds for hashing.

    Returns:
    str: The hashed output after multiple rounds.
    """
    for _ in range(rounds):
        new_output = ""
        unique_value = sum(ord(c) for c in output)
        for i in range(len(output)):
            unique_value += i
            new_output += chr(((ord(output[i * unique_value % len(output)]) * unique_value // (i + 1)) % 95) + 32)
        output = new_output
    return output

# Generate a salt file with improved exception handling
def generate_salt(filename: str, length: int) -> None:
    """
    Generate a binary salt file with random data.

    Parameters:
    filename (str): The filename where the salt will be saved.
    length (int): The length of the salt in bytes.
    """
    try:
        with open(filename, "wb") as f:
            f.write(os.urandom(length))
        print(f"Salt generated with size: {length} bytes, at \"{filename}\"")
    except IOError as e:
        print(f"Error while writing to file: {filename}. {str(e)}")

# Main user interaction menu
def main() -> None:
    """
    Main function providing a command-line interface for the user to hash plaintext
    or generate a salt file.
    """
    print("""
  _   _           _      ____                     _ 
 | | | | __ _ ___| |__  / ___|_   _  __ _ _ __ __| |
 | |_| |/ _` / __| '_ \| |  _| | | |/ _` | '__/ _` |
 |  _  | (_| \__ \ | | | |_| | |_| | (_| | | | (_| |
 |_| |_|\__,_|___/_| |_|\____|\__,_|\__,_|_|  \__,_| - v1.81""")
    print("-" * 64)
    
    while True:
        command = input("Hash Plaintext or Salt [-hash, -salt, -exit]: ")
        match command:
            case "-hash":
                ui_hash()
            case "-salt":
                ui_salt()
            case "-exit":
                break
            case _:
                print(f"Invalid command: {command}")

# UI for hashing input text
def ui_hash() -> None:
    fromfile = input("Get plaintext from file? [y, n]: ").strip().lower()
    txt = ""

    if fromfile == "y":
        plaintext_file = input("File (must be .txt file): ")
        if is_valid_file(plaintext_file):
            with open(plaintext_file, "r") as f:
                txt = f.read()
        else:
            print(f"File {plaintext_file} does not exist")
            return
    elif fromfile == "n":
        txt = input("Plaintext: ")
    else:
        print("Invalid option")
        return
    
    filename = input('Salt file ["salt.bin"] (type -generate to generate new salt): ').strip()
    if filename != "-generate":
        if filename.endswith(".bin") and is_valid_file(filename):
            hashing_alg = input("Hashing algorithm [hg64, hg256]: ").strip().lower()
            process_hash(txt, filename, hashing_alg)
        else:
            print(f"Invalid filename: {filename}")
    else:
        generate_salt_ui(txt)

# UI for generating salt
def generate_salt_ui(txt: str) -> None:
    filename = input("Enter filename for new salt (must be .bin file): ").strip()
    if filename.endswith(".bin"):
        default = input("Use default settings for generating salt? [y, n]: ").strip().lower()
        salt_length = DEFAULT_SALT_LENGTH if default == "y" else int(input(f"Length of salt in bytes [1 - {MAX_SALT_LENGTH}]: "))
        generate_salt(filename, salt_length)
        hashing_alg = input("Hashing algorithm [hg64, hg256]: ").strip().lower()
        process_hash(txt, filename, hashing_alg)
    else:
        print(f"Invalid filename: {filename}")

# Process hashing based on algorithm choice
def process_hash(txt: str, filename: str, hashing_alg: str) -> None:
    length = DEFAULT_HASH_LENGTH if hashing_alg == "hg64" else 256
    if hashing_alg in ["hg64", "hg256"]:
        hash_result = hashguard(txt, filename, length)
        print("-" * 64)
        print(hash_result)
        print("-" * 64)
        save = input("Save to file? [y, n]: ").strip().lower()
        if save == "y":
            hash_file = input("Where to save (must be .txt file): ").strip()
            with open(hash_file, "w") as f:
                f.write(hash_result)
            print(f"Successfully saved to {hash_file}")
    else:
        print(f"Invalid option: {hashing_alg}")

# Generate a salt file from user input
def ui_salt() -> None:
    filename = input("Enter filename for salt (must be .bin file): ").strip()
    if filename.endswith(".bin"):
        default = input("Use default settings for generating salt? [y, n]: ").strip().lower()
        salt_length = DEFAULT_SALT_LENGTH if default == "y" else int(input(f"Length of salt in bytes [1 - {MAX_SALT_LENGTH}]: "))
        generate_salt(filename, salt_length)
    else:
        print(f"Invalid filename: {filename}")

# Utility function to check if an integer is valid
def is_valid_int(n: str) -> bool:
    try:
        int(n)
        return True
    except ValueError:
        return False

# Utility function to check if a file exists
def is_valid_file(filename: str) -> bool:
    try:
        with open(filename, "rb") as f:
            f.read()
        return True
    except (FileNotFoundError, IOError):
        return False

if __name__ == "__main__":
    main()
