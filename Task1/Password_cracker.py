import hashlib
import itertools
import string
import os

# Load the hash and dictionary files
def load_files(hash_file, dictionary_file):
    # Read the hash file containing hashed passwords
    with open(hash_file, 'r') as hf:
        hashed_passwords = hf.read().splitlines()

    # Read the dictionary file containing common passwords
    with open(dictionary_file, 'r') as df:
        dictionary = df.read().splitlines()

    return hashed_passwords, dictionary

# Perform a dictionary attack
def dictionary_attack(hashed_passwords, dictionary):
    cracked_passwords = {}
    for password in dictionary:
        # Hash each password from the dictionary using SHA256
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()
        # Check if the hash matches any of the stored hashed passwords
        if hashed_pw in hashed_passwords:
            cracked_passwords[hashed_pw] = password
            print(f"Password cracked: {password}")
    return cracked_passwords

# Perform a brute-force attack (optional challenge)
def brute_force_attack(hashed_passwords, length=4):
    cracked_passwords = {}
    charset = string.ascii_letters + string.digits + string.punctuation

    # Attempt all combinations of the given charset with increasing length
    for pw_length in range(1, length + 1):
        for attempt in itertools.product(charset, repeat=pw_length):
            password = ''.join(attempt)
            hashed_pw = hashlib.sha256(password.encode()).hexdigest()
            if hashed_pw in hashed_passwords:
                cracked_passwords[hashed_pw] = password
                print(f"Password cracked: {password}")
                if len(cracked_passwords) == len(hashed_passwords):
                    return cracked_passwords
    return cracked_passwords

if __name__ == "__main__":
    # Print the current working directory
    print("Current Working Directory:", os.getcwd())

    # Set the file paths for the hash and dictionary files
    hash_file = 'C:/Users/dell/Desktop/Internship/Task1/hashed_passwords.txt'
    dictionary_file = 'C:/Users/dell/Desktop/Internship/Task1/dictionary.txt'


    # Load the hashed passwords and dictionary
    hashed_passwords, dictionary = load_files(hash_file, dictionary_file)

    # Run the dictionary attack
    print("Starting Dictionary Attack...")
    cracked_dict = dictionary_attack(hashed_passwords, dictionary)
    print("Cracked using Dictionary Attack:")
    print(cracked_dict)

    # Run the brute-force attack (optional challenge)
    print("Starting Brute-force Attack...")
    cracked_brute = brute_force_attack(hashed_passwords, length=4)
    print("Cracked using Brute-force Attack:")
    print(cracked_brute)
