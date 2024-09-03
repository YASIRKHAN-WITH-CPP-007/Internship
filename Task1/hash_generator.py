import hashlib

# Passwords to hash
password1 = "password"
password2 = "5555"

# Generate SHA256 hashes
hash1 = hashlib.sha256(password1.encode()).hexdigest()
hash2 = hashlib.sha256(password2.encode()).hexdigest()

# Print the hashes
print("Hash for 'password':", hash1)
print("Hash for '123':", hash2)
