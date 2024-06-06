import hashlib

# Function to encrypt a string with SHA-1
def encrypt_string_sha1(input_string):
    sha1_hash = hashlib.sha1()            # Create a new SHA-1 hash object
    sha1_hash.update(input_string.encode()) # Update the hash object with the bytes of the input string
    return sha1_hash.hexdigest()           # Get the hexadecimal representation of the digest

# Function to encrypt a string with MD5
def encrypt_string_md5(input_string):
    md5_hash = hashlib.md5()                # Create a new MD5 hash object
    md5_hash.update(input_string.encode())  # Update the hash object with the bytes of the input string
    return md5_hash.hexdigest()             # Get the hexadecimal representation of the digest
