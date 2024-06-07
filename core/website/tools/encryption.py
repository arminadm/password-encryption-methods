import hashlib
import hmac
import base64
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util import number
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long, long_to_bytes



# Function to encrypt a string with SHA-1
def encrypt_string_sha1(input_string):
    sha1_hash = hashlib.sha1()            
    sha1_hash.update(input_string.encode()) 
    return sha1_hash.hexdigest()
          
def encrypt_string_sha2(data):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data.encode('utf-8'))
    return sha256_hash.hexdigest()

def encrypt_string_md5(input_string):
    md5_hash = hashlib.md5()               
    md5_hash.update(input_string.encode()) 
    return md5_hash.hexdigest()             

# AES
def aes_encrypt(key, data):
    # Ensure the key is 16, 24, or 32 bytes long
    key = key.ljust(32, '\0')[:32].encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def aes_decrypt(key, iv, ct):
    key = key.ljust(32, '\0')[:32].encode('utf-8')
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')


# DES 
def des_encrypt(key, data):
    # Ensure the key is 8 bytes long
    key = key.ljust(8, '\0')[:8].encode('utf-8')
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), DES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def des_decrypt(key, iv, ct):
    key = key.ljust(8, '\0')[:8].encode('utf-8')
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), DES.block_size)
    return pt.decode('utf-8')


# Elgamal
def generate_elgamal_keys(bit_length=512):
    p = number.getPrime(bit_length)
    g = number.getRandomRange(2, p-1)
    x = number.getRandomRange(1, p-1)
    y = pow(g, x, p)
    public_key = (p, g, y)
    private_key = (p, g, x)
    return private_key, public_key

def elgamal_encrypt(public_key, data):
    p, g, y = public_key
    k = number.getRandomRange(1, p-1)
    a = pow(g, k, p)
    b = (bytes_to_long(data.encode('utf-8')) * pow(y, k, p)) % p
    return (a, b)

def elgamal_decrypt(private_key, ciphertext):
    p, g, x = private_key
    a, b = ciphertext
    s = pow(a, x, p)
    m = (b * number.inverse(s, p)) % p
    return long_to_bytes(m).decode('utf-8')


# RSA Encryption/Decryption
def rsa_encrypt(public_key, data):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(data.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def rsa_decrypt(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(base64.b64decode(ciphertext))
    return plaintext.decode('utf-8')

def generate_rsa_keys():
    key = RSA.generate(2048)
    return key, key.publickey()


# HMAC
def calculate_hmac_md5(key, message):
    hmac_md5 = hmac.new(key.encode('utf-8'), message.encode('utf-8'), hashlib.md5)
    return hmac_md5.hexdigest()

def calculate_hmac_sha1(key, message):
    hmac_sha1 = hmac.new(key.encode('utf-8'), message.encode('utf-8'), hashlib.sha1)
    return hmac_sha1.hexdigest()

def calculate_hmac_sha256(key, message):
    hmac_sha256 = hmac.new(key.encode('utf-8'), message.encode('utf-8'), hashlib.sha256)
    return hmac_sha256.hexdigest()

