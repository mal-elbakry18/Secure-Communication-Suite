from Cryptodome.Random import get_random_bytes
from src.modules.block_cipher import encrypt_message
from src.modules.public_key import generate_key_pair, encrypt_with_public_key
from src.modules.hashing import generate_hash
from src.modules.internet_security import Server
import base64

# Initialize server and keys
server = Server()
private_key_a, public_key_a = generate_key_pair()
server.exchange_keys('UserA', public_key_a)




print(f"UserA Public Key: {public_key_a.decode()[:50]}...")  # Debug public key
print('----------------------------')


# Key exchange with User B (mocked)
private_key_b, public_key_b = generate_key_pair()
server.exchange_keys('UserB', public_key_b)

print(f"UserB Public Key: {public_key_b.decode()[:50]}...")  # Debug public key
print('----------------------------')

# Encrypt message
message = "Hello, User john!"
print(f"Original Message: {message}")  # Debug original message
print('----------------------------')
aes_key = get_random_bytes(16)
print(f"AES Key (bytes): {aes_key.hex()}")  # Debug AES key
print('----------------------------')
nonce, ciphertext, tag = encrypt_message(message, aes_key)
print(f"Nonce: {nonce.hex()}")  # Debug nonce
print('----------------------------')
print(f"Ciphertext: {ciphertext.hex()}")  # Debug ciphertext
print('----------------------------')
print(f"Tag: {tag.hex()}")  # Debug tag
print('----------------------------')

# Encrypt AES key with RSA and Base64 encode it
encrypted_key = encrypt_with_public_key(aes_key, server.public_keys['UserB'])
print(f"Encrypted AES Key (bytes): {encrypted_key.hex()}")  # Debug encrypted AES key
print('----------------------------')
encoded_key = base64.b64encode(encrypted_key).decode()  # Base64 encode
print(f"Encoded AES Key (Base64): {encoded_key}")  # Debug Base64 encoded key
print('----------------------------')
print("Encoded key length in Client A:", len(encoded_key))  # Debug encoded key length
print('----------------------------')

# Generate message hash
message_hash = generate_hash(message)
print(f"Message Hash: {message_hash}")  # Debug message hash
print('----------------------------')

# Send to server
print(server.relay_message('UserB', (ciphertext, encoded_key, nonce, tag, message_hash)))  # Debug final data
print('----------------------------')
