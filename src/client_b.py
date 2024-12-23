from src.modules.block_cipher import decrypt_message
from src.modules.public_key import generate_key_pair, decrypt_with_private_key
from src.modules.hashing import generate_hash
import base64

# Mocked received data (simulating what User A sends)
ciphertext = b"...ciphered message..."
encoded_key = "...Base64 encoded AES key..."  # Base64 encoded encrypted key
nonce = b"...nonce..."
tag = b"...tag..."
message_hash = "mocked_hash_value"

# Function to fix Base64 padding
def fix_base64_padding(b64_string):
    if isinstance(b64_string, bytes):
        b64_string = b64_string.decode()
    missing_padding = len(b64_string) % 4
    if missing_padding:
        b64_string += "=" * (4 - missing_padding)
    return b64_string

# Decode encrypted key (Base64 decoding with padding fix)
try:
    encoded_key = fix_base64_padding(encoded_key)
    encrypted_key = base64.b64decode(encoded_key)  # Decode from Base64
    print("Decoded key length in Client B:", len(encrypted_key))
    if len(encrypted_key) != 256:  # Expected length for 2048-bit RSA ciphertext
        raise ValueError("Invalid key length")
except Exception as e:
    print("Error decoding or validating encrypted key:", e)
    exit(1)

# Generate RSA key pair for User B
private_key, public_key = generate_key_pair()

# Decrypt AES key
try:
    aes_key = decrypt_with_private_key(encrypted_key, private_key)
except ValueError as e:
    print("Decryption failed:", e)
    exit(1)

# Decrypt the received message
try:
    plaintext = decrypt_message(nonce, ciphertext, tag, aes_key)
except Exception as e:
    print("Error decrypting message:", e)
    exit(1)

# Verify the hash
if generate_hash(plaintext) == message_hash:
    print("Message integrity verified!")
else:
    print("Message tampered!")

print(f"Decrypted message: {plaintext}")
