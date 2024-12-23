from src.modules.block_cipher import BlockCipher
from src.modules.public_key import PublicKeyCryptosystem
from src.modules.hashing import HashingModule
from src.modules.key_management import KeyManagement
from src.modules.authentication import Authentication
from src.modules.internet_security import InternetSecurity

# Simulated user store for authentication
user_store = {}

# Step 1: User Registration
auth = Authentication()
username = "alice"
password = "secure_password"
auth.register_user(username, password, user_store)

# Step 2: Generate RSA keys
pkc = PublicKeyCryptosystem()
private_key, public_key = pkc.generate_keys()

# Step 3: Generate AES key
key_manager = KeyManagement()
aes_key = key_manager.generate_key()

# Step 4: Securely share AES key using RSA
encrypted_aes_key = pkc.encrypt(aes_key, public_key)
shared_aes_key = pkc.decrypt(encrypted_aes_key, private_key)

# Step 5: Simulate messaging
bc = BlockCipher()
internet_security = InternetSecurity()

# Message from Alice to Bob
message = "Hello, Bob! This is a secure message."
ciphertext, iv = bc.encrypt(message.encode(), shared_aes_key)
encrypted_data = internet_security.encrypt(message.encode(), shared_aes_key)
hashed_message = HashingModule.hash_sha256(message.encode())

print("Encrypted Message:", encrypted_data)
print("Message Hash:", hashed_message)

# Bob decrypts the message
decrypted_message = bc.decrypt(ciphertext, shared_aes_key, iv).decode()
print("Decrypted Message:", decrypted_message)
