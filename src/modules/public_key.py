from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

# Generate a new RSA key pair
def generate_key_pair():
    """Generate an RSA key pair (private and public keys)."""
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()

# Encrypt data with a public key
def encrypt_with_public_key(data, public_key):
    """Encrypt data using an RSA public key."""
    try:
        key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(key)
        return cipher.encrypt(data)
    except Exception as e:
        print(f"Error encrypting with public key: {e}")
        raise

# Decrypt data with a private key
def decrypt_with_private_key(data, private_key):
    """Decrypt data using an RSA private key."""
    try:
        key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(key)
        return cipher.decrypt(data)
    except Exception as e:
        print(f"Error decrypting with private key: {e}")
        raise
