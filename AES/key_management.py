from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

class KeyManagementModule:
    def __init__(self):
        # Generate RSA keys for secure key exchange
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()

    def encrypt_key(self, symmetric_key, receiver_public_key):
        """
        Encrypts a symmetric AES key using the receiver's RSA public key.

        Args:
            symmetric_key (bytes): The AES key to encrypt.
            receiver_public_key (RSA.RsaKey): The receiver's RSA public key.

        Returns:
            str: Encrypted AES key (base64 encoded).
        """
        cipher = PKCS1_OAEP.new(receiver_public_key)
        encrypted_key = cipher.encrypt(symmetric_key)
        return base64.b64encode(encrypted_key).decode('utf-8')

    def decrypt_key(self, encrypted_key):
        """
        Decrypts an encrypted AES key using the user's RSA private key.

        Args:
            encrypted_key (str): The encrypted AES key (base64 encoded).

        Returns:
            bytes: Decrypted AES key.
        """
        cipher = PKCS1_OAEP.new(self.private_key)
        decrypted_key = cipher.decrypt(base64.b64decode(encrypted_key))
        return decrypted_key

    def store_keys(self):
        """
        Stores the RSA keys securely (example uses files for simplicity).
        """
        with open('private_key.pem', 'wb') as private_file:
            private_file.write(self.private_key.export_key())

        with open('public_key.pem', 'wb') as public_file:
            public_file.write(self.public_key.export_key())

    def load_keys(self):
        """
        Loads the RSA keys from files.
        """
        with open('private_key.pem', 'rb') as private_file:
            self.private_key = RSA.import_key(private_file.read())

        with open('public_key.pem', 'rb') as public_file:
            self.public_key = RSA.import_key(public_file.read())

# Example Usage
def example_usage():
    # User 1: Key Management
    user1 = KeyManagementModule()
    user1.store_keys()
    print("User 1 Public Key:", user1.public_key.export_key().decode('utf-8'))

    # User 2: Key Management
    user2 = KeyManagementModule()
    symmetric_key = get_random_bytes(16)  # AES key
    print("Generated AES Key (User 2):", base64.b64encode(symmetric_key).decode('utf-8'))

    # Encrypt AES key with User 1's public key
    encrypted_key = user2.encrypt_key(symmetric_key, user1.public_key)
    print("Encrypted AES Key (sent to User 1):", encrypted_key)

    # User 1 decrypts the AES key
    user1.load_keys()
    decrypted_key = user1.decrypt_key(encrypted_key)
    print("Decrypted AES Key (User 1):", base64.b64encode(decrypted_key).decode('utf-8'))

if __name__ == "__main__":
    example_usage()
