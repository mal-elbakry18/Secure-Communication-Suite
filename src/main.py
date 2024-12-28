'''from src import BlockCipher, PublicKeyCryptosystem, Hashing

def main():
    print("Secure Communication Suite")
    print("1. Block Cipher (AES)")
    print("2. Public Key Cryptosystem (RSA)")
    print("3. Hashing (SHA-256/MD5)")

    choice = input("Select an option: ")

    if choice == "1":
        cipher = BlockCipher()
        message = input("Enter a message to encrypt: ")
        ciphertext, tag = cipher.encrypt(message)
        print(f"Ciphertext: {ciphertext}\nTag: {tag}")
        plaintext = cipher.decrypt(ciphertext, tag)
        print(f"Decrypted: {plaintext}")

    elif choice == "2":
        rsa = PublicKeyCryptosystem()
        message = input("Enter a message to encrypt: ")
        ciphertext = rsa.encrypt(message)
        print(f"Ciphertext: {ciphertext}")
        plaintext = rsa.decrypt(ciphertext)
        print(f"Decrypted: {plaintext}")

        signature = rsa.sign(message)
        print(f"Signature: {signature}")
        is_valid = rsa.verify(message, signature)
        print(f"Is signature valid? {is_valid}")

    elif choice == "3":
        algorithm = input("Enter hashing algorithm (sha256/md5): ")
        hasher = Hashing(algorithm=algorithm)
        message = input("Enter a message to hash: ")
        hash_value = hasher.generate_hash(message)
        print(f"Hash: {hash_value}")

        is_valid = hasher.verify_hash(message, hash_value)
        print(f"Is hash valid? {is_valid}")

    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()
'''
'''#MAIN IMPLEMENTATION

from server import start_server
from client import start_client
import threading

def run_system():
    # Start server in a separate thread
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()

    # Simulate client messages
    messages = ["Hello, Server!", "How are you?", "Goodbye!"]
    for message in messages:
        start_client(message)

if __name__ == "__main__":
    run_system()
'''
import queue
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
import threading
import json
import os

# ---- Server Code ----
class SecureServer:
    def __init__(self):
        self.users = {}  # Map for storing public keys and user states
        self.offline_messages = {}  # Map of user -> queue of offline messages
        self.session_keys = {}  # Map of user -> session key for live communication

    def register_user(self, username, public_key_pem):
        """Register a new user."""
        if username in self.users:
            return "Username already exists."
        self.users[username] = RSA.import_key(public_key_pem)
        self.offline_messages[username] = queue.Queue()
        return "User registered successfully."

    def authenticate_user(self, username, signed_challenge):
        """Authenticate a user using challenge-response."""
        if username not in self.users:
            return "User not found."

        challenge = os.urandom(16)
        user_public_key = self.users[username]
        h = SHA256.new(challenge)

        try:
            pkcs1_15.new(user_public_key).verify(h, signed_challenge)
            return True, challenge
        except (ValueError, TypeError):
            return False, None

    def store_offline_message(self, recipient, message):
        """Store a message for an offline user."""
        if recipient not in self.offline_messages:
            return "Recipient not found."
        self.offline_messages[recipient].put(message)
        return "Message stored successfully."

    def retrieve_offline_messages(self, username):
        """Retrieve all offline messages for a user."""
        if username not in self.offline_messages:
            return "No offline messages."
        messages = []
        while not self.offline_messages[username].empty():
            messages.append(self.offline_messages[username].get())
        return messages

    def establish_session(self, user1, user2):
        """Establish a session key for two users."""
        if user1 not in self.users or user2 not in self.users:
            return "User not found."
        session_key = get_random_bytes(16)
        self.session_keys[(user1, user2)] = session_key
        return session_key

# ---- Client Code ----
class SecureClient:
    def __init__(self, username):
        self.username = username
        self.key_pair = RSA.generate(2048)
        self.public_key = self.key_pair.publickey()
        self.server_public_key = None  # Assume this is provided

    def sign_challenge(self, challenge):
        """Sign a challenge with the private key."""
        h = SHA256.new(challenge)
        signature = pkcs1_15.new(self.key_pair).sign(h)
        return signature

    def encrypt_message(self, message, session_key):
        """Encrypt a message using AES."""
        cipher = AES.new(session_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())
        return cipher.nonce, ciphertext, tag

    def decrypt_message(self, nonce, ciphertext, tag, session_key):
        """Decrypt a message using AES."""
        cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()

    def send_message(self, recipient, message, session_key):
        """Encrypt and send a message to the recipient."""
        nonce, ciphertext, tag = self.encrypt_message(message, session_key)
        formatted_message = f"{self.username}|{recipient}|MESSAGE|{nonce.hex()}|{ciphertext.hex()}|{tag.hex()}"
        return formatted_message

    def send_file_or_email(self, recipient, file_content, session_key, file_type="FILE"):
        """Encrypt and send a file or email."""
        nonce, ciphertext, tag = self.encrypt_message(file_content, session_key)
        formatted_message = f"{self.username}|{recipient}|{file_type}|{nonce.hex()}|{ciphertext.hex()}|{tag.hex()}"
        return formatted_message

    def receive_message(self, formatted_message, session_key):
        """Decrypt a received message."""
        parts = formatted_message.split('|')
        if len(parts) < 6:
            return "Invalid message format."
        sender, recipient, msg_type, nonce_hex, ciphertext_hex, tag_hex = parts
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        tag = bytes.fromhex(tag_hex)
        plaintext = self.decrypt_message(nonce, ciphertext, tag, session_key)
        return f"From: {sender}, To: {recipient}, Type: {msg_type}, Message: {plaintext}"

# ---- Main Application Loop ----
def main():
    server = SecureServer()

    # User Setup
    alice = SecureClient("Alice")
    bob = SecureClient("Bob")

    server.register_user("Alice", alice.public_key.export_key())
    server.register_user("Bob", bob.public_key.export_key())

    session_key = server.establish_session("Alice", "Bob")

    while True:
        print("1. Send Message")
        print("2. Receive Messages")
        print("3. Send File/Email")
        print("4. Receive File/Email")
        print("5. Live Conversation")
        print("6. Quit")
        choice = input("Choose an option: ")

        if choice == "1":
            recipient = input("Enter recipient: ")
            message = input("Enter your message: ")
            encrypted_message = alice.send_message(recipient, message, session_key)
            server.store_offline_message(recipient, encrypted_message)

        elif choice == "2":
            messages = server.retrieve_offline_messages(alice.username)
            for msg in messages:
                print(alice.receive_message(msg, session_key))

        elif choice == "3":
            recipient = input("Enter recipient: ")
            file_content = input("Enter file/email content: ")
            file_type = input("Enter type (FILE/EMAIL): ").upper()
            encrypted_message = alice.send_file_or_email(recipient, file_content, session_key, file_type)
            server.store_offline_message(recipient, encrypted_message)

        elif choice == "4":
            messages = server.retrieve_offline_messages(alice.username)
            for msg in messages:
                print(alice.receive_message(msg, session_key))

        elif choice == "5":
            print("Live conversation feature is not implemented yet.")

        elif choice == "6":
            print("Exiting...")
            break

        else:
            print("Invalid option. Try again.")

if __name__ == "__main__":
    main()
