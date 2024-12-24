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
from modules.server import start_server
from modules.client import start_client
import threading
import time
import sys


def run_server():
    """Start the server in a separate thread."""
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()

    time.sleep(1)  # Give the server some time to start


def run_client(username):
    """Start a client simulation."""
    start_client(username)


if __name__ == "__main__":
    if len(sys.argv) == 1:  # Run as server
        run_server()
        print("Server started. Press Ctrl+C to stop the server.")
        while True:
            pass  # Keep the server running indefinitely
    elif len(sys.argv) == 3 and sys.argv[1] == 'client':  # Run as client
        username = sys.argv[2]
        run_client(username)
