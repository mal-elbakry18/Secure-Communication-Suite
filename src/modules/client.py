'''#CLIENT CODE IMPLEMENTATION
import socket
import os

def send_message(client, message):
    client.send("MESSAGE".encode())  # Notify server of content type
    client.send(message.encode())    # Send the actual message
    encrypted_response = client.recv(2048).decode()
    print("Encrypted message received:", encrypted_response)

def send_file(client, file_path):
    client.send("FILE".encode())  # Notify server of content type

    # Send file name and size
    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    client.send(file_name.encode())
    client.send(str(file_size).encode())

    # Send file content
    with open(file_path, "rb") as file:
        while chunk := file.read(1024):
            client.send(chunk)
    print(f"File '{file_name}' sent!")

    # Receive encrypted file
    encrypted_response = client.recv(2048).decode()
    print("Encrypted file data received:", encrypted_response)

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 5000))

    print("Connected to server. What would you like to do?")
    print("1. Send a Message")
    print("2. Send a File")

    choice = input("Enter your choice (1/2): ")
    if choice == '1':
        message = input("Enter your message: ")
        send_message(client, message)
    elif choice == '2':
        file_path = input("Enter the file path: ")
        if os.path.exists(file_path):
            send_file(client, file_path)
        else:
            print("Invalid file path.")
    else:
        print("Invalid choice. Disconnecting.")

    client.close()

if __name__ == "__main__":
    start_client()
'''
'''from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import socket
import os

def sign_challenge(challenge, private_key):
    """Sign the challenge with the private key."""
    h = SHA256.new(challenge)
    return pkcs1_15.new(private_key).sign(h)

def session_key_exchange(client, private_key):
    """Perform session key exchange."""
    public_key = private_key.publickey().export_key()
    client.send(public_key)

    encrypted_key = client.recv(1024)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_key)

def start_client(username):
    """Start the client."""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 5000))

    client.send(username.encode())
    response = client.recv(1024).decode()

    if response == "SIGN_UP":
        print(client.recv(4096).decode())
    elif response == "SIGN_IN":
        private_key = RSA.import_key(open(f"{username}_private.pem").read())
        challenge = client.recv(1024)
        signature = sign_challenge(challenge, private_key)
        client.send(signature)

        if client.recv(1024).decode() == "AUTH_FAILED":
            print("Authentication failed.")
            return

        aes_key = session_key_exchange(client, private_key)
        print(f"Session established with AES key: {aes_key.hex()}")

    client.close()
'''

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import socket
import os

def sign_challenge(challenge, private_key):
    """Sign the challenge with the private key."""
    h = SHA256.new(challenge)
    return pkcs1_15.new(private_key).sign(h)

def session_key_exchange(client, private_key):
    """Perform session key exchange."""
    public_key = private_key.publickey().export_key()
    client.send(public_key)

    encrypted_key = client.recv(1024)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_key)

def start_client(username):
    """Start the client."""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 5000))

    client.send(username.encode())
    response = client.recv(1024).decode()

    if response == "SIGN_UP":
        print(client.recv(4096).decode())
    elif response == "SIGN_IN":
        private_key = RSA.import_key(open(f"{username}_private.pem").read())
        challenge = client.recv(1024)
        signature = sign_challenge(challenge, private_key)
        client.send(signature)

        if client.recv(1024).decode() == "AUTH_FAILED":
            print("Authentication failed.")
            return

        aes_key = session_key_exchange(client, private_key)
        print(f"Session established with AES key: {aes_key.hex()}")

    while True:
        choice = input("Send (1) Message or (2) File? (q to quit): ")
        if choice == '1':
            message = input("Enter message: ").encode()
            client.send("MESSAGE".encode())
            client.send(message)
        elif choice == '2':
            file_path = input("Enter file path: ")
            if os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
                client.send("FILE".encode())
                client.send(os.path.basename(file_path).encode())
                client.send(str(file_size).encode())
                with open(file_path, "rb") as file:
                    while chunk := file.read(1024):
                        client.send(chunk)
                print(f"File {os.path.basename(file_path)} sent.")
            else:
                print("File does not exist.")
        elif choice == 'q':
            break

    client.close()

if __name__ == "__main__":
    start_client()