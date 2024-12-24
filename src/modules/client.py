
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
import socket
import os

def sign_challenge(challenge, private_key):
    h = SHA256.new(challenge)
    print(f"[DEBUG] Signing challenge with hash: {h.hexdigest()}")
    return pkcs1_15.new(private_key).sign(h)

def start_client(username):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect(('localhost', 5566))
        print(f"[DEBUG] Connected to server as {username}.")
        client.send(username.encode())
        response = client.recv(1024).decode()

        if response == "SIGN_UP":
            print(f"[DEBUG] {username} successfully registered.")
        elif response == "SIGN_IN":
            private_key = RSA.import_key(open(f"{username}_private.pem").read())
            challenge = client.recv(1024)
            client.send(sign_challenge(challenge, private_key))
            if client.recv(1024).decode() == "AUTH_FAILED":
                print("[DEBUG] Authentication failed. Exiting.")
                return

        while True:
            choice = input("[DEBUG] Choose (1) Send Message, (2) Receive Messages, (q) Quit: ").strip()
            if choice == '1':
                recipient = input("Recipient: ").strip()
                message = input("Message: ").strip()
                client.send("MESSAGE".encode())
                client.send(f"{recipient}|{message}".encode())
            elif choice == '2':
                client.send("RECEIVE".encode())
                while True:
                    message = client.recv(2048).decode()
                    if message == "END_OF_MESSAGES":
                        print("[DEBUG] No more messages.")
                        break
                    print(f"[DEBUG] Received message: {message}")
            elif choice == 'q':
                client.send("EXIT".encode())
                break
    except Exception as e:
        print(f"[DEBUG] Client error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    username = input("Enter your username: ")
    start_client(username)
