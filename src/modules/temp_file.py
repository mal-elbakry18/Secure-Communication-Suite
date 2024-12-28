import socket
import threading

def receive_messages(client):
    """Receives messages from the server."""
    while True:
        try:
            message = client.recv(1024).decode()
            if message.startswith("[INFO]") or message.startswith("[LIVE]"):
                print(message)
            if "You have left the live conversation" in message:
                break
        except Exception as e:
            print(f"[ERROR] Receiving error: {e}")
            break


def start_client(username):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect(("localhost", 5566))
        client.send(username.encode())

        threading.Thread(target=receive_messages, args=(client,), daemon=True).start()

        while True:
            choice = input("Choose an option: (3) Live Conversation, (q) Quit: ")
            if choice == "3":
                target_user = input("Enter the username of the user you want to talk to: ").strip()
                client.send("LIVE".encode())
                client.send(target_user.encode())
                response = client.recv(1024).decode()
                if response == "LIVE_READY":
                    print(f"[INFO] Live conversation started with {target_user}. Type 'exit' to leave.")
                    while True:
                        msg = input()
                        if msg.lower() == "exit":
                            client.send(msg.encode())
                            break
                        client.send(msg.encode())
                elif response == "USER_OFFLINE":
                    print(f"[INFO] {target_user} is offline or not available.")
            elif choice == "q":
                client.send("EXIT".encode())
                break
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
    finally:
        client.close()


if __name__ == "__main__":
    username = input("Enter your username: ")
    start_client(username)
