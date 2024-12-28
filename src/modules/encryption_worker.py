def handle_live_chat(user1, user2):
    """Handles synchronized live chat between two users."""
    try:
        client1 = CLIENTS[user1]
        client2 = CLIENTS[user2]

        # Notify both users that the live chat has started
        client1.send(f"[INFO] Live chat started with {user2}. Type 'exit' to leave.".encode())
        client2.send(f"[INFO] Live chat started with {user1}. Type 'exit' to leave.".encode())

        def relay_messages(sender, receiver, sender_name):
            """Relay messages between the two clients."""
            while True:
                try:
                    message = sender.recv(1024).decode()
                    if message.lower() == "exit":
                        receiver.send(f"[INFO] {sender_name} has left the live conversation.".encode())
                        sender.send("[INFO] You have left the live conversation.".encode())
                        break
                    receiver.send(f"[LIVE] {sender_name}: {message}".encode())
                except Exception as e:
                    print(f"[ERROR] Error in live chat relay: {e}")
                    break

        # Start threads for both directions
        thread1 = threading.Thread(target=relay_messages, args=(client1, client2, user1), daemon=True)
        thread2 = threading.Thread(target=relay_messages, args=(client2, client1, user2), daemon=True)
        thread1.start()
        thread2.start()

        # Wait for both threads to complete before ending live chat
        thread1.join()
        thread2.join()
    except Exception as e:
        print(f"[ERROR] Live chat synchronization failed: {e}")
