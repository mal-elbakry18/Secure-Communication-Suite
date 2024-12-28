
import tkinter as tk
from tkinter import messagebox, scrolledtext
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
import socket
import os
import threading


class SecureCommunicationClient:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Communication Suite")
        self.master.geometry("700x800")
        self.client = None
        self.username = ""

        # Frames
        self.login_frame = tk.Frame(master)
        self.chat_frame = tk.Frame(master)

        # Initialize Login Frame
        self.setup_login_frame()

    def update_message_area(self, message):
        """Update the message display area with new messages."""
        self.message_area.config(state=tk.NORMAL)
        self.message_area.insert(tk.END, message + "\n")
        self.message_area.config(state=tk.DISABLED)
        self.message_area.see(tk.END)

    def disconnect_from_server(self):
        """Gracefully disconnect from the server."""
        try:
            self.client.send("EXIT".encode())
            self.client.close()
            self.update_message_area("[INFO] Disconnected from server.")
        except Exception as e:
            self.update_message_area(f"[ERROR] Failed to disconnect: {e}")

    def handle_live_chat(self):
        """Handle live chat messages."""

        def receive_live_messages():
            """Continuously receive live chat messages."""
            while True:
                try:
                    message = self.client.recv(1024).decode(errors="ignore")
                    if not message or message.lower() == "exit":
                        self.update_message_area("[INFO] Live conversation ended.")
                        break
                    self.update_message_area(f"Live: {message}")
                except Exception as e:
                    self.update_message_area(f"[ERROR] {e}")
                    break

        # Thread for receiving live messages
        threading.Thread(target=receive_live_messages, daemon=True).start()

        def send_live_messages():
            """Continuously send live chat messages."""
            while True:
                msg = self.message_entry.get().strip()
                if msg.lower() == "exit":
                    self.client.send(msg.encode())
                    self.update_message_area("[INFO] You left the live chat.")
                    break
                if msg:
                    self.client.send(msg.encode())
                    self.message_entry.delete(0, tk.END)

        # Thread for sending live messages
        threading.Thread(target=send_live_messages, daemon=True).start()

    def listen_to_server(self):
        """Continuously listen for incoming messages or live chat requests from the server."""
        while True:
            try:
                message = self.client.recv(2048).decode(errors="ignore")

                if message.startswith("LIVE_REQUEST"):
                    sender = message.split("|")[1]
                    approve = messagebox.askyesno("Live Chat Request", f"Live chat request from {sender}. Accept?")
                    if approve:
                        self.client.send("LIVE_ACCEPT".encode())
                        self.update_message_area(f"[INFO] Live chat started with {sender}.")
                        self.handle_live_chat()
                    else:
                        self.client.send("LIVE_DECLINE".encode())
                        self.update_message_area(f"[INFO] Declined live chat request from {sender}.")

                elif message.startswith("[INFO]"):
                    self.update_message_area(message)

                elif message.startswith("[ERROR]"):
                    self.update_message_area(f"[ERROR] {message}")

                elif message == "END_OF_MESSAGES":
                    self.update_message_area("[INFO] End of message queue.")

                elif message.startswith("LIVE_READY"):
                    self.update_message_area("[INFO] Live chat is ready. Starting...")
                    self.handle_live_chat()

                else:
                    self.update_message_area(f"Received: {message}")

            except Exception as e:
                self.update_message_area(f"[ERROR] Lost connection to the server: {e}")
                break

    def setup_login_frame(self):
        """Setup the login frame."""
        self.clear_frame(self.login_frame)

        tk.Label(self.login_frame, text="Secure Communication Suite", font=("Arial", 20, "bold"), pady=20).pack()
        tk.Label(self.login_frame, text="Enter Username:", font=("Arial", 14)).pack(pady=10)

        self.username_entry = tk.Entry(self.login_frame, font=("Arial", 12))
        self.username_entry.pack(pady=10)

        tk.Button(self.login_frame, text="Start", command=self.start_client, font=("Arial", 12)).pack(pady=20)
        self.login_frame.pack(fill=tk.BOTH, expand=True)

    def setup_chat_frame(self):
        """Setup the chat frame."""
        self.clear_frame(self.chat_frame)

        tk.Label(self.chat_frame, text=f"Welcome, {self.username}!", font=("Arial", 16, "bold"), pady=20).pack()

        # Message Display Area
        self.message_area = scrolledtext.ScrolledText(self.chat_frame, height=20, width=70, state=tk.DISABLED)
        self.message_area.pack(pady=10)

        # Recipient and Message Input
        tk.Label(self.chat_frame, text="Recipient Username:", font=("Arial", 12)).pack(pady=5)
        self.recipient_entry = tk.Entry(self.chat_frame, font=("Arial", 12), width=50)
        self.recipient_entry.pack(pady=5)

        tk.Label(self.chat_frame, text="Message:", font=("Arial", 12)).pack(pady=5)
        self.message_entry = tk.Entry(self.chat_frame, font=("Arial", 12), width=50)
        self.message_entry.pack(pady=5)

        # Buttons
        tk.Button(self.chat_frame, text="Send Message", command=self.send_message, font=("Arial", 12)).pack(pady=10)
        tk.Button(self.chat_frame, text="Receive Messages", command=self.receive_messages, font=("Arial", 12)).pack(pady=10)
        tk.Button(self.chat_frame, text="Start Live Conversation", command=self.start_live_conversation, font=("Arial", 12)).pack(pady=10)
        tk.Button(self.chat_frame, text="Approve Live Request", command=self.approve_live_request, font=("Arial", 12)).pack(pady=10)
        self.chat_frame.pack(fill=tk.BOTH, expand=True)

    def start_client(self):
        """Start the client and handle authentication."""
        self.username = self.username_entry.get().strip()
        if not self.username:
            messagebox.showerror("Error", "Username cannot be empty!")
            return

        self.generate_and_save_keys()

        def connect_to_server():
            try:
                self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client.connect(('localhost', 5566))
                self.client.send(self.username.encode())

                response = self.client.recv(1024).decode(errors="ignore")

                if response == "SIGN_UP":
                    with open(f"{self.username}_public.pem", "rb") as pub_file:
                        public_key_pem = pub_file.read()
                    self.client.send(public_key_pem)
                    messagebox.showinfo("Info", "Registration successful.")
                elif response == "SIGN_IN":
                    self.sign_in()
                else:
                    messagebox.showerror("Error", "Unexpected server response.")
                    return

                self.master.after(0, self.setup_chat_frame)

                # Start listener thread
                threading.Thread(target=self.listen_to_server, daemon=True).start()

            except Exception as e:
                messagebox.showerror("Error", f"Unable to connect: {e}")

        threading.Thread(target=connect_to_server, daemon=True).start()

    def generate_and_save_keys(self):
        """Generate RSA keys and save them to .pem files."""
        if not os.path.exists(f"{self.username}_private.pem") or not os.path.exists(f"{self.username}_public.pem"):
            private_key = RSA.generate(2048)
            with open(f"{self.username}_private.pem", "wb") as priv_file:
                priv_file.write(private_key.export_key())
            with open(f"{self.username}_public.pem", "wb") as pub_file:
                pub_file.write(private_key.publickey().export_key())

    def sign_in(self):
        """Sign in an existing user."""
        try:
            challenge = self.client.recv(1024)
            with open(f"{self.username}_private.pem", "rb") as priv_file:
                private_key = RSA.import_key(priv_file.read())
            signature = self.sign_challenge(challenge, private_key)
            self.client.send(signature)

            auth_response = self.client.recv(1024).decode(errors="ignore")
            if auth_response == "AUTH_FAILED":
                messagebox.showerror("Error", "Authentication failed!")
                self.client.close()
        except Exception as e:
            messagebox.showerror("Error", f"Sign-in failed: {e}")

    def send_message(self):
        """Send a message to a recipient."""
        recipient = self.recipient_entry.get().strip()
        message = self.message_entry.get().strip()
        if not recipient:
            messagebox.showerror("Error", "Recipient username cannot be empty!")
            return
        if not message:
            messagebox.showerror("Error", "Message cannot be empty!")
            return

        try:
            self.client.send("MESSAGE".encode())
            self.client.send(f"{recipient}|{message}".encode())
            self.update_message_area(f"To {recipient}: {message}")
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {e}")

    def receive_messages(self):
        """Receive messages from the server."""
        try:
            self.client.send("RECEIVE".encode())

            def receive_loop():
                while True:
                    try:
                        message = self.client.recv(2048).decode(errors="ignore")
                        if message == "END_OF_MESSAGES":
                            break
                        self.update_message_area(f"Received: {message}")
                    except Exception as e:
                        self.update_message_area(f"[ERROR] {e}")
                        break

            threading.Thread(target=receive_loop, daemon=True).start()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to receive messages: {e}")

    def start_live_conversation(self):
        """Start a live conversation with another user."""
        target_user = self.recipient_entry.get().strip()
        if not target_user:
            messagebox.showerror("Error", "Target username cannot be empty!")
            return

        def handle_request():
            try:
                self.client.send("LIVE".encode())
                self.client.send(target_user.encode())

                response = self.client.recv(1024).decode(errors="ignore")

                if response == "LIVE_REQUEST_SENT":
                    self.update_message_area(f"[INFO] Live chat request sent to {target_user}. Waiting for response...")

                elif response == "LIVE_READY":
                    self.update_message_area(f"[INFO] Live chat started with {target_user}. Type 'exit' to leave.")
                    self.handle_live_chat()

                elif response == "USER_OFFLINE":
                    self.update_message_area(f"[INFO] {target_user} is offline or unavailable.")

                elif response == "LIVE_DECLINED":
                    self.update_message_area(f"[INFO] {target_user} declined the live chat request.")

            except Exception as e:
                self.update_message_area(f"[ERROR] Failed to start live conversation: {e}")

        threading.Thread(target=handle_request, daemon=True).start()

    def approve_live_request(self):
        """Approve or reject a live chat request."""
        try:
            self.client.send("LIVE_REQUEST_APPROVE".encode())
            response = self.client.recv(1024).decode(errors="ignore")

            if response.startswith("LIVE_REQUEST"):
                sender = response.split("|")[1]
                approve = messagebox.askyesno("Live Chat Request", f"Approve live chat request from {sender}?")
                if approve:
                    self.client.send("LIVE_ACCEPT".encode())
                    self.update_message_area(f"[INFO] Live chat started with {sender}.")
                    self.handle_live_chat()
                else:
                    self.client.send("LIVE_DECLINE".encode())
        except Exception as e:
            messagebox.showerror("Error", f"Failed to approve request: {e}")

    def handle_live_chat(self):
        """Handle live chat messages."""
        def receive_live_messages():
            while True:
                try:
                    message = self.client.recv(1024).decode(errors="ignore")
                    if not message or message.lower() == "exit":
                        self.update_message_area("[INFO] Live conversation ended.")
                        break
                    self.update_message_area(f"Live: {message}")
                except Exception as e:
                    self.update_message_area(f"[ERROR] {e}")
                    break

        threading.Thread(target=receive_live_messages, daemon=True).start()


        import tkinter as tk
        from tkinter import messagebox, scrolledtext
        from Cryptodome.PublicKey import RSA
        from Cryptodome.Signature import pkcs1_15
        from Cryptodome.Hash import SHA256
        import socket
        import os
        import threading

        class SecureCommunicationClient:
            def __init__(self, master):
                self.master = master
                self.master.title("Secure Communication Suite")
                self.master.geometry("700x800")
                self.client = None
                self.username = ""

                # Frames
                self.login_frame = tk.Frame(master)
                self.chat_frame = tk.Frame(master)

                # Initialize Login Frame
                self.setup_login_frame()

            def update_message_area(self, message):
                """Update the message display area with new messages."""
                self.message_area.config(state=tk.NORMAL)
                self.message_area.insert(tk.END, message + "\n")
                self.message_area.config(state=tk.DISABLED)
                self.message_area.see(tk.END)

            def disconnect_from_server(self):
                """Gracefully disconnect from the server."""
                try:
                    self.client.send("EXIT".encode())
                    self.client.close()
                    self.update_message_area("[INFO] Disconnected from server.")
                except Exception as e:
                    self.update_message_area(f"[ERROR] Failed to disconnect: {e}")

            def handle_live_chat(self):
                """Handle live chat messages."""

                def receive_live_messages():
                    """Continuously receive live chat messages."""
                    while True:
                        try:
                            message = self.client.recv(1024).decode(errors="ignore")
                            if not message or message.lower() == "exit":
                                self.update_message_area("[INFO] Live conversation ended.")
                                break
                            self.update_message_area(f"Live: {message}")
                        except Exception as e:
                            self.update_message_area(f"[ERROR] {e}")
                            break

                # Thread for receiving live messages
                threading.Thread(target=receive_live_messages, daemon=True).start()

                def send_live_messages():
                    """Continuously send live chat messages."""
                    while True:
                        msg = self.message_entry.get().strip()
                        if msg.lower() == "exit":
                            self.client.send(msg.encode())
                            self.update_message_area("[INFO] You left the live chat.")
                            break
                        if msg:
                            self.client.send(msg.encode())
                            self.message_entry.delete(0, tk.END)

                # Thread for sending live messages
                threading.Thread(target=send_live_messages, daemon=True).start()

            def listen_to_server(self):
                """Continuously listen for incoming messages or live chat requests from the server."""
                while True:
                    try:
                        message = self.client.recv(2048).decode(errors="ignore")

                        if message.startswith("LIVE_REQUEST"):
                            sender = message.split("|")[1]
                            approve = messagebox.askyesno("Live Chat Request",
                                                          f"Live chat request from {sender}. Accept?")
                            if approve:
                                self.client.send("LIVE_ACCEPT".encode())
                                self.update_message_area(f"[INFO] Live chat started with {sender}.")
                                self.handle_live_chat()
                            else:
                                self.client.send("LIVE_DECLINE".encode())
                                self.update_message_area(f"[INFO] Declined live chat request from {sender}.")

                        elif message.startswith("[INFO]"):
                            self.update_message_area(message)

                        elif message.startswith("[ERROR]"):
                            self.update_message_area(f"[ERROR] {message}")

                        elif message == "END_OF_MESSAGES":
                            self.update_message_area("[INFO] End of message queue.")

                        elif message.startswith("LIVE_READY"):
                            self.update_message_area("[INFO] Live chat is ready. Starting...")
                            self.handle_live_chat()

                        else:
                            self.update_message_area(f"Received: {message}")

                    except Exception as e:
                        self.update_message_area(f"[ERROR] Lost connection to the server: {e}")
                        break

            def setup_login_frame(self):
                """Setup the login frame."""
                self.clear_frame(self.login_frame)

                tk.Label(self.login_frame, text="Secure Communication Suite", font=("Arial", 20, "bold"),
                         pady=20).pack()
                tk.Label(self.login_frame, text="Enter Username:", font=("Arial", 14)).pack(pady=10)

                self.username_entry = tk.Entry(self.login_frame, font=("Arial", 12))
                self.username_entry.pack(pady=10)

                tk.Button(self.login_frame, text="Start", command=self.start_client, font=("Arial", 12)).pack(pady=20)
                self.login_frame.pack(fill=tk.BOTH, expand=True)

            def setup_chat_frame(self):
                """Setup the chat frame."""
                self.clear_frame(self.chat_frame)

                tk.Label(self.chat_frame, text=f"Welcome, {self.username}!", font=("Arial", 16, "bold"), pady=20).pack()

                # Message Display Area
                self.message_area = scrolledtext.ScrolledText(self.chat_frame, height=20, width=70, state=tk.DISABLED)
                self.message_area.pack(pady=10)

                # Recipient and Message Input
                tk.Label(self.chat_frame, text="Recipient Username:", font=("Arial", 12)).pack(pady=5)
                self.recipient_entry = tk.Entry(self.chat_frame, font=("Arial", 12), width=50)
                self.recipient_entry.pack(pady=5)

                tk.Label(self.chat_frame, text="Message:", font=("Arial", 12)).pack(pady=5)
                self.message_entry = tk.Entry(self.chat_frame, font=("Arial", 12), width=50)
                self.message_entry.pack(pady=5)

                # Buttons
                tk.Button(self.chat_frame, text="Send Message", command=self.send_message, font=("Arial", 12)).pack(
                    pady=10)
                tk.Button(self.chat_frame, text="Receive Messages", command=self.receive_messages,
                          font=("Arial", 12)).pack(pady=10)
                tk.Button(self.chat_frame, text="Start Live Conversation", command=self.start_live_conversation,
                          font=("Arial", 12)).pack(pady=10)
                tk.Button(self.chat_frame, text="Approve Live Request", command=self.approve_live_request,
                          font=("Arial", 12)).pack(pady=10)
                self.chat_frame.pack(fill=tk.BOTH, expand=True)

            def start_client(self):
                """Start the client and handle authentication."""
                self.username = self.username_entry.get().strip()
                if not self.username:
                    messagebox.showerror("Error", "Username cannot be empty!")
                    return

                self.generate_and_save_keys()

                def connect_to_server():
                    try:
                        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        self.client.connect(('localhost', 5566))
                        self.client.send(self.username.encode())

                        response = self.client.recv(1024).decode(errors="ignore")

                        if response == "SIGN_UP":
                            with open(f"{self.username}_public.pem", "rb") as pub_file:
                                public_key_pem = pub_file.read()
                            self.client.send(public_key_pem)
                            messagebox.showinfo("Info", "Registration successful.")
                        elif response == "SIGN_IN":
                            self.sign_in()
                        else:
                            messagebox.showerror("Error", "Unexpected server response.")
                            return

                        self.master.after(0, self.setup_chat_frame)

                        # Start listener thread
                        threading.Thread(target=self.listen_to_server, daemon=True).start()

                    except Exception as e:
                        messagebox.showerror("Error", f"Unable to connect: {e}")

                threading.Thread(target=connect_to_server, daemon=True).start()

            def generate_and_save_keys(self):
                """Generate RSA keys and save them to .pem files."""
                if not os.path.exists(f"{self.username}_private.pem") or not os.path.exists(
                        f"{self.username}_public.pem"):
                    private_key = RSA.generate(2048)
                    with open(f"{self.username}_private.pem", "wb") as priv_file:
                        priv_file.write(private_key.export_key())
                    with open(f"{self.username}_public.pem", "wb") as pub_file:
                        pub_file.write(private_key.publickey().export_key())

            def sign_in(self):
                """Sign in an existing user."""
                try:
                    challenge = self.client.recv(1024)
                    with open(f"{self.username}_private.pem", "rb") as priv_file:
                        private_key = RSA.import_key(priv_file.read())
                    signature = self.sign_challenge(challenge, private_key)
                    self.client.send(signature)

                    auth_response = self.client.recv(1024).decode(errors="ignore")
                    if auth_response == "AUTH_FAILED":
                        messagebox.showerror("Error", "Authentication failed!")
                        self.client.close()
                except Exception as e:
                    messagebox.showerror("Error", f"Sign-in failed: {e}")

            def send_message(self):
                """Send a message to a recipient."""
                recipient = self.recipient_entry.get().strip()
                message = self.message_entry.get().strip()
                if not recipient:
                    messagebox.showerror("Error", "Recipient username cannot be empty!")
                    return
                if not message:
                    messagebox.showerror("Error", "Message cannot be empty!")
                    return

                try:
                    self.client.send("MESSAGE".encode())
                    self.client.send(f"{recipient}|{message}".encode())
                    self.update_message_area(f"To {recipient}: {message}")
                    self.message_entry.delete(0, tk.END)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to send message: {e}")

            def receive_messages(self):
                """Receive messages from the server."""
                try:
                    self.client.send("RECEIVE".encode())

                    def receive_loop():
                        while True:
                            try:
                                message = self.client.recv(2048).decode(errors="ignore")
                                if message == "END_OF_MESSAGES":
                                    break
                                self.update_message_area(f"Received: {message}")
                            except Exception as e:
                                self.update_message_area(f"[ERROR] {e}")
                                break

                    threading.Thread(target=receive_loop, daemon=True).start()

                except Exception as e:
                    messagebox.showerror("Error", f"Failed to receive messages: {e}")

            def start_live_conversation(self):
                """Start a live conversation with another user."""
                target_user = self.recipient_entry.get().strip()
                if not target_user:
                    messagebox.showerror("Error", "Target username cannot be empty!")
                    return

                def handle_request():
                    try:
                        self.client.send("LIVE".encode())
                        self.client.send(target_user.encode())

                        response = self.client.recv(1024).decode(errors="ignore")

                        if response == "LIVE_REQUEST_SENT":
                            self.update_message_area(
                                f"[INFO] Live chat request sent to {target_user}. Waiting for response...")

                        elif response == "LIVE_READY":
                            self.update_message_area(
                                f"[INFO] Live chat started with {target_user}. Type 'exit' to leave.")
                            self.handle_live_chat()

                        elif response == "USER_OFFLINE":
                            self.update_message_area(f"[INFO] {target_user} is offline or unavailable.")

                        elif response == "LIVE_DECLINED":
                            self.update_message_area(f"[INFO] {target_user} declined the live chat request.")

                    except Exception as e:
                        self.update_message_area(f"[ERROR] Failed to start live conversation: {e}")

                threading.Thread(target=handle_request, daemon=True).start()

            def approve_live_request(self):
                """Approve or reject a live chat request."""
                try:
                    self.client.send("LIVE_REQUEST_APPROVE".encode())
                    response = self.client.recv(1024).decode(errors="ignore")

                    if response.startswith("LIVE_REQUEST"):
                        sender = response.split("|")[1]
                        approve = messagebox.askyesno("Live Chat Request", f"Approve live chat request from {sender}?")
                        if approve:
                            self.client.send("LIVE_ACCEPT".encode())
                            self.update_message_area(f"[INFO] Live chat started with {sender}.")
                            self.handle_live_chat()
                        else:
                            self.client.send("LIVE_DECLINE".encode())
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to approve request: {e}")

            def handle_live_chat(self):
                """Handle live chat messages."""

                def receive_live_messages():
                    while True:
                        try:
                            message = self.client.recv(1024).decode(errors="ignore")
                            if not message or message.lower() == "exit":
                                self.update_message_area("[INFO] Live conversation ended.")
                                break
                            self.update_message_area(f"Live: {message}")
                        except Exception as e:
                            self.update_message_area(f"[ERROR] {e}")
                            break

                threading.Thread(target=receive_live_messages, daemon=True).start()

                def send_live_messages():
                    while True:
                        msg = self.message_entry.get().strip()
                        if msg.lower() == "exit":
                            self.client.send(msg.encode())
                            break
                        self.client.send(msg.encode())
                        self.message_entry.delete(0, tk.END)

                threading.Thread(target=send_live_messages, daemon=True).start()

            def sign_challenge(self, challenge, private_key):
                """Sign the received challenge."""
                h = SHA256.new(challenge)
                return pkcs1_15.new(private_key).sign(h)

            def update_message_area(self, message):
                """Update the message display area with new messages."""
                self.message_area.config(state=tk.NORMAL)
                self.message_area.insert(tk.END, message + "\n")
                self.message_area.config(state=tk.DISABLED)

            @staticmethod
            def clear_frame(frame):
                """Clear all widgets from a frame."""
                for widget in frame.winfo_children():
                    widget.destroy()

        if __name__ == "__main__":
            root = tk.Tk()
            app = SecureCommunicationClient(root)
            root.mainloop()

        def send_live_messages():
            while True:
                msg = self.message_entry.get().strip()
                if msg.lower() == "exit":
                    self.client.send(msg.encode())
                    break
                self.client.send(msg.encode())
                self.message_entry.delete(0, tk.END)

        threading.Thread(target=send_live_messages, daemon=True).start()

    def sign_challenge(self, challenge, private_key):
        """Sign the received challenge."""
        h = SHA256.new(challenge)
        return pkcs1_15.new(private_key).sign(h)

    def update_message_area(self, message):
        """Update the message display area with new messages."""
        self.message_area.config(state=tk.NORMAL)
        self.message_area.insert(tk.END, message + "\n")
        self.message_area.config(state=tk.DISABLED)

    @staticmethod
    def clear_frame(frame):
        """Clear all widgets from a frame."""
        for widget in frame.winfo_children():
            widget.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureCommunicationClient(root)
    root.mainloop()
