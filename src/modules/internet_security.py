from src.modules.public_key import encrypt_with_public_key, decrypt_with_private_key

class Server:
    def __init__(self):
        self.public_keys = {}

    def exchange_keys(self, user_id, public_key):
        self.public_keys[user_id] = public_key
        return self.public_keys

    def relay_message(self, recipient_id, message):
        # Simulate relaying the message
        return f"Message to {recipient_id}: {message}"
