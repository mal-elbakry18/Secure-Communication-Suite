import hashlib

def generate_hash(message):
    return hashlib.sha256(message.encode()).hexdigest()
