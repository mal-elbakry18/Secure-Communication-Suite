#HASHING USING SHA-256 IMPLEMENTATION

import hashlib

def generate_hash(message):
    return hashlib.sha256(message.encode()).hexdigest()

def verify_hash(message, received_hash):
    return generate_hash(message) == received_hash
