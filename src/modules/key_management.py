key_storage = {}

def store_key(user_id, key):
    key_storage[user_id] = key

def retrieve_key(user_id):
    return key_storage.get(user_id)
