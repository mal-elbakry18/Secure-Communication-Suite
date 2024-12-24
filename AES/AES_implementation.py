#from Crypto.Cipher import AES
from Cryptodome.Cipher import AES
from Crypto.Random import get_random_bytes
import base64


class AESModule:
    def __init__(self):
        self.key = get_random_bytes(16)  # Generate a 128-bit AES key

    def encrypt(self, plaintext):
        """
        Encrypts the given plaintext using AES in EAX mode.

        Args:
            plaintext (str): The plaintext message to encrypt.

        Returns:
            dict: Contains ciphertext (base64), nonce (base64), and tag (base64).
        """
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(cipher.nonce).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8')
        }

    def decrypt(self, ciphertext, nonce, tag):
        """
        Decrypts the given ciphertext using AES in EAX mode.

        Args:
            ciphertext (str): The encrypted message (base64 encoded).
            nonce (str): The nonce used during encryption (base64 encoded).
            tag (str): The authentication tag (base64 encoded).

        Returns:
            str: The decrypted plaintext message.

        Raises:
            ValueError: If the ciphertext cannot be decrypted or the tag does not match.
        """
        try:
            cipher = AES.new(self.key, AES.MODE_EAX, nonce=base64.b64decode(nonce))
            plaintext = cipher.decrypt_and_verify(base64.b64decode(ciphertext), base64.b64decode(tag))
            return plaintext.decode('utf-8')
        except (ValueError, KeyError):
            raise ValueError("Decryption failed or integrity check failed.")

# Example Usage
def example_usage():
    aes = AESModule()
    print("Generated AES Key:", base64.b64encode(aes.key).decode('utf-8'))

    # Encrypt a message
    plaintext = "New Message."
    encrypted = aes.encrypt(plaintext)
    print("Encrypted Message:", encrypted)

    # Decrypt the message
    try:
        decrypted = aes.decrypt(encrypted['ciphertext'], encrypted['nonce'], encrypted['tag'])
        print("Decrypted Message:", decrypted)
    except ValueError as e:
        print("Error:", str(e))

if __name__ == "__main__":
    example_usage()