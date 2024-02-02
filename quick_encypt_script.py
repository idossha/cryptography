from cryptography.fernet import Fernet
import base64

# Function to write and read key to a file
def write_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("secret.key", "rb").read()

# Encrypt a message
def encrypt_message(message, key):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    # Encode the bytes to a base64 string for safe printing/storing
    return base64.urlsafe_b64encode(encrypted_message).decode()

# Decrypt a message
def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    # Decode the base64 string to bytes
    encrypted_message_bytes = base64.urlsafe_b64decode(encrypted_message)
    decrypted_message = f.decrypt(encrypted_message_bytes)
    return decrypted_message.decode()

# Main flow
if __name__ == "__main__":
    choice = input("Do you want to generate a new key? (yes/no): ")
    if choice.lower() == 'yes':
        write_key()
    
    key = load_key()
    action = input("Do you want to (encrypt/decrypt) a password?: ")

    if action.lower() == 'encrypt':
        password = input("Enter the password to encrypt: ")
        encrypted_password = encrypt_message(password, key)
        print(f"Encrypted password: {encrypted_password}")
    elif action.lower() == 'decrypt':
        encrypted_password = input("Enter the encrypted password: ")
        try:
            decrypted_password = decrypt_message(encrypted_password, key)
            print(f"Decrypted password: {decrypted_password}")
        except Exception as e:  # More specific exception handling
            print(f"An error occurred: {e}")
    else:
        print("Invalid action.")
