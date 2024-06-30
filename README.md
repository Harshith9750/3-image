# 3-image
Encrypting images involves converting the image data into a format that can only be reverted to its original state using a secure key. This can be achieved using symmetric encryption algorithms such as AES (Advanced Encryption Standard). Here's a basic outline of how to create a Python script for image encryption and decryption.

Steps to Create an Image Encryption Script
Setup Environment:

Install the required libraries: pip install cryptography pillow
Create the Image Encryption Script:

Create a Python file (e.g., image_encryptor.py).
Image Encryption Code:

python
Copy code
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from PIL import Image
import os
import base64
import io

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_image(image_path, password):
    # Load the image
    with Image.open(image_path) as img:
        img_bytes = io.BytesIO()
        img.save(img_bytes, format=img.format)
        plaintext = img_bytes.getvalue()

    # Generate salt and derive key
    salt = os.urandom(16)
    key = derive_key(password, salt)

    # Encrypt the image data
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Save encrypted data to a file
    encrypted_image_path = image_path + ".enc"
    with open(encrypted_image_path, 'wb') as f:
        f.write(salt + iv + ciphertext)

    return encrypted_image_path

def decrypt_image(encrypted_image_path, password):
    # Read encrypted data from file
    with open(encrypted_image_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()

    # Derive key
    key = derive_key(password, salt)

    # Decrypt the image data
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Load decrypted image data into an image object
    img = Image.open(io.BytesIO(plaintext))
    decrypted_image_path = encrypted_image_path + ".dec." + img.format.lower()
    img.save(decrypted_image_path)

    return decrypted_image_path

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Encrypt or decrypt an image.")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode to run the script in: encrypt or decrypt.")
    parser.add_argument("image_path", help="Path to the image file.")
    parser.add_argument("password", help="Password for encryption/decryption.")

    args = parser.parse_args()

    if args.mode == "encrypt":
        encrypted_image = encrypt_image(args.image_path, args.password)
        print(f"Encrypted image saved to {encrypted_image}")
    elif args.mode == "decrypt":
        decrypted_image = decrypt_image(args.image_path, args.password)
        print(f"Decrypted image saved to {decrypted_image}")
Explanation:
Libraries:

cryptography.hazmat: Provides cryptographic primitives.
PIL (Pillow): A Python Imaging Library used to handle image operations.
os: Used for generating random salt and IV.
base64 and io: For handling image data in memory.
Key Derivation:

Uses PBKDF2HMAC with SHA256 to derive a secure key from the password and salt.
Encryption and Decryption:

Encryption: Converts the image to bytes, encrypts the bytes using AES in CFB mode, and saves the result to a file.
Decryption: Reads the encrypted data, decrypts it using the same AES in CFB mode, and saves the decrypted image.
Running the Script:
Save the image_encryptor.py file.
Encrypt an image:
sh
Copy code
python image_encryptor.py encrypt path/to/your/image.png yourpassword
Decrypt the image:
sh
Copy code
python image_encryptor.py decrypt path/to/your/image.png.enc yourpassword
Security Considerations:
Password Strength: Ensure that a strong password is used for encryption to prevent brute-force attacks.
Key Management: Securely store and handle the password used for encryption and decryption.
This project will give you hands-on experience with cryptographic algorithms and key management, essential skills in cybersecurity. Always ensure that you understand and follow ethical guidelines and legal requirements when working with encryption and sensitive data.
