import argparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def generate_aes_key():
    return Fernet.generate_key()

def encrypt_text(text, key):
    f = Fernet(key)
    encrypted_text = f.encrypt(text.encode())
    return encrypted_text

def decrypt_text(encrypted_text, key):
    f = Fernet(key)
    decrypted_text = f.decrypt(encrypted_text).decode()
    return decrypted_text

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key

def serialize_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as key_file:
        key_file.write(pem)

def load_private_key(filename):
    with open(filename, 'rb') as key_file:
        pem = key_file.read()
        private_key = serialization.load_pem_private_key(pem, password=None)
    return private_key

def encrypt_aes_key(aes_key, public_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), 
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def decrypt_aes_key(encrypted_key, private_key):
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  
            algorithm=hashes.SHA256(),  
            label=None
        )
    )
    return aes_key

def main():
    parser = argparse.ArgumentParser(description="AES Text Encryption and Decryption")
    subparsers = parser.add_subparsers(dest='action', help="Choose an action")

    # Key Management Subparser
    key_parser = subparsers.add_parser("key", help="Manage RSA key")
    key_parser.add_argument("--generate", action="store_true", help="Generate a new RSA private key")
    key_parser.add_argument("--private-key", help="Specify the private key file (default: private_key.pem)")

    # Encryption Subparser
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt text")
    encrypt_parser.add_argument("text", help="Text to encrypt")
    encrypt_parser.add_argument("--public-key", required=True, help="Recipient's public key file")
    encrypt_parser.add_argument("--output-file", help="Output file for the encrypted text")

    # Decryption Subparser
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt text")
    decrypt_parser.add_argument("--encrypted-text", required=True, help="Encrypted text file")  
    decrypt_parser.add_argument("--private-key", required=True, help="Your private key file")

    args = parser.parse_args()

    if args.action == "key":
        if args.generate:
            private_key = generate_rsa_key_pair()
            private_key_file = args.private_key if args.private_key else "private_key.pem"
            serialize_private_key(private_key, private_key_file)
            print(f"Private key generated and saved to {private_key_file}")

    elif args.action == "encrypt":
        with open(args.public_key, 'rb') as key_file:
            public_key_pem = key_file.read()
            public_key = serialization.load_pem_public_key(public_key_pem)

        aes_key = generate_aes_key()
        
        encrypted_aes_key = encrypt_aes_key(aes_key, public_key) 
        with open("encrypted_aes_key.bin", 'wb') as key_file:
            key_file.write(encrypted_aes_key)
            
        encrypted_text = encrypt_text(args.text, aes_key)

        if args.output_file:
            with open(args.output_file, 'wb') as output_file:
                output_file.write(encrypted_text)
            print(f"Text encrypted and saved to {args.output_file}")
            print(f"Encrypted AES key saved to encrypted_aes_key.bin")
            with open("encrypted_aes_key.bin", 'wb') as key_file:
                key_file.write(encrypted_aes_key)
        else:
            print("Encrypted text:")
            print(encrypted_text)

    elif args.action == "decrypt":
        with open(args.private_key, 'rb') as key_file:
            private_key_pem = key_file.read()
            private_key = serialization.load_pem_private_key(private_key_pem, password=None)

        with open("encrypted_aes_key.bin", 'rb') as key_file:
            encrypted_aes_key = key_file.read()
            
        with open(args.encrypted_text, 'rb') as text_file:
            encrypted_text = text_file.read()
        
        decrypted_aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
        if decrypted_aes_key:
            decrypted_text = decrypt_text(encrypted_text, decrypted_aes_key)

            print("Decrypted text:")
            print(decrypted_text)
        else:
            print("Decryption failed. Check the keys or input data.")

if __name__ == "__main__":
    main()

