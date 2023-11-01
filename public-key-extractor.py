from cryptography.hazmat.primitives import serialization

# Load the recipient's private key from their file
with open('private_key.pem', 'rb') as private_key_file:
    private_key_pem = private_key_file.read()

private_key = serialization.load_pem_private_key(private_key_pem, password=None)

# Extract the public key from the private key
public_key = private_key.public_key()

# Save the public key to a new file
with open('public_key.pem', 'wb') as public_key_file:
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_file.write(public_key_pem)

