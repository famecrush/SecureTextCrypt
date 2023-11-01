# SecureTextCrypt

**SecureTextCrypt** is a Python utility for secure text encryption and decryption using RSA and AES cryptography. Safeguard your sensitive data during storage and transmission.

## Features

- Generate RSA key pairs (private and public keys).
- Encrypt text messages with a recipient's public key.
- Decrypt encrypted messages using your private key.
- Strong encryption for data privacy.

## Usage

### Generate RSA Keys

python program.py key --generate --private-key my_private_key.pem

Encrypt Text
````
python program.py encrypt "Your secret message" --public-key recipient_public_key.pem --output-file encrypted_text.bin
````
Decrypt Text
````
python program.py decrypt encrypted_text.bin --private-key my_private_key.pem
````


## Installation
Clone the repository:
````
git clone https://github.com/yourusername/SecureTextCrypt.git
````
Install the required dependencies:
````
pip install -r requirements.txt
````
## Features Contributing
Contributions are welcome! Feel free to open issues and pull requests.
