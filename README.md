# SecureTextCrypt

**SecureTextCrypt** is a Python utility for secure text encryption and decryption using RSA and AES cryptography. Safeguard your sensitive data during storage and transmission.

## Features

- Generate RSA key pairs (private and public keys).
- Encrypt text messages with a recipient's public key.
- Decrypt encrypted messages using your private key.
- Strong encryption for data privacy.

## Usage

### Generate RSA Keys
#### WINDOWS

Generate Private key
````
python SecureTextCrypt.py key --generate --private-key my_private_key.pem
````
Encrypt Text
````
python SecureTextCrypt.py encrypt "Your secret message" --public-key recipient_public_key.pem --output-file encrypted_text.bin
````
Decrypt Text
````
python SecureTextCrypt.py decrypt --encrypted-text encrypted_text.bin --private-key private_key.pem
````
To extract public key from private key
````
python public-key-extractor.py
#CHECK THE CODE AND CHANGE THE FILE NAME ACCORDING TO YOUR NEED.
````
#### LINUX
Generate Private key
````
python3 SecureTextCrypt.py key --generate --private-key my_private_key.pem
````
Encrypt Text
````
python3 SecureTextCrypt.py encrypt "Your secret message" --public-key recipient_public_key.pem --output-file encrypted_text.bin
````
Decrypt Text
````
python3 SecureTextCrypt.py decrypt --encrypted-text encrypted_text.bin --private-key private_key.pem
````
To extract public key from private key
````
python3 public-key-extractor.py
#CHECK THE CODE AND CHANGE THE FILE NAME ACCORDING TO YOUR NEED.
````
### Installation
Clone the repository:
````
git clone https://github.com/famecrush/TEXT-ENCRYPTER.git
````
Install the required dependencies:
````
pip install -r requirements.txt
````
## Features Contributing
Contributions are welcome! Feel free to open issues and pull requests.

## Contact
My LinkedIn :- https://www.linkedin.com/in/mahipal-choudhary-b8181823a/
