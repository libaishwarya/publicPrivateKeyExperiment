from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Generate an RSA private key with a key length of 2048 bits
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Serialize the private key to PEM format
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Generate the corresponding public key
public_key = private_key.public_key()

# Serialize the public key to PEM format
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Print the private and public keys in PEM format
print("Private Key:\n", private_key_pem.decode())
print("Public Key:\n", public_key_pem.decode())

# Message to be encrypted
message = b'This is a secret message'

# Encrypt the message using the public key
encrypted_message = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Decrypt the encrypted message using the private key
decrypted_message = private_key.decrypt(
    encrypted_message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Print the original message and decrypted message
print("Original message:", message)
print("Decrypted message:", decrypted_message)



# Generate an RSA private key with a key length of 2048 bits
private_key2 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Serialize the private key to PEM format
private_key_pem2 = private_key2.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Generate the corresponding public key
public_key2 = private_key2.public_key()

# Serialize the public key to PEM format
public_key_pem2 = public_key2.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Print the private and public keys in PEM format
print("Private Key2:\n", private_key_pem2.decode())
print("Public Key2:\n", public_key_pem2.decode())

# Decrypt the encrypted message using the private key
decrypted_message = private_key2.decrypt(
    encrypted_message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Print the original message and decrypted message
print("Original message:", message)
print("Decrypted message:", decrypted_message)
