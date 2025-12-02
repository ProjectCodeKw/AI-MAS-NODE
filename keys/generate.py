from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# Generate Ed25519 keypair
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Export private key
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Export public key
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Print private key
print("PRIVATE KEY:")
print(private_pem.decode())

# Print public key
print("\nPUBLIC KEY:")
print(public_pem.decode())