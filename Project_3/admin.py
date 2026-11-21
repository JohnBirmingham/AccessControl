import os
import base64
import rsa
from Crypto.Random import get_random_bytes

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CA_DIR = os.path.join(BASE_DIR, "Certification_creation")

users = ["Alice", "Bob", "Charlie", "Daisy", "Emmy"]

def get_public_key(user):
    """Ask the 'CA' for a user's public key (line 1 of their CA file)."""
    with open(os.path.join(CA_DIR, f"{user}_ca.txt")) as f:
        pub_line = f.readline().strip()
    return rsa.PublicKey.load_pkcs1(base64.b64decode(pub_line), "DER")

# Generate the symmetric key K (16 bytes = AES-128)
K = get_random_bytes(16)

# Wrap K separately for each user and write their share key file
for user in users:
    wrapped = rsa.encrypt(K, get_public_key(user))
    path = os.path.join(BASE_DIR, f"{user}_sharekey.txt")
    with open(path, "w") as f:
        f.write(base64.b64encode(wrapped).decode())
    print("Wrote", path)