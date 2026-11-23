import os
import re
import base64
import rsa
from datetime import datetime
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CA_DIR = os.path.join(BASE_DIR, "Certification_creation")

users = ["Alice", "Bob", "Charlie", "Daisy", "Emmy"]
POLICY = "(Att1 AND Att2) OR (Att3 AND Att4 AND Att5)"


# CA
def get_public_key(user):
    """Ask the 'CA' for a user's public key (line 1 of their CA file)."""
    with open(os.path.join(CA_DIR, f"{user}_ca.txt")) as f:
        pub_line = f.readline().strip()
    return rsa.PublicKey.load_pkcs1(base64.b64decode(pub_line), "DER")

def get_private_key(user):
    """A user's private key (line 2 of their CA file)."""
    with open(os.path.join(CA_DIR, f"{user}_ca.txt")) as f:
        f.readline()  # public key
        priv_line = f.readline().strip()
    return rsa.PrivateKey.load_pkcs1(base64.b64decode(priv_line), "DER")

def get_attributes(user):
    """Ask the 'CA' for a user's attributes (line 3 of their CA file)."""
    with open(os.path.join(CA_DIR, f"{user}_ca.txt")) as f:
        f.readline()  # public key
        f.readline()  # private key
        line = f.readline().strip()
    return {a.strip() for a in line.split(",") if a.strip()}


# Authorization policy
def attr_num(a):
    """Attribute number, so 'Att1' and 'Attr1' both count as attribute 1."""
    return int(re.search(r"\d+", a).group())

def satisfies_policy(policy, attrs):
    """Evaluate a policy string like '(Att1 AND Att2) OR (Att3 AND Att4 AND Att5)'."""
    token_re = r"Att\d+|AND|OR|\(|\)"
    # Reject anything that isn't an attribute, AND, OR, or a parenthesis
    if re.sub(token_re + r"|\s", "", policy):
        raise ValueError("Invalid policy")
    parts = []
    for t in re.findall(token_re, policy):
        if t.startswith("Att"):
            parts.append("True" if t in attrs else "False")
        elif t == "AND":
            parts.append("and")
        elif t == "OR":
            parts.append("or")
        else:
            parts.append(t)
    return eval(" ".join(parts), {"__builtins__": {}}, {})


# K and sharekey files
K = get_random_bytes(16)  # AES-128

for user in users:
    wrapped = rsa.encrypt(K, get_public_key(user))
    with open(os.path.join(BASE_DIR, f"{user}_sharekey.txt"), "w") as f:
        f.write(base64.b64encode(wrapped).decode())

print("=== Share key files ===")
for user in users:
    filename = f"{user}_sharekey.txt"
    with open(os.path.join(BASE_DIR, filename)) as f:
        print(f"\n{filename}:")
        print(f.read())


#plaintext
plain_path = os.path.join(BASE_DIR, "plaintext.txt")
enc_path = os.path.join(BASE_DIR, "plaintext.txt.enc")

with open(plain_path, "w") as f:
    f.write("Hello there my friend welcome to accounting")

with open(plain_path, "rb") as f:
    data = f.read()

iv = get_random_bytes(AES.block_size)
cipher = AES.new(K, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(data, AES.block_size))
blob = base64.b64encode(iv + ciphertext).decode()

with open(enc_path, "w") as f:
    f.write(POLICY + "\n")   # line 1: embedded access control policy
    f.write(blob + "\n")     # line 2: IV + ciphertext (base64)

# Evaluation output: encrypted data and embedded policy
print("\n=== plaintext.txt.enc ===")
print("Embedded policy:", POLICY)
print("Encrypted data: ", blob)

#authorization check

def access_file(user, enc_file=enc_path):
    # 1. Read the embedded policy and the encrypted blob from the .enc file
    with open(enc_file) as f:
        policy = f.readline().strip()
        blob = f.readline().strip()

    # 2. Check the user's current attributes against the embedded policy
    if not satisfies_policy(policy, get_attributes(user)):
        print(f"{user}: None")
        return None
    print(f"{user}: Satisfied!")

    # 3. K <- RSA.Decryption(private key of user, <user>_sharekey.txt)
    share_path = os.path.join(BASE_DIR, f"{user}_sharekey.txt")
    if not os.path.exists(share_path):
        print(f"{user}: no share key file")
        return None
    with open(share_path) as f:
        wrapped = base64.b64decode(f.read().strip())
    try:
        K_user = rsa.decrypt(wrapped, get_private_key(user))
    except rsa.DecryptionError:
        print(f"{user}: could not unwrap share key")
        return None
    print(f"{user}: K recovered ->", K_user.hex())

    # 4. Content <- AES.Decryption(K, plaintext.txt.enc)
    raw = base64.b64decode(blob)
    iv, ciphertext = raw[:AES.block_size], raw[AES.block_size:]
    try:
        content = unpad(AES.new(K_user, AES.MODE_CBC, iv).decrypt(ciphertext),
                        AES.block_size)
    except ValueError:
        print(f"{user}: Decryption failed")
        return None

    print("Content:", content.decode())
    return content


print("\n=== Decryption test cases ===")
for user in users:
    print()
    access_file(user)