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

LOG_PATH = os.path.join(BASE_DIR, "revocation_log.txt")


# ---------------------------------------------------------------- helpers
def sharekey_path(user):
    return os.path.join(BASE_DIR, f"{user}_sharekey.txt")


def ca_path(user):
    return os.path.join(CA_DIR, f"{user}_ca.txt")


def attr_sort(attrs):
    return sorted(attrs, key=attr_num)


def write_sharekey(user, key):
    wrapped = rsa.encrypt(key, get_public_key(user))
    with open(sharekey_path(user), "w") as f:
        f.write(base64.b64encode(wrapped).decode())


def list_sharekeys():
    return [f"{u}_sharekey.txt" for u in users if os.path.exists(sharekey_path(u))]


def encrypt_plaintext(key):
    """Re-encrypt plaintext.txt with `key`; same embedded policy on line 1."""
    with open(plain_path, "rb") as f:
        d = f.read()
    new_iv = get_random_bytes(AES.block_size)
    ct = AES.new(key, AES.MODE_CBC, new_iv).encrypt(pad(d, AES.block_size))
    new_blob = base64.b64encode(new_iv + ct).decode()
    with open(enc_path, "w") as f:
        f.write(POLICY + "\n")
        f.write(new_blob + "\n")
    return new_blob


def read_enc():
    with open(enc_path) as f:
        policy = f.readline().strip()
        enc_blob = f.readline().strip()
    return policy, enc_blob


def aes_decrypt(key, enc_blob):
    raw = base64.b64decode(enc_blob)
    d_iv, ct = raw[:AES.block_size], raw[AES.block_size:]
    content = unpad(AES.new(key, AES.MODE_CBC, d_iv).decrypt(ct), AES.block_size)
    return content.decode()   # wrong key -> ValueError / UnicodeDecodeError


def pick_user():
    name = input("User name: ").strip().capitalize()
    if name not in users:
        print("Unknown user. Choose from:", ", ".join(users))
        return None
    return name


# ------------------------------------------------- member side (decryption)
def access_file(user):
    policy, enc_blob = read_enc()                      # embedded policy from the file
    if not satisfies_policy(policy, get_attributes(user)):
        print(f"{user}: None (policy not satisfied)")
        return
    print(f"{user}: Satisfied!")
    if not os.path.exists(sharekey_path(user)):
        print(f"{user}: None (no share key file)")
        return
    with open(sharekey_path(user)) as f:
        wrapped = base64.b64decode(f.read().strip())
    try:
        user_K = rsa.decrypt(wrapped, get_private_key(user))
    except rsa.DecryptionError:
        print(f"{user}: could not unwrap share key")
        return
    print(f"K <- RSA.Decryption(Secret Key of {user}, {user}_sharekey.txt): {user_K.hex()}")
    try:
        content = aes_decrypt(user_K, enc_blob)
    except (ValueError, UnicodeDecodeError):
        print("Decryption failed (this key does not decrypt plaintext.txt.enc)")
        return
    print("Content <- AES.Decryption(K, plaintext.txt.enc)")
    print("Content:", content)


def test_all():
    for u in users:
        print()
        access_file(u)


# ------------------------------------------------------- admin menu actions
def show_users():
    print(f"\nPolicy: {POLICY}\n")
    print(f"{'User':8} {'Attributes':32} {'Meets policy':13} Share key file")
    for u in users:
        attrs = attr_sort(get_attributes(u))
        ok = satisfies_policy(POLICY, set(attrs))
        has = "yes" if os.path.exists(sharekey_path(u)) else "no"
        print(f"{u:8} {', '.join(attrs):32} {'yes' if ok else 'no':13} {has}")


def change_attribute(action):
    """CA revokes/grants one attribute: edit line 3 of the CA file and log it."""
    user = pick_user()
    if not user:
        return
    attrs = get_attributes(user)
    print(f"{user} currently has: {', '.join(attr_sort(attrs))}")
    raw = input("Attribute (e.g. Att1, or just 1): ").strip()
    m = re.fullmatch(r"(?i)(?:attr|att)?\s*([1-5])", raw)
    if not m:
        print("Attribute must be 1 through 5 (for example Att1, Attr1 or 1).")
        return
    num = int(m.group(1))
    existing = next((a for a in attrs if attr_num(a) == num), None)
    if action == "REVOKED":
        if existing is None:
            print(f"{user} does not have attribute {num}.")
            return
        att = existing                       # keep the spelling used in the CA file
        attrs.remove(att)
    else:
        if existing is not None:
            print(f"{user} already has {existing}.")
            return
        style = "Attr" if any(a.startswith("Attr") for a in attrs) else "Att"
        att = f"{style}{num}"
        attrs.add(att)

    with open(ca_path(user)) as f:
        lines = f.read().splitlines()
    lines[2] = ", ".join(attr_sort(attrs))             # only line 3 changes
    with open(ca_path(user), "w") as f:
        f.write("\n".join(lines) + "\n")

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_PATH, "a") as f:
        f.write(f"{ts}, {user}, {att}, {action}\n")

    print(f"\n{action}: {att} for {user}.")
    print(f"\n{user}_ca.txt line 3 is now:", lines[2])
    print("\nrevocation_log.txt:")
    with open(LOG_PATH) as f:
        print(f.read())
    print("Note: the old K still works until you rotate the key.")


def rotate_key():
    global K
    old_K = K
    _, old_blob = read_enc()

    new_K = get_random_bytes(16)
    new_blob = encrypt_plaintext(new_K)

    # Nobody is preselected; the admin picks who gets K'
    # (eligible is only used to label who meets the policy)
    eligible = {u for u in users if satisfies_policy(POLICY, get_attributes(u))}
    recipients = set()
    while True:
        print("\nRecipients of the NEW key (* = selected):")
        for u in users:
            mark = "*" if u in recipients else " "
            elig = "meets policy" if u in eligible else "does NOT meet policy"
            print(f"  [{mark}] {u:8} {elig:22} ({', '.join(attr_sort(get_attributes(u)))})")
        ans = input("Type names to select/deselect (comma separated), or Enter to confirm: ").strip()
        if not ans:
            break
        for name in ans.split(","):
            name = name.strip().capitalize()
            if name in users:
                recipients.symmetric_difference_update({name})
            else:
                print(f"  Unknown user: {name}")

    for u in recipients - eligible:
        print(f"Warning: {u} does not meet the policy but will get the new key file.")

    stale = set()
    non_recipients = set(users) - recipients
    if non_recipients:
        print("\nNon-recipients:", ", ".join(u for u in users if u in non_recipients))
        if input("Let them keep a share key for the OLD key instead of nothing? (y/N): ").strip().lower() == "y":
            stale = non_recipients

    # Delete old share key files, then write the new set
    for u in users:
        if os.path.exists(sharekey_path(u)):
            os.remove(sharekey_path(u))
    for u in users:
        if u in recipients:
            write_sharekey(u, new_K)
        elif u in stale:
            write_sharekey(u, old_K)

    K = new_K
    old_K = None   # drop the old key reference

    print("\n=== After rotation ===")
    print("Share key files:", ", ".join(list_sharekeys()) or "(none)")
    for u in users:
        if u in stale:
            print(f"  {u}_sharekey.txt wraps the OLD key (stale)")
    print("\nOld encrypted data:", old_blob)
    print("New encrypted data:", new_blob)
    print("Encrypted data differs:", old_blob != new_blob)


# --------------------------------------------------------------- the menu
MENU = """
===== Admin Console =====
 1) View users, attributes, share key status
 2) Revoke an attribute (updates CA file + log)
 3) Grant an attribute (updates CA file + log)
 4) Rotate key (choose who gets the new key)
 5) Test decryption as one user
 6) Test decryption for all users
 0) Exit
"""


def main():
    actions = {
        "1": show_users,
        "2": lambda: change_attribute("REVOKED"),
        "3": lambda: change_attribute("GRANTED"),
        "4": rotate_key,
        "5": lambda: (lambda u: access_file(u) if u else None)(pick_user()),
        "6": test_all,
    }
    print("\n=== Decryption test cases (before any changes) ===")
    test_all()
    while True:
        print(MENU)
        choice = input("Choose: ").strip()
        if choice == "0":
            break
        action = actions.get(choice)
        if action is None:
            print("Invalid choice.")
            continue
        action()

main()