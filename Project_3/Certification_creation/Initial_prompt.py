import os
import rsa
import base64

# Folder that contains this script (not the directory you ran it from)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

users = ["Alice", "Bob", "Charlie", "Daisy", "Emmy"]

attributes = {
    "Alice":   ["Att1", "Att2", "Att5"],
    "Bob":     ["Att1", "Att3", "Att4"],
    "Charlie": ["Att4", "Att5"],
    "Daisy":   ["Att1", "Att2"],
    "Emmy":    ["Att1", "Att2", "Att3", "Att4", "Att5"],
}

for user in users:
    pub, priv = rsa.newkeys(1024)
    pub_line  = base64.b64encode(pub.save_pkcs1("DER")).decode()
    priv_line = base64.b64encode(priv.save_pkcs1("DER")).decode()

    path = os.path.join(BASE_DIR, f"{user}_ca.txt")
    with open(path, "w") as f:
        f.write(pub_line + "\n")
        f.write(priv_line + "\n")
        f.write(", ".join(attributes[user]) + "\n")
