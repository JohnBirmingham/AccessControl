import rsa, base64

users = ["Alice", "Bob", "Charlie", "Daisy", "Emmy"]

# Fill this in from your assignment's table
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
    with open(f"{user}_ca.txt", "w") as f:
        f.write(pub_line + "\n")
        f.write(priv_line + "\n")
        f.write(", ".join(attributes[user]) + "\n")