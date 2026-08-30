import hashlib


def store(password, salt):
    # ruleid: korea.py.unsalted-hash
    digest = hashlib.sha256(password.encode())
    # ok: korea.py.unsalted-hash
    digest2 = hashlib.sha256(password.encode() + salt)
    # ok: korea.py.unsalted-hash
    kdf = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
