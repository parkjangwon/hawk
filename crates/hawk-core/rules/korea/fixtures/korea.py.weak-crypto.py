# ruleid: korea.py.weak-crypto
h = hashlib.md5(pw.encode()).hexdigest()
# ok: korea.py.weak-crypto
h = hashlib.sha256(pw.encode()).hexdigest()
