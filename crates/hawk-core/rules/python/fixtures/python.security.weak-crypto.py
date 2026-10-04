# ruleid: python.security.weak-crypto
h = hashlib.md5(data.encode()).hexdigest()
# ok: python.security.weak-crypto
h256 = hashlib.sha256(data.encode()).hexdigest()
