# ruleid: korea.py.weak-random
token = "".join(str(random.randrange(10)) for _ in range(6))
# ok: korea.py.weak-random
token = secrets.token_hex(16)
