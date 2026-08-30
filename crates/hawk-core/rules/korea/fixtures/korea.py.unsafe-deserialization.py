# ruleid: korea.py.unsafe-deserialization
data = yaml.load(stream)
# ok: korea.py.unsafe-deserialization
data = yaml.safe_load(stream)
