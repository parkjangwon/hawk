# ruleid: korea.py.toctou
if os.path.exists(path):
    open(path).read()
# ok: korea.py.toctou
with open(path) as f:
    data = f.read()
