user_path = request.args.get("file")
# ruleid: korea.py.path-traversal
with open(user_path) as f:
    data = f.read()
# ok: korea.py.path-traversal
with open('/etc/hosts') as f:
    data = f.read()
