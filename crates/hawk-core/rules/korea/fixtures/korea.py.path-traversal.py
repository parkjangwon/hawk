# ruleid: korea.py.path-traversal
with open(request_file) as f:
    data = f.read()
# ok: korea.py.path-traversal
with open('/etc/hosts') as f:
    data = f.read()
