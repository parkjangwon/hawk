# ruleid: python.security.yaml-unsafe-load
cfg = yaml.load(user_stream)
# ok: python.security.yaml-unsafe-load
safe_cfg = yaml.safe_load(user_stream)
