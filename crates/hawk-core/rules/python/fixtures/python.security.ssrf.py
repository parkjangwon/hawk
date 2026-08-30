def f(req):
    # ruleid: python.security.ssrf
    return requests.get(req.get("url"))
    # ok: python.security.ssrf
    return requests.get("https://example.com")
