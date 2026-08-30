def f(req):
    # ruleid: python.security.ssrf
    return requests.get(request.args.get("url"))
    url = request.args.get("url")
    # ruleid: python.security.ssrf
    return requests.get(url)
    url2 = request.args["url"]
    # ruleid: python.security.ssrf
    httpx.get(url2)
    # ok: python.security.ssrf
    return requests.get("https://example.com")
    url3 = "https://example.com"
    # ok: python.security.ssrf
    return requests.post(url3)
