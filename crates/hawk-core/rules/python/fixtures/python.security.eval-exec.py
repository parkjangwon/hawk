def f():
    # ruleid: python.security.eval-exec
    return eval(request.args.get("code"))
    # ok: python.security.eval-exec
    return json.loads(text)
