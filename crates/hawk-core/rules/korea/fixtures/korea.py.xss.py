def view():
    # ruleid: korea.py.xss
    return mark_safe(request.args.get("q"))
    # ok: korea.py.xss
    return escape(request.args.get("q"))
