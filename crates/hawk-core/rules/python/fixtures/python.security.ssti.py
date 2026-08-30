def index():
    # ruleid: python.security.ssti
    return render_template_string("Hello " + request.args.get("name"))
    # ok: python.security.ssti
    return render_template_string("Hello")
