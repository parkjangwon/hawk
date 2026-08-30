class A {
    // ruleid: korea.java.code-injection
    void m() { engine.eval(request.getParameter("code")); }
    // ok: korea.java.code-injection
    void s() { engine.put("x", value); }
}
