class A {
    // ruleid: java.security.cookie-http-only
    void m() { Cookie c = new Cookie("name", value); }
    // ok: java.security.cookie-http-only
    void s() { String name = "cookie"; }
}
