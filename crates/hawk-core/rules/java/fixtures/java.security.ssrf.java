class A {
    void m(javax.servlet.http.HttpServletRequest req) throws Exception {
        String url = req.getParameter("url");
        // ruleid: java.security.ssrf
        java.net.URL u = new java.net.URL(url);
        // ok: java.security.ssrf
        java.net.URL v = new java.net.URL("https://example.com");
    }
}
