class A {
    void m(javax.servlet.http.HttpServletRequest req) {
        String cmd = req.getParameter("cmd");
        // ruleid: java.security.command-injection
        Runtime.getRuntime().exec(cmd);
        // ok: java.security.command-injection
        Runtime.getRuntime().exit(0);
    }
}
