class A {
    void m(javax.servlet.http.HttpServletRequest req) {
        String name = req.getParameter("file");
        // ruleid: java.security.path-traversal
        File f = new File("/data/" + name);
        // ok: java.security.path-traversal
        File g = new File("/data/fixed.txt");
    }
}
