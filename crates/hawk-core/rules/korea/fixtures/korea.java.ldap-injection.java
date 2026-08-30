class A {
    void m(javax.servlet.http.HttpServletRequest req, javax.naming.directory.DirContext ctx) throws Exception {
        String filter = req.getParameter("filter");
        // ruleid: korea.java.ldap-injection
        ctx.search("ou=people", filter, null);
        // ok: korea.java.ldap-injection
        ctx.search("ou=people", "(uid=admin)", null);
    }
}
