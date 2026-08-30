class A {
    void m(javax.servlet.http.HttpServletRequest req, javax.servlet.http.HttpServletResponse resp) {
        String name = req.getParameter("name");
        // ruleid: java.security.xss-response
        resp.getWriter().write(name);
        // ok: java.security.xss-response
        resp.setStatus(200);
    }
}
