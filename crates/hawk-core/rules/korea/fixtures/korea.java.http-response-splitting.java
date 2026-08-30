class A {
    void m(javax.servlet.http.HttpServletRequest req, javax.servlet.http.HttpServletResponse resp) {
        String value = req.getParameter("value");
        // ruleid: korea.java.http-response-splitting
        resp.setHeader("X-Custom", value);
        // ok: korea.java.http-response-splitting
        resp.setHeader("X-Custom", "static");
    }
}
