class A {
    void m(javax.servlet.http.HttpServletRequest req, javax.servlet.http.HttpServletResponse resp) {
        String url = req.getParameter("url");
        // ruleid: korea.java.open-redirect
        resp.sendRedirect(url);
        // ok: korea.java.open-redirect
        resp.sendRedirect("/home");
    }
}
