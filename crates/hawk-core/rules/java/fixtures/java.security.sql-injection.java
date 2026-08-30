class A {
    void m(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) {
        String id = req.getParameter("id");
        String sql = "SELECT * FROM u WHERE id=" + id;
        // ruleid: java.security.sql-injection
        st.executeQuery(sql);
        // ok: java.security.sql-injection
        st.executeQuery("SELECT 1");
    }
}
