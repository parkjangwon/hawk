class A {
    void m(
        javax.servlet.http.HttpServletRequest req,
        org.springframework.jdbc.core.JdbcTemplate jdbcTemplate
    ) {
        String q = req.getParameter("q");
        // ruleid: java.security.spring-sql-jdbc-template
        jdbcTemplate.query(q, rs -> {});
        // ok: java.security.spring-sql-jdbc-template
        jdbcTemplate.query("SELECT 1", rs -> {});
    }
}
