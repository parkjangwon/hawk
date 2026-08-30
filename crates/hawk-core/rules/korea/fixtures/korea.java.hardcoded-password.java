class A {
    // ruleid: korea.java.hardcoded-password
    String password = "s3cr3t!";
    // ok: korea.java.hardcoded-password
    String password = System.getenv("DB_PASS");
}
