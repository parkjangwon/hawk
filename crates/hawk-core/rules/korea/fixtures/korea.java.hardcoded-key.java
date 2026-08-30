class A {
    // ruleid: korea.java.hardcoded-key
    String secret = "ABCDEFGHIJKLMNOP";
    // ok: korea.java.hardcoded-key
    String secret = System.getenv("KEY");
}
