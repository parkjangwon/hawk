class A {
    // ruleid: korea.java.unsafe-api
    void m() { System.gc(); }
    // ok: korea.java.unsafe-api
    void s() { System.exit(0); }
}
