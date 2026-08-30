class A {
    // ruleid: java.security.process-builder
    void m() { new ProcessBuilder("sh", "-c", input); }
    // ok: java.security.process-builder
    void s() { new StringBuilder("ok"); }
}
