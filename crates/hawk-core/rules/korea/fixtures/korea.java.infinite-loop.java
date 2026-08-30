class A {
    // ruleid: korea.java.infinite-loop
    void m() { while (true) { work(); } }
    // ok: korea.java.infinite-loop
    void s() { while (running) { work(); } }
}
