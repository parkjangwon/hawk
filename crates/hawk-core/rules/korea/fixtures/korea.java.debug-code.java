class A {
    // ruleid: korea.java.debug-code
    void m() { System.out.println("start"); }
    // ok: korea.java.debug-code
    void s() { logger.info("start"); }
}
