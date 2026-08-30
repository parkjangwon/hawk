class A {
    // ruleid: korea.java.improper-exception
    void m() { try { work(); } catch (Exception e) {} }
    // ok: korea.java.improper-exception
    void s() { try { work(); } catch (Exception e) { log.error("boom", e); } }
}
