class A {
    // ruleid: java.security.runtime-exec
    void m() { Runtime.getRuntime().exec(cmd); }
    // ok: java.security.runtime-exec
    void s() { System.out.println("hi"); }
}
