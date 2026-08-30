class A {
    // ruleid: korea.java.unsigned-code-download
    void m() throws Exception { URLClassLoader l = new URLClassLoader(urls); }
    // ok: korea.java.unsigned-code-download
    void s() { String name = "URLClassLoader"; }
}
