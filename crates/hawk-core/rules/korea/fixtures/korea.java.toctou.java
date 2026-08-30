class A {
    // ruleid: korea.java.toctou
    void m() { if (file.exists()) { open(file); } }
    // ok: korea.java.toctou
    void s() { InputStream in = new FileInputStream(file); }
}
