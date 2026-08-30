class A {
    // ruleid: korea.java.short-crypto-key
    void m() throws Exception { KeyGenerator.getInstance("AES").init(56); }
    // ok: korea.java.short-crypto-key
    void s() throws Exception { KeyGenerator.getInstance("AES").init(256); }
}
