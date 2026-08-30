class A {
    // ruleid: korea.java.weak-signature
    void m() throws Exception { Signature s = Signature.getInstance("MD5withRSA"); }
    // ok: korea.java.weak-signature
    void s() throws Exception { Signature s = Signature.getInstance("SHA256withRSA"); }
}
