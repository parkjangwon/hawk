class A {
    // ruleid: korea.java.weak-crypto-algorithm
    void m() throws Exception { Cipher c = Cipher.getInstance("DES"); }
    // ok: korea.java.weak-crypto-algorithm
    void s() throws Exception { Cipher c = Cipher.getInstance("AES/GCM/NoPadding"); }
}
