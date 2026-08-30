class A {
    // ruleid: korea.java.raw-socket
    void m() throws Exception { Socket s = new Socket("kisa.or.kr", 8080); }
    // ok: korea.java.raw-socket
    void s() throws Exception { Socket s = socketFactory.createSocket("kisa.or.kr", 443); }
}
