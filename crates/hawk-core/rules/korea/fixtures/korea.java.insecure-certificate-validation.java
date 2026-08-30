class A {
    // ruleid: korea.java.insecure-certificate-validation
    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) { return true; }
    // ok: korea.java.insecure-certificate-validation
    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) { log.debug("trusted"); }
}
