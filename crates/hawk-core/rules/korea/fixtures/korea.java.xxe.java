class A {
    // ruleid: korea.java.xxe
    void m() { DocumentBuilderFactory f = DocumentBuilderFactory.newInstance(); }
    // ok: korea.java.xxe
    void s() { DocumentBuilderFactory f = DocumentBuilderFactory.newInstance(); f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); }
}
