class A {
    // ruleid: korea.java.unsafe-deserialization
    void m() throws Exception { ObjectInputStream in = new ObjectInputStream(is); Object o = in.readObject(); }
    // ok: korea.java.unsafe-deserialization
    void s() throws Exception { Object o = jsonMapper.readValue(bytes, User.class); }
}
