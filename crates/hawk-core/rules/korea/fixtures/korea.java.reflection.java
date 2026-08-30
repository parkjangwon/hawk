class A {
    void load(String userInput) {
        // ruleid: korea.java.reflection
        Class<?> dynamic = Class.forName(userInput);
        // ok: korea.java.reflection
        Class<?> fixed = Class.forName("com.example.Foo");
    }
}
