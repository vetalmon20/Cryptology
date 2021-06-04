package ua.knu.hash;

public class Haval {
    private final HavalHash hash;

    public Haval() {
        hash = new HavalHash();
    }

    public Haval(int size, int rounds) {
        hash = new HavalHash(size, rounds);
    }

    public String hash(String string) {
        hash.reset();
        hash.update(string.getBytes(), 0, string.length());
        return Util.toString(hash.digest());
    }
}
