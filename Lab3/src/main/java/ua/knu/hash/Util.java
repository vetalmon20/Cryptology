package ua.knu.hash;

public class Util {
    private static final char[] HEX_DIGITS = "0123456789ABCDEF".toCharArray();

    public static String toString(byte[] ba) {
        return toString(ba, 0, ba.length);
    }

    public static String toString(byte[] ba, int offset, int length) {
        char[] buf = new char[length * 2];
        for (int i = 0, j = 0, k; i < length; ) {
            k = ba[offset + i++];
            buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[ k        & 0x0F];
        }
        return new String(buf);
    }
}
