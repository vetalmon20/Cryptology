public class Main {
    public static void main(String[] args) {
        String strToEncrypt = "Test string for encoding and decoding";
        String key = "Test key for encoding and decoding";
        byte[] keyBytes = key.getBytes();
        byte[] byteArray = MarsCipher.encrypt(strToEncrypt.getBytes(), keyBytes);
        byte[] afterDecryption = MarsCipher.decrypt(byteArray, keyBytes);
        String result = new String(afterDecryption);
        System.out.println(result + " - result");
    }
}
