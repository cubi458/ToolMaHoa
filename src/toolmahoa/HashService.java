package toolmahoa;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashService {
    public String hashText(String algorithm, String text) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] hashed = digest.digest(CryptoUtils.utf8Bytes(text));
        return toHex(hashed);
    }

    private String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
