package toolmahoa;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class CryptoUtils {
    private CryptoUtils() {
    }

    public static String toBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] fromBase64(String text) {
        return Base64.getDecoder().decode(text.trim());
    }

    public static byte[] utf8Bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    public static String utf8String(byte[] data) {
        return new String(data, StandardCharsets.UTF_8);
    }
}
