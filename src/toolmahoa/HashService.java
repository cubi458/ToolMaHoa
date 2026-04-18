package toolmahoa;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashService {
    // Băm một chiều chuỗi đầu vào bằng thuật toán đã chọn (MD5, SHA-1, SHA-256, ...).
    // Kết quả băm là mảng byte, sau đó được đổi sang hex để người dùng dễ đọc.
    public String hashText(String algorithm, String text) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] hashed = digest.digest(CryptoUtils.utf8Bytes(text));
        return toHex(hashed);
    }

    // Chuyển từng byte sang 2 ký tự hex (00-ff) để hiển thị đầy đủ giá trị băm.
    private String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
