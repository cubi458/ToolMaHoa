package toolmahoa;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

public class AsymmetricCryptoService {
    // RSA: Tạo cặp khóa bất đối xứng (Public/Private) theo độ dài người dùng chọn.
    // Khóa trả về ở dạng Base64 để dễ hiển thị/copy trong giao diện.
    public RsaKeyPair generateRsaKeyPair(int keySize) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keySize);
        KeyPair pair = generator.generateKeyPair();
        return new RsaKeyPair(
                CryptoUtils.toBase64(pair.getPublic().getEncoded()),
                CryptoUtils.toBase64(pair.getPrivate().getEncoded()));
    }

    // RSA: Mã hóa bằng Public Key.
    // Lưu ý: RSA phù hợp cho dữ liệu ngắn (thực tế thường mã hóa khóa phiên).
    public String encryptWithPublicKey(String publicKeyBase64, String plainText) throws Exception {
        PublicKey publicKey = parsePublicKey(publicKeyBase64);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(CryptoUtils.utf8Bytes(plainText));
        return CryptoUtils.toBase64(encrypted);
    }

    // RSA: Giải mã bằng Private Key tương ứng với Public Key đã dùng lúc mã hóa.
    public String decryptWithPrivateKey(String privateKeyBase64, String cipherTextBase64) throws Exception {
        PrivateKey privateKey = parsePrivateKey(privateKeyBase64);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plain = cipher.doFinal(CryptoUtils.fromBase64(cipherTextBase64));
        return CryptoUtils.utf8String(plain);
    }

    // Parse Public Key từ Base64 theo chuẩn X.509.
    // Đây là định dạng phổ biến khi lưu/truyền public key.
    public PublicKey parsePublicKey(String publicKeyBase64) throws Exception {
        byte[] keyBytes = CryptoUtils.fromBase64(publicKeyBase64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    // Parse Private Key từ Base64 theo chuẩn PKCS#8.
    // Đây là định dạng chuẩn để biểu diễn private key trong Java.
    public PrivateKey parsePrivateKey(String privateKeyBase64) throws Exception {
        byte[] keyBytes = CryptoUtils.fromBase64(privateKeyBase64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    public record RsaKeyPair(String publicKeyBase64, String privateKeyBase64) {
    }
}
