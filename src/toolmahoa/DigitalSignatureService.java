package toolmahoa;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class DigitalSignatureService {
    // Tái sử dụng dịch vụ RSA để parse khóa từ chuỗi Base64 người dùng nhập.
    private final AsymmetricCryptoService asymmetricCryptoService = new AsymmetricCryptoService();

    // Chữ ký số: ký thông điệp bằng private key RSA.
    // signatureAlgorithm quyết định hàm băm đi kèm RSA (ví dụ SHA256withRSA).
    public String sign(String privateKeyBase64, String message, String signatureAlgorithm) throws Exception {
        PrivateKey privateKey = asymmetricCryptoService.parsePrivateKey(privateKeyBase64);
        Signature signature = Signature.getInstance(signatureAlgorithm);
        signature.initSign(privateKey);
        signature.update(CryptoUtils.utf8Bytes(message));
        return CryptoUtils.toBase64(signature.sign());
    }

    // Chữ ký số: xác minh chữ ký bằng public key RSA.
    // Trả về true nếu chữ ký hợp lệ với đúng thông điệp và đúng khóa công khai.
    public boolean verify(String publicKeyBase64, String message, String signatureBase64, String signatureAlgorithm)
            throws Exception {
        PublicKey publicKey = asymmetricCryptoService.parsePublicKey(publicKeyBase64);
        Signature signature = Signature.getInstance(signatureAlgorithm);
        signature.initVerify(publicKey);
        signature.update(CryptoUtils.utf8Bytes(message));
        return signature.verify(CryptoUtils.fromBase64(signatureBase64));
    }
}
