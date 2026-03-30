package toolmahoa;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class DigitalSignatureService {
    private final AsymmetricCryptoService asymmetricCryptoService = new AsymmetricCryptoService();

    public String sign(String privateKeyBase64, String message, String signatureAlgorithm) throws Exception {
        PrivateKey privateKey = asymmetricCryptoService.parsePrivateKey(privateKeyBase64);
        Signature signature = Signature.getInstance(signatureAlgorithm);
        signature.initSign(privateKey);
        signature.update(CryptoUtils.utf8Bytes(message));
        return CryptoUtils.toBase64(signature.sign());
    }

    public boolean verify(String publicKeyBase64, String message, String signatureBase64, String signatureAlgorithm)
            throws Exception {
        PublicKey publicKey = asymmetricCryptoService.parsePublicKey(publicKeyBase64);
        Signature signature = Signature.getInstance(signatureAlgorithm);
        signature.initVerify(publicKey);
        signature.update(CryptoUtils.utf8Bytes(message));
        return signature.verify(CryptoUtils.fromBase64(signatureBase64));
    }
}
