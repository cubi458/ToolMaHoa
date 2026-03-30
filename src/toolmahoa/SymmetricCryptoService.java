package toolmahoa;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricCryptoService {
    private final SecureRandom secureRandom = new SecureRandom();

    public String generateKeyBase64(String algorithm, int keySize)
            throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(normalizeForKeyGen(algorithm));
        keyGenerator.init(keySize, secureRandom);
        SecretKey key = keyGenerator.generateKey();
        return CryptoUtils.toBase64(key.getEncoded());
    }

    public String encrypt(String algorithm, String keyBase64, String plainText) throws Exception {
        SecretKeySpec key = new SecretKeySpec(CryptoUtils.fromBase64(keyBase64), normalizeForKeySpec(algorithm));

        if ("ChaCha20".equalsIgnoreCase(algorithm)) {
            byte[] nonce = new byte[12];
            secureRandom.nextBytes(nonce);
            int counter = 1;
            Cipher cipher = Cipher.getInstance("ChaCha20");
            AlgorithmParameterSpec spec = new ChaCha20ParameterSpec(nonce, counter);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            byte[] encrypted = cipher.doFinal(CryptoUtils.utf8Bytes(plainText));

            byte[] merged = new byte[nonce.length + encrypted.length];
            System.arraycopy(nonce, 0, merged, 0, nonce.length);
            System.arraycopy(encrypted, 0, merged, nonce.length, encrypted.length);
            return CryptoUtils.toBase64(merged);
        }

        Cipher cipher = Cipher.getInstance(getCipherTransformation(algorithm));
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(CryptoUtils.utf8Bytes(plainText));
        return CryptoUtils.toBase64(encrypted);
    }

    public String decrypt(String algorithm, String keyBase64, String cipherTextBase64) throws Exception {
        SecretKeySpec key = new SecretKeySpec(CryptoUtils.fromBase64(keyBase64), normalizeForKeySpec(algorithm));

        if ("ChaCha20".equalsIgnoreCase(algorithm)) {
            byte[] merged = CryptoUtils.fromBase64(cipherTextBase64);
            if (merged.length <= 12) {
                throw new IllegalArgumentException("Du lieu ma hoa ChaCha20 khong hop le.");
            }
            byte[] nonce = new byte[12];
            byte[] encrypted = new byte[merged.length - 12];
            System.arraycopy(merged, 0, nonce, 0, 12);
            System.arraycopy(merged, 12, encrypted, 0, encrypted.length);

            int counter = 1;
            Cipher cipher = Cipher.getInstance("ChaCha20");
            AlgorithmParameterSpec spec = new ChaCha20ParameterSpec(nonce, counter);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            byte[] plain = cipher.doFinal(encrypted);
            return CryptoUtils.utf8String(plain);
        }

        Cipher cipher = Cipher.getInstance(getCipherTransformation(algorithm));
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plain = cipher.doFinal(CryptoUtils.fromBase64(cipherTextBase64));
        return CryptoUtils.utf8String(plain);
    }

    private String normalizeForKeyGen(String algorithm) {
        if ("RC4".equalsIgnoreCase(algorithm)) {
            return "ARCFOUR";
        }
        return algorithm;
    }

    private String normalizeForKeySpec(String algorithm) {
        if ("RC4".equalsIgnoreCase(algorithm)) {
            return "ARCFOUR";
        }
        return algorithm;
    }

    private String getCipherTransformation(String algorithm)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        if ("AES".equalsIgnoreCase(algorithm)) {
            return "AES/ECB/PKCS5Padding";
        }
        if ("DES".equalsIgnoreCase(algorithm)) {
            return "DES/ECB/PKCS5Padding";
        }
        if ("DESede".equalsIgnoreCase(algorithm)) {
            return "DESede/ECB/PKCS5Padding";
        }
        if ("Blowfish".equalsIgnoreCase(algorithm)) {
            return "Blowfish/ECB/PKCS5Padding";
        }
        if ("RC4".equalsIgnoreCase(algorithm)) {
            return "ARCFOUR";
        }
        if ("Twofish".equalsIgnoreCase(algorithm)) {
            // Yeu cau provider BC trong runtime.
            return "Twofish/ECB/PKCS5Padding";
        }
        if ("Serpent".equalsIgnoreCase(algorithm)) {
            // Yeu cau provider BC trong runtime.
            return "Serpent/ECB/PKCS5Padding";
        }

        throw new NoSuchAlgorithmException("Giai thuat khong duoc ho tro: " + algorithm);
    }
}
