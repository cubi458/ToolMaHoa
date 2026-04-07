package toolmahoa;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
    private static final int ALPHABET_SIZE = 26;
    private static final int[] AFFINE_A_VALUES = new int[] { 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25 };

    public String generateKeyBase64(String algorithm, int keySize)
            throws NoSuchAlgorithmException {
        if (isManualAlgorithm(algorithm)) {
            return generateManualKey(algorithm);
        }

        KeyGenerator keyGenerator = KeyGenerator.getInstance(normalizeForKeyGen(algorithm));
        keyGenerator.init(keySize, secureRandom);
        SecretKey key = keyGenerator.generateKey();
        return CryptoUtils.toBase64(key.getEncoded());
    }

    public boolean isManualAlgorithm(String algorithm) {
        return "Caesar".equalsIgnoreCase(algorithm)
                || "Vigenere".equalsIgnoreCase(algorithm)
                || "Playfair".equalsIgnoreCase(algorithm)
                || "Hill".equalsIgnoreCase(algorithm)
                || "Affine".equalsIgnoreCase(algorithm);
    }

    private String generateManualKey(String algorithm) {
        if ("Caesar".equalsIgnoreCase(algorithm)) {
            return String.valueOf(1 + secureRandom.nextInt(25));
        }
        if ("Vigenere".equalsIgnoreCase(algorithm)) {
            return randomUppercaseKey(8);
        }
        if ("Playfair".equalsIgnoreCase(algorithm)) {
            return randomUppercaseKey(8);
        }
        if ("Affine".equalsIgnoreCase(algorithm)) {
            int a = AFFINE_A_VALUES[secureRandom.nextInt(AFFINE_A_VALUES.length)];
            int b = secureRandom.nextInt(ALPHABET_SIZE);
            return a + "," + b;
        }
        if ("Hill".equalsIgnoreCase(algorithm)) {
            while (true) {
                int a = secureRandom.nextInt(ALPHABET_SIZE);
                int b = secureRandom.nextInt(ALPHABET_SIZE);
                int c = secureRandom.nextInt(ALPHABET_SIZE);
                int d = secureRandom.nextInt(ALPHABET_SIZE);
                int det = mod(a * d - b * c, ALPHABET_SIZE);
                if (gcd(det, ALPHABET_SIZE) == 1) {
                    return a + "," + b + "," + c + "," + d;
                }
            }
        }
        throw new IllegalArgumentException("Giải thuật không được hỗ trợ: " + algorithm);
    }

    public String encrypt(String algorithm, String keyBase64, String plainText) throws Exception {
        if (isManualAlgorithm(algorithm)) {
            return encryptManual(algorithm, keyBase64, plainText);
        }

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
        if (isManualAlgorithm(algorithm)) {
            return decryptManual(algorithm, keyBase64, cipherTextBase64);
        }

        SecretKeySpec key = new SecretKeySpec(CryptoUtils.fromBase64(keyBase64), normalizeForKeySpec(algorithm));

        if ("ChaCha20".equalsIgnoreCase(algorithm)) {
            byte[] merged = CryptoUtils.fromBase64(cipherTextBase64);
            if (merged.length <= 12) {
                throw new IllegalArgumentException("Dữ liệu mã hóa ChaCha20 không hợp lệ.");
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
            // Yêu cầu provider BC trong runtime.
            return "Twofish/ECB/PKCS5Padding";
        }
        if ("Serpent".equalsIgnoreCase(algorithm)) {
            // Yêu cầu provider BC trong runtime.
            return "Serpent/ECB/PKCS5Padding";
        }

        throw new NoSuchAlgorithmException("Giải thuật không được hỗ trợ: " + algorithm);
    }

    private String encryptManual(String algorithm, String key, String plainText) {
        if ("Caesar".equalsIgnoreCase(algorithm)) {
            int shift = Integer.parseInt(key.trim());
            return caesarTransform(plainText, shift);
        }
        if ("Vigenere".equalsIgnoreCase(algorithm)) {
            return vigenereEncrypt(plainText, key);
        }
        if ("Playfair".equalsIgnoreCase(algorithm)) {
            return playfairEncrypt(plainText, key);
        }
        if ("Affine".equalsIgnoreCase(algorithm)) {
            int[] parts = parseAffineKey(key);
            return affineEncrypt(plainText, parts[0], parts[1]);
        }
        if ("Hill".equalsIgnoreCase(algorithm)) {
            int[] m = parseHillKey(key);
            return hillEncrypt(plainText, m);
        }
        throw new IllegalArgumentException("Giải thuật không được hỗ trợ: " + algorithm);
    }

    private String decryptManual(String algorithm, String key, String cipherText) {
        if ("Caesar".equalsIgnoreCase(algorithm)) {
            int shift = Integer.parseInt(key.trim());
            return caesarTransform(cipherText, -shift);
        }
        if ("Vigenere".equalsIgnoreCase(algorithm)) {
            return vigenereDecrypt(cipherText, key);
        }
        if ("Playfair".equalsIgnoreCase(algorithm)) {
            return playfairDecrypt(cipherText, key);
        }
        if ("Affine".equalsIgnoreCase(algorithm)) {
            int[] parts = parseAffineKey(key);
            return affineDecrypt(cipherText, parts[0], parts[1]);
        }
        if ("Hill".equalsIgnoreCase(algorithm)) {
            int[] m = parseHillKey(key);
            return hillDecrypt(cipherText, m);
        }
        throw new IllegalArgumentException("Giải thuật không được hỗ trợ: " + algorithm);
    }

    private String randomUppercaseKey(int len) {
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append((char) ('A' + secureRandom.nextInt(ALPHABET_SIZE)));
        }
        return sb.toString();
    }

    private String caesarTransform(String input, int shift) {
        StringBuilder sb = new StringBuilder(input.length());
        int normalized = mod(shift, ALPHABET_SIZE);
        for (char ch : input.toCharArray()) {
            if (ch >= 'A' && ch <= 'Z') {
                sb.append((char) ('A' + mod((ch - 'A') + normalized, ALPHABET_SIZE)));
            } else if (ch >= 'a' && ch <= 'z') {
                sb.append((char) ('a' + mod((ch - 'a') + normalized, ALPHABET_SIZE)));
            } else {
                sb.append(ch);
            }
        }
        return sb.toString();
    }

    private String vigenereEncrypt(String text, String key) {
        String cleanKey = cleanLetters(key);
        if (cleanKey.isEmpty()) {
            throw new IllegalArgumentException("Khóa Vigenère không hợp lệ.");
        }
        StringBuilder sb = new StringBuilder(text.length());
        int keyIndex = 0;
        for (char ch : text.toCharArray()) {
            if (Character.isLetter(ch)) {
                int shift = Character.toUpperCase(cleanKey.charAt(keyIndex % cleanKey.length())) - 'A';
                boolean lower = Character.isLowerCase(ch);
                int base = lower ? 'a' : 'A';
                int value = Character.toUpperCase(ch) - 'A';
                char out = (char) (base + mod(value + shift, ALPHABET_SIZE));
                sb.append(out);
                keyIndex++;
            } else {
                sb.append(ch);
            }
        }
        return sb.toString();
    }

    private String vigenereDecrypt(String text, String key) {
        String cleanKey = cleanLetters(key);
        if (cleanKey.isEmpty()) {
            throw new IllegalArgumentException("Khóa Vigenère không hợp lệ.");
        }
        StringBuilder sb = new StringBuilder(text.length());
        int keyIndex = 0;
        for (char ch : text.toCharArray()) {
            if (Character.isLetter(ch)) {
                int shift = Character.toUpperCase(cleanKey.charAt(keyIndex % cleanKey.length())) - 'A';
                boolean lower = Character.isLowerCase(ch);
                int base = lower ? 'a' : 'A';
                int value = Character.toUpperCase(ch) - 'A';
                char out = (char) (base + mod(value - shift, ALPHABET_SIZE));
                sb.append(out);
                keyIndex++;
            } else {
                sb.append(ch);
            }
        }
        return sb.toString();
    }

    private String affineEncrypt(String text, int a, int b) {
        validateAffineA(a);
        StringBuilder sb = new StringBuilder(text.length());
        for (char ch : text.toCharArray()) {
            if (Character.isLetter(ch)) {
                boolean lower = Character.isLowerCase(ch);
                int base = lower ? 'a' : 'A';
                int value = Character.toUpperCase(ch) - 'A';
                char out = (char) (base + mod(a * value + b, ALPHABET_SIZE));
                sb.append(out);
            } else {
                sb.append(ch);
            }
        }
        return sb.toString();
    }

    private String affineDecrypt(String text, int a, int b) {
        validateAffineA(a);
        int invA = modInverse(a, ALPHABET_SIZE);
        StringBuilder sb = new StringBuilder(text.length());
        for (char ch : text.toCharArray()) {
            if (Character.isLetter(ch)) {
                boolean lower = Character.isLowerCase(ch);
                int base = lower ? 'a' : 'A';
                int value = Character.toUpperCase(ch) - 'A';
                char out = (char) (base + mod(invA * (value - b), ALPHABET_SIZE));
                sb.append(out);
            } else {
                sb.append(ch);
            }
        }
        return sb.toString();
    }

    private int[] parseAffineKey(String key) {
        String[] parts = key.trim().split(",");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Khóa Affine phải có dạng a,b. Ví dụ: 5,8");
        }
        int a = Integer.parseInt(parts[0].trim());
        int b = Integer.parseInt(parts[1].trim());
        validateAffineA(a);
        return new int[] { a, mod(b, ALPHABET_SIZE) };
    }

    private void validateAffineA(int a) {
        if (gcd(mod(a, ALPHABET_SIZE), ALPHABET_SIZE) != 1) {
            throw new IllegalArgumentException("Giá trị a của Affine phải nguyên tố cùng nhau với 26.");
        }
    }

    private int[] parseHillKey(String key) {
        String[] parts = key.trim().split(",");
        if (parts.length != 4) {
            throw new IllegalArgumentException("Khóa Hill phải có dạng a,b,c,d cho ma trận 2x2.");
        }
        int[] m = new int[4];
        for (int i = 0; i < 4; i++) {
            m[i] = mod(Integer.parseInt(parts[i].trim()), ALPHABET_SIZE);
        }
        int det = mod(m[0] * m[3] - m[1] * m[2], ALPHABET_SIZE);
        if (gcd(det, ALPHABET_SIZE) != 1) {
            throw new IllegalArgumentException("Ma trận Hill không khả nghịch mod 26.");
        }
        return m;
    }

    private String hillEncrypt(String text, int[] m) {
        String clean = cleanLetters(text).toUpperCase();
        if (clean.length() % 2 != 0) {
            clean += "X";
        }
        StringBuilder out = new StringBuilder(clean.length());
        for (int i = 0; i < clean.length(); i += 2) {
            int x1 = clean.charAt(i) - 'A';
            int x2 = clean.charAt(i + 1) - 'A';
            int y1 = mod(m[0] * x1 + m[1] * x2, ALPHABET_SIZE);
            int y2 = mod(m[2] * x1 + m[3] * x2, ALPHABET_SIZE);
            out.append((char) ('A' + y1));
            out.append((char) ('A' + y2));
        }
        return out.toString();
    }

    private String hillDecrypt(String text, int[] m) {
        String clean = cleanLetters(text).toUpperCase();
        if (clean.length() % 2 != 0) {
            throw new IllegalArgumentException("Bản mã Hill phải có số ký tự chẵn.");
        }

        int det = mod(m[0] * m[3] - m[1] * m[2], ALPHABET_SIZE);
        int invDet = modInverse(det, ALPHABET_SIZE);
        int[] inv = new int[] {
                mod(invDet * m[3], ALPHABET_SIZE),
                mod(invDet * (-m[1]), ALPHABET_SIZE),
                mod(invDet * (-m[2]), ALPHABET_SIZE),
                mod(invDet * m[0], ALPHABET_SIZE)
        };

        StringBuilder out = new StringBuilder(clean.length());
        for (int i = 0; i < clean.length(); i += 2) {
            int y1 = clean.charAt(i) - 'A';
            int y2 = clean.charAt(i + 1) - 'A';
            int x1 = mod(inv[0] * y1 + inv[1] * y2, ALPHABET_SIZE);
            int x2 = mod(inv[2] * y1 + inv[3] * y2, ALPHABET_SIZE);
            out.append((char) ('A' + x1));
            out.append((char) ('A' + x2));
        }
        return out.toString();
    }

    private String playfairEncrypt(String text, String key) {
        char[][] matrix = buildPlayfairMatrix(key);
        List<char[]> pairs = splitPlayfairPairs(text);
        StringBuilder out = new StringBuilder();
        for (char[] pair : pairs) {
            int[] p1 = findPlayfairPosition(matrix, pair[0]);
            int[] p2 = findPlayfairPosition(matrix, pair[1]);

            if (p1[0] == p2[0]) {
                out.append(matrix[p1[0]][(p1[1] + 1) % 5]);
                out.append(matrix[p2[0]][(p2[1] + 1) % 5]);
            } else if (p1[1] == p2[1]) {
                out.append(matrix[(p1[0] + 1) % 5][p1[1]]);
                out.append(matrix[(p2[0] + 1) % 5][p2[1]]);
            } else {
                out.append(matrix[p1[0]][p2[1]]);
                out.append(matrix[p2[0]][p1[1]]);
            }
        }
        return out.toString();
    }

    private String playfairDecrypt(String text, String key) {
        char[][] matrix = buildPlayfairMatrix(key);
        String clean = cleanLetters(text).toUpperCase().replace('J', 'I');
        if (clean.length() % 2 != 0) {
            throw new IllegalArgumentException("Bản mã Playfair phải có số ký tự chẵn.");
        }

        StringBuilder out = new StringBuilder();
        for (int i = 0; i < clean.length(); i += 2) {
            char a = clean.charAt(i);
            char b = clean.charAt(i + 1);
            int[] p1 = findPlayfairPosition(matrix, a);
            int[] p2 = findPlayfairPosition(matrix, b);

            if (p1[0] == p2[0]) {
                out.append(matrix[p1[0]][mod(p1[1] - 1, 5)]);
                out.append(matrix[p2[0]][mod(p2[1] - 1, 5)]);
            } else if (p1[1] == p2[1]) {
                out.append(matrix[mod(p1[0] - 1, 5)][p1[1]]);
                out.append(matrix[mod(p2[0] - 1, 5)][p2[1]]);
            } else {
                out.append(matrix[p1[0]][p2[1]]);
                out.append(matrix[p2[0]][p1[1]]);
            }
        }
        return out.toString();
    }

    private char[][] buildPlayfairMatrix(String key) {
        String source = (cleanLetters(key) + "ABCDEFGHIKLMNOPQRSTUVWXYZ").toUpperCase().replace('J', 'I');
        Set<Character> seen = new HashSet<>();
        List<Character> chars = new ArrayList<>(25);
        for (char ch : source.toCharArray()) {
            if (ch >= 'A' && ch <= 'Z' && ch != 'J' && seen.add(ch)) {
                chars.add(ch);
            }
        }
        if (chars.size() != 25) {
            throw new IllegalArgumentException("Không thể tạo ma trận Playfair từ khóa đã nhập.");
        }

        char[][] matrix = new char[5][5];
        int idx = 0;
        for (int r = 0; r < 5; r++) {
            for (int c = 0; c < 5; c++) {
                matrix[r][c] = chars.get(idx++);
            }
        }
        return matrix;
    }

    private List<char[]> splitPlayfairPairs(String text) {
        String clean = cleanLetters(text).toUpperCase().replace('J', 'I');
        List<char[]> pairs = new ArrayList<>();
        int i = 0;
        while (i < clean.length()) {
            char a = clean.charAt(i);
            char b;
            if (i + 1 >= clean.length()) {
                b = 'X';
                i++;
            } else {
                b = clean.charAt(i + 1);
                if (a == b) {
                    b = 'X';
                    i++;
                } else {
                    i += 2;
                }
            }
            pairs.add(new char[] { a, b });
        }
        return pairs;
    }

    private int[] findPlayfairPosition(char[][] matrix, char target) {
        char t = target == 'J' ? 'I' : target;
        for (int r = 0; r < 5; r++) {
            for (int c = 0; c < 5; c++) {
                if (matrix[r][c] == t) {
                    return new int[] { r, c };
                }
            }
        }
        throw new IllegalArgumentException("Ký tự không tồn tại trong ma trận Playfair: " + target);
    }

    private String cleanLetters(String text) {
        StringBuilder sb = new StringBuilder(text.length());
        for (char ch : text.toCharArray()) {
            if (Character.isLetter(ch)) {
                sb.append(ch);
            }
        }
        return sb.toString();
    }

    private int modInverse(int a, int mod) {
        int x = mod(a, mod);
        for (int i = 1; i < mod; i++) {
            if (mod(x * i, mod) == 1) {
                return i;
            }
        }
        throw new IllegalArgumentException("Không tồn tại nghịch đảo modulo.");
    }

    private int gcd(int a, int b) {
        int x = Math.abs(a);
        int y = Math.abs(b);
        while (y != 0) {
            int t = x % y;
            x = y;
            y = t;
        }
        return x;
    }

    private int mod(int value, int mod) {
        int r = value % mod;
        return r < 0 ? r + mod : r;
    }
}
