package toolmahoa;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.WindowConstants;

public class MainFrame extends JFrame {
    // Mỗi service phụ trách một nhóm chức năng mật mã riêng để tách logic khỏi giao diện.
    private final SymmetricCryptoService symmetricService = new SymmetricCryptoService();
    private final AsymmetricCryptoService asymmetricService = new AsymmetricCryptoService();
    private final HashService hashService = new HashService();
    private final DigitalSignatureService signatureService = new DigitalSignatureService();

    public MainFrame() {
        // Cấu hình cửa sổ chính của ứng dụng.
        setTitle("Tool Mã Hóa - Giữa Kỳ Java 2025");
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setSize(new Dimension(980, 680));
        setLocationRelativeTo(null);

        // Tổ chức UI theo tab để người dùng thao tác theo từng chủ đề.
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Đối xứng", buildSymmetricPanel());
        tabbedPane.addTab("Mã hóa cơ bản", buildBasicCryptoPanel());
        tabbedPane.addTab("Bất đối xứng (RSA)", buildAsymmetricPanel());
        tabbedPane.addTab("Hash", buildHashPanel());
        tabbedPane.addTab("Chữ ký số", buildSignaturePanel());

        add(tabbedPane, BorderLayout.CENTER);
    }

    private JPanel buildSymmetricPanel() {
        // Tab Đối xứng hiện đại: làm việc với các thuật toán hỗ trợ bởi JCE.
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel top = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = createDefaultGbc();

        JComboBox<String> algorithmCombo = new JComboBox<>(new String[] {
                "AES", "DES", "DESede", "Blowfish", "RC4", "ChaCha20", "Twofish", "Serpent"
        });
        JComboBox<String> keySizeCombo = new JComboBox<>(new String[] {
                "AES:128", "AES:192", "AES:256",
                "DES:56",
                "DESede:112", "DESede:168",
                "Blowfish:128", "Blowfish:256", "Blowfish:448",
                "RC4:128", "RC4:256",
                "ChaCha20:256",
                "Twofish:128", "Twofish:192", "Twofish:256",
                "Serpent:128", "Serpent:192", "Serpent:256"
        });
        JTextField keyField = new JTextField(58);

        gbc.gridx = 0;
        gbc.gridy = 0;
        top.add(new JLabel("Giải thuật:"), gbc);
        gbc.gridx = 1;
        top.add(algorithmCombo, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        top.add(new JLabel("Kích thước key:"), gbc);
        gbc.gridx = 1;
        top.add(keySizeCombo, gbc);

        gbc.gridx = 0;
        gbc.gridy = 2;
        top.add(new JLabel("Key Base64:"), gbc);
        gbc.gridx = 1;
        top.add(keyField, gbc);

        JButton btnGenerateKey = new JButton("Tạo Key");
        gbc.gridx = 2;
        gbc.gridy = 2;
        top.add(btnGenerateKey, gbc);

        JTextArea plainTextArea = new JTextArea(8, 72);
        JTextArea cipherTextArea = new JTextArea(8, 72);

        JPanel center = new JPanel(new GridBagLayout());
        GridBagConstraints cg = createDefaultGbc();
        cg.gridx = 0;
        cg.gridy = 0;
        cg.fill = GridBagConstraints.HORIZONTAL;
        center.add(new JLabel("Bản rõ:"), cg);
        cg.gridy = 1;
        cg.fill = GridBagConstraints.BOTH;
        cg.weightx = 1;
        cg.weighty = 1;
        center.add(new JScrollPane(plainTextArea), cg);

        cg.gridy = 2;
        cg.fill = GridBagConstraints.HORIZONTAL;
        cg.weighty = 0;
        center.add(new JLabel("Bản mã (Base64):"), cg);

        cg.gridy = 3;
        cg.fill = GridBagConstraints.BOTH;
        cg.weighty = 1;
        center.add(new JScrollPane(cipherTextArea), cg);

        JPanel bottom = new JPanel();
        JButton btnEncrypt = new JButton("Mã hóa");
        JButton btnDecrypt = new JButton("Giải mã");
        bottom.add(btnEncrypt);
        bottom.add(btnDecrypt);

        // Khi đổi thuật toán, tự động chọn kích thước khóa mặc định phù hợp.
        algorithmCombo.addActionListener(e -> keySizeCombo.setSelectedItem(defaultKeySizeByAlgorithm((String) algorithmCombo
            .getSelectedItem())));

        // Sinh khóa mới và đưa vào ô Key Base64 để người dùng dùng ngay.
        btnGenerateKey.addActionListener(e -> {
            try {
                String algorithm = (String) algorithmCombo.getSelectedItem();
                int keySize = parseKeySize(keySizeCombo, algorithm);
                String key = symmetricService.generateKeyBase64(algorithm, keySize);
                keyField.setText(key);
            } catch (Exception ex) {
                showError(ex);
            }
        });

        // Mã hóa bản rõ -> bản mã Base64.
        btnEncrypt.addActionListener(e -> {
            try {
                String algorithm = (String) algorithmCombo.getSelectedItem();
                String cipherText = symmetricService.encrypt(algorithm, keyField.getText(), plainTextArea.getText());
                cipherTextArea.setText(cipherText);
            } catch (Exception ex) {
                showError(ex);
            }
        });

        // Giải mã bản mã Base64 -> bản rõ.
        btnDecrypt.addActionListener(e -> {
            try {
                String algorithm = (String) algorithmCombo.getSelectedItem();
                String plainText = symmetricService.decrypt(algorithm, keyField.getText(), cipherTextArea.getText());
                plainTextArea.setText(plainText);
            } catch (Exception ex) {
                showError(ex);
            }
        });

        panel.add(top, BorderLayout.NORTH);
        panel.add(center, BorderLayout.CENTER);
        panel.add(bottom, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel buildBasicCryptoPanel() {
        // Tab Mã hóa cơ bản: các thuật toán cổ điển tự cài đặt.
        // Khóa là chuỗi nhập tay (không phải key nhị phân Base64 như nhóm hiện đại).
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel top = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = createDefaultGbc();

        JComboBox<String> algorithmCombo = new JComboBox<>(
                new String[] { "Caesar", "Vigenere", "Playfair", "Hill", "Affine" });
        JTextField keyField = new JTextField(58);

        gbc.gridx = 0;
        gbc.gridy = 0;
        top.add(new JLabel("Giải thuật cơ bản:"), gbc);
        gbc.gridx = 1;
        top.add(algorithmCombo, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        top.add(new JLabel("Khóa:"), gbc);
        gbc.gridx = 1;
        top.add(keyField, gbc);

        JButton btnGenerateKey = new JButton("Tạo Khóa");
        gbc.gridx = 2;
        gbc.gridy = 1;
        top.add(btnGenerateKey, gbc);

        JTextArea plainTextArea = new JTextArea(8, 72);
        JTextArea cipherTextArea = new JTextArea(8, 72);

        JPanel center = new JPanel(new GridBagLayout());
        GridBagConstraints cg = createDefaultGbc();
        cg.gridx = 0;
        cg.gridy = 0;
        cg.fill = GridBagConstraints.HORIZONTAL;
        center.add(new JLabel("Bản rõ:"), cg);

        cg.gridy = 1;
        cg.fill = GridBagConstraints.BOTH;
        cg.weightx = 1;
        cg.weighty = 1;
        center.add(new JScrollPane(plainTextArea), cg);

        cg.gridy = 2;
        cg.fill = GridBagConstraints.HORIZONTAL;
        cg.weighty = 0;
        center.add(new JLabel("Bản mã:"), cg);

        cg.gridy = 3;
        cg.fill = GridBagConstraints.BOTH;
        cg.weighty = 1;
        center.add(new JScrollPane(cipherTextArea), cg);

        JPanel bottom = new JPanel();
        JButton btnEncrypt = new JButton("Mã hóa");
        JButton btnDecrypt = new JButton("Giải mã");
        bottom.add(btnEncrypt);
        bottom.add(btnDecrypt);

        // Gợi ý format khóa để người dùng nhập đúng ngay từ lần đầu.
        JLabel keyHint = new JLabel(
                "Gợi ý khóa: Caesar=3 | Vigenere=LEMON | Playfair=MONARCHY | Hill=3,3,2,5 | Affine=5,8");

        // Sinh khóa mẫu đúng định dạng theo thuật toán cơ bản đang chọn.
        btnGenerateKey.addActionListener(e -> {
            try {
                String algorithm = (String) algorithmCombo.getSelectedItem();
                String key = symmetricService.generateKeyBase64(algorithm, 0);
                keyField.setText(key);
            } catch (Exception ex) {
                showError(ex);
            }
        });

        // Mã hóa bản rõ bằng thuật toán cơ bản.
        btnEncrypt.addActionListener(e -> {
            try {
                String algorithm = (String) algorithmCombo.getSelectedItem();
                String cipherText = symmetricService.encrypt(algorithm, keyField.getText(), plainTextArea.getText());
                cipherTextArea.setText(cipherText);
            } catch (Exception ex) {
                showError(ex);
            }
        });

        // Giải mã bản mã bằng đúng thuật toán/khóa cơ bản tương ứng.
        btnDecrypt.addActionListener(e -> {
            try {
                String algorithm = (String) algorithmCombo.getSelectedItem();
                String plainText = symmetricService.decrypt(algorithm, keyField.getText(), cipherTextArea.getText());
                plainTextArea.setText(plainText);
            } catch (Exception ex) {
                showError(ex);
            }
        });

        panel.add(top, BorderLayout.NORTH);
        panel.add(center, BorderLayout.CENTER);
        JPanel southPanel = new JPanel(new BorderLayout());
        southPanel.add(keyHint, BorderLayout.NORTH);
        southPanel.add(bottom, BorderLayout.SOUTH);
        panel.add(southPanel, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel buildAsymmetricPanel() {
        // Tab Bất đối xứng: RSA (Public Key để mã hóa, Private Key để giải mã).
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel top = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = createDefaultGbc();

        JComboBox<String> keySizeCombo = new JComboBox<>(new String[] { "1024", "2048", "3072", "4096" });
        JButton btnGenerate = new JButton("Tạo cặp key RSA");

        gbc.gridx = 0;
        gbc.gridy = 0;
        top.add(new JLabel("Độ dài key:"), gbc);
        gbc.gridx = 1;
        top.add(keySizeCombo, gbc);
        gbc.gridx = 2;
        top.add(btnGenerate, gbc);

        JTextArea publicKeyArea = new JTextArea(6, 72);
        JTextArea privateKeyArea = new JTextArea(6, 72);
        JTextArea plainTextArea = new JTextArea(6, 72);
        JTextArea cipherTextArea = new JTextArea(6, 72);

        JPanel center = new JPanel(new GridBagLayout());
        GridBagConstraints cg = createDefaultGbc();
        cg.gridx = 0;
        cg.gridy = 0;
        cg.weightx = 1;
        cg.fill = GridBagConstraints.HORIZONTAL;

        center.add(new JLabel("Public Key (Base64 - X.509):"), cg);
        cg.gridy++;
        cg.fill = GridBagConstraints.BOTH;
        cg.weighty = 0.5;
        center.add(new JScrollPane(publicKeyArea), cg);

        cg.gridy++;
        cg.fill = GridBagConstraints.HORIZONTAL;
        cg.weighty = 0;
        center.add(new JLabel("Private Key (Base64 - PKCS#8):"), cg);
        cg.gridy++;
        cg.fill = GridBagConstraints.BOTH;
        cg.weighty = 0.5;
        center.add(new JScrollPane(privateKeyArea), cg);

        cg.gridy++;
        cg.fill = GridBagConstraints.HORIZONTAL;
        cg.weighty = 0;
        center.add(new JLabel("Bản rõ:"), cg);
        cg.gridy++;
        cg.fill = GridBagConstraints.BOTH;
        cg.weighty = 0.4;
        center.add(new JScrollPane(plainTextArea), cg);

        cg.gridy++;
        cg.fill = GridBagConstraints.HORIZONTAL;
        cg.weighty = 0;
        center.add(new JLabel("Bản mã (Base64):"), cg);
        cg.gridy++;
        cg.fill = GridBagConstraints.BOTH;
        cg.weighty = 0.4;
        center.add(new JScrollPane(cipherTextArea), cg);

        JPanel bottom = new JPanel();
        JButton btnEncrypt = new JButton("Mã hóa bằng Public Key");
        JButton btnDecrypt = new JButton("Giải mã bằng Private Key");
        bottom.add(btnEncrypt);
        bottom.add(btnDecrypt);

        // Sinh cặp khóa RSA và hiển thị để người dùng có thể sao chép qua tab khác.
        btnGenerate.addActionListener(e -> {
            try {
                int keySize = Integer.parseInt((String) keySizeCombo.getSelectedItem());
                AsymmetricCryptoService.RsaKeyPair keyPair = asymmetricService.generateRsaKeyPair(keySize);
                publicKeyArea.setText(keyPair.publicKeyBase64());
                privateKeyArea.setText(keyPair.privateKeyBase64());
            } catch (Exception ex) {
                showError(ex);
            }
        });

        // Mã hóa bản rõ bằng Public Key.
        btnEncrypt.addActionListener(e -> {
            try {
                String cipherText = asymmetricService.encryptWithPublicKey(publicKeyArea.getText(), plainTextArea.getText());
                cipherTextArea.setText(cipherText);
            } catch (Exception ex) {
                showError(ex);
            }
        });

        // Giải mã bản mã bằng Private Key.
        btnDecrypt.addActionListener(e -> {
            try {
                String plainText = asymmetricService.decryptWithPrivateKey(privateKeyArea.getText(), cipherTextArea.getText());
                plainTextArea.setText(plainText);
            } catch (Exception ex) {
                showError(ex);
            }
        });

        panel.add(top, BorderLayout.NORTH);
        panel.add(center, BorderLayout.CENTER);
        panel.add(bottom, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel buildHashPanel() {
        // Tab Hash: băm một chiều dữ liệu, không có bước giải mã.
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel top = new JPanel();
        JComboBox<String> algorithmCombo = new JComboBox<>(
                new String[] { "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA3-256" });
        JButton btnHash = new JButton("Hash");
        top.add(new JLabel("Thuật toán:"));
        top.add(algorithmCombo);
        top.add(btnHash);

        JTextArea inputArea = new JTextArea(10, 72);
        JTextArea outputArea = new JTextArea(8, 72);
        outputArea.setEditable(false);

        JPanel center = new JPanel(new GridBagLayout());
        GridBagConstraints cg = createDefaultGbc();
        cg.gridx = 0;
        cg.gridy = 0;
        cg.weightx = 1;
        cg.fill = GridBagConstraints.HORIZONTAL;
        center.add(new JLabel("Dữ liệu đầu vào:"), cg);
        cg.gridy++;
        cg.fill = GridBagConstraints.BOTH;
        cg.weighty = 0.7;
        center.add(new JScrollPane(inputArea), cg);

        cg.gridy++;
        cg.fill = GridBagConstraints.HORIZONTAL;
        cg.weighty = 0;
        center.add(new JLabel("Giá trị hash (hex):"), cg);

        cg.gridy++;
        cg.fill = GridBagConstraints.BOTH;
        cg.weighty = 0.3;
        center.add(new JScrollPane(outputArea), cg);

        // Tính giá trị băm theo thuật toán người dùng chọn.
        btnHash.addActionListener(e -> {
            try {
                String result = hashService.hashText((String) algorithmCombo.getSelectedItem(), inputArea.getText());
                outputArea.setText(result);
            } catch (Exception ex) {
                showError(ex);
            }
        });

        panel.add(top, BorderLayout.NORTH);
        panel.add(center, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildSignaturePanel() {
        // Tab Chữ ký số: ký và xác minh tính toàn vẹn/xác thực của thông điệp.
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel top = new JPanel();
        JComboBox<String> signatureAlgo = new JComboBox<>(new String[] { "SHA256withRSA", "SHA512withRSA" });
        top.add(new JLabel("Giải thuật ký:"));
        top.add(signatureAlgo);

        JTextArea publicKeyArea = new JTextArea(5, 72);
        JTextArea privateKeyArea = new JTextArea(5, 72);
        JTextArea messageArea = new JTextArea(6, 72);
        JTextArea signatureArea = new JTextArea(6, 72);

        JPanel center = new JPanel(new GridBagLayout());
        GridBagConstraints cg = createDefaultGbc();
        cg.gridx = 0;
        cg.gridy = 0;
        cg.fill = GridBagConstraints.HORIZONTAL;
        cg.weightx = 1;
        center.add(new JLabel("Public Key (Base64):"), cg);

        cg.gridy++;
        cg.fill = GridBagConstraints.BOTH;
        cg.weighty = 0.3;
        center.add(new JScrollPane(publicKeyArea), cg);

        cg.gridy++;
        cg.fill = GridBagConstraints.HORIZONTAL;
        cg.weighty = 0;
        center.add(new JLabel("Private Key (Base64):"), cg);

        cg.gridy++;
        cg.fill = GridBagConstraints.BOTH;
        cg.weighty = 0.3;
        center.add(new JScrollPane(privateKeyArea), cg);

        cg.gridy++;
        cg.fill = GridBagConstraints.HORIZONTAL;
        cg.weighty = 0;
        center.add(new JLabel("Thông điệp cần ký:"), cg);

        cg.gridy++;
        cg.fill = GridBagConstraints.BOTH;
        cg.weighty = 0.4;
        center.add(new JScrollPane(messageArea), cg);

        cg.gridy++;
        cg.fill = GridBagConstraints.HORIZONTAL;
        cg.weighty = 0;
        center.add(new JLabel("Chữ ký số (Base64):"), cg);

        cg.gridy++;
        cg.fill = GridBagConstraints.BOTH;
        cg.weighty = 0.4;
        center.add(new JScrollPane(signatureArea), cg);

        JPanel bottom = new JPanel();
        JButton btnSign = new JButton("Ký số");
        JButton btnVerify = new JButton("Xác minh");
        bottom.add(btnSign);
        bottom.add(btnVerify);

        // Ký thông điệp bằng private key và hiển thị chữ ký dưới dạng Base64.
        btnSign.addActionListener(e -> {
            try {
                String signature = signatureService.sign(privateKeyArea.getText(), messageArea.getText(),
                        (String) signatureAlgo.getSelectedItem());
                signatureArea.setText(signature);
            } catch (Exception ex) {
                showError(ex);
            }
        });

        // Xác minh chữ ký bằng public key và hiển thị kết quả cho người dùng.
        btnVerify.addActionListener(e -> {
            try {
                boolean verified = signatureService.verify(publicKeyArea.getText(), messageArea.getText(),
                        signatureArea.getText(), (String) signatureAlgo.getSelectedItem());
                JOptionPane.showMessageDialog(this,
                    verified ? "Chữ ký HỢP LỆ" : "Chữ ký KHÔNG hợp lệ",
                    "Kết quả xác minh", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                showError(ex);
            }
        });

        panel.add(top, BorderLayout.NORTH);
        panel.add(center, BorderLayout.CENTER);
        panel.add(bottom, BorderLayout.SOUTH);
        return panel;
    }

    private GridBagConstraints createDefaultGbc() {
        // Thiết lập ràng buộc mặc định để tránh lặp code layout cho nhiều panel.
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.anchor = GridBagConstraints.WEST;
        return gbc;
    }

    private int parseKeySize(JComboBox<String> keySizeCombo, String algorithm) {
        // Đảm bảo keySize luôn khớp thuật toán (ví dụ tránh chọn DES nhưng key lại AES:256).
        String value = (String) keySizeCombo.getSelectedItem();
        if (value == null || !value.startsWith(algorithm + ":")) {
            value = defaultKeySizeByAlgorithm(algorithm);
            keySizeCombo.setSelectedItem(value);
        }
        String[] parts = value.split(":");
        return Integer.parseInt(parts[1]);
    }

    private String defaultKeySizeByAlgorithm(String algorithm) {
        // Trả về kích thước khóa mặc định phục vụ thao tác nhanh trên UI.
        if ("AES".equalsIgnoreCase(algorithm)) {
            return "AES:256";
        }
        if ("DES".equalsIgnoreCase(algorithm)) {
            return "DES:56";
        }
        if ("DESede".equalsIgnoreCase(algorithm)) {
            return "DESede:168";
        }
        if ("Blowfish".equalsIgnoreCase(algorithm)) {
            return "Blowfish:256";
        }
        if ("RC4".equalsIgnoreCase(algorithm)) {
            return "RC4:256";
        }
        if ("ChaCha20".equalsIgnoreCase(algorithm)) {
            return "ChaCha20:256";
        }
        if ("Twofish".equalsIgnoreCase(algorithm)) {
            return "Twofish:256";
        }
        if ("Serpent".equalsIgnoreCase(algorithm)) {
            return "Serpent:256";
        }
        return "AES:256";
    }

    private void showError(Exception ex) {
        // Hộp thoại lỗi dùng chung cho mọi thao tác, giúp thông báo nhất quán.
        JOptionPane.showMessageDialog(this, ex.getMessage(), "Lỗi", JOptionPane.ERROR_MESSAGE);
    }
}
