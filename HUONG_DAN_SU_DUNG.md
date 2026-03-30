# HUONG DAN SU DUNG TOOL MA HOA

## 1. Tong quan chuc nang
Ung dung gom 4 nhom chuc nang dung theo yeu cau giua ky:

1. Ma hoa doi xung (8 lua chon): AES, DES, DESede (3DES), Blowfish, RC4, ChaCha20, Twofish, Serpent.
2. Ma hoa bat doi xung: RSA.
3. Hash: MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256.
4. Chu ky dien tu: SHA256withRSA, SHA512withRSA.

Luu y:
- Hai giai thuat Twofish va Serpent la cac giai thuat thuong can provider tu thu vien bo sung (vi du Bouncy Castle) trong runtime.
- Cac giai thuat con lai chay duoc bang JDK mac dinh.

## 2. Cau truc source
- src/toolmahoa/Main.java: diem vao chuong trinh.
- src/toolmahoa/MainFrame.java: giao dien Swing 4 tab.
- src/toolmahoa/SymmetricCryptoService.java: xu ly doi xung.
- src/toolmahoa/AsymmetricCryptoService.java: xu ly RSA.
- src/toolmahoa/HashService.java: xu ly hash.
- src/toolmahoa/DigitalSignatureService.java: xu ly chu ky so.
- src/toolmahoa/CryptoUtils.java: tien ich Base64 va UTF-8.

## 3. Build va chay
Yeu cau: JDK 17+ (khuyen nghi JDK 21).

### 3.1 Build class
Trong thu muc project, chay:

```powershell
if (-not (Test-Path out)) { New-Item -ItemType Directory -Path out | Out-Null }
javac -d out (Get-ChildItem -Recurse -Path src -Filter *.java | ForEach-Object { $_.FullName })
```

### 3.2 Tao file JAR

```powershell
if (-not (Test-Path dist)) { New-Item -ItemType Directory -Path dist | Out-Null }
jar cfe dist/ToolMaHoa.jar toolmahoa.Main -C out .
```

### 3.3 Chay ung dung

```powershell
java -jar dist/ToolMaHoa.jar
```

## 4. Su dung nhanh

### 4.1 Tab Doi xung
1. Chon giai thuat.
2. Neu co key san: dan key Base64 vao o Key.
3. Neu chua co key: chon kich thuoc key va bam "Tao Key".
4. Nhap ban ro va bam "Ma hoa".
5. De giai ma, dan ban ma Base64 vao va bam "Giai ma".

### 4.2 Tab Bat doi xung (RSA)
1. Chon do dai key va bam "Tao cap key RSA" (hoac dan key san co).
2. Dung Public Key de ma hoa.
3. Dung Private Key de giai ma.

### 4.3 Tab Hash
1. Chon thuat toan hash.
2. Nhap du lieu.
3. Bam "Hash" de lay chuoi hex.

### 4.4 Tab Chu ky so
1. Dan Public/Private key RSA hoac tao ben tab RSA roi copy sang.
2. Nhap thong diep can ky.
3. Bam "Ky so" de tao chu ky Base64.
4. Bam "Xac minh" de kiem tra chu ky.

## 5. Nop bai
Ban co the nop:
1. File JAR: `dist/ToolMaHoa.jar`.
2. File huong dan: `HUONG_DAN_SU_DUNG.md`.
3. Source code nen ZIP (toan bo thu muc project, toi da 25MB).

Neu can file EXE, co the dong goi tu JAR bang Launch4j/Inno Setup (ngoai pham vi source Java).
