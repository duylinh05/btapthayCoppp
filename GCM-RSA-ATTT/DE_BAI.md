# ĐỀ BÀI: AES-GCM, RSA-OAEP, SHA-512 và chữ ký số

Môn: An toàn và Bảo mật thông tin. Ngôn ngữ: C# (.NET 8 trở lên), ứng dụng console có menu.

## Bài 1. Mã hóa đối xứng AES-GCM (`GcmApp`)

Viết chương trình thực hiện:

1. Sinh khóa AES ngẫu nhiên (128, 192 hoặc 256 bit).
2. Lưu khóa ra file `gcm.key` (dạng base64).
3. Nhập (import) khóa từ file, kiểm tra độ dài hợp lệ.
4. Mã hóa một đoạn văn bản tiếng Việt có dấu, in bản mã dạng base64, rồi giải mã lại để đối chiếu.
5. Mã hóa và giải mã **file lớn** (từ vài trăm MB đến vài GB) bằng AES-GCM, **cắt file thành các khối 1 MB**, mỗi khối có nonce 12 byte ngẫu nhiên và tag 16 byte. Không được đọc nguyên file vào RAM.
6. So sánh file gốc với file sau giải mã theo từng byte.
7. Đo thời gian mã hóa, giải mã và tốc độ (MB/s) với các kích thước 10, 100, 500, 2000 MB; ghi ra file CSV.
8. **Thí nghiệm giả mạo:** lật 1 bit trong file đã mã hóa rồi giải mã. Quan sát và giải thích vì sao GCM phát hiện được còn CBC thuần túy thì không.

## Bài 2. RSA, SHA-512, chữ ký số (`RsaLab`)

1. Sinh cặp khóa RSA 2048, 3072 hoặc 4096 bit; xuất ra `pub_key.pem` (X.509 SPKI) và `priv_key.pem` (PKCS#8).
2. Đọc file PEM: tách header/footer, giải base64 ra DER, in cây ASN.1 và giải thích ý nghĩa các byte (tag, length, value).
3. Nhập file PEM và hiển thị `n`, `e`; với private key hiển thị thêm `d, p, q, dP, dQ, qInv`.
4. Mã hóa một khóa AES-256 (hoặc văn bản ngắn) bằng **RSA-OAEP với SHA-384**, lưu bản mã `ct.b64`. Cho biết giới hạn độ dài dữ liệu với khóa 2048 bit (gợi ý: `256 - 2*48 - 2`).
5. Giải mã bằng private key và so sánh với dữ liệu gốc.
6. Đo tốc độ **mã hóa, giải mã, ký, xác minh** với khóa 2048, 3072, 4096 bit. Giải thích vì sao phép dùng public key nhanh hơn nhiều so với phép dùng private key.
7. Băm **SHA-512** các chuỗi nhập vào; chứng minh hiệu ứng thác đổ: đổi đúng 1 bit của đầu vào 128 byte, lặp 10000 lần, thống kê số bit băm thay đổi (trung bình, nhỏ nhất, lớn nhất).
8. Chữ ký số với SHA-384: so sánh **RSA PKCS#1 v1.5** (xác định) với **RSA-PSS** (salt ngẫu nhiên 48 byte). Ký cùng một dữ liệu 5 lần bằng cùng private key. Đề xuất và cài đặt cách để mỗi lần ký ra chữ ký khác nhau nhưng vẫn xác minh đúng bằng public key.

## Yêu cầu nộp

- Mã nguồn hai ứng dụng, chạy được bằng `dotnet run`.
- Báo cáo (mẫu ở `docs/BAO_CAO_MAU.md`) kèm ảnh chụp màn hình các bước chạy **trên máy của bạn**, có ghi họ tên và mã sinh viên trong dữ liệu thử.
- Bảng số liệu đo thật từ ứng dụng của bạn (không chép số liệu tham chiếu).
- Không đưa `*.key`, `*.pem` lên GitHub (đã có `.gitignore`).

## Gợi ý chấm điểm

| Phần | Điểm |
|---|---:|
| Bài 1: khóa, văn bản, file lớn theo khối, so sánh byte | 3.0 |
| Bài 1: đo hiệu năng, thí nghiệm giả mạo, nhận xét | 1.5 |
| Bài 2: PEM (xem, nhập), mã hóa/giải mã OAEP-SHA384 | 2.5 |
| Bài 2: đo tốc độ, SHA-512 thác đổ | 1.5 |
| Bài 2: chữ ký PKCS#1 v1.5 vs PSS, đề xuất chữ ký khác nhau mỗi lần | 1.0 |
| Báo cáo, ảnh minh chứng, trình bày | 0.5 |
| **Tổng** | **10.0** |
