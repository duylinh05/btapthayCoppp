using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace GcmApp;

/// <summary>
/// Bài 1 - Mã hóa đối xứng AES-GCM (console, .NET 8).
/// Chế độ: AES-GCM (mã hóa có xác thực). File được cắt thành các khối 1 MB;
/// mỗi khối có nonce 12 byte ngẫu nhiên riêng và thẻ xác thực (tag) 16 byte.
///
/// Định dạng file mã hóa (.sec):
///   [4 byte "GCM1"][4 byte cỡ khối][8 byte độ dài gốc]                 -> tiêu đề 16 byte
///   lặp theo từng khối: [12 byte nonce][16 byte tag][dữ liệu mã hóa]   -> dữ liệu mã hóa dài bằng dữ liệu gốc
/// Dữ liệu xác thực kèm theo (AAD) của khối i = tiêu đề 16 byte + số thứ tự khối i (8 byte),
/// nên đổi thứ tự khối, cắt bớt khối hay sửa tiêu đề đều bị phát hiện.
/// </summary>
internal static class Program
{
    private const int ChunkSize = 1 << 20;   // 1 MB
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int HeaderSize = 16;
    private static readonly byte[] Magic = { (byte)'G', (byte)'C', (byte)'M', (byte)'1' };

    private static byte[]? _key;

    private static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.InputEncoding = Encoding.UTF8; // để nhập được tiếng Việt có dấu
        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("========== AES-GCM (đối xứng, có xác thực) ==========");
            Console.WriteLine($"Khóa hiện tại: {(_key == null ? "(chưa có)" : _key.Length * 8 + " bit")}");
            Console.WriteLine("1. Sinh khóa AES");
            Console.WriteLine("2. Lưu khóa ra file");
            Console.WriteLine("3. Nhập (import) khóa từ file");
            Console.WriteLine("4. Mã hóa / giải mã 1 đoạn văn bản");
            Console.WriteLine("5. Mã hóa 1 file lớn (theo khối 1 MB)");
            Console.WriteLine("6. Giải mã 1 file");
            Console.WriteLine("7. So sánh 2 file theo byte");
            Console.WriteLine("8. TEST TỰ ĐỘNG: tạo file lớn -> mã hóa -> giải mã -> so sánh -> bảng số liệu");
            Console.WriteLine("9. THÍ NGHIỆM GIẢ MẠO: lật 1 bit trong file mã hóa rồi thử giải mã");
            Console.WriteLine("0. Thoát");
            Console.Write("Chọn: ");
            string? c = Console.ReadLine()?.Trim();
            try
            {
                switch (c)
                {
                    case "1": GenKey(); break;
                    case "2": SaveKey(); break;
                    case "3": ImportKey(); break;
                    case "4": TextDemo(); break;
                    case "5": FileEncryptMenu(); break;
                    case "6": FileDecryptMenu(); break;
                    case "7": CompareMenu(); break;
                    case "8": AutoTest(); break;
                    case "9": TamperDemo(); break;
                    case "0": return;
                    default: Console.WriteLine("Lựa chọn không hợp lệ."); break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("LỖI: " + ex.Message);
            }
        }
    }

    // ---------------------------------------------------------------- khóa
    private static void GenKey()
    {
        Console.Write("Độ dài khóa (128/192/256) [256]: ");
        string s = Console.ReadLine()?.Trim() ?? "";
        int bits = s == "" ? 256 : int.Parse(s);
        if (bits != 128 && bits != 192 && bits != 256) throw new ArgumentException("Chỉ hỗ trợ 128, 192, 256.");
        _key = RandomNumberGenerator.GetBytes(bits / 8);
        Console.WriteLine($"Đã sinh khóa {bits} bit (base64): {Convert.ToBase64String(_key)}");
    }

    private static void SaveKey()
    {
        RequireKey();
        string path = Ask("Đường dẫn file lưu khóa [gcm.key]", "gcm.key");
        File.WriteAllText(path, Convert.ToBase64String(_key!));
        Console.WriteLine("Đã lưu khóa (dạng base64) vào " + Path.GetFullPath(path));
    }

    private static void ImportKey()
    {
        string path = Ask("Đường dẫn file khóa [gcm.key]", "gcm.key");
        byte[] k = Convert.FromBase64String(File.ReadAllText(path).Trim());
        if (k.Length != 16 && k.Length != 24 && k.Length != 32)
            throw new CryptographicException($"Khóa không hợp lệ: {k.Length} byte (cần 16/24/32).");
        _key = k;
        Console.WriteLine($"Đã nhập khóa {k.Length * 8} bit.");
    }

    private static void RequireKey()
    {
        if (_key == null) throw new InvalidOperationException("Chưa có khóa. Hãy sinh khóa (1) hoặc nhập khóa (3) trước.");
    }

    // ---------------------------------------------------------------- văn bản
    private static void TextDemo()
    {
        RequireKey();
        Console.Write("Nhập đoạn văn bản cần mã hóa: ");
        string text = Console.ReadLine() ?? "";
        string b64 = EncryptText(text, _key!);
        Console.WriteLine("Kết quả mã hóa (base64 của nonce 12 byte | tag 16 byte | bản mã):");
        Console.WriteLine(b64);
        Console.WriteLine("Giải mã lại: " + DecryptText(b64, _key!));
    }

    public static string EncryptText(string text, byte[] key)
    {
        byte[] plain = Encoding.UTF8.GetBytes(text);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] tag = new byte[TagSize];
        byte[] cipher = new byte[plain.Length];
        using var gcm = new AesGcm(key, TagSize);
        gcm.Encrypt(nonce, plain, cipher, tag);
        byte[] all = new byte[NonceSize + TagSize + cipher.Length];
        nonce.CopyTo(all, 0);
        tag.CopyTo(all, NonceSize);
        cipher.CopyTo(all, NonceSize + TagSize);
        return Convert.ToBase64String(all);
    }

    public static string DecryptText(string b64, byte[] key)
    {
        byte[] all = Convert.FromBase64String(b64);
        if (all.Length < NonceSize + TagSize) throw new CryptographicException("Dữ liệu quá ngắn.");
        byte[] nonce = all[..NonceSize];
        byte[] tag = all[NonceSize..(NonceSize + TagSize)];
        byte[] cipher = all[(NonceSize + TagSize)..];
        byte[] plain = new byte[cipher.Length];
        using var gcm = new AesGcm(key, TagSize);
        gcm.Decrypt(nonce, cipher, tag, plain);
        return Encoding.UTF8.GetString(plain);
    }

    // ---------------------------------------------------------------- file
    private static void FileEncryptMenu()
    {
        RequireKey();
        string src = Ask("File nguồn", null);
        string dst = Ask("File mã hóa [" + src + ".sec]", src + ".sec");
        TimeSpan t = EncryptFile(src, dst, _key!);
        Console.WriteLine($"Xong. Thời gian mã hóa: {t.TotalSeconds:F3} s");
    }

    private static void FileDecryptMenu()
    {
        RequireKey();
        string src = Ask("File đã mã hóa", null);
        string dst = Ask("File giải mã [" + src + ".out]", src + ".out");
        TimeSpan t = DecryptFile(src, dst, _key!);
        Console.WriteLine($"Xong. Thời gian giải mã: {t.TotalSeconds:F3} s");
    }

    private static byte[] MakeHeader(long total)
    {
        byte[] h = new byte[HeaderSize];
        Magic.CopyTo(h, 0);
        BinaryPrimitives.WriteInt32LittleEndian(h.AsSpan(4), ChunkSize);
        BinaryPrimitives.WriteInt64LittleEndian(h.AsSpan(8), total);
        return h;
    }

    private static byte[] Aad(byte[] header, long index)
    {
        byte[] a = new byte[HeaderSize + 8];
        header.CopyTo(a, 0);
        BinaryPrimitives.WriteInt64LittleEndian(a.AsSpan(HeaderSize), index);
        return a;
    }

    public static TimeSpan EncryptFile(string src, string dst, byte[] key)
    {
        var sw = Stopwatch.StartNew();
        using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, ChunkSize, FileOptions.SequentialScan);
        using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, ChunkSize);
        long total = fin.Length;
        byte[] header = MakeHeader(total);
        fout.Write(header, 0, header.Length);

        using var gcm = new AesGcm(key, TagSize);
        byte[] plain = new byte[ChunkSize];
        byte[] cipher = new byte[ChunkSize];
        byte[] nonce = new byte[NonceSize];
        byte[] tag = new byte[TagSize];
        long remaining = total;
        long index = 0;
        while (remaining > 0)
        {
            int n = (int)Math.Min(ChunkSize, remaining);
            fin.ReadExactly(plain, 0, n);
            RandomNumberGenerator.Fill(nonce);
            gcm.Encrypt(nonce, plain.AsSpan(0, n), cipher.AsSpan(0, n), tag, Aad(header, index));
            fout.Write(nonce, 0, NonceSize);
            fout.Write(tag, 0, TagSize);
            fout.Write(cipher, 0, n);
            remaining -= n;
            index++;
        }
        fout.Flush();
        sw.Stop();
        return sw.Elapsed;
    }

    public static TimeSpan DecryptFile(string src, string dst, byte[] key)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            DecryptCore(src, dst, key);
        }
        catch
        {
            // Không để lại file giải mã dở dang khi xác thực thất bại
            if (File.Exists(dst)) File.Delete(dst);
            throw;
        }
        sw.Stop();
        return sw.Elapsed;
    }

    private static void DecryptCore(string src, string dst, byte[] key)
    {
        using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, ChunkSize, FileOptions.SequentialScan);
        byte[] header = new byte[HeaderSize];
        fin.ReadExactly(header, 0, HeaderSize);
        if (!header.AsSpan(0, 4).SequenceEqual(Magic)) throw new InvalidDataException("Sai định dạng: không có dấu hiệu GCM1.");
        int chunk = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(4));
        long total = BinaryPrimitives.ReadInt64LittleEndian(header.AsSpan(8));
        if (chunk <= 0 || chunk > (1 << 26) || total < 0) throw new InvalidDataException("Tiêu đề file không hợp lệ.");

        using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, ChunkSize);
        using var gcm = new AesGcm(key, TagSize);
        byte[] cipher = new byte[chunk];
        byte[] plain = new byte[chunk];
        byte[] nonce = new byte[NonceSize];
        byte[] tag = new byte[TagSize];
        long remaining = total;
        long index = 0;
        while (remaining > 0)
        {
            int n = (int)Math.Min(chunk, remaining);
            fin.ReadExactly(nonce, 0, NonceSize);
            fin.ReadExactly(tag, 0, TagSize);
            fin.ReadExactly(cipher, 0, n);
            gcm.Decrypt(nonce, cipher.AsSpan(0, n), tag, plain.AsSpan(0, n), Aad(header, index));
            fout.Write(plain, 0, n);
            remaining -= n;
            index++;
        }
        if (fin.Position != fin.Length) throw new InvalidDataException("File có dữ liệu thừa phía sau.");
        fout.Flush();
    }

    // ---------------------------------------------------------------- so sánh theo byte
    private static void CompareMenu()
    {
        string a = Ask("File 1", null);
        string b = Ask("File 2", null);
        long diff = CompareFiles(a, b);
        Console.WriteLine(diff < 0 ? "GIỐNG HỆT nhau theo từng byte." : $"KHÁC nhau, byte khác đầu tiên ở vị trí {diff}.");
    }

    /// <returns>-1 nếu hai file giống hệt; ngược lại là vị trí byte khác đầu tiên.</returns>
    public static long CompareFiles(string a, string b)
    {
        using var fa = new FileStream(a, FileMode.Open, FileAccess.Read, FileShare.Read, ChunkSize, FileOptions.SequentialScan);
        using var fb = new FileStream(b, FileMode.Open, FileAccess.Read, FileShare.Read, ChunkSize, FileOptions.SequentialScan);
        if (fa.Length != fb.Length) return Math.Min(fa.Length, fb.Length);
        byte[] ba = new byte[ChunkSize];
        byte[] bb = new byte[ChunkSize];
        long pos = 0;
        while (true)
        {
            int na = fa.Read(ba, 0, ChunkSize);
            if (na == 0) return -1;
            fb.ReadExactly(bb, 0, na);
            var sa = ba.AsSpan(0, na);
            var sb = bb.AsSpan(0, na);
            if (!sa.SequenceEqual(sb))
            {
                int i = sa.CommonPrefixLength(sb);
                return pos + i;
            }
            pos += na;
        }
    }

    // ---------------------------------------------------------------- test tự động
    private static void AutoTest()
    {
        RequireKey();
        Console.Write("Các kích thước test, đơn vị MB, cách nhau bằng dấu phẩy [10,100,500,2000]: ");
        string s = Console.ReadLine()?.Trim() ?? "";
        if (s == "") s = "10,100,500,2000";
        long[] sizesMb = s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(long.Parse).ToArray();
        string dir = Ask("Thư mục chứa file tạm [./gcm_test]", "./gcm_test");
        Directory.CreateDirectory(dir);

        var csv = new StringBuilder("size_mb,encrypt_s,decrypt_s,enc_MBps,dec_MBps,identical\n");
        Console.WriteLine();
        Console.WriteLine($"{"Size(MB)",10} {"Enc(s)",10} {"Dec(s)",10} {"Enc MB/s",10} {"Dec MB/s",10} {"Giống?",8}");
        foreach (long mb in sizesMb)
        {
            string src = Path.Combine(dir, $"src_{mb}MB.bin");
            string enc = src + ".sec";
            string dec = src + ".out";
            CreateRandomFile(src, mb);
            double te = EncryptFile(src, enc, _key!).TotalSeconds;
            double td = DecryptFile(enc, dec, _key!).TotalSeconds;
            bool same = CompareFiles(src, dec) < 0;
            Console.WriteLine($"{mb,10} {te,10:F2} {td,10:F2} {mb / te,10:F1} {mb / td,10:F1} {(same ? "ĐÚNG" : "SAI"),8}");
            csv.AppendLine(FormattableString.Invariant($"{mb},{te:F3},{td:F3},{mb / te:F1},{mb / td:F1},{same}"));
            File.Delete(src); File.Delete(enc); File.Delete(dec); // tránh đầy ổ đĩa
        }
        string csvPath = Path.Combine(dir, "gcm_results.csv");
        File.WriteAllText(csvPath, csv.ToString());
        Console.WriteLine("Đã ghi số liệu: " + Path.GetFullPath(csvPath));
    }

    private static void CreateRandomFile(string path, long mb)
    {
        var rnd = new Random(2024);
        byte[] buf = new byte[ChunkSize];
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, ChunkSize);
        for (long i = 0; i < mb; i++)
        {
            rnd.NextBytes(buf);
            fs.Write(buf, 0, buf.Length);
        }
    }

    // ---------------------------------------------------------------- thí nghiệm giả mạo
    private static void TamperDemo()
    {
        RequireKey();
        string enc = Ask("File đã mã hóa bằng menu 5", null);
        string bad = enc + ".bad";
        File.Copy(enc, bad, true);
        long len = new FileInfo(bad).Length;
        if (len <= HeaderSize + NonceSize + TagSize) throw new ArgumentException("File mã hóa quá ngắn để thử (cần file gốc không rỗng).");
        long def = len / 2;
        long pos = long.Parse(Ask($"Vị trí byte cần lật 1 bit, 0..{len - 1} [{def}]", def.ToString()));
        if (pos < 0 || pos >= len) throw new ArgumentException("Vị trí nằm ngoài file.");
        using (var fs = new FileStream(bad, FileMode.Open, FileAccess.ReadWrite))
        {
            fs.Position = pos;
            int b = fs.ReadByte();
            fs.Position = pos;
            fs.WriteByte((byte)(b ^ 1));
        }
        Console.WriteLine($"Đã lật 1 bit ở byte {pos} của {Path.GetFullPath(bad)}");
        try
        {
            DecryptFile(bad, bad + ".out", _key!);
            Console.WriteLine("KHÔNG phát hiện được sửa đổi (bất thường, cần kiểm tra lại).");
        }
        catch (Exception ex) when (ex is CryptographicException || ex is InvalidDataException || ex is EndOfStreamException)
        {
            Console.WriteLine("PHÁT HIỆN sửa đổi, từ chối giải mã: " + ex.GetType().Name);
            Console.WriteLine("(AES-CBC thuần túy sẽ không phát hiện được, chỉ cho ra dữ liệu sai.)");
        }
    }

    // ---------------------------------------------------------------- tiện ích
    private static string Ask(string prompt, string? def)
    {
        Console.Write(prompt + ": ");
        string s = Console.ReadLine()?.Trim().Trim('"') ?? "";
        if (s == "")
        {
            if (def == null) throw new ArgumentException("Bạn chưa nhập giá trị.");
            return def;
        }
        return s;
    }
}
