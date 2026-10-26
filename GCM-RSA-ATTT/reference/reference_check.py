"""Bản tham chiếu bằng Python: cùng thuật toán và cùng định dạng file (.sec) với 2 app C#,
dùng để kiểm chứng logic và lấy số liệu minh họa."""
import os, time, random, hashlib, struct, tempfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as apad
from cryptography.exceptions import InvalidTag

CHUNK = 1 << 20
MAGIC = b"GCM1"
DIR = tempfile.mkdtemp(prefix="gcm_ref_")

def make_file(path, mb):
    rnd = random.Random(2024)
    with open(path, "wb") as f:
        for _ in range(mb):
            f.write(rnd.randbytes(CHUNK))

def header(total):
    return MAGIC + struct.pack("<i", CHUNK) + struct.pack("<q", total)

def aad(h, i):
    return h + struct.pack("<q", i)

def enc_file(src, dst, key):
    g = AESGCM(key)
    total = os.path.getsize(src)
    h = header(total)
    t = time.perf_counter()
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        fo.write(h)
        i = 0
        while chunk := fi.read(CHUNK):
            nonce = os.urandom(12)
            ct = g.encrypt(nonce, chunk, aad(h, i))   # trả về cipher || tag(16)
            fo.write(nonce + ct[-16:] + ct[:-16])      # nonce | tag | cipher (đúng định dạng C#)
            i += 1
    return time.perf_counter() - t

def dec_file(src, dst, key):
    g = AESGCM(key)
    t = time.perf_counter()
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        h = fi.read(16)
        assert h[:4] == MAGIC
        chunk = struct.unpack("<i", h[4:8])[0]
        remaining = struct.unpack("<q", h[8:16])[0]
        i = 0
        while remaining > 0:
            n = min(chunk, remaining)
            nonce = fi.read(12); tag = fi.read(16); ct = fi.read(n)
            fo.write(g.decrypt(nonce, ct + tag, aad(h, i)))
            remaining -= n; i += 1
        assert fi.read(1) == b""
    return time.perf_counter() - t

def same(a, b):
    with open(a, "rb") as fa, open(b, "rb") as fb:
        while True:
            x, y = fa.read(CHUNK), fb.read(CHUNK)
            if x != y: return False
            if not x: return True

print("=== AES-256-GCM theo khối 1 MB, file lớn ===")
key = AESGCM.generate_key(256)
print(f"{'MB':>6} {'enc s':>8} {'dec s':>8} {'enc MB/s':>9} {'dec MB/s':>9} identical")
for mb in (10, 100, 500, 2000):
    s = f"{DIR}/s.bin"; e = s + ".sec"; d = s + ".out"
    make_file(s, mb)
    te = enc_file(s, e, key); td = dec_file(e, d, key)
    ok = same(s, d)
    print(f"{mb:>6} {te:>8.2f} {td:>8.2f} {mb/te:>9.0f} {mb/td:>9.0f} {ok}")
    if mb == 10:
        # thí nghiệm giả mạo: lật 1 bit giữa file mã hóa
        with open(e, "rb") as f: data = bytearray(f.read())
        data[len(data)//2] ^= 1
        with open(e + ".bad", "wb") as f: f.write(data)
        try:
            dec_file(e + ".bad", d + ".x", key); print("   giả mạo: KHÔNG phát hiện (SAI)")
        except InvalidTag:
            print("   giả mạo: phát hiện, từ chối giải mã (InvalidTag) - đúng như mong đợi")
        os.remove(e + ".bad")
        if os.path.exists(d + ".x"): os.remove(d + ".x")
    for x in (s, e, d): os.remove(x)

print("\n=== RSA-OAEP-SHA384 / PSS-SHA384, 32 byte ===")
print(f"{'bits':>5} {'e bit':>6} {'d bit':>6} {'enc ms':>9} {'dec ms':>9} {'sign ms':>9} {'ver ms':>9} {'dec/enc':>8}")
data = os.urandom(32)
oaep = apad.OAEP(mgf=apad.MGF1(hashes.SHA384()), algorithm=hashes.SHA384(), label=None)
pss = apad.PSS(mgf=apad.MGF1(hashes.SHA384()), salt_length=48)
for bits in (2048, 3072, 4096):
    k = rsa.generate_private_key(65537, bits)
    n = 100
    ct = k.public_key().encrypt(data, oaep)
    t = time.perf_counter()
    for _ in range(n): ct = k.public_key().encrypt(data, oaep)
    enc = (time.perf_counter() - t) / n * 1000
    t = time.perf_counter()
    for _ in range(n): k.decrypt(ct, oaep)
    dec = (time.perf_counter() - t) / n * 1000
    sg = k.sign(data, pss, hashes.SHA384())
    t = time.perf_counter()
    for _ in range(n): sg = k.sign(data, pss, hashes.SHA384())
    sign = (time.perf_counter() - t) / n * 1000
    t = time.perf_counter()
    for _ in range(n): k.public_key().verify(sg, data, pss, hashes.SHA384())
    ver = (time.perf_counter() - t) / n * 1000
    dbits = k.private_numbers().d.bit_length()
    print(f"{bits:>5} {17:>6} {dbits:>6} {enc:>9.4f} {dec:>9.4f} {sign:>9.4f} {ver:>9.4f} {dec/enc:>8.1f}")

k = rsa.generate_private_key(65537, 2048)
mx = 256 - 2*48 - 2
print(f"Giới hạn OAEP-SHA384 với 2048 bit: {mx} byte; thử {mx} byte:", end=" ")
k.public_key().encrypt(os.urandom(mx), oaep); print("OK", end="; ")
try:
    k.public_key().encrypt(os.urandom(mx + 1), oaep); print(f"{mx+1} byte: OK (bất thường)")
except ValueError:
    print(f"{mx+1} byte: bị từ chối")

print("\n=== SHA-512 avalanche (đổi 1 bit của đầu vào 128 byte, 10000 lần) ===")
rnd = random.Random(7); tot = 0; mn, mxx = 512, 0
for _ in range(10000):
    m = bytearray(rnd.randbytes(128))
    h1 = hashlib.sha512(m).digest()
    b = rnd.randrange(1024); m[b // 8] ^= 1 << (b % 8)
    h2 = hashlib.sha512(m).digest()
    d = bin(int.from_bytes(h1, "big") ^ int.from_bytes(h2, "big")).count("1")
    tot += d; mn = min(mn, d); mxx = max(mxx, d)
print(f"trung bình {tot/10000:.2f}/512 bit ({tot/10000/5.12:.2f}%), min {mn}, max {mxx}")
a = hashlib.sha512(b"Bonjour").hexdigest(); b = hashlib.sha512(b"Bonjous").hexdigest()
print("Bonjour:", a[:64] + "..."); print("Bonjous:", b[:64] + "...")

print("\n=== Chữ ký: PKCS#1 v1.5 vs PSS (SHA-384), cùng dữ liệu, cùng khóa, 5 lần ===")
msg = b"Bien ban nghiem thu 07"
v15 = {k.sign(msg, apad.PKCS1v15(), hashes.SHA384()) for _ in range(5)}
sigs = [k.sign(msg, pss, hashes.SHA384()) for _ in range(5)]
print("PKCS#1 v1.5: số chữ ký khác nhau =", len(v15), "/ 5")
print("PSS        : số chữ ký khác nhau =", len(set(sigs)), "/ 5")
ok = True
for s in sigs:
    try: k.public_key().verify(s, msg, pss, hashes.SHA384())
    except Exception: ok = False
print("PSS: cả 5 chữ ký xác minh đúng =", ok)
try:
    k.public_key().verify(sigs[0], b"Bien ban nghiem thu 08", pss, hashes.SHA384()); print("sửa dữ liệu: vẫn đúng (SAI)")
except Exception:
    print("sửa dữ liệu: xác minh thất bại (đúng như mong đợi)")
