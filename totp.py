#!/usr/bin/env python3
"""
从零实现 TOTP（Time-based One-Time Password）

实现 RFC 4226（HOTP）和 RFC 6238（TOTP），生成的 6 位验证码与
Google Authenticator / Microsoft Authenticator / 1Password 等 App 一致。

为了学习，HMAC（RFC 2104）和动态截断都是手写的；只有底层哈希函数
（SHA-1 / SHA-256 / SHA-512）用了标准库 hashlib。测试会把手写 HMAC
与标准库 hmac 模块逐字节比对。

只依赖 Python 标准库，Python 3.8+ 可直接运行。
"""

import argparse
import base64
import getpass
import hashlib
import hmac as std_hmac  # 只用 compare_digest（常量时间比较），HMAC 本身是手写的
import os
import secrets
import struct
import sys
import time
import urllib.parse

ALGORITHMS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}

DEFAULT_DIGITS = 6
DEFAULT_PERIOD = 30
DEFAULT_ALGORITHM = "SHA1"


# ---------------------------------------------------------------------------
# 第 1 层：HMAC（RFC 2104），手写
# ---------------------------------------------------------------------------

def hmac_digest(key: bytes, message: bytes, algorithm: str = DEFAULT_ALGORITHM) -> bytes:
    """
    HMAC(K, m) = H((K' ⊕ opad) ‖ H((K' ⊕ ipad) ‖ m))

    K' 是把密钥处理成"块大小"后的结果：太长先哈希，再用 0x00 补齐。
    SHA-1/SHA-256 的块大小是 64 字节，SHA-512 是 128 字节。
    """
    hash_fn = ALGORITHMS[algorithm.upper()]
    block_size = hash_fn().block_size
    if len(key) > block_size:
        key = hash_fn(key).digest()
    key = key.ljust(block_size, b"\x00")
    o_key = bytes(b ^ 0x5C for b in key)
    i_key = bytes(b ^ 0x36 for b in key)
    inner = hash_fn(i_key + message).digest()
    return hash_fn(o_key + inner).digest()


# ---------------------------------------------------------------------------
# 第 2 层：HOTP（RFC 4226）
# ---------------------------------------------------------------------------

def dynamic_truncate(digest: bytes) -> int:
    """
    RFC 4226 §5.3 动态截断：
      1. 取最后一个字节的低 4 位作为偏移量 offset（0–15）
      2. 从 offset 开始取 4 个字节，组成一个大端 32 位整数
      3. 把最高位清零（& 0x7FFFFFFF），避免有符号/无符号歧义
    """
    offset = digest[-1] & 0x0F
    chunk = digest[offset:offset + 4]
    return struct.unpack(">I", chunk)[0] & 0x7FFFFFFF


def hotp(key: bytes, counter: int, digits: int = DEFAULT_DIGITS,
         algorithm: str = DEFAULT_ALGORITHM) -> str:
    """HOTP(K, C) = Truncate(HMAC(K, C)) mod 10^digits，C 是 8 字节大端计数器。"""
    if counter < 0:
        raise ValueError("计数器不能为负数")
    if not 1 <= digits <= 10:
        raise ValueError("位数必须在 1–10 之间")
    msg = struct.pack(">Q", counter)
    code = dynamic_truncate(hmac_digest(key, msg, algorithm)) % (10 ** digits)
    return str(code).zfill(digits)


# ---------------------------------------------------------------------------
# 第 3 层：TOTP（RFC 6238）
# ---------------------------------------------------------------------------

def time_counter(timestamp: float, period: int = DEFAULT_PERIOD, t0: int = 0) -> int:
    """T = floor((当前 Unix 时间 - T0) / 时间步长)。"""
    if period <= 0:
        raise ValueError("时间步长必须为正数")
    return int((timestamp - t0) // period)


def totp(key: bytes, timestamp: float = None, digits: int = DEFAULT_DIGITS,
         period: int = DEFAULT_PERIOD, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """TOTP 就是"用时间当计数器"的 HOTP。"""
    if timestamp is None:
        timestamp = time.time()
    return hotp(key, time_counter(timestamp, period), digits, algorithm)


def seconds_remaining(timestamp: float = None, period: int = DEFAULT_PERIOD) -> int:
    if timestamp is None:
        timestamp = time.time()
    return period - int(timestamp) % period


def verify(key: bytes, code: str, timestamp: float = None, window: int = 1,
           digits: int = DEFAULT_DIGITS, period: int = DEFAULT_PERIOD,
           algorithm: str = DEFAULT_ALGORITHM):
    """
    校验验证码，允许前后 window 个时间步的误差（应对时钟偏差和输入延迟）。
    返回匹配的偏移量（-1 / 0 / +1 …），不匹配返回 None。
    用常量时间比较，避免通过响应时间逐位猜测验证码。
    """
    if timestamp is None:
        timestamp = time.time()
    code = code.strip().replace(" ", "")
    if len(code) != digits or not code.isdigit():
        return None
    base = time_counter(timestamp, period)
    matched = None
    for offset in range(-window, window + 1):
        counter = base + offset
        if counter < 0:
            continue
        expected = hotp(key, counter, digits, algorithm)
        # 不提前 break：每个窗口都算一遍，耗时与是否匹配无关
        if std_hmac.compare_digest(expected, code) and matched is None:
            matched = offset
    return matched


# ---------------------------------------------------------------------------
# 密钥与 otpauth:// URI
# ---------------------------------------------------------------------------

def generate_secret(num_bytes: int = 20) -> str:
    """生成随机密钥（默认 160 位，RFC 4226 推荐长度），返回不带填充的 Base32。"""
    return base64.b32encode(secrets.token_bytes(num_bytes)).decode("ascii").rstrip("=")


def decode_secret(secret: str) -> bytes:
    """
    解码 Base32 密钥。宽容处理 App/网站里常见的写法：
    小写、空格或短横线分组、缺少 '=' 填充。
    """
    cleaned = secret.replace(" ", "").replace("-", "").upper()
    if not cleaned:
        raise ValueError("密钥为空")
    cleaned += "=" * (-len(cleaned) % 8)
    try:
        key = base64.b32decode(cleaned, casefold=False)
    except Exception:
        raise ValueError("密钥不是合法的 Base32（只能包含 A–Z 和 2–7）") from None
    if not key:
        raise ValueError("密钥为空")
    return key


def build_uri(secret: str, account: str, issuer: str = None,
              digits: int = DEFAULT_DIGITS, period: int = DEFAULT_PERIOD,
              algorithm: str = DEFAULT_ALGORITHM) -> str:
    """
    生成 Key URI（Google Authenticator 格式），把它做成二维码即可被 App 扫描：
    otpauth://totp/Issuer:account?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30
    """
    label = urllib.parse.quote(f"{issuer}:{account}" if issuer else account, safe=":@")
    params = {"secret": secret}
    if issuer:
        params["issuer"] = issuer
    params.update(algorithm=algorithm.upper(), digits=digits, period=period)
    return f"otpauth://totp/{label}?{urllib.parse.urlencode(params, quote_via=urllib.parse.quote)}"


def parse_uri(uri: str) -> dict:
    """解析 otpauth://totp/... URI，返回 secret/digits/period/algorithm 等参数。"""
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme != "otpauth" or parsed.netloc != "totp":
        raise ValueError("只支持 otpauth://totp/ 形式的 URI")
    q = urllib.parse.parse_qs(parsed.query)
    if "secret" not in q:
        raise ValueError("URI 中缺少 secret 参数")
    algorithm = q.get("algorithm", [DEFAULT_ALGORITHM])[0].upper()
    if algorithm not in ALGORITHMS:
        raise ValueError(f"不支持的算法：{algorithm}")
    return {
        "label": urllib.parse.unquote(parsed.path.lstrip("/")),
        "secret": q["secret"][0],
        "issuer": q.get("issuer", [None])[0],
        "digits": int(q.get("digits", [DEFAULT_DIGITS])[0]),
        "period": int(q.get("period", [DEFAULT_PERIOD])[0]),
        "algorithm": algorithm,
    }


# ---------------------------------------------------------------------------
# RFC 测试向量（离线自检）
# ---------------------------------------------------------------------------

# RFC 4226 附录 D：密钥 "12345678901234567890"，计数器 0–9
RFC4226_KEY = b"12345678901234567890"
RFC4226_VECTORS = ["755224", "287082", "359152", "969429", "338314",
                   "254676", "287922", "162583", "399871", "520489"]

# RFC 6238 附录 B：8 位验证码，步长 30 秒；三种算法的种子长度不同
RFC6238_KEYS = {
    "SHA1": b"12345678901234567890",
    "SHA256": b"12345678901234567890123456789012",
    "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234",
}
RFC6238_VECTORS = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]


def run_vectors(out=None) -> bool:
    out = out or sys.stdout
    ok = True
    print("RFC 4226（HOTP，SHA-1，6 位）", file=out)
    for counter, expected in enumerate(RFC4226_VECTORS):
        got = hotp(RFC4226_KEY, counter)
        mark = "✅" if got == expected else "❌"
        ok &= got == expected
        print(f"  {mark} 计数器={counter}  期望={expected}  实际={got}", file=out)
    print("RFC 6238（TOTP，30 秒，8 位）", file=out)
    for t, *codes in RFC6238_VECTORS:
        for alg, expected in zip(("SHA1", "SHA256", "SHA512"), codes):
            got = totp(RFC6238_KEYS[alg], t, digits=8, algorithm=alg)
            mark = "✅" if got == expected else "❌"
            ok &= got == expected
            print(f"  {mark} T={t:<12} {alg:<7} 期望={expected}  实际={got}", file=out)
    print("全部通过 ✅" if ok else "存在不一致 ❌", file=out)
    return ok


# ---------------------------------------------------------------------------
# 命令行
# ---------------------------------------------------------------------------

def read_secret(args) -> str:
    """
    密钥来源优先级：--uri > 环境变量 TOTP_SECRET > 交互输入（不回显）。
    不提供"把密钥写在命令行参数里"的方式，避免它进入 shell 历史和进程列表。
    """
    if getattr(args, "uri", None):
        return args.uri
    env = os.environ.get("TOTP_SECRET")
    if env:
        return env
    return getpass.getpass("请输入 Base32 密钥（不回显）：")


def resolve_params(args):
    """返回 (key, digits, period, algorithm)。--uri 里的参数会覆盖默认值。"""
    raw = read_secret(args)
    digits, period, algorithm = args.digits, args.period, args.algorithm
    if raw.startswith("otpauth://"):
        info = parse_uri(raw)
        raw = info["secret"]
        digits, period, algorithm = info["digits"], info["period"], info["algorithm"]
    return decode_secret(raw), digits, period, algorithm


def cmd_new(args):
    secret = generate_secret(args.bytes)
    uri = build_uri(secret, args.account, args.issuer, args.digits, args.period, args.algorithm)
    print(f"密钥（Base32）：{secret}")
    print(f"Key URI：      {uri}")
    print()
    print("把 Key URI 做成二维码（例如 `qrencode -t ansiutf8 '<URI>'`），用 Authenticator App 扫描；")
    print("或在 App 里选“输入设置密钥”，手动填入上面的 Base32 密钥。")
    print("⚠️  密钥等同于密码：不要提交到 Git、不要截图分享。")
    return 0


def cmd_code(args):
    key, digits, period, algorithm = resolve_params(args)
    if not args.watch:
        print(totp(key, digits=digits, period=period, algorithm=algorithm))
        if args.verbose:
            now = time.time()
            print(f"T={time_counter(now, period)}  剩余 {seconds_remaining(now, period)} 秒  "
                  f"({algorithm}, {digits} 位, {period} 秒)", file=sys.stderr)
        return 0
    try:
        last = None
        while True:
            now = time.time()
            code = totp(key, now, digits, period, algorithm)
            left = seconds_remaining(now, period)
            bar = "█" * left + "·" * (period - left) if period <= 60 else ""
            if code != last:
                print()
                last = code
            print(f"\r{code}  {bar} {left:>2}s", end="", flush=True)
            time.sleep(1 - now % 1)
    except KeyboardInterrupt:
        print()
        return 0


def cmd_verify(args):
    key, digits, period, algorithm = resolve_params(args)
    offset = verify(key, args.code, window=args.window,
                    digits=digits, period=period, algorithm=algorithm)
    if offset is None:
        print("❌ 验证码无效")
        return 1
    where = "当前时间窗口" if offset == 0 else f"偏移 {offset:+d} 个时间窗口（时钟可能有偏差）"
    print(f"✅ 验证通过（{where}）")
    return 0


def cmd_vectors(args):
    return 0 if run_vectors() else 1


def build_parser():
    p = argparse.ArgumentParser(description="从零实现的 TOTP（RFC 6238）工具")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp):
        sp.add_argument("--digits", type=int, default=DEFAULT_DIGITS, help="验证码位数（默认 6）")
        sp.add_argument("--period", type=int, default=DEFAULT_PERIOD, help="时间步长秒数（默认 30）")
        sp.add_argument("--algorithm", default=DEFAULT_ALGORITHM, type=str.upper,
                        choices=sorted(ALGORITHMS), help="HMAC 哈希算法（默认 SHA1）")

    sp = sub.add_parser("new", help="生成新密钥和 otpauth:// URI")
    sp.add_argument("--account", default="user@example.com", help="账户名（显示在 App 里）")
    sp.add_argument("--issuer", default="totp-from-scratch", help="服务名（显示在 App 里）")
    sp.add_argument("--bytes", type=int, default=20, help="密钥字节数（默认 20 = 160 位）")
    common(sp)
    sp.set_defaults(func=cmd_new)

    sp = sub.add_parser("code", help="计算当前验证码")
    sp.add_argument("--uri", help="otpauth://totp/... URI（会覆盖 --digits 等参数）")
    sp.add_argument("-w", "--watch", action="store_true", help="持续显示，每个周期刷新")
    sp.add_argument("-v", "--verbose", action="store_true", help="显示计数器和剩余秒数")
    common(sp)
    sp.set_defaults(func=cmd_code)

    sp = sub.add_parser("verify", help="校验一个验证码")
    sp.add_argument("code", help="要校验的验证码")
    sp.add_argument("--uri", help="otpauth://totp/... URI")
    sp.add_argument("--window", type=int, default=1, help="允许前后误差的时间窗口数（默认 1）")
    common(sp)
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("vectors", help="用 RFC 4226 / RFC 6238 官方测试向量自检")
    sp.set_defaults(func=cmd_vectors)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ValueError as e:
        print(f"错误：{e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
