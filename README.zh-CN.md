# 从零实现 TOTP（TOTP from Scratch）

[English](README.md) | **简体中文**

用 Python 从零实现 **TOTP**（[RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)）和
**HOTP**（[RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226)），也就是 Google Authenticator、
Microsoft Authenticator、1Password 等 App 里那串 6 位验证码背后的算法。
对同一个密钥，它算出的验证码与这些 App 完全一致。

连 **HMAC**（[RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104)）都是手写的，只有底层哈希函数
（SHA-1/256/512）用了 `hashlib`。测试会把手写 HMAC 与 Python 标准库 `hmac` 逐字节比对，
并用 RFC 官方测试向量验证整个实现。

只用 Python 标准库，不需要 `pip install`，不联网。

## 怎么用

```bash
python3 totp.py vectors                    # 用 RFC 4226 + RFC 6238 官方测试向量自检
python3 totp.py new --account me@example.com --issuer MyApp   # 生成新密钥和 otpauth:// URI
python3 totp.py code                       # 计算当前验证码（密钥交互输入，不回显）
python3 totp.py code -w                    # 持续显示，每个周期自动刷新
TOTP_SECRET=JBSWY3DPEHPK3PXP python3 totp.py code -v   # 从环境变量读密钥，并显示计数器
python3 totp.py code --uri 'otpauth://totp/...'        # 从 Key URI 读取密钥和参数
python3 totp.py verify 123456              # 校验验证码（允许前后 1 个时间窗口）
python3 -m unittest -v                     # 运行离线单元测试
```

`code` / `verify` / `new` 的通用参数：`--digits`（默认 6）、`--period`（默认 30 秒）、
`--algorithm SHA1|SHA256|SHA512`（默认 SHA1）。`verify` 另有 `--window N`。

工具**不接受把密钥直接写在命令行参数里**，以免它留在 shell 历史和 `ps` 进程列表中。
密钥只能来自 `--uri`、环境变量 `TOTP_SECRET`，或不回显的交互输入。

退出码：`0` 成功 / 验证通过，`1` 验证码无效（或测试向量不一致），`2` 输入错误（如 Base32 不合法）。

示例：

```
$ python3 totp.py vectors
RFC 4226（HOTP，SHA-1，6 位）
  ✅ 计数器=0  期望=755224  实际=755224
  ...
RFC 6238（TOTP，30 秒，8 位）
  ✅ T=59           SHA1    期望=94287082  实际=94287082
  ✅ T=59           SHA256  期望=46119246  实际=46119246
  ...
全部通过 ✅
```

### 用手机实际对比一下

1. 运行 `python3 totp.py new`，复制 Base32 密钥。
2. 在 Google Authenticator 里点 **+** → **输入设置密钥**，粘贴密钥，类型选**基于时间**。
   （也可以把 Key URI 做成二维码再扫，例如 `qrencode -t ansiutf8 '<URI>'`。）
3. 运行 `python3 totp.py code -w`，两边会显示同一个验证码。

## MFA 是怎么工作的

### 为什么需要第二个因素
密码属于“你知道的东西”，而它很容易泄露：钓鱼、多站点复用、数据库被拖库。
多因素认证（MFA）再加一个**不同类型**的因素，这样光偷到密码还不够：

| 因素 | 例子 |
|---|---|
| 你知道的东西 | 密码、PIN |
| 你拥有的东西 | 装了 Authenticator 的手机、硬件密钥 |
| 你本身的特征 | 指纹、人脸 |

TOTP App 让你的手机变成“你拥有的东西”。

### 共享密钥
绑定时，服务器生成一个随机密钥（本工具默认 160 位，RFC 4226 推荐长度），用二维码给你看一次，然后自己保存。
你的 App 也保存同一个密钥。此后**双方各自独立计算验证码，手机和服务器之间不传输任何数据**，
所以飞行模式下 Authenticator 照样能用。

二维码里其实就是一个 [Key URI](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)：

```
otpauth://totp/MyApp:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp&algorithm=SHA1&digits=6&period=30
```

### 算法，一层一层拆开

```
          密钥 K（字节）           T = floor(Unix 时间 / 30)
                 │                          │ 8 字节大端
                 └────────► HMAC-SHA1 ◄─────┘
                               │ 20 字节摘要
                               ▼
                           动态截断
          offset = 最后一字节 & 0x0F；从 offset 取 4 字节；
                   清掉最高位 → 31 位整数
                               │
                               ▼
                     整数 mod 10^6 → "287082"
```

1. **HMAC**（`hmac_digest`）：`H((K ⊕ opad) ‖ H((K ⊕ ipad) ‖ 消息))`。带密钥的哈希：没有 K 就算不出来，
   看到输出也反推不出 K。
2. **HOTP**（`hotp`）：对 8 字节计数器做 HMAC，再用**动态截断**从摘要里由摘要自身决定的位置取 4 个字节，
   最后 `mod 10^位数` 得到验证码，保留前导零。
3. **TOTP**（`totp`）：把计数器换成当前时间步 `floor((now − T0) / 30)` 的 HOTP。
   每过 30 秒计数器加 1，验证码就变一次。

**校验**（`verify`）：服务器不仅计算当前时间步的验证码，也计算前后 `window` 个时间步的，
以容忍时钟偏差和输入耗时。比较使用 `hmac.compare_digest`（常量时间），并且每次都检查所有窗口，
这样响应时间不会暴露是哪个窗口匹配。

### 测试向量

`python3 totp.py vectors` 会复现 RFC 4226 附录 D（10 个 HOTP 验证码）和 RFC 6238 附录 B
（6 个时间戳 × SHA-1/SHA-256/SHA-512，8 位），包括 `T = 20000000000`（公元 2603 年，超出 32 位时间范围）。
注意 RFC 6238 对三种算法用了**不同长度的种子**（20/32/64 字节）；三种都用 20 字节种子是经典错误，
会导致 SHA-256/512 的向量对不上。

## 安全说明与局限

- **密钥就是密码。** 和密码不同，服务器无法只存它的哈希，因为计算验证码需要原始密钥。真实系统会加密存储。
- **TOTP 防不了钓鱼。** 假登录页可以骗你输入验证码，并在 30 秒内转发给真网站。
  WebAuthn / Passkey / FIDO2 硬件密钥会绑定网站来源（origin），能解决这个问题。
- **防重放是服务器的责任。** 一个验证码在整个窗口内都有效。真实服务器应记录每个用户上次通过的时间步，
  拒绝该时间步及更早的验证码。本工具的 `verify` 是无状态的，没有做这一步；它返回匹配的偏移量，调用方可以据此实现。
- **要限制尝试次数。** 6 位只有 10^6 种可能，开启 ±1 窗口后每次猜测有 3 次命中机会。几次失败后就应锁定。
- **这里用 SHA-1 没问题。** SHA-1 的碰撞攻击不影响 HMAC-SHA1，而且几乎所有 App 默认就是 SHA1。
  很多 App 会忽略 `algorithm`/`digits`/`period` 参数，为了兼容最好用默认值。
- **时钟很重要。** 电脑时间偏差超过约 30 秒，验证码就对不上。请开启 NTP 自动校时。
- 这是学习项目，用来展示 TOTP 的原理。生产环境请使用经过充分审查的库，并把密钥放进专门的密钥管理系统。

## 文件

- `totp.py`：HMAC、HOTP、TOTP、校验、Base32/Key URI 工具函数、命令行
- `test_totp.py`：离线测试（RFC 向量、手写 HMAC 对比标准库、校验窗口、URI 解析、命令行）
