# TOTP from Scratch

**English** | [简体中文](README.zh-CN.md)

A from-scratch Python implementation of **TOTP** ([RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238))
and **HOTP** ([RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226)), the algorithm behind the
6-digit codes in Google Authenticator, Microsoft Authenticator, 1Password and friends.
Codes it generates are identical to what those apps show for the same secret.

Even **HMAC** ([RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104)) is written by hand;
only the raw hash functions (SHA-1/256/512) come from `hashlib`. The tests check the hand-written
HMAC byte-for-byte against Python's `hmac` module, and the whole stack against the official RFC test vectors.

Standard library only: no `pip install`, no network.

## Usage

```bash
python3 totp.py vectors                    # self-check against RFC 4226 + RFC 6238 test vectors
python3 totp.py new --account me@example.com --issuer MyApp   # new secret + otpauth:// URI
python3 totp.py code                       # current code (secret typed in, hidden)
python3 totp.py code -w                    # live view, refreshes every period
TOTP_SECRET=JBSWY3DPEHPK3PXP python3 totp.py code -v   # secret from env var, show counter
python3 totp.py code --uri 'otpauth://totp/...'        # read secret + params from a Key URI
python3 totp.py verify 123456              # check a code (±1 time step allowed)
python3 -m unittest -v                     # offline unit tests
```

Options for `code` / `verify` / `new`: `--digits` (default 6), `--period` (default 30 s),
`--algorithm SHA1|SHA256|SHA512` (default SHA1). `verify` also takes `--window N`.

The secret is never accepted as a plain command-line argument, so it doesn't end up in
your shell history or in `ps` output. It comes from `--uri`, the `TOTP_SECRET` env var, or a hidden prompt.

Exit codes: `0` OK / valid, `1` code invalid (or a test vector failed), `2` bad input (e.g. invalid Base32).

The CLI output is in Chinese. Example:

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

### Try it with your phone

1. `python3 totp.py new` and copy the Base32 secret.
2. In Google Authenticator: **+** → **Enter a setup key**, paste it, type **Time based**.
   (Or turn the Key URI into a QR code, e.g. `qrencode -t ansiutf8 '<URI>'`, and scan it.)
3. `python3 totp.py code -w` and watch the same code appear on both screens.

## How MFA works

### Why a second factor
A password is *something you know*, and it leaks: phishing, reuse across sites, database dumps.
Multi-factor authentication adds a factor of a different kind, so a stolen password alone isn't enough:

| Factor | Examples |
|---|---|
| Something you know | password, PIN |
| Something you have | phone with an authenticator app, hardware key |
| Something you are | fingerprint, face |

A TOTP app turns your phone into *something you have*.

### The shared secret
At enrollment the server generates a random secret (here 160 bits, as RFC 4226 recommends),
shows it to you once as a QR code, and stores it. Your app stores the same secret.
After that, **both sides compute the code independently. Nothing is sent between phone and server**,
which is why authenticator apps work in airplane mode.

The QR code just contains a [Key URI](https://github.com/google/google-authenticator/wiki/Key-Uri-Format):

```
otpauth://totp/MyApp:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp&algorithm=SHA1&digits=6&period=30
```

### The algorithm, layer by layer

```
          secret K (bytes)        T = floor(unix_time / 30)
                 │                          │ 8-byte big-endian
                 └────────► HMAC-SHA1 ◄─────┘
                               │ 20-byte digest
                               ▼
                     dynamic truncation
          offset = last byte & 0x0F; take 4 bytes at offset;
                   clear top bit → 31-bit integer
                               │
                               ▼
                     integer mod 10^6 → "287082"
```

1. **HMAC** (`hmac_digest`): `H((K ⊕ opad) ‖ H((K ⊕ ipad) ‖ message))`. A keyed hash: without K
   you can't compute it, and seeing outputs doesn't reveal K.
2. **HOTP** (`hotp`): HMAC of an 8-byte counter, then *dynamic truncation* picks 4 bytes from a
   position determined by the digest itself, and `mod 10^digits` gives the code. Leading zeros are kept.
3. **TOTP** (`totp`): HOTP where the counter is the current time step, `floor((now − T0) / 30)`.
   Every 30 seconds the counter goes up by one and you get a new code.

**Verification** (`verify`): the server computes the code for the current step and also ±`window`
steps, to tolerate clock drift and the seconds it takes to type. Comparison uses
`hmac.compare_digest` (constant time), and all windows are checked every time so the response time
doesn't reveal which one matched.

### Test vectors

`python3 totp.py vectors` reproduces RFC 4226 Appendix D (10 HOTP codes) and RFC 6238 Appendix B
(6 timestamps × SHA-1/SHA-256/SHA-512, 8 digits), including `T = 20000000000` (year 2603, beyond 32-bit time).
Note that RFC 6238 uses a different seed length per algorithm (20/32/64 bytes); copying the 20-byte
seed for all three is a classic mistake that makes SHA-256/512 vectors fail.

## Security notes and limitations

- **The secret is a password.** Unlike a password, the server can't store just a hash of it,
  because it needs the raw secret to compute codes. Real servers encrypt it at rest.
- **TOTP is not phishing-resistant.** A fake login page can ask for your code and replay it to the real
  site within 30 seconds. WebAuthn / passkeys / FIDO2 hardware keys fix this by binding to the site's origin.
- **Replay protection is the server's job.** A code stays valid for its whole window. A real server should
  remember the last accepted time step per user and reject codes for that step or earlier. `verify` here is
  stateless and doesn't do this; it returns the matched offset so a caller could.
- **Rate-limit attempts.** 6 digits is only 10^6 possibilities; with ±1 window an attacker gets 3 chances
  per guess. Lock out after a handful of failures.
- **SHA-1 is fine here.** SHA-1 collisions don't break HMAC-SHA1, and SHA1 is what nearly every app
  expects. Many apps silently ignore `algorithm`/`digits`/`period`, so stick to the defaults for compatibility.
- **Clock matters.** If your computer's clock is off by more than ~30 s, codes won't match. Use NTP.
- This is a learning project: it shows how TOTP works. For production, use a well-reviewed library and
  store secrets in a proper secrets manager.

## Files

- `totp.py`: HMAC, HOTP, TOTP, verification, Base32/Key URI helpers, CLI
- `test_totp.py`: offline tests (RFC vectors, HMAC vs stdlib, verification windows, URI parsing, CLI)
