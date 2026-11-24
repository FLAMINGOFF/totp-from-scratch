"""离线单元测试：python3 -m unittest -v"""

import base64
import hashlib
import hmac
import io
import os
import unittest
from unittest import mock

import totp


class TestHmac(unittest.TestCase):
    def test_matches_stdlib(self):
        cases = [b"", b"k", b"12345678901234567890", b"x" * 64, b"y" * 65, b"z" * 200]
        for alg, fn in totp.ALGORITHMS.items():
            for key in cases:
                for msg in (b"", b"hello", b"\x00" * 8, b"m" * 300):
                    self.assertEqual(totp.hmac_digest(key, msg, alg),
                                     hmac.new(key, msg, fn).digest(), (alg, key, msg))

    def test_rfc2202_vector(self):
        # RFC 2202 测试用例 2
        self.assertEqual(totp.hmac_digest(b"Jefe", b"what do ya want for nothing?").hex(),
                         "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")


class TestHotp(unittest.TestCase):
    def test_rfc4226_vectors(self):
        for counter, expected in enumerate(totp.RFC4226_VECTORS):
            self.assertEqual(totp.hotp(totp.RFC4226_KEY, counter), expected)

    def test_rfc4226_truncation_example(self):
        # RFC 4226 §5.4 的示例 HMAC 值
        digest = bytes.fromhex("1f8698690e02ca16618550ef7f19da8e945b555a")
        self.assertEqual(totp.dynamic_truncate(digest), 0x50EF7F19)
        self.assertEqual(totp.dynamic_truncate(digest) % 10 ** 6, 872921)

    def test_leading_zeros_kept(self):
        # RFC 6238 向量 T=1111111109 的 SHA1 结果以 0 开头
        self.assertEqual(totp.totp(totp.RFC6238_KEYS["SHA1"], 1111111109, digits=8), "07081804")

    def test_invalid_args(self):
        with self.assertRaises(ValueError):
            totp.hotp(b"k", -1)
        with self.assertRaises(ValueError):
            totp.hotp(b"k", 0, digits=0)


class TestTotp(unittest.TestCase):
    def test_rfc6238_vectors(self):
        for t, *codes in totp.RFC6238_VECTORS:
            for alg, expected in zip(("SHA1", "SHA256", "SHA512"), codes):
                self.assertEqual(totp.totp(totp.RFC6238_KEYS[alg], t, digits=8, algorithm=alg),
                                 expected, (t, alg))

    def test_six_digit_is_suffix_of_eight(self):
        # mod 10^6 就是 mod 10^8 结果的后 6 位
        key = totp.RFC6238_KEYS["SHA1"]
        for t, eight, *_ in totp.RFC6238_VECTORS:
            self.assertEqual(totp.totp(key, t), eight[-6:])

    def test_same_code_within_period(self):
        key = b"secret-key-123"
        self.assertEqual(totp.totp(key, 60), totp.totp(key, 89.9))
        self.assertNotEqual(totp.totp(key, 89.9), totp.totp(key, 90))

    def test_counter_and_remaining(self):
        self.assertEqual(totp.time_counter(59), 1)
        self.assertEqual(totp.time_counter(60), 2)
        self.assertEqual(totp.seconds_remaining(60), 30)
        self.assertEqual(totp.seconds_remaining(89), 1)

    def test_known_google_authenticator_secret(self):
        # 常用演示密钥 JBSWY3DPEHPK3PXP（= "Hello!\xde\xad\xbe\xef"）
        key = totp.decode_secret("JBSWY3DPEHPK3PXP")
        self.assertEqual(key, b"Hello!\xde\xad\xbe\xef")
        expected = totp.hotp(key, 1700000000 // 30)
        self.assertEqual(totp.totp(key, 1700000000), expected)


class TestVerify(unittest.TestCase):
    key = totp.RFC6238_KEYS["SHA1"]
    t = 1234567890

    def test_current_window(self):
        self.assertEqual(totp.verify(self.key, totp.totp(self.key, self.t), self.t), 0)

    def test_adjacent_windows(self):
        prev = totp.totp(self.key, self.t - 30)
        nxt = totp.totp(self.key, self.t + 30)
        self.assertEqual(totp.verify(self.key, prev, self.t), -1)
        self.assertEqual(totp.verify(self.key, nxt, self.t), 1)
        self.assertIsNone(totp.verify(self.key, prev, self.t, window=0))

    def test_outside_window(self):
        old = totp.totp(self.key, self.t - 90)
        self.assertIsNone(totp.verify(self.key, old, self.t))

    def test_malformed(self):
        for bad in ("", "12345", "1234567", "abcdef", "12 34 5x"):
            self.assertIsNone(totp.verify(self.key, bad, self.t))

    def test_spaces_allowed(self):
        code = totp.totp(self.key, self.t)
        self.assertEqual(totp.verify(self.key, f"{code[:3]} {code[3:]}", self.t), 0)

    def test_near_epoch(self):
        self.assertEqual(totp.verify(self.key, totp.totp(self.key, 0), 0), 0)


class TestSecretAndUri(unittest.TestCase):
    def test_generate_roundtrip(self):
        s = totp.generate_secret()
        self.assertEqual(len(s), 32)
        self.assertNotIn("=", s)
        self.assertEqual(len(totp.decode_secret(s)), 20)
        self.assertNotEqual(s, totp.generate_secret())

    def test_decode_lenient(self):
        key = totp.decode_secret("JBSWY3DPEHPK3PXP")
        self.assertEqual(totp.decode_secret("jbsw y3dp ehpk 3pxp"), key)
        self.assertEqual(totp.decode_secret("JBSW-Y3DP-EHPK-3PXP"), key)
        raw = b"12345678901234567890"
        unpadded = base64.b32encode(raw[:7]).decode().rstrip("=")
        self.assertEqual(totp.decode_secret(unpadded), raw[:7])

    def test_decode_invalid(self):
        for bad in ("", "   ", "ABC1", "ABC!DEFG"):
            with self.assertRaises(ValueError):
                totp.decode_secret(bad)

    def test_uri_roundtrip(self):
        uri = totp.build_uri("JBSWY3DPEHPK3PXP", "alice@example.com", "Acme Co",
                             digits=8, period=60, algorithm="sha256")
        self.assertTrue(uri.startswith("otpauth://totp/Acme%20Co:alice@example.com?"))
        info = totp.parse_uri(uri)
        self.assertEqual(info["secret"], "JBSWY3DPEHPK3PXP")
        self.assertEqual(info["issuer"], "Acme Co")
        self.assertEqual(info["label"], "Acme Co:alice@example.com")
        self.assertEqual((info["digits"], info["period"], info["algorithm"]), (8, 60, "SHA256"))

    def test_uri_defaults_and_errors(self):
        info = totp.parse_uri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")
        self.assertEqual((info["digits"], info["period"], info["algorithm"]), (6, 30, "SHA1"))
        for bad in ("https://totp/x?secret=A", "otpauth://hotp/x?secret=A",
                    "otpauth://totp/x", "otpauth://totp/x?secret=A&algorithm=MD5"):
            with self.assertRaises(ValueError):
                totp.parse_uri(bad)


class TestCli(unittest.TestCase):
    def run_cli(self, argv, env=None):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env or {}, clear=False), \
                mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
            rc = totp.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_vectors_command(self):
        rc, out, _ = self.run_cli(["vectors"])
        self.assertEqual(rc, 0)
        self.assertIn("全部通过", out)
        self.assertNotIn("❌", out)

    def test_code_and_verify_with_env(self):
        env = {"TOTP_SECRET": "JBSWY3DPEHPK3PXP"}
        with mock.patch("time.time", return_value=1700000000.0):
            rc, out, _ = self.run_cli(["code"], env)
            self.assertEqual(rc, 0)
            code = out.strip()
            self.assertEqual(code, totp.totp(totp.decode_secret("JBSWY3DPEHPK3PXP"), 1700000000))
            self.assertEqual(self.run_cli(["verify", code], env)[0], 0)
            self.assertEqual(self.run_cli(["verify", "000000" if code != "000000" else "111111"], env)[0], 1)

    def test_code_with_uri(self):
        uri = totp.build_uri("JBSWY3DPEHPK3PXP", "a", digits=8)
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch("time.time", return_value=1700000000.0):
            rc, out, _ = self.run_cli(["code", "--uri", uri])
        self.assertEqual(rc, 0)
        self.assertEqual(len(out.strip()), 8)

    def test_bad_secret_exit_code(self):
        rc, _, err = self.run_cli(["code"], {"TOTP_SECRET": "not base32!"})
        self.assertEqual(rc, 2)
        self.assertIn("Base32", err)


if __name__ == "__main__":
    unittest.main()
