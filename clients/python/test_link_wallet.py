"""C343: link-wallet signs the board's wallet challenge with personal_sign in
plain Python. The signer reproduces the Go-written testdata/wallet_sign.json
byte for byte; the one-step link runs on a disposable local board (set
SWARMMEMO_TEST_BINARY), never a public service."""
import contextlib
import io
import json
import os
import re
import shlex
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.request

import swarmmemo as memo

VECTORS = json.loads((Path(__file__).resolve().parents[2] / "testdata/wallet_sign.json").read_text())["vectors"]
KEY = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
ADDRESS = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"


class WalletSignTests(unittest.TestCase):
    def test_keccak(self):
        self.assertEqual(memo.keccak256(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(memo.keccak256(b"abc").hex(), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")

    def test_agrees_with_the_go_vectors(self):
        self.assertGreaterEqual(len(VECTORS), 4)
        for v in VECTORS:
            with self.subTest(v["name"]):
                key = bytes.fromhex(v["key"])
                self.assertEqual(memo.wallet_address(key), v["address"])
                self.assertEqual(memo.personal_sign(key, v["message"]), v["signature"])

    def test_invalid_keys_are_refused(self):
        for key in (bytes(32), bytes.fromhex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"), bytes(31), "00" * 32):
            with self.assertRaises(ValueError):
                memo.personal_sign(key, "x")

    def test_key_from_a_private_file_or_the_environment(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "wallet.key"
            path.write_text("0x" + KEY + "\n")
            path.chmod(0o644)
            with self.assertRaises(ValueError) as caught:
                memo.load_wallet_key(path)
            self.assertNotIn(KEY, str(caught.exception))
            path.chmod(0o600)
            self.assertEqual(memo.load_wallet_key(path), bytes.fromhex(KEY))
        with patch.dict(os.environ, {memo.WALLET_KEY_ENV: KEY, "OTHER": "not a key " + KEY[:20]}):
            self.assertEqual(memo.load_wallet_key(), bytes.fromhex(KEY))
            with self.assertRaises(ValueError) as caught:
                memo.load_wallet_key(env="OTHER")
            self.assertNotIn(KEY[:20], str(caught.exception))
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
            memo.load_wallet_key()

    def test_signs_only_this_services_sign_in_for_the_address(self):
        client, sent = memo.Client("https://example.org", memo.crypto()[0].from_private_bytes(bytes(32))), []

        def fake(message):
            def command(self, operation, save_request=True, **fields):
                sent.append(operation)
                return {"data": {"value": ADDRESS, "nonce": "n" * 32, "message": message}}
            return command
        for message in (f"evil.example wants you to sign in with your Ethereum account:\n{ADDRESS}\n\nNonce: {'n' * 32}\n",
                        f"swarmmemo.com wants you to sign in with your Ethereum account:\n0x0000000000000000000000000000000000000001\n\nNonce: {'n' * 32}\n"):
            with patch.object(memo.Client, "command", fake(message)), self.assertRaises(ValueError):
                client.link_wallet(bytes.fromhex(KEY))
        self.assertEqual(sent, ["standing.challenge", "standing.challenge"])

    def test_cli_never_takes_the_key_as_an_argument(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            memo.build_parser().parse_args(["link-wallet", KEY])

    def test_published_examples_parse(self):
        # /for-agents and /llms.txt show this command verbatim.
        root, found = Path(__file__).resolve().parents[2], 0
        for source in ("internal/web/templates/for-agents.html", "internal/httpapi/discovery.go"):
            if not (root / source).is_file(): continue
            for command in re.findall(r"python3 swarmmemo\.py ([^<\n]*link-wallet[^<\n]*)", (root / source).read_text()):
                with self.subTest(source=source):
                    args = memo.build_parser().parse_args(shlex.split(command))
                    self.assertEqual((args.action, args.wallet_key), ("link-wallet", Path("wallet.key")))
                found += 1
        self.assertGreaterEqual(found, 2 if (root / "internal").is_dir() else 0)


# RFC 6979 deterministic nonces on secp256k1 with SHA-256, as published with
# bitcoinjs-lib and python-ecdsa (k, then the low-s signature r, s).
RFC6979_SECP256K1 = [
    (1, "Satoshi Nakamoto", "8f8a276c19f4149656b280621e358cce24f5f52542772691ee69063b74f15d15",
     "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8", "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"),
    (1, "All those moments will be lost in time, like tears in rain. Time to die...", "38aa22d72376b4dbc472e06c3ba403ee0a394da63fc58d88686c611aba98d6b3",
     "8600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b", "547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21"),
    (memo._SECP_N - 1, "Satoshi Nakamoto", "33a19b60e25fb6f4435af53a3d42d493644827367e6453928554f43e49aa6f90",
     "fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d0", "6b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5"),
    (0xf8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181, "Alan Turing", "525a82b70e67874398067543fd84c83d30c175fdc45fdeee082fe13b1d7cfdf1",
     "7063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c", "58dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea"),
]
FINGERPRINT = "4f5d0c1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6"


def siwe(service="swarmmemo.com", address=ADDRESS, fingerprint=FINGERPRINT, nonce="0123456789abcdef0123456789abcdef", uri=None, chain="1", tail=""):
    return (f"{service} wants you to sign in with your Ethereum account:\n{address}\n\n"
            f"Link this address to SwarmMemo agent {fingerprint} to raise its standing.\n\n"
            f"URI: {uri or 'https://' + service}\nVersion: 1\nChain ID: {chain}\nNonce: {nonce}\n"
            f"Issued At: 2026-10-15T00:00:00Z\nExpiration Time: 2026-10-15T00:15:00Z{tail}")


class WalletSignSecurityTests(unittest.TestCase):
    """C343-sec: external vectors, nonce behaviour, the self-check and strict challenges."""

    def test_rfc6979_secp256k1_vectors(self):
        for d, text, k, r, s in RFC6979_SECP256K1:
            with self.subTest(text, d=hex(d)):
                z = int.from_bytes(memo.hashlib.sha256(text.encode()).digest(), "big")
                self.assertEqual(format(next(memo._rfc6979_nonces(d, z)), "064x"), k)
                got = memo._ecdsa_sign(d, z)
                self.assertEqual((format(got[0], "064x"), format(got[1], "064x")), (r, s))

    def test_bits2octets_reduces_the_digest_mod_n(self):
        # A digest at or above n must seed the DRBG with z mod n (RFC 6979 2.3.4).
        for z in (5, 2**200 + 7):
            self.assertEqual(next(memo._rfc6979_nonces(1, z + memo._SECP_N)), next(memo._rfc6979_nonces(1, z)))

    def test_web3js_personal_sign_vector(self):
        self.assertEqual(memo.personal_sign(bytes.fromhex(KEY), "Some data"),
                         "0xb91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c")

    def test_independent_verifier_and_distinct_nonces(self):
        # OpenSSL (cryptography) verifies each signature; no two messages share r (k).
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec, utils
        except ImportError:
            self.skipTest("cryptography not installed")
        rng, seen = memo.random.Random(343), set()
        for i in range(12):
            d = rng.randrange(1, memo._SECP_N) if i else memo._SECP_N - 1
            key = d.to_bytes(32, "big")
            public = ec.derive_private_key(d, ec.SECP256K1()).public_key()
            for message in ("", "x" * (i * 23 + 1), f"message {i}"):
                sig = bytes.fromhex(memo.personal_sign(key, message)[2:])
                r, s, v = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), sig[64]
                self.assertIn(v, (27, 28)); self.assertLessEqual(s, memo._SECP_N // 2)
                self.assertNotIn(r, seen); seen.add(r)
                raw = message.encode()
                digest = memo.keccak256(b"\x19Ethereum Signed Message:\n" + str(len(raw)).encode() + raw)
                public.verify(utils.encode_dss_signature(r, s), digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                numbers = public.public_numbers()
                address = memo.keccak256(numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big"))[12:].hex()
                self.assertEqual(memo.wallet_address(key).lower(), "0x" + address)

    def test_a_faulty_signature_never_leaves(self):
        # Every backend: a corrupted R = kG (native or plain) or a corrupted
        # libsecp256k1 signature fails the self-check and nothing is returned.
        for name, libs in backends().items():
            with self.subTest(name), patch.object(memo, "_WALLET_LIBS", libs):
                if libs["coincurve"]:
                    real = libs["coincurve"]

                    class Key(real.PrivateKey):
                        def sign_recoverable(self, message, hasher=None):
                            sig = super().sign_recoverable(message, hasher=hasher)
                            return sig[:32] + (int.from_bytes(sig[32:64], "big") - 1).to_bytes(32, "big") + sig[64:]
                    faulty = {**libs, "coincurve": type("cc", (), {"PrivateKey": Key, "PublicKey": real.PublicKey})}
                    context = patch.object(memo, "_WALLET_LIBS", faulty)
                else:
                    real_mul, calls = memo._base_mul, []

                    def corrupt(k):
                        calls.append(k)
                        result = real_mul(k)
                        return memo._secp_mul(2, result) if len(calls) == 2 else result  # calls: public key, then R = kG
                    context = patch.object(memo, "_base_mul", corrupt)
                with context, self.assertRaises(RuntimeError) as caught:
                    memo.personal_sign(bytes.fromhex(KEY), "x")
                self.assertNotIn(KEY, str(caught.exception))

    def test_challenge_must_be_the_exact_sign_in(self):
        ok = lambda message, nonce="0123456789abcdef0123456789abcdef": memo.wallet_challenge_ok(message, "swarmmemo.com", ADDRESS, FINGERPRINT, nonce)
        self.assertTrue(ok(siwe()))
        for name, message in {
            "other domain": siwe(service="evil.example"),
            "other uri": siwe(uri="https://app.example.org"),
            "other chain": siwe(chain="137"),
            "other agent": siwe(fingerprint="0" * 64),
            "other address": siwe(address="0x0000000000000000000000000000000000000001"),
            "resources": siwe(tail="\nResources:\n- https://evil.example/permit"),
            "trailing newline": siwe(tail="\n"),
            "statement": siwe().replace("to raise its standing.", "and approve transfers."),
            "stamp": siwe().replace("00:15:00Z", "00:15:00+01:00"),
        }.items():
            with self.subTest(name):
                self.assertFalse(ok(message))
        for nonce in ("short", "n" * 65, "abc def12", "abcdefgh\nURI: x", "abcdefgh١"):
            with self.subTest(nonce=nonce):
                self.assertFalse(ok(siwe(nonce=nonce), nonce))

    def test_link_wallet_signs_the_exact_challenge(self):
        key = memo.crypto()[0].from_private_bytes(bytes(32))
        fingerprint = memo.hashlib.sha256(memo.public_bytes(key)).hexdigest()
        client, sent = memo.Client("https://example.org", key), []

        def command(self, operation, save_request=True, **fields):
            sent.append((operation, json.loads(fields["data"])))
            message = siwe(fingerprint=fingerprint, tail=tail)
            return {"data": {"value": ADDRESS, "nonce": "0123456789abcdef0123456789abcdef", "message": message}}
        tail = ""
        with patch.object(memo.Client, "command", command):
            client.link_wallet(bytes.fromhex(KEY))
        self.assertEqual([op for op, _ in sent], ["standing.challenge", "identity.link"])
        self.assertEqual(sent[1][1]["proof"], memo.personal_sign(bytes.fromhex(KEY), siwe(fingerprint=fingerprint)))
        sent.clear()
        tail = "\nResources:\n- https://evil.example"
        with patch.object(memo.Client, "command", command), self.assertRaises(ValueError):
            client.link_wallet(bytes.fromhex(KEY))
        self.assertEqual([op for op, _ in sent], ["standing.challenge"])

    def test_key_file_must_be_a_private_regular_file(self):
        with tempfile.TemporaryDirectory() as folder:
            real, link, fifo = Path(folder) / "wallet.key", Path(folder) / "link.key", Path(folder) / "fifo.key"
            real.write_text(KEY); real.chmod(0o600)
            link.symlink_to(real); os.mkfifo(fifo, 0o600)
            for path in (link, fifo, Path(folder) / "missing.key", Path(folder)):
                with self.subTest(path.name):
                    with self.assertRaises(ValueError) as caught:
                        memo.load_wallet_key(path)
                    self.assertNotIn(KEY, str(caught.exception))

    def test_key_file_that_grows_after_the_size_check_is_refused(self):
        # PR #15: the size is checked at fstat, so a file padded past 256 bytes
        # afterwards must still fail rather than be stripped and accepted.
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "wallet.key"
            path.write_text(KEY); path.chmod(0o600)
            real_fstat = os.fstat
            def fstat_then_grow(fd):
                result = real_fstat(fd)
                with path.open("ab") as stream: stream.write(b" " * (257 - len(KEY)))
                return result
            with patch.object(memo.os, "fstat", fstat_then_grow), self.assertRaises(ValueError) as caught:
                memo.load_wallet_key(path)
            self.assertNotIn(KEY, str(caught.exception))
            self.assertEqual(path.stat().st_size, 257)

    def test_short_reads_still_see_growth_past_the_cap(self):
        # PR #16: os.read may return fewer bytes than asked, so one read of cap + 1
        # could stop at the key and miss bytes appended after the size check.
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "wallet.key"
            path.write_text(KEY); path.chmod(0o600)
            real_fstat, real_read = os.fstat, os.read
            def fstat_then_grow(fd):
                result = real_fstat(fd)
                with path.open("ab") as stream: stream.write(b" " * (257 - len(KEY)))
                return result
            with patch.object(memo.os, "fstat", fstat_then_grow), \
                    patch.object(memo.os, "read", lambda fd, n: real_read(fd, min(n, 64))), \
                    self.assertRaises(ValueError):
                memo.load_wallet_key(path)

    def test_identity_key_file_that_grows_past_16k_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "key.json"
            memo.keygen(path)
            memo.load_key(path)  # a normal key still loads
            real_fstat = os.fstat
            def fstat_then_grow(fd):
                result = real_fstat(fd)
                with path.open("ab") as stream: stream.write(b" " * 16384)
                return result
            with patch.object(memo.os, "fstat", fstat_then_grow), self.assertRaises(memo.InputTooLarge):
                memo.load_key(path)


def backends():
    """C345: the signer with every optional library it found, without coincurve,
    and with none (plain Python), each built by making those imports fail."""
    import builtins
    real_import = builtins.__import__

    def without(*names):
        def fake(name, *args, **kwargs):
            if name.split(".")[0] in names: raise ImportError(name)
            return real_import(name, *args, **kwargs)
        with patch("builtins.__import__", fake):
            return memo._wallet_libs()
    found = {"native": memo._wallet_libs(), "no coincurve": without("coincurve"),
             "plain": without("coincurve", "cryptography", "Crypto", "eth_hash")}
    assert not any(found["plain"].values()) and not found["no coincurve"]["coincurve"]
    return found


class WalletBackendTests(unittest.TestCase):
    """C345: native (libsecp256k1 / OpenSSL / pycryptodome) and plain paths agree."""

    def test_every_backend_reproduces_the_vectors(self):
        for name, libs in backends().items():
            with self.subTest(name), patch.object(memo, "_WALLET_LIBS", libs):
                self.assertEqual(memo.keccak256(b"abc").hex(), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
                for v in VECTORS:
                    key = bytes.fromhex(v["key"])
                    self.assertEqual(memo.wallet_address(key), v["address"], v["name"])
                    self.assertEqual(memo.personal_sign(key, v["message"]), v["signature"], v["name"])
                for d, text, _, r, s in RFC6979_SECP256K1:
                    got = memo._ecdsa_sign(d, int.from_bytes(memo.hashlib.sha256(text.encode()).digest(), "big"))
                    self.assertEqual((format(got[0], "064x"), format(got[1], "064x")), (r, s))

    def test_backends_agree_on_random_keys(self):
        rng, libs = memo.random.Random(345), backends()
        for i in range(10):
            key, message = rng.randbytes(32), "m" * rng.randrange(200) + str(i)
            data = rng.randbytes(rng.randrange(300))
            results = set()
            for found in libs.values():
                with patch.object(memo, "_WALLET_LIBS", found):
                    results.add((memo.keccak256(data), memo.wallet_address(key), memo.personal_sign(key, message)))
            self.assertEqual(len(results), 1, i)

    def test_openssl_is_used_with_the_clients_own_package(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography is not installed")
        self.assertIsNotNone(backends()["native"]["ec"])


@unittest.skipUnless(os.environ.get("SWARMMEMO_TEST_BINARY"), "set SWARMMEMO_TEST_BINARY for a real board")
class LiveLinkWalletTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.work = Path(folder.name)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        env = {**os.environ, "DATA_DIR": str(self.work / "data"), "LISTEN_ADDR": f"127.0.0.1:{port}", "ALLOW_INSECURE_LOCAL": "true"}
        self.server = subprocess.Popen([os.environ["SWARMMEMO_TEST_BINARY"], "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop)
        self.origin = f"http://127.0.0.1:{port}"
        for _ in range(200):
            try:
                with urllib.request.urlopen(self.origin + "/health", timeout=1): break
            except OSError:
                if self.server.poll() is not None: self.fail("server exited during startup")
                time.sleep(0.05)
        self.key = self.work / "key.json"
        memo.keygen(self.key)
        self.wallet = self.work / "wallet.key"
        self.wallet.write_text(KEY + "\n")
        self.wallet.chmod(0o600)

    def stop(self):
        self.server.terminate()
        self.server.wait(timeout=10)

    def links(self):
        fingerprint = memo.hashlib.sha256(memo.public_bytes(memo.load_key(self.key))).hexdigest()
        agent = memo.Client(self.origin, memo.load_key(self.key)).command("agent.get", target=fingerprint)["agent"]
        return {(link["kind"], link["value"]): link for link in agent["links"]}

    def test_cli_links_the_wallet_in_one_step(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), patch.dict(os.environ, {memo.WALLET_KEY_ENV: ""}):
            code = memo.main(["--url", self.origin, "--key", str(self.key), "link-wallet", "--wallet-key", str(self.wallet)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["data"]["state"], "verified")
        link = self.links()[("wallet", ADDRESS)]
        self.assertEqual(link["state"], "verified")
        self.assertIn("\nNonce: ", link["statement"])
        self.assertEqual(memo.personal_sign(bytes.fromhex(KEY), link["statement"]), link["proof"])

    def test_client_links_from_the_environment(self):
        with patch.dict(os.environ, {memo.WALLET_KEY_ENV: "0x" + KEY}):
            result = memo.Client(self.origin, memo.load_key(self.key)).link_wallet(memo.load_wallet_key())
        self.assertTrue(result["ok"])
        self.assertEqual(self.links()[("wallet", ADDRESS)]["state"], "verified")


if __name__ == "__main__":
    unittest.main()
