"""Ed25519 without pip (F4): the client's plain-Python RFC 8032 code, used when the
cryptography package does not import, gives the RFC's own vectors and the very
signatures cryptography gives, refuses malformed keys and signatures, and carries
keygen, signed posts, register, home, updates and work claim/submit end to end."""
import builtins
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.request

import swarmmemo as memo

HERE = Path(__file__).resolve().parent
PLAIN_PRIVATE, PLAIN_PUBLIC, PLAIN_SERIALIZATION = memo.PLAIN_ED25519
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    Ed25519PrivateKey = None

# RFC 8032 section 7.1, every Ed25519 test: TEST 1, 2, 3, 1024 and SHA(abc).
RFC8032 = [
    {
        "name": "TEST 1",
        "secret": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "public": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "signature": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        "message": "",
    },
    {
        "name": "TEST 2",
        "secret": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "public": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "signature": "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        "message": "72",
    },
    {
        "name": "TEST 3",
        "secret": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "public": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "signature": "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        "message": "af82",
    },
    {
        "name": "TEST 1024",
        "secret": "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
        "public": "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        "signature": "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
        "message": (
            "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1"
            "e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d"
            "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a"
            "7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"
            "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc10"
            "3b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1"
            "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d"
            "502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270"
            "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089b"
            "eccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba"
            "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969b"
            "e3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7"
            "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988d"
            "cda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df"
            "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7"
            "984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4"
            "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac09"
            "43bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f"
            "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f161"
            "0e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d"
            "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8ca"
            "c60c905c15fc910840b94c00a0b9d0"
        ),
    },
    {
        "name": "TEST SHA(abc)",
        "secret": "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "public": "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "signature": "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        "message": (
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
            "454d4423643ce80e2a9ac94fa54ca49f"
        ),
    },
]

# Prefix every CLI subprocess with this so cryptography cannot import there.
NO_CRYPTOGRAPHY = "import runpy, sys; sys.modules['cryptography'] = None; sys.argv[0] = %r; runpy.run_path(sys.argv[0], run_name='__main__')"


def without_cryptography():
    """memo.crypto() as chosen when the cryptography package is not installed."""
    real_import = builtins.__import__

    def fake(name, *args, **kwargs):
        if name.split(".")[0] == "cryptography": raise ImportError(name)
        return real_import(name, *args, **kwargs)
    with patch("builtins.__import__", fake), patch.object(memo, "_ED25519", None):
        return memo.crypto()


def backends():
    found = {"plain": memo.PLAIN_ED25519}
    if Ed25519PrivateKey is not None: found["cryptography"] = memo.crypto()
    return found


class VectorTests(unittest.TestCase):
    def test_rfc8032_vectors(self):
        self.assertEqual(len(RFC8032), 5)
        for name, (private, public, serialization) in backends().items():
            for v in RFC8032:
                with self.subTest(backend=name, vector=v["name"]):
                    key = private.from_private_bytes(bytes.fromhex(v["secret"]))
                    message, signature = bytes.fromhex(v["message"]), bytes.fromhex(v["signature"])
                    self.assertEqual(memo.public_bytes(key).hex(), v["public"])
                    self.assertEqual(key.sign(message).hex(), v["signature"])
                    verifier = public.from_public_bytes(bytes.fromhex(v["public"]))
                    verifier.verify(signature, message)
                    with self.assertRaises(Exception):
                        verifier.verify(signature, message + b"\x00")
                    for i in (0, 31, 32, 63):  # a bit flipped in R or in S
                        bad = bytearray(signature)
                        bad[i] ^= 1
                        with self.assertRaises(Exception):
                            verifier.verify(bytes(bad), message)

    def test_the_repositorys_signing_vector(self):
        vector = json.loads((HERE / "signing-vector.json").read_text())
        key = PLAIN_PRIVATE.from_private_bytes(bytes.fromhex(vector["seed_hex"]))
        command = {k: v for k, v in vector["command"].items() if k != "signature"}
        with patch.object(memo, "_ED25519", memo.PLAIN_ED25519):
            signed = memo.sign(command, key, vector["service"])
        self.assertEqual(memo.canonical(signed, vector["service"]).decode(), vector["canonical"])
        self.assertEqual(signed, vector["command"])

    @unittest.skipIf(Ed25519PrivateKey is None, "cryptography is not installed")
    def test_random_keys_and_messages_match_cryptography(self):
        rng = memo.random.Random(8032)
        for i in range(64):
            seed, message = rng.randbytes(32), rng.randbytes(rng.randrange(0 if i == 0 else 1, 2000))
            plain, native = PLAIN_PRIVATE.from_private_bytes(seed), Ed25519PrivateKey.from_private_bytes(seed)
            public = native.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            self.assertEqual(memo.public_bytes(plain), public, i)
            self.assertEqual(plain.sign(message), native.sign(message), i)
            PLAIN_PUBLIC.from_public_bytes(public).verify(native.sign(message), message)
            Ed25519PublicKey.from_public_bytes(public).verify(plain.sign(message), message)


class MalformedInputTests(unittest.TestCase):
    def test_private_keys_are_32_bytes(self):
        for raw in (b"", bytes(31), bytes(33), bytes(64), "x" * 32, None):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                PLAIN_PRIVATE.from_private_bytes(raw)

    def test_public_keys_must_be_canonical_curve_points(self):
        p = 2**255 - 19
        off_curve = next(y for y in range(2, 100) if memo._ed_decode(y.to_bytes(32, "little")) is None)
        for raw in (bytes(31), bytes(33),
                    p.to_bytes(32, "little"), (p + 1).to_bytes(32, "little"),  # y >= p
                    (1 | 1 << 255).to_bytes(32, "little"),                     # x = 0 with the sign bit
                    off_curve.to_bytes(32, "little")):                         # no square root
            with self.subTest(raw=raw.hex()), self.assertRaises(ValueError):
                PLAIN_PUBLIC.from_public_bytes(raw)

    def test_malleable_and_misshapen_signatures_are_refused(self):
        v = RFC8032[1]
        message, signature = bytes.fromhex(v["message"]), bytes.fromhex(v["signature"])
        s = int.from_bytes(signature[32:], "little")
        malleated = signature[:32] + (s + memo._ED_L).to_bytes(32, "little")  # S + L: same check, S out of range
        for name, (_, public, _) in backends().items():
            verifier = public.from_public_bytes(bytes.fromhex(v["public"]))
            for bad in (malleated, signature[:63], signature + b"\x00", b"", bytes(64)):
                with self.subTest(backend=name, signature=bad.hex()), self.assertRaises(Exception):
                    verifier.verify(bad, message)
        with self.assertRaises(memo.InvalidSignature):
            PLAIN_PUBLIC.from_public_bytes(bytes.fromhex(v["public"])).verify(malleated, message)

    def test_backups_load_by_seed_or_pkcs8_and_nothing_else(self):
        seed = bytes(range(32))
        for name, found in backends().items():
            with self.subTest(backend=name), patch.object(memo, "_ED25519", found):
                expected = memo.public_bytes(found[0].from_private_bytes(seed))
                self.assertEqual(memo.public_bytes(memo.private_key_from_bytes(seed)), expected)
                self.assertEqual(memo.public_bytes(memo.private_key_from_bytes(memo._PKCS8_ED25519 + seed)), expected)
                for raw in (seed[:31], seed + b"\x00", bytes(16) + seed, memo._PKCS8_ED25519[:-1] + b"\x21" + seed):
                    with self.assertRaises(ValueError):
                        memo.private_key_from_bytes(raw)


class BackendTests(unittest.TestCase):
    def test_plain_python_without_cryptography(self):
        self.assertIs(without_cryptography(), memo.PLAIN_ED25519)

    @unittest.skipIf(Ed25519PrivateKey is None, "cryptography is not installed")
    def test_cryptography_when_installed(self):
        with patch.object(memo, "_ED25519", None):
            self.assertIs(memo.crypto()[0], Ed25519PrivateKey)

    def test_keygen_and_load_key_without_cryptography(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(memo, "_ED25519", memo.PLAIN_ED25519):
            path = Path(folder) / "key.json"
            made = memo.keygen(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            record = json.loads(path.read_text())
            key = memo.load_key(path)
            self.assertIsInstance(key, PLAIN_PRIVATE)
            self.assertEqual((record["public_key"], made["id"]), (memo.b64(memo.public_bytes(key)), record["fingerprint"]))
            command = memo.sign({"operation": "post", "room": "lobby", "text": "hi"}, key)
            PLAIN_PUBLIC.from_public_bytes(memo.unb64(command["public_key"])).verify(memo.unb64(command["signature"]), memo.canonical(command))
            if Ed25519PrivateKey is not None:  # the same file under cryptography signs the same bytes
                with patch.object(memo, "_ED25519", None):
                    self.assertEqual(memo.sign(command, memo.load_key(path))["signature"], command["signature"])

    def test_sealed_conversations_name_the_install_command(self):
        import swarmmemo_seal
        with patch.object(swarmmemo_seal, "_crypto", side_effect=RuntimeError(swarmmemo_seal.NEEDS_CRYPTOGRAPHY)):
            with self.assertRaises(memo.ChatStop) as caught:
                memo.seal_module()
        self.assertIn("python3 -m pip install --user cryptography", str(caught.exception))
        self.assertIn("sealed conversations", str(caught.exception))

    def test_the_cli_never_imports_cryptography_for_keygen(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "key.json"
            run = subprocess.run([sys.executable, "-c", NO_CRYPTOGRAPHY % str(HERE / "swarmmemo.py"), "keygen", str(path)],
                                 capture_output=True, text=True, timeout=60)
            self.assertEqual(run.returncode, 0, run.stderr)
            made, record = json.loads(run.stdout), json.loads(path.read_text())
            self.assertEqual(made["public_key"], record["public_key"])
            key = PLAIN_PRIVATE.from_private_bytes(memo.unb64(record["private_key"]))
            self.assertEqual(memo.b64(memo.public_bytes(key)), record["public_key"])


@unittest.skipUnless(os.environ.get("SWARMMEMO_TEST_BINARY"), "set SWARMMEMO_TEST_BINARY for a real board")
class LiveWithoutCryptographyTests(unittest.TestCase):
    """The CLI, with cryptography made unimportable, on a disposable local board."""

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

    def stop(self):
        self.server.terminate()
        self.server.wait(timeout=10)

    def cli(self, *argv, key=None):
        root = ["--url", self.origin] + (["--key", str(self.work / f"{key}.json")] if key else [])
        run = subprocess.run([sys.executable, "-c", NO_CRYPTOGRAPHY % str(HERE / "swarmmemo.py"), *root, *argv],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 0, f"{argv}: {run.stderr}")
        return json.loads(run.stdout) if run.stdout.strip().startswith("{") else run.stdout

    def test_keygen_post_register_home_updates_and_work(self):
        for who in ("requester", "worker"):
            self.cli("keygen", str(self.work / f"{who}.json"))
            self.cli("post", "lobby", "main", f"{who} is here, signed without cryptography", key=who)
        self.cli("register", "plain-worker", key="worker")
        request = self.cli("post", "lobby", "main", "Count the vowels in 'swarm'", "--kind", "request", key="requester")
        message_id = request["receipt"]["id"]
        self.cli("work", "create", message_id, "--title", "Count vowels", key="requester")
        claimed = self.cli("work", "claim", message_id, key="worker")
        result = self.cli("post", "lobby", "main", "One: a.", "--reply-to", message_id, key="worker")
        self.cli("work", "submit", message_id, str(claimed["data"]["ack"]["fence"]), result["receipt"]["id"], key="worker")
        with urllib.request.urlopen(f"{self.origin}/api/work/{message_id}", timeout=5) as response:
            self.assertEqual(json.loads(response.read())["data"]["work"]["state"], "submitted")
        self.cli("home", key="worker")
        self.cli("updates", key="requester")
        self.assertIn("plain-worker", json.dumps(self.cli("agent", "get", "plain-worker")))


if __name__ == "__main__":
    unittest.main()
