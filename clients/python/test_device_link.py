"""C576: swarmmemo.py device link|approve|list|remove. The new device's key
signs only its own request and its proof over the approved command; the main
key's approval is device.add without a proof; nothing ever sends a private key."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

import swarmmemo as memo

CODE = "K7QM-4XPD"


class DeviceLinkTests(unittest.TestCase):
    def setUp(self):
        private = memo.crypto()[0]
        self.main = private.from_private_bytes(bytes([1]) * 32)
        self.phone = private.from_private_bytes(bytes([2]) * 32)
        self.phone_pub = memo.b64(memo.public_bytes(self.phone))
        self.approved = memo.sign({"operation": "device.add", "target": self.phone_pub, "request_id": "r1",
                                   "data": memo.data_json("device.add", {"schema": 1, "label": "phone", "code_sha256": "a" * 64})}, self.main)

    def run_cli(self, key, argv, answers=("y",), approval=True):
        sent, out, err = [], io.StringIO(), io.StringIO()

        def fake(client, path, body=None):
            sent.append(body)
            op = body["operation"]
            if op == "device.request":
                return {"ok": True, "data": {"code": CODE, "link": "https://swarmmemo.com/me#link=K7QM4XPD", "expires_at": 4102444800, "match": ["apple", "boat", "comet", "drum"], "device": "f" * 64}}
            if op == "device.request.get":
                data = {"device": "f" * 64, "public_key": self.phone_pub, "label": "phone", "code_sha256": "a" * 64, "match": ["apple"]}
                if approval and body["public_key"] == self.phone_pub:
                    data["approval"] = {"account": "c" * 64, "handle": "hugo", "command": dict(approval if isinstance(approval, dict) else self.approved)}
                return {"ok": True, "data": data}
            return {"ok": True, "data": {"op": op}}
        with patch.object(memo, "load_key", return_value=key), patch.object(memo.Client, "_request", fake), \
                patch("builtins.input", side_effect=list(answers)), patch.object(memo.time, "sleep", lambda _: None), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = memo.main(["--key", "k.json", "device", *argv])
            except SystemExit as exc:
                code = exc.code
        return code, sent, err.getvalue()

    def test_link_signs_the_approved_command_as_proof(self):
        code, sent, err = self.run_cli(self.phone, ["link", "--label", "phone"])
        self.assertEqual(code, 0, err)
        self.assertIn("device approve " + CODE, err)
        self.assertEqual([c["operation"] for c in sent], ["device.request", "device.request.get", "device.add"])
        final = sent[-1]
        self.assertEqual(final["signature"], self.approved["signature"])  # the main key's own command, unchanged
        payload = memo.canonical({k: v for k, v in final.items() if k != "proof"})
        memo.crypto()[1].from_public_bytes(memo.public_bytes(self.phone)).verify(memo.unb64(final["proof"]), payload)
        for seed in (bytes([1]) * 32, bytes([2]) * 32):  # no private key leaves, in any spelling
            self.assertNotIn(memo.b64(seed), json.dumps(sent))
            self.assertNotIn(seed.hex(), json.dumps(sent))
        self.assertIn("This device is now @hugo.", err)

    def test_link_refuses_an_approval_for_another_key(self):
        other = memo.sign({"operation": "device.add", "target": memo.b64(memo.public_bytes(self.main)), "data": "{}"}, self.main)
        code, sent, err = self.run_cli(self.phone, ["link"], approval=other)
        self.assertNotEqual(code, 0)
        self.assertNotIn("device.add", [c["operation"] for c in sent])

    def test_declined_join_sends_nothing(self):
        code, sent, err = self.run_cli(self.phone, ["link"], answers=("n",))
        self.assertNotEqual(code, 0)
        self.assertEqual([c["operation"] for c in sent], ["device.request", "device.request.get"])

    def test_approve_sends_device_add_without_proof(self):
        code, sent, err = self.run_cli(self.main, ["approve", CODE])
        self.assertEqual(code, 0, err)
        add = sent[-1]
        self.assertEqual(add["operation"], "device.add")
        self.assertNotIn("proof", add)
        self.assertEqual(add["target"], self.phone_pub)
        self.assertEqual(json.loads(add["data"]), {"schema": 1, "label": "phone", "code_sha256": "a" * 64})
        self.assertIn("Only link a device you are holding", err)

    def test_list_and_remove(self):
        _, sent, _ = self.run_cli(self.main, ["list", "hugo"])
        self.assertEqual((sent[0]["operation"], sent[0]["target"]), ("devices.list", "hugo"))
        _, sent, _ = self.run_cli(self.phone, ["remove"])
        self.assertEqual(sent[0]["operation"], "device.revoke")
        self.assertNotIn("target", sent[0])


if __name__ == "__main__":
    unittest.main()
