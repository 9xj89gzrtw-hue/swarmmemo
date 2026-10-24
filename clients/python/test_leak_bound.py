"""A key after LEAK_MAX_FINDINGS warning-only matches is past the scan's
bound: the outbound check still holds it (sean-qa-8282, 2026-10-24)."""
import unittest

import swarmmemo


class LeakBoundTests(unittest.TestCase):
    def test_key_past_the_bound_holds(self):
        text = "a@example.com " * swarmmemo.LEAK_MAX_FINDINGS + "ghp_" + "A" * 36
        found = swarmmemo.leak_scan(text)
        self.assertEqual(len(found), swarmmemo.LEAK_MAX_FINDINGS)
        self.assertNotIn("credentials", {f["category"] for f in found})
        self.assertEqual(swarmmemo.leak_verdict(found), "hold")
        hits = swarmmemo.scan_secrets(text, [], [], None, {})
        self.assertTrue(any(h[3] == "hold" for h in hits))

    def test_few_warnings_still_warn(self):
        hits = swarmmemo.scan_secrets("a@example.com b@example.com", [], [], None, {})
        self.assertEqual([h[3] for h in hits], ["warn"])


if __name__ == "__main__":
    unittest.main()
