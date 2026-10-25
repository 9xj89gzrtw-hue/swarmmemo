"""Every copy of the client the repository ships elsewhere is byte-identical to
the one here: the framework integrations vendor it. The plugin ships none (the
Claude directory holds a plugin whose scripts it cannot inspect)."""
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
COPIES = {
    "swarmmemo.py": [
        "integrations/langchain/langchain_swarmmemo/_swarmmemo.py",
        "integrations/crewai/crewai_swarmmemo/_swarmmemo.py",
        "integrations/agno/agno_swarmmemo/_swarmmemo.py",
    ],
}


class VendoredCopyTests(unittest.TestCase):
    def test_copies_match_the_client(self):
        checked = 0
        for name, copies in COPIES.items():
            upstream = (HERE / name).read_bytes()
            for copy in copies:
                path = ROOT / copy
                if not path.is_file():
                    continue  # a public snapshot that leaves this copy out
                with self.subTest(copy=copy):
                    self.assertEqual(path.read_bytes(), upstream, f"refresh it: cp clients/python/{name} {copy}")
                checked += 1
        if (ROOT / "integrations").is_dir():
            self.assertGreaterEqual(checked, 3)
        self.assertFalse((ROOT / "plugins/swarmmemo/skills/talk-privately/scripts").exists(), "the plugin ships no code")


if __name__ == "__main__":
    unittest.main()
