"""Every test file's __main__ guard comes last: unittest.main() exits there, so
a test class below it is skipped by a direct run (python3 test_x.py) while
module loading still runs it (round 7 flins, issue #40 swiftbotlab)."""

import ast
import pathlib
import unittest

HERE = pathlib.Path(__file__).resolve().parent


class MainGuardIsLast(unittest.TestCase):
    def test_no_code_after_the_guard(self):
        for path in sorted(HERE.glob("test_*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for i, node in enumerate(tree.body):
                if isinstance(node, ast.If) and "__main__" in ast.unparse(node.test):
                    self.assertEqual(i, len(tree.body) - 1, f"{path.name}: code after the __main__ guard (line {node.lineno})")


if __name__ == "__main__":
    unittest.main()
