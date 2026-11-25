import json
from pathlib import Path
import subprocess
import sys
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "inline_helpers.py"


class InlineHelperReportTest(unittest.TestCase):
    def run_report(self, inventory, *args):
        return subprocess.run(
            [sys.executable, SCRIPT, *args], input=json.dumps(inventory),
            capture_output=True, text=True, timeout=10,
        )

    def test_selected_inventory_preserves_distinct_identities_and_sites(self):
        first = {"source": "pdb", "id": "0x4", "name": "adjust", "depth": 0,
                 "ranges": [["0x11", "0x12"], ["0x14", "0x18"]]}
        second = dict(first, depth=1, ranges=[["0x19", "0x20"]])
        overload = dict(first, id="0x5")
        caller = {"name": "outer", "address_hex": "0x10",
                  "inline_sites": [first, second, overload, dict(first, id="0x6", name="other")]}
        inventory = {"binary": "sample", "error": None, "count": 1, "total": 3,
                     "limits": {"max": 1}, "functions": [caller]}
        p = self.run_report(inventory, "--name", "adjust")
        self.assertEqual(p.returncode, 0, p.stderr)
        report = json.loads(p.stdout)
        self.assertEqual((report["inventory_count"], report["inventory_total"]), (1, 3))
        self.assertEqual(report["limits"], inventory["limits"])
        groups = report["helpers"]
        self.assertEqual([group["id"] for group in groups], ["0x4", "0x5"])
        self.assertEqual([len(group["sites"]) for group in groups], [2, 1])
        self.assertEqual([(s["depth"], s["ranges"]) for s in groups[0]["sites"]],
                         [(0, first["ranges"]), (1, second["ranges"])])

    def test_failed_inventory_is_reported_as_an_error(self):
        p = self.run_report({"error": "fixture failed to load", "functions": []})
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")
        self.assertIn("fixture failed to load", p.stderr)
