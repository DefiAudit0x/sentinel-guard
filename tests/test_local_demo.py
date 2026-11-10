import re
import subprocess
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYTHON = PROJECT_ROOT / ".venv" / "bin" / "python"


class LocalDemoTests(unittest.TestCase):
    def run_demo(self):
        return subprocess.run(
            [str(PYTHON), "examples/local_demo.py"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_local_demo_is_deterministic_and_reports_expected_results(self):
        first = self.run_demo()
        second = self.run_demo()

        self.assertEqual(first.returncode, 0, msg=first.stderr)
        self.assertEqual(second.returncode, 0, msg=second.stderr)
        self.assertEqual(first.stderr, "")
        self.assertEqual(second.stderr, "")
        self.assertEqual(first.stdout, second.stdout)

        scenario_sections = re.split(
            r"(?=^\[\d+\] )", first.stdout, flags=re.MULTILINE
        )
        scenario_sections = [section for section in scenario_sections if section.startswith("[")]
        self.assertEqual(len(scenario_sections), 3)

        expected_results = (("ALLOW", 0), ("WARN", 30), ("BLOCK", 100))
        for index, (section, (decision, score)) in enumerate(
            zip(scenario_sections, expected_results), start=1
        ):
            with self.subTest(scenario=index):
                self.assertTrue(section.startswith(f"[{index}] "))
                self.assertIn(f"Expected final decision: {decision}", section)
                self.assertIn(f"risk_score={score},", section)
                self.assertIn(
                    f"Simulation: status=COMPLETED, decision={decision},", section
                )
                self.assertIn("Expected-result check: PASS", section)

        self.assertIn("Overall: PASS", first.stdout)


if __name__ == "__main__":
    unittest.main()
