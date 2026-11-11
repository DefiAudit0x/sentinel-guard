import re
import subprocess
import textwrap
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

    def run_demo_by_absolute_path_from_tmp(self):
        return subprocess.run(
            [str(PYTHON), str(PROJECT_ROOT / "examples" / "local_demo.py")],
            cwd="/tmp",
            capture_output=True,
            text=True,
            check=False,
        )

    def test_import_is_silent_and_leaves_sys_path_unchanged(self):
        import_probe = textwrap.dedent(
            f"""
            import contextlib
            import importlib.util
            import io
            import sys

            source = {str(PROJECT_ROOT / "examples" / "local_demo.py")!r}
            original_path = list(sys.path)
            captured_stdout = io.StringIO()
            captured_stderr = io.StringIO()
            spec = importlib.util.spec_from_file_location(
                "local_demo_import_probe", source
            )
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module

            with contextlib.redirect_stdout(captured_stdout):
                with contextlib.redirect_stderr(captured_stderr):
                    spec.loader.exec_module(module)

            assert sys.path == original_path, (original_path, sys.path)
            assert captured_stdout.getvalue() == "", captured_stdout.getvalue()
            assert captured_stderr.getvalue() == "", captured_stderr.getvalue()
            assert callable(module.main)
            print("IMPORT_OK")
            """
        )
        result = subprocess.run(
            [str(PYTHON), "-c", import_probe],
            cwd="/tmp",
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, "IMPORT_OK\n")

    def test_local_demo_is_deterministic_and_reports_expected_results(self):
        first = self.run_demo()
        second = self.run_demo()
        from_tmp = self.run_demo_by_absolute_path_from_tmp()

        self.assertEqual(first.returncode, 0, msg=first.stderr)
        self.assertEqual(second.returncode, 0, msg=second.stderr)
        self.assertEqual(from_tmp.returncode, 0, msg=from_tmp.stderr)
        self.assertEqual(first.stderr, "")
        self.assertEqual(second.stderr, "")
        self.assertEqual(from_tmp.stderr, "")
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(first.stdout, from_tmp.stdout)

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
