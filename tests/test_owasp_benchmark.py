import tempfile
import unittest
from pathlib import Path

from xss_sentinel.benchmark import load_expected_xss, score_report


class OwaspBenchmarkScoreTest(unittest.TestCase):
    def test_scores_only_cwe79_cases_and_reports_full_confusion_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            expected_path = Path(directory) / "expectedresults-1.2.csv"
            expected_path.write_text(
                "# test name, category, real vulnerability, cwe, Benchmark version: 1.2\n"
                "BenchmarkTest00001,xss,true,79\n"
                "BenchmarkTest00002,xss,false,79\n"
                "BenchmarkTest00003,xss,true,79\n"
                "BenchmarkTest00004,xss,false,79\n"
                "BenchmarkTest00005,sqli,true,89\n",
                encoding="utf-8",
            )
            expected, version = load_expected_xss(expected_path)

        report = {
            "resources": [
                {"url": f"https://benchmark.test/benchmark/{test_id}", "kind": "page", "status_code": 200}
                for test_id in expected
            ],
            "findings": [
                {"url": "https://benchmark.test/benchmark/BenchmarkTest00001", "state": "confirmed", "category": "reflected_xss"},
                {"url": "https://benchmark.test/benchmark/BenchmarkTest00004", "state": "confirmed", "category": "blind_xss"},
            ],
        }
        result = score_report(report, expected, version)
        self.assertEqual(version, "1.2")
        self.assertEqual((result["tp"], result["fn"], result["tn"], result["fp"]), (1, 1, 1, 1))
        self.assertEqual(result["tested"], 4)
        self.assertTrue(result["complete"])
        self.assertEqual(result["score_percent"], 0.0)

    def test_unvisited_cases_are_reported_as_untested(self):
        expected = {"BenchmarkTest00001": True, "BenchmarkTest00002": False}
        result = score_report({"resources": [], "findings": []}, expected, "1.2")
        self.assertEqual(result["untested"], 2)
        self.assertEqual(result["tested"], 0)
        self.assertFalse(result["complete"])
        self.assertIsNone(result["score_percent"])


if __name__ == "__main__":
    unittest.main()
