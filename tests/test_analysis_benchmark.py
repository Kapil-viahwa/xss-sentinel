import unittest

from xss_sentinel.javascript_analysis import analyze_javascript


BENCHMARK_CASES = [
    ("direct_dom_sink", True,
     "function render() { const value = location.search; document.querySelector('#out').innerHTML = value; }"),
    ("interprocedural_dom_sink", True,
     "function render(value) { document.querySelector('#out').insertAdjacentHTML('beforeend', value); } function route() { const input = location.hash; render(input); }"),
    ("safe_text_sink", False,
     "function render() { const value = location.search; document.querySelector('#out').textContent = value; }"),
    ("unrelated_source_and_sink", False,
     "function render() { const value = location.search; document.querySelector('#out').innerHTML = 'constant'; }"),
]


class StaticTaintBenchmarkTest(unittest.TestCase):
    def test_synthetic_benchmark_reports_precision_and_recall(self):
        true_positive = false_positive = false_negative = 0
        for name, expected, javascript in BENCHMARK_CASES:
            with self.subTest(case=name):
                detected = bool(analyze_javascript(javascript)["observations"])
                if detected and expected:
                    true_positive += 1
                elif detected:
                    false_positive += 1
                elif expected:
                    false_negative += 1

        precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0
        recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0
        self.assertGreaterEqual(precision, 0.9)
        self.assertGreaterEqual(recall, 0.9)


if __name__ == "__main__":
    unittest.main()
