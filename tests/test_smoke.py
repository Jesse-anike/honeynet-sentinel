import json
import unittest
from pathlib import Path

from main import analyze

ROOT = Path(__file__).resolve().parents[1]


class SmokeTests(unittest.TestCase):
    def test_analyzer_returns_json_serializable_result(self):
        sample = (ROOT / "sample.log").read_text(encoding="utf-8")
        result = analyze(sample)
        json.dumps(result, default=str)
        self.assertIsNotNone(result)

    def test_sample_event_counts(self):
        sample = (ROOT / "sample.log").read_text(encoding="utf-8")
        result = analyze(sample)
        self.assertEqual(result["events_parsed"], 3)
        self.assertEqual(result["failed_logins"], 1)
        self.assertEqual(result["unique_sessions"], 1)


if __name__ == "__main__":
    unittest.main()
