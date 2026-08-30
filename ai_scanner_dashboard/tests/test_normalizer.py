from __future__ import annotations

import unittest

from normalizers import normalize_scan_result


class NormalizerTests(unittest.TestCase):
    def test_missing_fields_are_safe(self):
        result = normalize_scan_result({})
        self.assertEqual(result.scan_id, "unknown-scan")
        self.assertEqual(result.findings, [])

    def test_unknown_vulnerability_type_is_preserved(self):
        result = normalize_scan_result(
            {"findings": [{"id": "F-9", "type": "Future Protocol Confusion"}]}
        )
        self.assertEqual(result.findings[0].vulnerability_type, "Future Protocol Confusion")
        self.assertEqual(result.findings[0].uri, "/")

    def test_percent_confidence_and_aliases(self):
        result = normalize_scan_result(
            {
                "scan_summary": {"scanned_pages": 7},
                "findings": [
                    {
                        "finding_id": "F-1",
                        "category": "SQL Injection",
                        "url": "/login.php",
                        "confidence": "55%",
                        "verification_status": "verified",
                    }
                ],
            }
        )
        self.assertEqual(result.scanned_pages, 7)
        self.assertAlmostEqual(result.findings[0].confidence or 0, 0.55)
        self.assertEqual(result.findings[0].review_status, "verified")

    def test_invalid_root_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_scan_result([])  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
