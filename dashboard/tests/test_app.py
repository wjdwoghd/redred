from __future__ import annotations

import unittest
from datetime import datetime
from pathlib import Path

from streamlit.testing.v1 import AppTest

from models import Evidence


class StreamlitAppTests(unittest.TestCase):
    def test_initial_button_renders_scan_result(self):
        app_path = Path(__file__).resolve().parents[1] / "app.py"
        app = AppTest.from_file(str(app_path), default_timeout=10).run()
        self.assertFalse(app.exception)
        button = next(item for item in app.button if item.label == "1차 자동 스캔 시작")
        button.click().run()
        self.assertFalse(app.exception)
        self.assertTrue(any(item.value == "취약점 후보" for item in app.subheader))
        reanalysis = next(item for item in app.button if item.label == "증적 반영 재분석 실행")
        self.assertTrue(reanalysis.disabled)

        finding_id = app.session_state.scan_result.findings[0].finding_id
        app.session_state.session_reviews = {
            finding_id: {
                "finding_id": finding_id,
                "review_status": "verified",
                "reviewer_memo": "재현 확인",
            }
        }
        app.session_state.session_evidence = [
            {
                "evidence": Evidence(
                    evidence_id="session-proof",
                    finding_id=finding_id,
                    evidence_type="txt",
                    filename="proof.txt",
                    uploaded_at=datetime.now(),
                ),
                "content": b"proof",
            }
        ]
        app.run()
        reanalysis = next(item for item in app.button if item.label == "증적 반영 재분석 실행")
        self.assertFalse(reanalysis.disabled)
        reanalysis.click().run()
        self.assertFalse(app.exception)
        self.assertEqual(app.session_state.workflow_phase, "reanalysis_completed")


if __name__ == "__main__":
    unittest.main()
