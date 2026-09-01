from __future__ import annotations

import json
import base64

from pdf_reporter import _markdown_to_html, generate_pdf


def test_markdown_renderer_keeps_korean_http_tables_and_code() -> None:
    html = _markdown_to_html(
        "# 진단 보고서\n\n## 요청\n\n| 항목 | 값 |\n| --- | --- |\n| URL | http://192.168.0.1/a.php |\n\n```http\nGET /a.php HTTP/1.1\n```",
        title="진단 보고서",
    )
    assert "진단 보고서" in html
    assert "<table>" in html
    assert "<pre>" in html
    assert "http://192.168.0.1/a.php" in html


def test_generate_pdf_creates_local_pdf_and_ignores_missing_screenshot(tmp_path) -> None:
    (tmp_path / "review.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "F-001",
                        "manual_evidence": [
                            {"type": "screenshot", "file": "evidence/F-001/missing.png", "description": "없음"}
                        ],
                    }
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    markdown = tmp_path / "diagnostic_guide.md"
    markdown.write_text("# 진단 이정표\n\n- URL: `http://localhost/test`\n- 응답: `HTTP/1.1 200 OK`\n", encoding="utf-8")
    output = generate_pdf(markdown, tmp_path / "diagnostic_guide.pdf", "diagnostic")
    assert output.exists()
    assert output.read_bytes().startswith(b"%PDF-")


def test_pdf_report_types_are_written_without_ai(tmp_path) -> None:
    markdown = tmp_path / "report.md"
    markdown.write_text("# 보고서\n\n확인된 내용", encoding="utf-8")
    for report_type, name in (("final", "final_report.pdf"), ("secure_coding", "secure_coding_guide.pdf")):
        output = generate_pdf(markdown, tmp_path / name, report_type)
        assert output.stat().st_size > 100


def test_existing_screenshot_is_embedded_in_html_when_registered(tmp_path) -> None:
    image = tmp_path / "evidence" / "F-001" / "result.png"
    image.parent.mkdir(parents=True)
    image.write_bytes(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="))
    (tmp_path / "review.json").write_text(json.dumps({"findings": [{"manual_evidence": [{"type": "screenshot", "file": "evidence/F-001/result.png", "description": "검증 화면"}]}]}, ensure_ascii=False), encoding="utf-8")
    rendered = _markdown_to_html("# 결과", title="결과", base_dir=tmp_path)
    assert "result.png" in rendered
