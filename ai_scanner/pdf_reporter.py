"""Local Markdown-to-PDF reporting with optional renderer fallbacks.

PDF generation never calls an AI provider.  Markdown remains the source of
truth; PDF is a presentation artifact and failures are reported to the caller
without invalidating the JSON/Markdown results.
"""

from __future__ import annotations

import html
import json
import logging
import os
import re
from pathlib import Path
from typing import Iterable

LOGGER = logging.getLogger(__name__)


def _markdown_to_html(markdown: str, *, title: str, base_dir: Path | None = None) -> str:
    """Convert the project Markdown subset to styled, self-contained HTML."""

    lines = markdown.replace("\r\n", "\n").split("\n")
    output: list[str] = []
    in_code = False
    in_table = False
    in_list = False

    def inline(value: str) -> str:
        value = html.escape(value, quote=False)
        value = re.sub(r"`([^`]+)`", r"<code>\1</code>", value)
        value = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", value)
        return value

    def close_list() -> None:
        nonlocal in_list
        if in_list:
            output.append("</ul>")
            in_list = False

    for line in lines:
        if line.startswith("```"):
            close_list()
            if in_code:
                output.append("</pre>")
            else:
                output.append("<pre>")
            in_code = not in_code
            continue
        if in_code:
            output.append(html.escape(line, quote=False))
            continue
        if line.startswith("|") and line.endswith("|"):
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if all(set(cell) <= {"-", ":", " "} for cell in cells):
                continue
            if not in_table:
                output.append("<table><thead><tr>" + "".join(f"<th>{inline(cell)}</th>" for cell in cells) + "</tr></thead><tbody>")
                in_table = True
            else:
                output.append("<tr>" + "".join(f"<td>{inline(cell)}</td>" for cell in cells) + "</tr>")
            continue
        if in_table:
            output.append("</tbody></table>")
            in_table = False
        if not line.strip():
            close_list()
            continue
        heading = re.match(r"^(#{1,6})\s+(.+)$", line)
        if heading:
            close_list()
            level = len(heading.group(1))
            output.append(f"<h{level}>{inline(heading.group(2))}</h{level}>")
        elif line.startswith("> "):
            close_list()
            output.append(f"<blockquote>{inline(line[2:])}</blockquote>")
        elif re.match(r"^[-*]\s+", line):
            if not in_list:
                output.append("<ul>")
                in_list = True
            output.append(f"<li>{inline(re.sub(r'^[-*]\s+', '', line))}</li>")
        elif re.match(r"^\d+\.\s+", line):
            close_list()
            output.append(f"<p class=step>{inline(re.sub(r'^\d+\.\s+', '', line))}</p>")
        else:
            close_list()
            output.append(f"<p>{inline(line)}</p>")
    close_list()
    if in_table:
        output.append("</tbody></table>")
    if in_code:
        output.append("</pre>")
    screenshot_html = ""
    if base_dir is not None:
        for image_path, description in _screenshot_paths(base_dir / "diagnostic_guide.md"):
            screenshot_html += (
                '<h2>Evidence screenshots</h2>'
                f'<p>{inline(description)}</p>'
                f'<img class="evidence-image" src="{html.escape(image_path.as_uri())}" />'
            )
    if screenshot_html:
        output.append(screenshot_html)
    return """<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>%s</title>
<style>
@page { size: A4; margin: 18mm 16mm 18mm 16mm; @bottom-right { content: counter(page); font-size: 9pt; color: #64748b; } }
body { font-family: "Malgun Gothic", "Noto Sans KR", Arial, sans-serif; color: #172033; font-size: 10.5pt; line-height: 1.55; }
h1 { color: #0f2f56; border-bottom: 2px solid #0f2f56; padding-bottom: 7px; margin-top: 0; }
h2 { color: #164e7a; border-bottom: 1px solid #cbd5e1; padding-bottom: 4px; margin-top: 22px; }
h3 { color: #1e5b85; margin-top: 16px; }
table { width: 100%%; border-collapse: collapse; margin: 10px 0 16px; font-size: 9pt; }
th { background: #e8f0f7; color: #123b5d; } th, td { border: 1px solid #b8c4d1; padding: 5px 6px; vertical-align: top; }
blockquote { border-left: 4px solid #6b9cc4; background: #f3f7fa; padding: 8px 12px; margin: 10px 0; }
code, pre { font-family: Consolas, "DejaVu Sans Mono", monospace; } code { background: #eef2f6; padding: 1px 3px; } pre { background: #f5f7fa; border: 1px solid #d5dde6; padding: 9px; white-space: pre-wrap; font-size: 8.5pt; }
li { margin: 3px 0; } .step { margin-left: 16px; }
.cover { text-align: center; margin: 35mm 0 20mm; } .cover h1 { border: 0; font-size: 26pt; } .cover p { color: #52657a; }
.evidence-image { max-width: 100%%; max-height: 220mm; display: block; margin: 8px auto; }
</style></head><body><div class="cover"><h1>RED RED</h1><p>Cortis Company Portal 보안 진단</p><p>%s</p></div>%s</body></html>""" % (html.escape(title), html.escape(title), "\n".join(output))


def _font_path() -> Path | None:
    windows_fonts = Path(os.environ["WINDIR"]) / "Fonts" if os.environ.get("WINDIR") else None
    candidates: list[Path] = []
    if windows_fonts:
        candidates.extend(windows_fonts / name for name in ("malgun.ttf", "malgunsl.ttf"))
    candidates.extend([
        Path("/usr/share/fonts/truetype/nanum/NanumGothic.ttf"),
        Path("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
    ])
    return next((path for path in candidates if path.exists()), None)


def _screenshot_paths(markdown_path: Path) -> Iterable[tuple[Path, str]]:
    review_path = markdown_path.parent / "review.json"
    if not review_path.exists():
        return ()
    try:
        review = json.loads(review_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ()
    found: list[tuple[Path, str]] = []
    for finding in review.get("findings", []) if isinstance(review, dict) else []:
        for evidence in finding.get("manual_evidence", []) if isinstance(finding, dict) else []:
            if not isinstance(evidence, dict) or evidence.get("type") != "screenshot":
                continue
            path = Path(str(evidence.get("file", "")))
            path = path if path.is_absolute() else markdown_path.parent / path
            if path.suffix.casefold() in {".png", ".jpg", ".jpeg"} and path.is_file():
                found.append((path.resolve(), str(evidence.get("description", ""))))
    return found


def _write_reportlab(markdown_path: Path, output_path: Path, title: str) -> None:
    """Render with ReportLab when WeasyPrint is unavailable."""

    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Image, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    font = _font_path()
    font_name = "Helvetica"
    if font and font.suffix.casefold() == ".ttf":
        pdfmetrics.registerFont(TTFont("REDREDFont", str(font)))
        font_name = "REDREDFont"
    styles = getSampleStyleSheet()
    body = ParagraphStyle("Body", parent=styles["BodyText"], fontName=font_name, fontSize=9.5, leading=14, spaceAfter=5)
    heading = ParagraphStyle("Heading", parent=styles["Heading1"], fontName=font_name, textColor=colors.HexColor("#123b5d"), spaceBefore=12, spaceAfter=7)
    subheading = ParagraphStyle("SubHeading", parent=styles["Heading2"], fontName=font_name, textColor=colors.HexColor("#1e5b85"), spaceBefore=9, spaceAfter=5)
    cover = ParagraphStyle("Cover", parent=styles["Title"], fontName=font_name, alignment=TA_CENTER, fontSize=22, leading=28, spaceAfter=15)
    story = [Spacer(1, 35 * mm), Paragraph("RED RED", cover), Paragraph("Cortis Company Portal 보안 진단", ParagraphStyle("CoverSub", parent=body, alignment=TA_CENTER)), Paragraph(title, ParagraphStyle("CoverTitle", parent=body, alignment=TA_CENTER)), Spacer(1, 18 * mm)]
    in_code = False
    code_lines: list[str] = []
    table_rows: list[list[str]] = []

    def flush_table() -> None:
        if not table_rows:
            return
        cells = [[Paragraph(html.escape(cell), body) for cell in row] for row in table_rows]
        table = Table(cells, repeatRows=1, hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8f0f7")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#b8c4d1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(table)
        table_rows.clear()

    for line in markdown_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("```"):
            if in_code:
                story.append(Preformatted("\n".join(code_lines), body))
                code_lines = []
            in_code = not in_code
            continue
        if in_code:
            code_lines.append(line)
            continue
        if line.startswith("|") and line.endswith("|"):
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if not all(set(cell) <= {"-", ":", " "} for cell in cells):
                table_rows.append(cells)
            continue
        flush_table()
        heading_match = re.match(r"^(#{1,3})\s+(.+)$", line)
        if heading_match:
            story.append(Paragraph(html.escape(heading_match.group(2)), heading if len(heading_match.group(1)) == 1 else subheading))
        elif line.startswith("- "):
            story.append(Paragraph("• " + html.escape(line[2:]), body))
        elif line.strip():
            text = html.escape(line).replace("**", "")
            story.append(Paragraph(text, body))
        else:
            story.append(Spacer(1, 3))
    flush_table()
    for image_path, description in _screenshot_paths(markdown_path):
        story.extend([Paragraph("증적 화면", subheading), Image(str(image_path), width=160 * mm, height=90 * mm), Paragraph(html.escape(description), body)])
    document = SimpleDocTemplate(str(output_path), pagesize=A4, rightMargin=16 * mm, leftMargin=16 * mm, topMargin=16 * mm, bottomMargin=16 * mm, title=title, author="RED RED")
    def add_page_number(canvas: object, doc: object) -> None:
        canvas.saveState()  # type: ignore[attr-defined]
        canvas.setFont(font_name, 8)  # type: ignore[attr-defined]
        canvas.drawRightString(A4[0] - 16 * mm, 8 * mm, str(getattr(doc, "page", "")))  # type: ignore[attr-defined]
        canvas.restoreState()  # type: ignore[attr-defined]

    document.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)


def _write_minimal_pdf(markdown_path: Path, output_path: Path, title: str) -> None:
    """Last-resort valid PDF so report generation never blocks Markdown output."""

    text = markdown_path.read_text(encoding="utf-8", errors="replace")
    ascii_lines = [re.sub(r"[^\x20-\x7e]", "?", line)[:110] for line in text.splitlines()][:180]
    content = "BT /F1 9 Tf 40 800 Td " + " ".join(f"({line.replace('\\\\', '\\\\\\\\').replace('(', '[').replace(')', ']')}) Tj 0 -12 Td" for line in ascii_lines) + " ET"
    objects = ["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", f"<< /Length {len(content.encode('latin-1'))} >>\nstream\n{content}\nendstream"]
    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(pdf))
        pdf.extend(f"{index} 0 obj\n{obj}\nendobj\n".encode("latin-1", errors="replace"))
    xref = len(pdf)
    pdf.extend(f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode())
    pdf.extend(f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    output_path.write_bytes(pdf)


def generate_pdf(markdown_path: str | Path, output_path: str | Path, report_type: str) -> Path:
    """Generate one PDF locally; raise only if all safe renderers fail."""

    source = Path(markdown_path).expanduser().resolve()
    destination = Path(output_path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    title = {"diagnostic": "Diagnostic Guide", "final": "Final Report", "secure_coding": "Secure Coding Guide"}.get(report_type, report_type)
    markdown = source.read_text(encoding="utf-8", errors="replace")
    try:
        from weasyprint import HTML  # type: ignore
        HTML(string=_markdown_to_html(markdown, title=title), base_url=str(source.parent)).write_pdf(str(destination))
    except Exception as weasy_error:
        LOGGER.debug("WeasyPrint unavailable: %s", weasy_error)
        try:
            _write_reportlab(source, destination, title)
        except Exception as reportlab_error:
            LOGGER.debug("ReportLab unavailable: %s", reportlab_error)
            _write_minimal_pdf(source, destination, title)
    if not destination.exists() or destination.stat().st_size < 100:
        raise RuntimeError(f"PDF renderer did not create a valid file: {destination}")
    return destination


__all__ = ["generate_pdf"]
