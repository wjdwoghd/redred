"""Report availability and safe download controls."""

from __future__ import annotations

import streamlit as st

from models import ScanResult
from services import ScannerService


REPORTS = [
    ("diagnostic_guide", "1차 취약점 진단 가이드"),
    ("final_report", "최종 모의해킹 보고서"),
    ("secure_coding_guide", "시큐어코딩 가이드"),
]


def render_reports(service: ScannerService, scan: ScanResult) -> None:
    with st.container(border=True):
        st.markdown("**보고서 산출물**")
        st.caption("실제 PDF 파일이 존재할 때만 다운로드할 수 있습니다.")
        for report_type, label in REPORTS:
            download = service.get_report_download(scan.scan_id, report_type)
            if download:
                st.download_button(
                    label,
                    data=download.content,
                    file_name=download.filename,
                    mime=download.mime_type,
                    icon=":material/download:",
                    width="stretch",
                    key=f"download_{report_type}",
                )
            else:
                st.button(
                    f"{label} · 파일 없음",
                    icon=":material/description:",
                    disabled=True,
                    width="stretch",
                    key=f"missing_{report_type}",
                )
