"""Report availability and safe download controls."""

from __future__ import annotations

import streamlit as st

from models import ScanResult
from services import ScannerService
from services.evidence_downloads import build_evidence_zip


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
                if report_type == "diagnostic_guide" and hasattr(st, "pdf"):
                    try:
                        with st.expander("Diagnostic guide preview", expanded=False):
                            st.pdf(download.content)
                    except Exception:
                        # Preview support depends on the installed Streamlit
                        # version/browser; download remains available.
                        pass
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

        # Keep the evidence bundle aligned with Scanner finalize: only
        # CONFIRMED and NEW_FINDING records are included. This is a read-only
        # Dashboard download and never changes the original evidence files.
        evidence_zip = build_evidence_zip(scan.findings)
        if evidence_zip:
            st.download_button(
                "\uc804\uccb4 \uac80\uc99d \uc99d\uc801 \ub2e4\uc6b4\ub85c\ub4dc (.zip)",
                data=evidence_zip,
                file_name="evidence_bundle.zip",
                mime="application/zip",
                icon=":material/folder_zip:",
                width="stretch",
                key=f"evidence-bundle-{scan.scan_id}",
            )
        else:
            st.button(
                "\uc804\uccb4 \uac80\uc99d \uc99d\uc801 \ub2e4\uc6b4\ub85c\ub4dc (.zip) \u00b7 \ud30c\uc77c \uc5c6\uc74c",
                icon=":material/folder_zip:",
                disabled=True,
                width="stretch",
                key=f"missing-evidence-bundle-{scan.scan_id}",
            )
