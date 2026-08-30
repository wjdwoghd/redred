"""Two-stage AI Scanner dashboard with swappable integration adapters."""

from __future__ import annotations

import streamlit as st

from adapters import ScannerAdapterError
from components.evidence import evidence_payload, render_evidence_review, review_payload
from components.findings import render_finding_detail, render_findings_table
from components.overview import render_charts, render_kpis, render_pipeline
from components.reports import render_reports
from services import create_scanner_service
from services.metrics import compute_dashboard_metrics
from settings import ScannerSettings


st.set_page_config(
    page_title="AI Scanner Dashboard",
    page_icon=":material/security:",
    layout="wide",
)


def initialize_state(settings: ScannerSettings) -> None:
    signature = (
        settings.mode,
        str(settings.mock_data_path),
        str(settings.results_dir),
        settings.cli_command,
        settings.api_base_url,
    )
    if st.session_state.get("service_signature") != signature:
        st.session_state.scanner_service = create_scanner_service(settings)
        st.session_state.service_signature = signature
        st.session_state.workflow_phase = "ready"
        st.session_state.scan_result = None
        st.session_state.session_reviews = {}
        st.session_state.session_evidence = []
        st.session_state.dashboard_error = None
    st.session_state.setdefault("workflow_phase", "ready")
    st.session_state.setdefault("scan_result", None)
    st.session_state.setdefault("session_reviews", {})
    st.session_state.setdefault("session_evidence", [])
    st.session_state.setdefault("dashboard_error", None)


settings = ScannerSettings.from_env()
initialize_state(settings)
service = st.session_state.scanner_service

st.logo(":material/security:", size="large")
with st.sidebar:
    st.markdown("### AI Scanner")
    st.badge(service.source_label, color="gray", icon=":material/database:")
    healthy, health_message = service.health_check()
    if healthy:
        st.success(health_message, icon=":material/check_circle:")
    else:
        st.warning(health_message, icon=":material/info:")
    st.caption("대시보드는 대상 서버나 외부 API를 임의로 호출하지 않습니다.")
    if st.button("세션 초기화", icon=":material/restart_alt:", width="stretch"):
        for key in ["workflow_phase", "scan_result", "session_reviews", "session_evidence", "dashboard_error"]:
            st.session_state.pop(key, None)
        st.rerun()

header, source = st.columns([4, 2], vertical_alignment="center")
header.title("AI Scanner 보안 진단", anchor=False)
with source:
    st.badge(service.source_label, color="gray", icon=":material/science:")
st.caption("1차 자동 스캔으로 후보를 만들고, 담당자 증적을 연결해 최종 위험도를 재판정합니다.")

target_url = st.text_input(
    "진단 대상 URL",
    value=settings.default_target_url,
    placeholder="http://example.local/login.php",
    disabled=st.session_state.workflow_phase == "reanalysis_completed",
)

has_review = bool(st.session_state.session_reviews)
has_evidence = bool(st.session_state.session_evidence)
can_reanalyze = st.session_state.scan_result is not None and has_review and has_evidence
first, second = st.columns(2)
with first:
    initial_clicked = st.button(
        "1차 자동 스캔 시작",
        type="primary",
        icon=":material/radar:",
        width="stretch",
    )
    if settings.mode == "filesystem":
        st.caption("로컬 조회 모드에서는 최신 active-scan-* 결과를 읽습니다.")
with second:
    reanalysis_clicked = st.button(
        "증적 반영 재분석 실행",
        icon=":material/replay:",
        width="stretch",
        disabled=not can_reanalyze,
    )
    if not can_reanalyze:
        st.caption("1차 결과, 담당자 검토 메모, 증적 파일이 모두 필요합니다.")

if initial_clicked:
    try:
        with st.spinner("1차 결과를 준비하고 있습니다..."):
            st.session_state.scan_result = service.run_initial_scan(target_url)
        st.session_state.workflow_phase = "initial_completed"
        st.session_state.session_reviews = {}
        st.session_state.session_evidence = []
        st.session_state.dashboard_error = None
        st.rerun()
    except (ScannerAdapterError, ValueError) as exc:
        st.session_state.dashboard_error = str(exc)

if reanalysis_clicked:
    try:
        scan_id = st.session_state.scan_result.scan_id
        with st.spinner("검토 의견과 증적을 반영하고 있습니다..."):
            service.submit_review(scan_id, review_payload(), evidence_payload())
            st.session_state.scan_result = service.run_reanalysis(scan_id)
        st.session_state.workflow_phase = "reanalysis_completed"
        st.session_state.dashboard_error = None
        st.rerun()
    except (ScannerAdapterError, ValueError) as exc:
        st.session_state.dashboard_error = str(exc)

if st.session_state.dashboard_error:
    st.error(st.session_state.dashboard_error, icon=":material/error:")

render_pipeline(st.session_state.workflow_phase)
scan = st.session_state.scan_result
if scan is None:
    st.info("진단 대상 URL을 확인한 뒤 1차 자동 스캔을 시작하세요.", icon=":material/touch_app:")
    st.stop()

metrics = compute_dashboard_metrics(scan, len(st.session_state.session_evidence))
render_kpis(metrics, st.session_state.workflow_phase)
render_charts(scan, st.session_state.workflow_phase)

selected = render_findings_table(scan.findings)
if selected:
    render_finding_detail(selected)

st.subheader("검토와 산출물", anchor=False)
review_column, report_column = st.columns([1.15, 0.85], vertical_alignment="top")
with review_column:
    render_evidence_review(scan.findings, settings.max_upload_mb)
with report_column:
    render_reports(service, scan)

st.caption("PDF 화면은 설계 참고 자료로만 사용했으며, 대시보드 데이터로 파싱하지 않습니다.")
