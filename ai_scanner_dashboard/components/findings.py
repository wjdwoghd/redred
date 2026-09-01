"""Finding list and concise detail panel."""

from __future__ import annotations

import streamlit as st

from components.evidence import _is_real_evidence
from models import Finding
from services.evidence_downloads import downloadable_evidence, evidence_mime_type
from services.metrics import effective_severity, findings_frame, review_status_label


SEVERITY_COLORS = {"CRITICAL": "red", "HIGH": "orange", "MEDIUM": "yellow", "LOW": "gray", "UNKNOWN": "gray"}


def render_findings_table(findings: list[Finding]) -> Finding | None:
    st.subheader("취약점 후보", anchor=False)
    if not findings:
        st.info("탐지된 취약점 후보가 없습니다.", icon=":material/search_off:")
        return None

    types = sorted({item.vulnerability_type for item in findings})
    with st.popover("필터", icon=":material/filter_list:"):
        selected_types = st.multiselect("취약점 유형", types, default=types)
        evidence_only = st.checkbox("증적이 연결된 항목만")
    filtered = [item for item in findings if item.vulnerability_type in selected_types]
    if evidence_only:
        filtered = [item for item in filtered if any(_is_real_evidence(ev) for ev in item.evidence)]
    if not filtered:
        st.caption("필터 조건에 맞는 항목이 없습니다.")
        return None

    event = st.dataframe(
        findings_frame(filtered),
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        key="finding_table",
        height=300,
        column_config={
            "신뢰도": st.column_config.ProgressColumn(min_value=0, max_value=1, format="percent"),
            "증적": st.column_config.NumberColumn(format="%d개"),
        },
    )
    rows = event.selection.rows
    return filtered[rows[0]] if rows else filtered[0]


def render_finding_detail(finding: Finding) -> None:
    with st.container(border=True):
        title, badge = st.columns([4, 1], vertical_alignment="center")
        title.markdown(f"### {finding.finding_id} · {finding.vulnerability_type}")
        st.caption("담당자 추가 발견" if finding.finding_id.upper().startswith("NF-") or finding.scanner_status.upper() == "MANUAL" else "자동 탐지")
        severity = effective_severity(finding)
        with badge:
            st.badge(severity, color=SEVERITY_COLORS.get(severity, "gray"))

        cols = st.columns(4)
        cols[0].metric("URI", finding.uri)
        cols[1].metric("Method", finding.http_method or "-")
        cols[2].metric("Parameter", finding.parameter or "-")
        cols[3].metric("신뢰도", f"{finding.confidence:.0%}" if finding.confidence is not None else "-")

        summary_tab, evidence_tab, action_tab = st.tabs(["판정 요약", "요청·응답 / 증적", "분류 및 대응"])
        with summary_tab:
            if finding.ai_diagnostic_summary:
                st.info(finding.ai_diagnostic_summary, icon=":material/psychology:")
            if finding.recommended_verification:
                st.markdown("**AI recommended verification**")
                for recommendation in finding.recommended_verification:
                    st.markdown(f"- {recommendation}")
            st.write(finding.summary or finding.scanner_judgment or "스캐너 요약이 없습니다.")
            st.markdown(f"**스캐너 상태** · {finding.scanner_status}")
            st.markdown(f"**담당자 검토** · {review_status_label(finding.review_status)}")
            if finding.reviewer_memo:
                st.markdown(f"**검토 메모** · {finding.reviewer_memo}")
            if finding.final_judgment:
                st.markdown(f"**최종 판정** · {finding.final_judgment}")
            policy = finding.policy_reference
            if policy:
                st.markdown("#### 진단 기준 참고")
                st.markdown(f"- 기준 출처: {policy.get('policy_source', '-')}")
                item_name = policy.get("policy_item_name", "-")
                item_number = policy.get("policy_item_number")
                item_label = f"{item_number}. {item_name}" if item_number else str(item_name)
                st.markdown(f"- 관련 항목: {item_label}")
                st.markdown(f"- 점검 목적: {policy.get('inspection_purpose', '-')}")
                criteria = policy.get("inspection_criteria") or []
                if criteria:
                    st.markdown("- 점검 기준:")
                    for criterion in criteria:
                        st.markdown(f"  - {criterion}")
                mapping = policy.get("indicator_mapping") or {}
                if mapping:
                    st.markdown("- Scanner Indicator 매핑:")
                    for indicator, explanation in mapping.items():
                        st.markdown(f"  - `{indicator}`: {explanation}")
        with evidence_tab:
            st.markdown("**Request**")
            st.code(finding.request_summary or "요청 요약 없음", language=None, wrap_lines=True)
            st.markdown("**Response**")
            if finding.rules_evidence:
                st.markdown("**Rules / HTTP evidence**")
                st.json(finding.rules_evidence, expanded=False)
            st.code(finding.response_summary or "응답 요약 없음", language=None, wrap_lines=True)
            if finding.baseline_comparison:
                st.json(finding.baseline_comparison, expanded=False)
            real_evidence = [item for item in finding.evidence if _is_real_evidence(item)]
            if real_evidence:
                st.dataframe(
                    [{"파일명": item.filename, "유형": item.evidence_type, "설명": item.description or "-"} for item in real_evidence],
                    hide_index=True,
                )
                for index, (evidence, content) in enumerate(downloadable_evidence(finding)):
                    filename = evidence.filename or f"evidence-{index + 1}"
                    st.download_button(
                        f"증적 다운로드: {filename}",
                        data=content,
                        file_name=filename,
                        mime=evidence_mime_type(evidence),
                        key=f"finding-evidence-{finding.finding_id}-{index}-{evidence.evidence_id or filename}",
                        icon=":material/download:",
                    )
            else:
                st.caption("연결된 증적이 없습니다.")
        with action_tab:
            cols = st.columns(3)
            cols[0].metric("CWE", finding.cwe or "-")
            cols[1].metric("OWASP", finding.owasp_category or "-")
            cols[2].metric("CVSS", f"{finding.cvss:.1f}" if finding.cvss is not None else "-")
            st.markdown(f"**영향** · {finding.impact or '정보 없음'}")
            st.markdown(f"**권장 대응** · {finding.remediation or '정보 없음'}")
            if finding.secure_coding:
                st.info(finding.secure_coding, icon=":material/code:")
