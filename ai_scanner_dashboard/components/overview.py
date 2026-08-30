"""Workflow, KPI, and chart components."""

from __future__ import annotations

import altair as alt
import streamlit as st

from models import ScanResult
from services.metrics import (
    DashboardMetrics,
    category_counts,
    severity_comparison,
    severity_counts,
)


WORKFLOW = ["데이터 생성", "수집", "연결", "분석", "시각화"]
SEVERITY_DOMAIN = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEVERITY_RANGE = ["#B42318", "#E05D37", "#D4A72C", "#667085", "#98A2B3"]


def render_pipeline(phase: str) -> None:
    st.subheader("진단 데이터 흐름", anchor=False)
    completed = 5 if phase in {"initial_completed", "reanalysis_completed"} else 0
    columns = st.columns(5)
    for index, (column, label) in enumerate(zip(columns, WORKFLOW, strict=True), start=1):
        with column:
            icon = ":material/check_circle:" if index <= completed else ":material/radio_button_unchecked:"
            st.metric(f"{index}. {label}", "완료" if index <= completed else "대기", border=True)
            st.caption(icon)


def render_kpis(metrics: DashboardMetrics, phase: str) -> None:
    st.subheader("핵심 지표", anchor=False)
    values = [
        ("스캔 페이지", metrics.scanned_pages),
        ("취약점 후보", metrics.total_findings),
        ("검토 완료", metrics.reviewed_findings),
        ("오탐/제외", metrics.false_positives),
        ("Critical / High", metrics.critical_high),
        ("연결 증적", metrics.evidence_count),
    ]
    for column, (label, value) in zip(st.columns(6), values, strict=True):
        column.metric(label, value, border=True)
    if phase == "initial_completed":
        st.info("1차 결과는 취약점 후보입니다. 담당자 검토와 증적을 추가한 뒤 재분석하세요.", icon=":material/fact_check:")
    elif phase == "reanalysis_completed":
        st.success("증적이 반영된 재분석 결과입니다.", icon=":material/task_alt:")


def render_charts(scan: ScanResult, phase: str) -> None:
    st.subheader("취약점 분석", anchor=False)
    left, right = st.columns(2)
    categories = category_counts(scan.findings)
    severities = severity_counts(scan.findings)
    with left.container(border=True):
        st.markdown("**취약점 유형별 탐지**")
        if categories.empty:
            st.caption("표시할 탐지 결과가 없습니다.")
        else:
            chart = alt.Chart(categories).mark_bar(cornerRadiusEnd=4).encode(
                x=alt.X("탐지 건수:Q", title=None, axis=alt.Axis(tickMinStep=1)),
                y=alt.Y("취약점 유형:N", title=None, sort="-x"),
                tooltip=["취약점 유형:N", "탐지 건수:Q"],
            ).properties(height=230)
            st.altair_chart(chart)
    with right.container(border=True):
        st.markdown("**현재 위험도 분포**")
        chart = alt.Chart(severities).mark_bar(cornerRadiusEnd=4).encode(
            x=alt.X("위험도:N", title=None, sort=SEVERITY_DOMAIN),
            y=alt.Y("탐지 건수:Q", title=None, axis=alt.Axis(tickMinStep=1)),
            color=alt.Color("위험도:N", scale=alt.Scale(domain=SEVERITY_DOMAIN, range=SEVERITY_RANGE), legend=None),
            tooltip=["위험도:N", "탐지 건수:Q"],
        ).properties(height=230)
        st.altair_chart(chart)

    if phase == "reanalysis_completed":
        with st.container(border=True):
            st.markdown("**1차 판정과 최종 판정 비교**")
            comparison = severity_comparison(scan.findings)
            chart = alt.Chart(comparison).mark_bar(cornerRadiusEnd=3).encode(
                x=alt.X("위험도:N", title=None, sort=SEVERITY_DOMAIN),
                y=alt.Y("탐지 건수:Q", title=None, axis=alt.Axis(tickMinStep=1)),
                xOffset="판정 시점:N",
                color=alt.Color("판정 시점:N", title=None),
                tooltip=["위험도:N", "판정 시점:N", "탐지 건수:Q"],
            ).properties(height=230)
            st.altair_chart(chart)
