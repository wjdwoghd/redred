"""Session-only reviewer input and evidence upload UI."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping

import streamlit as st

from models import Evidence, Finding


ALLOWED_SUFFIXES = {".png", ".jpg", ".jpeg", ".txt", ".log", ".json", ".pdf"}


def _is_real_evidence(evidence: Evidence) -> bool:
    """Whether this item is backed by a real file or uploaded bytes."""
    filename = (evidence.filename or "").strip()
    if not filename or filename.casefold() in {"unnamed", "none"}:
        return False
    if evidence.content is not None:
        return True
    return bool(evidence.local_path and Path(evidence.local_path).is_file())


def _is_real_session_item(item: object) -> bool:
    """Apply the same filter to a session wrapper (which may hold bytes)."""
    if not isinstance(item, dict) or not isinstance(item.get("evidence"), Evidence):
        return False
    evidence = item["evidence"]
    if not _is_real_evidence(evidence):
        return item.get("content") is not None and bool((evidence.filename or "").strip())
    return True


def _validate_upload(filename: str, content: bytes, max_upload_mb: int) -> str | None:
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        return "PNG, JPG, TXT, LOG, JSON, PDF 파일만 등록할 수 있습니다."
    if len(content) > max_upload_mb * 1024 * 1024:
        return f"파일당 최대 크기는 {max_upload_mb}MB입니다."
    if suffix == ".json":
        try:
            json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return "JSON 파일 형식이 올바르지 않습니다."
    return None


def render_manual_finding_form(
    add_callback: Callable[[Mapping[str, str]], Mapping[str, Any]] | None,
) -> None:
    """Render the small reviewer-only form for a NEW_FINDING record."""
    with st.expander("+ 새 취약점 추가", expanded=False):
        if add_callback is None:
            st.info("현재 연결 방식에서는 수동 Finding 추가를 지원하지 않습니다.")
            return
        vuln_type = st.selectbox(
            "취약점 유형",
            ["SQL_INJECTION", "XSS", "FILE_UPLOAD", "OTHER"],
            format_func=lambda value: {
                "SQL_INJECTION": "SQL Injection",
                "XSS": "XSS",
                "FILE_UPLOAD": "File Upload",
                "OTHER": "기타",
            }.get(value, value),
            key="manual_finding_type",
        )
        uri = st.text_input("URI", key="manual_finding_uri", placeholder="/REDRED/example.php")
        method = st.selectbox("Method", ["GET", "POST", "PUT", "PATCH", "DELETE"], key="manual_finding_method")
        parameter = st.text_input("Parameter", key="manual_finding_parameter")
        severity = st.selectbox("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], index=2, key="manual_finding_severity")
        note = st.text_area("검토 메모", key="manual_finding_note")
        if st.button("수동 Finding 생성", type="primary", key="create_manual_finding"):
            if not uri.strip():
                st.error("URI를 입력해 주세요.")
                return
            try:
                record = add_callback(
                    {
                        "type": vuln_type,
                        "uri": uri.strip(),
                        "method": method,
                        "parameter": parameter.strip(),
                        "severity": severity,
                        "reviewer_note": note.strip(),
                    }
                )
                finding_id = str(record.get("id"))
                st.session_state.session_reviews[finding_id] = {
                    "finding_id": finding_id,
                    "review_status": "NEW_FINDING",
                    "reviewer_note": note.strip(),
                    "reviewer_memo": note.strip(),
                }
                st.session_state.flash_success = f"수동 Finding {finding_id}이(가) 저장되었습니다."
                st.rerun()
            except Exception as exc:
                st.error(f"수동 Finding 저장에 실패했습니다: {exc}")


def render_evidence_review(
    findings: list[Finding],
    max_upload_mb: int,
    persist_callback: Callable[[], None] | None = None,
    add_finding_callback: Callable[[Mapping[str, str]], Mapping[str, Any]] | None = None,
) -> None:
    with st.container(border=True):
        st.markdown("**담당자 검토 및 증적**")
        st.caption("등록 내용은 현재 브라우저 세션 메모리에만 보관되며 서버 파일로 저장되지 않습니다.")
        render_manual_finding_form(add_finding_callback)
        if not findings:
            st.caption("먼저 1차 자동 스캔을 실행하세요.")
            return

        finding_ids = [item.finding_id for item in findings]
        selected_id = st.selectbox(
            "검토할 취약점",
            finding_ids,
            format_func=lambda value: next(
                f"{item.finding_id} · {item.vulnerability_type}" for item in findings if item.finding_id == value
            ),
            key="review_finding_id",
        )
        existing = st.session_state.session_reviews.get(selected_id, {})
        is_manual_finding = selected_id.upper().startswith("NF-")
        status_options = ["CONFIRMED", "FALSE_POSITIVE", "PENDING"]
        if is_manual_finding:
            status_options.append("NEW_FINDING")
        current_status = str(existing.get("review_status", "PENDING")).upper()
        current_status = {"VERIFIED": "CONFIRMED", "REANALYSIS_REQUIRED": "PENDING"}.get(current_status, current_status)
        if current_status not in status_options:
            current_status = "PENDING"
        review_status = st.selectbox(
            "담당자 판단",
            status_options,
            index=status_options.index(current_status),
            format_func={
                "CONFIRMED": "CONFIRMED",
                "FALSE_POSITIVE": "FALSE_POSITIVE",
                "PENDING": "PENDING",
                "NEW_FINDING": "NEW_FINDING",
                "verified": "취약점 확인",
                "false_positive": "오탐/제외",
                "reanalysis_required": "재분석 필요",
            }.get,
            key=f"review_status_{selected_id}",
        )
        reviewer_memo = st.text_area(
            "검토 메모",
            value=existing.get("reviewer_note", existing.get("reviewer_memo", "")),
            placeholder="재현 여부와 확인 근거를 간단히 기록하세요.",
            key=f"review_memo_{selected_id}",
        )
        if st.button("검토 의견 저장", icon=":material/save:", width="stretch"):
            # A review state is meaningful even when the reviewer has not
            # entered a note yet; do not leave the finding stuck at PENDING.
            if review_status in status_options:
                st.session_state.session_reviews[selected_id] = {
                    "finding_id": selected_id,
                    "review_status": review_status,
                    "reviewer_note": reviewer_memo.strip(),
                    "reviewer_memo": reviewer_memo.strip(),
                }
                if persist_callback:
                    try:
                        persist_callback()
                        st.session_state.flash_success = "검토 의견이 저장되었습니다."
                    except Exception as exc:
                        st.session_state.flash_error = f"검토 의견 저장에 실패했습니다: {exc}"
                st.toast("검토 의견을 현재 세션에 저장했습니다.")
                st.rerun()
            else:
                st.warning("검토 메모를 입력해 주세요.")

        uploads = st.file_uploader(
            "증적 파일",
            type=["png", "jpg", "jpeg", "txt", "log", "json", "pdf"],
            accept_multiple_files=True,
            key=f"evidence_upload_{selected_id}",
            help=f"파일당 최대 {max_upload_mb}MB · 업로드만 하며 실행하지 않습니다.",
        )
        description = st.text_input(
            "증적 설명",
            placeholder="예: 정상 요청과 공격 요청의 응답 비교",
            key=f"evidence_description_{selected_id}",
        )
        if st.button("증적 등록", icon=":material/attach_file:", width="stretch"):
            if not uploads:
                st.warning("등록할 증적 파일을 선택해 주세요.")
            else:
                added = 0
                for uploaded in uploads:
                    content = uploaded.getvalue()
                    error = _validate_upload(uploaded.name, content, max_upload_mb)
                    if error:
                        st.error(f"{Path(uploaded.name).name}: {error}")
                        continue
                    digest = hashlib.sha256(content).hexdigest()[:12]
                    evidence_id = f"session-{selected_id}-{digest}"
                    if any(item["evidence"].evidence_id == evidence_id for item in st.session_state.session_evidence):
                        continue
                    evidence = Evidence(
                        evidence_id=evidence_id,
                        finding_id=selected_id,
                        evidence_type=Path(uploaded.name).suffix.lower().lstrip("."),
                        filename=Path(uploaded.name).name,
                        description=description.strip() or None,
                        uploaded_at=datetime.now().astimezone(),
                        mime_type=uploaded.type,
                        size_bytes=len(content),
                        content=content,
                    )
                    st.session_state.session_evidence.append({"evidence": evidence, "content": content})
                    added += 1
                if added:
                    if persist_callback:
                        try:
                            persist_callback()
                            st.session_state.flash_success = "증적 파일이 등록되었습니다."
                        except Exception as exc:
                            st.session_state.flash_error = f"증적 파일 등록에 실패했습니다: {exc}"
                    st.toast(f"증적 {added}개를 현재 세션에 등록했습니다.")
                    st.rerun()

        show_all = st.checkbox("전체 증적 보기", value=False, key="show_all_evidence")
        visible_evidence = [
            item
            for item in st.session_state.session_evidence
            if isinstance(item, dict)
            and _is_real_session_item(item)
            and (show_all or item["evidence"].finding_id == selected_id)
        ]
        if visible_evidence:
            st.dataframe(
                [
                    {
                        "취약점": item["evidence"].finding_id,
                        "파일명": item["evidence"].filename,
                        "유형": item["evidence"].evidence_type,
                        "크기": item["evidence"].size_bytes,
                    }
                    for item in visible_evidence
                ],
                hide_index=True,
                height=180,
                column_config={"크기": st.column_config.NumberColumn(format="%d bytes")},
            )
        else:
            st.caption("현재 세션에 등록된 증적이 없습니다.")


def review_payload() -> list[dict[str, str]]:
    return list(st.session_state.get("session_reviews", {}).values())


def evidence_payload() -> list[Evidence]:
    return [
        item["evidence"]
        for item in st.session_state.get("session_evidence", [])
        if isinstance(item, dict)
        and _is_real_session_item(item)
    ]
