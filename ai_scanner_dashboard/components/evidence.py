"""Session-only reviewer input and evidence upload UI."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

import streamlit as st

from models import Evidence, Finding


ALLOWED_SUFFIXES = {".png", ".jpg", ".jpeg", ".txt", ".log", ".json", ".pdf"}


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


def render_evidence_review(findings: list[Finding], max_upload_mb: int) -> None:
    with st.container(border=True):
        st.markdown("**담당자 검토 및 증적**")
        st.caption("등록 내용은 현재 브라우저 세션 메모리에만 보관되며 서버 파일로 저장되지 않습니다.")
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
        review_status = st.selectbox(
            "담당자 판단",
            ["verified", "false_positive", "reanalysis_required"],
            index=["verified", "false_positive", "reanalysis_required"].index(
                existing.get("review_status", "verified")
            ),
            format_func={
                "verified": "취약점 확인",
                "false_positive": "오탐/제외",
                "reanalysis_required": "재분석 필요",
            }.get,
            key=f"review_status_{selected_id}",
        )
        reviewer_memo = st.text_area(
            "검토 메모",
            value=existing.get("reviewer_memo", ""),
            placeholder="재현 여부와 확인 근거를 간단히 기록하세요.",
            key=f"review_memo_{selected_id}",
        )
        if st.button("검토 의견 저장", icon=":material/save:", width="stretch"):
            if reviewer_memo.strip():
                st.session_state.session_reviews[selected_id] = {
                    "finding_id": selected_id,
                    "review_status": review_status,
                    "reviewer_memo": reviewer_memo.strip(),
                }
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
                    )
                    st.session_state.session_evidence.append({"evidence": evidence, "content": content})
                    added += 1
                if added:
                    st.toast(f"증적 {added}개를 현재 세션에 등록했습니다.")
                    st.rerun()

        if st.session_state.session_evidence:
            st.dataframe(
                [
                    {
                        "취약점": item["evidence"].finding_id,
                        "파일명": item["evidence"].filename,
                        "유형": item["evidence"].evidence_type,
                        "크기": item["evidence"].size_bytes,
                    }
                    for item in st.session_state.session_evidence
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
    return [item["evidence"] for item in st.session_state.get("session_evidence", [])]
