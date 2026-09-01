"""Tests for traversal-safe, validated artifact persistence."""

from __future__ import annotations

import json

import pytest

from result_store import ResultStore, ResultStoreError


def test_result_store_writes_expected_files(tmp_path) -> None:
    store = ResultStore(tmp_path)
    paths = store.save_all(
        scan_id="scan-test-001",
        scan_input={"request": {"url": "http://192.168.94.128/"}},
        analysis={"analysis_summary": {"finding_count": 0}},
        report_markdown="# report\n",
    )

    assert json.loads(paths.input_json.read_text(encoding="utf-8"))["request"]
    assert json.loads(paths.analysis_json.read_text(encoding="utf-8"))[
        "analysis_summary"
    ]["finding_count"] == 0
    assert paths.report_markdown.read_text(encoding="utf-8") == "# report\n"


@pytest.mark.parametrize("scan_id", ["../escape", "scan-../../escape", "bad", "scan-/root"])
def test_result_store_rejects_unsafe_scan_id(tmp_path, scan_id: str) -> None:
    with pytest.raises(ResultStoreError):
        ResultStore(tmp_path).paths_for(scan_id)

