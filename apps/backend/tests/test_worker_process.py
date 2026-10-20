from __future__ import annotations

import json
import subprocess
import sys

import pytest
from app.services.page_fetch import PageArtifact
from app.services.worker_process import (
    MAX_WIRE_BYTES,
    WorkerFailure,
    bounded_process,
    run_worker,
)


def test_worker_does_not_inherit_server_credentials(monkeypatch):
    monkeypatch.setenv("ALLSAFE_INTEGRATION_KEY", "private-test-credential")
    monkeypatch.setenv("TRAINING_ADMIN_TOKEN", "private-test-token")
    output = bounded_process(
        [
            sys.executable,
            "-I",
            "-c",
            "import os,json; print(json.dumps(sorted(os.environ)))",
        ],
        b"",
        10,
    )
    names = json.loads(output)
    assert "ALLSAFE_INTEGRATION_KEY" not in names
    assert "TRAINING_ADMIN_TOKEN" not in names


def test_timeout_kills_and_reaps_the_actual_child(monkeypatch):
    real_popen = subprocess.Popen
    children = []

    def capture(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", capture)
    with pytest.raises(WorkerFailure, match="worker_timeout"):
        bounded_process(
            [sys.executable, "-I", "-c", "import time; time.sleep(60)"], b"", 0.3
        )
    assert len(children) == 1
    assert children[0].poll() is not None


def test_excess_output_is_not_loaded_as_an_analysis_result():
    with pytest.raises(WorkerFailure, match="worker_output_limit"):
        bounded_process(
            [
                sys.executable,
                "-I",
                "-c",
                f"import sys; sys.stdout.buffer.write(b'x'*{MAX_WIRE_BYTES + 1})",
            ],
            b"",
            10,
        )


def test_html_worker_uses_only_the_supplied_artifact_without_network():
    page = PageArtifact(
        "https://example.com/",
        "https://example.com/",
        200,
        "text/html",
        b"<html><title>Example</title><p>Ordinary static content</p></html>",
        (),
        "2026-10-20T00:00:00+00:00",
    )
    result = run_worker(
        "html", {"page": page.to_wire(), "model_path": None}, timeout=20
    )
    assert "error" not in result
    assert result["stage"]["status"] == "completed"
    assert result["stage"]["details"]["html_model"]["available"] is False
    assert result["training_features"]["html_features"]


def test_corrupt_worker_body_is_rejected():
    page = PageArtifact(
        "https://example.com/",
        "https://example.com/",
        200,
        "text/html",
        b"hello",
        (),
        "2026-10-20T00:00:00+00:00",
    )
    data = page.to_wire()
    data["body"] = "eA=="
    with pytest.raises(ValueError):
        PageArtifact.from_wire(data)
