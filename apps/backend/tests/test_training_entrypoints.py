from __future__ import annotations

import importlib
import sys

import joblib
import pandas as pd
import pytest


@pytest.mark.parametrize("module_name", ["train_model", "train_html_model"])
@pytest.mark.parametrize("output_mode", ["default", "active", "candidate", "symlink"])
def test_retired_trainers_never_fit_read_or_write_artifacts(
    module_name, output_mode, tmp_path, monkeypatch, capsys
):
    module = importlib.import_module(module_name)
    active = tmp_path / "custom-active-model.pkl"
    metadata = tmp_path / "custom-active-model.metadata.json"
    active.write_bytes(b"active-model-sentinel")
    metadata.write_text("active-metadata-sentinel", encoding="utf-8")
    monkeypatch.setenv("ML_MODEL_PATH", str(active))
    monkeypatch.setenv("HTML_MODEL_PATH", str(active))
    output = active
    if output_mode == "candidate":
        output = tmp_path / "candidate.pkl"
    elif output_mode == "symlink":
        output = tmp_path / "candidate-alias.pkl"
        try:
            output.symlink_to(active)
        except OSError:
            pytest.skip("Symlinks require privileges on this Windows installation")

    def forbidden(*args, **kwargs):
        pytest.fail("Retired trainers must not read datasets, fit, or write artifacts")

    monkeypatch.setattr(pd, "read_csv", forbidden)
    monkeypatch.setattr(joblib, "dump", forbidden)
    if module_name == "train_model":
        monkeypatch.setattr(module, "build_model", forbidden)
    else:
        monkeypatch.setattr(module, "parse_mendeley_index", forbidden)
        monkeypatch.setattr(module, "build_training_model", forbidden)

    arguments = [f"{module_name}.py"]
    if output_mode != "default":
        arguments += ["--model-output", str(output)]
        if module_name == "train_html_model":
            arguments += ["--metadata-output", str(metadata)]
    monkeypatch.setattr(sys, "argv", arguments)
    assert module.main() == 2
    message = capsys.readouterr().err
    assert "scripts/retrain_models.py" in message
    assert "scripts/promote_candidate_models.py" in message
    assert active.read_bytes() == b"active-model-sentinel"
    assert metadata.read_text(encoding="utf-8") == "active-metadata-sentinel"
    if output_mode == "candidate":
        assert not output.exists()


def test_safe_retrainer_retains_html_builders():
    from scripts.retrain_models import build_html_model, build_sample_weights

    assert callable(build_html_model)
    weights, class_weights = build_sample_weights(pd.Series([0, 0, 1]), "balanced")
    assert weights is not None
    assert set(class_weights) == {0, 1}


@pytest.mark.parametrize("module_name", ["train_model", "train_html_model"])
def test_retired_entrypoint_help_explains_migration(module_name, monkeypatch, capsys):
    module = importlib.import_module(module_name)
    monkeypatch.setattr(sys, "argv", [f"{module_name}.py", "--help"])
    with pytest.raises(SystemExit) as result:
        module.main()
    assert result.value.code == 0
    assert "scripts/retrain_models.py" in capsys.readouterr().out
