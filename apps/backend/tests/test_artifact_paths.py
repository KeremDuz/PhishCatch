from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core.config import settings
from app.ml.artifact_paths import (
    UnsafeArtifactPath,
    atomic_registry_write,
    validate_training_file,
    validate_training_outputs,
)
from scripts import promote_candidate_models as promote
from scripts import retrain_models as retrain


@pytest.fixture
def active_artifacts(tmp_path, monkeypatch):
    active_dir = tmp_path / "active"
    active_dir.mkdir()
    paths = [active_dir / name for name in ("url.pkl", "html.pkl", "scaler.pkl")]
    for path in paths:
        path.write_bytes(b"active-artifact")
        path.with_suffix(".metadata.json").write_bytes(b"active-metadata")
    monkeypatch.setattr(settings, "ml_model_path", str(paths[0]))
    monkeypatch.setattr(settings, "html_model_path", str(paths[1]))
    monkeypatch.setattr(settings, "ml_scaler_path", str(paths[2]))
    return paths


@pytest.mark.parametrize("artifact_index", range(3))
@pytest.mark.parametrize("metadata", [False, True])
def test_configured_active_model_scaler_and_metadata_cannot_be_training_outputs(
    active_artifacts, artifact_index, metadata
):
    target = active_artifacts[artifact_index]
    if metadata:
        target = target.with_suffix(".metadata.json")
    original = target.read_bytes()
    with pytest.raises(UnsafeArtifactPath, match="active"):
        validate_training_file(target)
    with pytest.raises(UnsafeArtifactPath):
        atomic_registry_write(target, "replacement")
    assert target.read_bytes() == original


def test_candidates_use_separate_directory_and_never_overwrite_existing_candidate(
    active_artifacts, tmp_path
):
    with pytest.raises(UnsafeArtifactPath, match="separate directory"):
        validate_training_file(active_artifacts[0].parent / "candidate.pkl", new_candidate=True)
    candidate = tmp_path / "generated" / "candidates" / "new.pkl"
    assert validate_training_file(candidate, new_candidate=True) == candidate.resolve()
    candidate.parent.mkdir(parents=True)
    candidate.write_bytes(b"evaluated-candidate")
    with pytest.raises(UnsafeArtifactPath, match="already exists"):
        validate_training_file(candidate, new_candidate=True)
    assert candidate.read_bytes() == b"evaluated-candidate"


@pytest.mark.parametrize("alias_kind", ["symlink", "hardlink", "directory_symlink"])
def test_candidate_and_registry_aliases_to_active_artifacts_are_rejected(
    active_artifacts, tmp_path, alias_kind
):
    alias = tmp_path / "alias"
    try:
        if alias_kind == "directory_symlink":
            alias.symlink_to(active_artifacts[0].parent, target_is_directory=True)
            alias = alias / "url.pkl"
        elif alias_kind == "symlink":
            alias.symlink_to(active_artifacts[0])
        else:
            alias.hardlink_to(active_artifacts[0])
    except OSError:
        pytest.skip("This filesystem or Windows account does not support the alias")
    with pytest.raises(UnsafeArtifactPath):
        validate_training_file(alias)
    assert active_artifacts[0].read_bytes() == b"active-artifact"


def test_relative_configured_active_paths_are_resolved_against_runtime_directory(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(settings, "ml_model_path", "custom/url.pkl")
    target = tmp_path / "custom" / "url.pkl"
    with pytest.raises(UnsafeArtifactPath, match="active"):
        validate_training_file(target)


def test_output_files_must_not_alias_or_contain_each_other(tmp_path):
    first = tmp_path / "candidate.pkl"
    with pytest.raises(UnsafeArtifactPath, match="distinct"):
        validate_training_outputs(first, first)
    with pytest.raises(UnsafeArtifactPath, match="distinct"):
        validate_training_outputs(first, first / "registry.json")


def test_retrain_rejects_registry_alias_before_export_or_training(
    active_artifacts, tmp_path, monkeypatch
):
    args = SimpleNamespace(
        model_dir=tmp_path / "generated" / "candidates",
        registry_path=active_artifacts[0], export_first=True,
    )
    monkeypatch.setattr(retrain, "parse_args", lambda: args)

    def forbidden(*args, **kwargs):
        pytest.fail("Unsafe output must be rejected before export or model fitting")

    monkeypatch.setattr(retrain, "export_training_datasets", forbidden)
    monkeypatch.setattr(retrain, "train_candidate", forbidden)
    with pytest.raises(UnsafeArtifactPath):
        retrain.main()
    assert active_artifacts[0].read_bytes() == b"active-artifact"
    assert not args.model_dir.exists()


def test_direct_train_candidate_rejects_active_output_before_reading_dataset(
    active_artifacts, tmp_path, monkeypatch
):
    monkeypatch.setattr(retrain.pd, "read_csv", lambda *a, **k: pytest.fail("Must not read dataset"))
    with pytest.raises(UnsafeArtifactPath):
        retrain.train_candidate(
            name="url", dataset_path=tmp_path / "missing.csv", feature_columns=["x"],
            build_model=lambda: pytest.fail("Must not fit"), model_path=active_artifacts[0],
            min_samples=20, test_size=0.2, threshold=0.5, seed=42,
        )
    assert active_artifacts[0].read_bytes() == b"active-artifact"


def test_atomic_registry_write_keeps_active_artifacts_and_cleans_temporary_files(
    active_artifacts, tmp_path
):
    registry = active_artifacts[0].parent / "registry.json"
    atomic_registry_write(registry, '{"run":1}')
    atomic_registry_write(registry, '{"run":2}')
    assert registry.read_text(encoding="utf-8") == '{"run":2}'
    assert active_artifacts[0].read_bytes() == b"active-artifact"
    assert list(registry.parent.glob(".registry-*.tmp")) == []


def passing_candidate(path: Path, metadata_path: Path | None = None) -> dict[str, object]:
    proof = {
        "strategy": "grouped-temporal-v1", "verified_labels": True, "refit_on_holdout": False,
        "domain_overlap": 0, "template_overlap": 0, "feature_overlap": 0,
        "test_unique_domains": 100, "threshold": 0.5, "test_rows": 500,
        "dataset_sha256": "a" * 64, "test_identity_sha256": "b" * 64,
        "model_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    result = {"status": "trained", "model_path": str(path), "validation": {
        "evaluation": proof, "precision": 1, "recall": 1, "f1": 1,
        "test_label_counts": {0: 300, 1: 200}, "false_positive_rate": 0,
        "false_positive_rate_upper_95": 0.01,
    }}
    if metadata_path is not None:
        result["metadata_path"] = str(metadata_path)
    return result


def promote_fixture(candidate, active, backup_dir):
    return promote.evaluate_and_promote(
        model_name="url", model_result=candidate, active_path=active, backup_dir=backup_dir,
        timestamp="fixture", dry_run=False, force=False, no_backup=False,
        min_rows=500, min_precision=0.98, min_recall=0.9, min_f1=0.94,
    )


@pytest.mark.parametrize("alias_kind", ["candidate", "metadata", "metadata_symlink", "hardlink"])
def test_promotion_rejects_aliases_before_touching_either_active_artifact(
    tmp_path, alias_kind
):
    active = tmp_path / "active.pkl"
    active_metadata = active.with_suffix(".metadata.json")
    active.write_bytes(b"active-before")
    active_metadata.write_bytes(b"metadata-before")
    candidate = tmp_path / "candidate.pkl"
    candidate.write_bytes(b"candidate-after")
    metadata = None
    if alias_kind == "candidate":
        candidate = active
    elif alias_kind == "metadata":
        metadata = active
    elif alias_kind == "metadata_symlink":
        metadata = tmp_path / "candidate.metadata.json"
        try:
            metadata.symlink_to(active_metadata)
        except OSError:
            pytest.skip("Symlinks unavailable")
    else:
        candidate.unlink()
        try:
            candidate.hardlink_to(active)
        except OSError:
            pytest.skip("Hard links unavailable")
    result = promote_fixture(passing_candidate(candidate, metadata), active, tmp_path / "backups")
    assert result["status"] == "rejected"
    assert active.read_bytes() == b"active-before"
    assert active_metadata.read_bytes() == b"metadata-before"
    assert not (tmp_path / "backups").exists()


def test_atomic_promotion_ignores_old_predictable_temp_symlink(tmp_path):
    source, target, victim = [tmp_path / name for name in ("source.pkl", "active.pkl", "victim.pkl")]
    source.write_bytes(b"candidate")
    target.write_bytes(b"old-active")
    victim.write_bytes(b"must-remain")
    old_temporary = target.with_name(f"{target.name}.tmp")
    try:
        old_temporary.symlink_to(victim)
    except OSError:
        pytest.skip("Symlinks unavailable")
    promote.copy_atomic(source, target)
    assert target.read_bytes() == b"candidate"
    assert victim.read_bytes() == b"must-remain"
    assert old_temporary.is_symlink()
    assert list(tmp_path.glob(".active.pkl.*.tmp")) == []


def test_atomic_promotion_failure_leaves_target_and_no_temporary_file(tmp_path, monkeypatch):
    source, target = tmp_path / "source.pkl", tmp_path / "active.pkl"
    source.write_bytes(b"candidate")
    target.write_bytes(b"old-active")

    def interrupted(*args):
        raise OSError("Controlled interrupted copy")

    monkeypatch.setattr(promote.shutil, "copyfileobj", interrupted)
    with pytest.raises(OSError):
        promote.copy_atomic(source, target)
    assert target.read_bytes() == b"old-active"
    assert list(tmp_path.glob(".active.pkl.*.tmp")) == []


def test_successful_promotion_preserves_immutable_backup(tmp_path):
    source, target = tmp_path / "candidate.pkl", tmp_path / "active.pkl"
    source.write_bytes(b"candidate")
    target.write_bytes(b"old-active")
    backups = tmp_path / "backups"
    result = promote_fixture(passing_candidate(source), target, backups)
    assert result["status"] == "promoted"
    assert target.read_bytes() == b"candidate"
    assert (backups / "url_fixture.pkl").read_bytes() == b"old-active"
    with pytest.raises(UnsafeArtifactPath, match="Backup already exists"):
        promote.backup_existing(target, backups, "url", "fixture", False)
    assert (backups / "url_fixture.pkl").read_bytes() == b"old-active"


def test_promotion_defaults_target_configured_runtime_models(active_artifacts, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["promote_candidate_models.py"])
    args = promote.parse_args()
    assert args.active_url_model == active_artifacts[0]
    assert args.active_html_model == active_artifacts[1]
