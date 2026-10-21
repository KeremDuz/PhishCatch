"""Keep candidate training writes separate from configured active artifacts."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from app.core.config import BACKEND_ROOT, settings


class UnsafeArtifactPath(ValueError):
    pass


def active_artifact_paths() -> set[Path]:
    values = [
        settings.ml_model_path,
        settings.html_model_path,
        settings.ml_scaler_path,
        str(BACKEND_ROOT / "phishcatch_url_model.pkl"),
        str(BACKEND_ROOT / "phishcatch_html_model.pkl"),
        str(BACKEND_ROOT / "models" / "phishcatch_url_model.pkl"),
        str(BACKEND_ROOT / "models" / "phishcatch_html_model.pkl"),
    ]
    protected: set[Path] = set()
    for value in values:
        if not value:
            continue
        configured = Path(value)
        candidates = [configured] if configured.is_absolute() else [Path.cwd() / configured, BACKEND_ROOT / configured]
        for candidate in candidates:
            resolved = candidate.resolve()
            protected.add(resolved)
            protected.add(resolved.with_suffix(".metadata.json"))
    return protected


def reject_linked_path(path: Path) -> None:
    for component in (path, *path.parents):
        if component.is_symlink() or component.is_junction():
            raise UnsafeArtifactPath("Training outputs must not use symbolic links or junctions")


def same_artifact(first: Path, second: Path) -> bool:
    return first == second or (first.exists() and second.exists() and first.samefile(second))


def validate_training_file(path: Path, *, new_candidate: bool = False) -> Path:
    absolute = path.absolute()
    reject_linked_path(absolute)
    resolved = absolute.resolve()
    if resolved.exists() and not resolved.is_file():
        raise UnsafeArtifactPath("Training output must name a regular file")
    for protected in active_artifact_paths():
        if same_artifact(resolved, protected) or protected in resolved.parents:
            raise UnsafeArtifactPath("Training cannot overwrite an active model, scaler, or metadata artifact")
        if new_candidate and resolved.parent == protected.parent:
            raise UnsafeArtifactPath("Candidate models must use a separate directory from active artifacts")
    if new_candidate and resolved.exists():
        raise UnsafeArtifactPath("Candidate output already exists; choose a new candidate filename")
    for parent in resolved.parents:
        if parent.exists() and not parent.is_dir():
            raise UnsafeArtifactPath("Training output parent must be a directory")
    return resolved


def validate_training_outputs(*paths: Path) -> None:
    for index, first in enumerate(paths):
        first_resolved = first.resolve()
        for second in paths[index + 1:]:
            second_resolved = second.resolve()
            if (same_artifact(first_resolved, second_resolved) or
                first_resolved in second_resolved.parents or
                second_resolved in first_resolved.parents):
                raise UnsafeArtifactPath("Candidate, metadata, dataset, and registry outputs must be distinct")


def atomic_registry_write(path: Path, content: str) -> None:
    target = validate_training_file(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=target.parent, prefix=".registry-", suffix=".tmp", delete=False) as file:
            temporary = Path(file.name)
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        # Recheck configuration and aliases after generating the new file.
        validate_training_file(target)
        temporary.replace(target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
