from __future__ import annotations

import argparse
import json
import hashlib
import math
import os
import shutil
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.ml.artifact_paths import (
    UnsafeArtifactPath,
    atomic_registry_write,
    reject_linked_path,
    validate_training_file,
    validate_training_outputs,
)
from app.core.config import settings

DEFAULT_REGISTRY_PATH = PROJECT_ROOT / "models" / "registry.json"
DEFAULT_BACKUP_DIR = PROJECT_ROOT / "models" / "backups"
DEFAULT_ACTIVE_MODELS = {
    "url": PROJECT_ROOT / "phishcatch_url_model.pkl",
    "html": PROJECT_ROOT / "phishcatch_html_model.pkl",
}


def main() -> int:
    args = parse_args()
    validate_training_file(args.registry_path)
    validate_training_outputs(
        args.registry_path, args.active_url_model, args.active_url_model.with_suffix(".metadata.json"),
        args.active_html_model, args.active_html_model.with_suffix(".metadata.json"),
    )
    registry = read_registry(args.registry_path)
    latest_run = registry.get("latest_run") or {}
    models = latest_run.get("models") or {}
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    selected = ("url", "html") if args.model == "both" else (args.model,)
    promotions: dict[str, Any] = {}

    for model_name in selected:
        result = evaluate_and_promote(
            model_name=model_name,
            model_result=models.get(model_name),
            active_path=active_path_for(model_name, args),
            backup_dir=args.backup_dir,
            timestamp=timestamp,
            dry_run=args.dry_run,
            force=args.force,
            no_backup=args.no_backup,
            min_rows=args.min_rows,
            min_precision=args.min_precision,
            min_recall=args.min_recall,
            min_f1=args.min_f1,
        )
        promotions[model_name] = result
        print_status(model_name.upper(), result)

    registry["updated_at"] = datetime.now(timezone.utc).isoformat()
    registry.setdefault("promotion_history", []).append(
        {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "dry_run": args.dry_run,
            "force": args.force,
            "models": promotions,
        }
    )
    active = registry.setdefault("active", {})
    for model_name, result in promotions.items():
        if result["status"] == "promoted":
            active[model_name] = {
                "promoted_at": result["promoted_at"],
                "active_model_path": result["active_model_path"],
                "active_metadata_path": result.get("active_metadata_path"),
                "candidate_model_path": result["candidate_model_path"],
                "validation": result["validation"],
            }

    if not args.dry_run:
        args.registry_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_registry_write(args.registry_path, json.dumps(registry, indent=2))

    return 1 if any(result["status"] == "rejected" for result in promotions.values()) else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Promote retrained candidate models after metric gates pass.")
    parser.add_argument("--registry-path", type=Path, default=DEFAULT_REGISTRY_PATH)
    parser.add_argument("--model", choices=("url", "html", "both"), default="both")
    parser.add_argument("--active-url-model", type=Path, default=Path(settings.ml_model_path) if settings.ml_model_path else DEFAULT_ACTIVE_MODELS["url"])
    parser.add_argument("--active-html-model", type=Path, default=Path(settings.html_model_path) if settings.html_model_path else DEFAULT_ACTIVE_MODELS["html"])
    parser.add_argument("--backup-dir", type=Path, default=DEFAULT_BACKUP_DIR)
    parser.add_argument("--min-rows", type=int, default=500, help="Minimum holdout rows, not total training rows.")
    parser.add_argument("--min-precision", type=float, default=0.98)
    parser.add_argument("--min-recall", type=float, default=0.90)
    parser.add_argument("--min-f1", type=float, default=0.94)
    parser.add_argument("--dry-run", action="store_true", help="Evaluate gates without copying active model files.")
    parser.add_argument("--force", action="store_true", help="Deprecated; cannot bypass evaluation gates.")
    parser.add_argument("--no-backup", action="store_true", help="Overwrite active model files without creating backups.")
    return parser.parse_args()


def read_registry(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"Registry not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def active_path_for(model_name: str, args: argparse.Namespace) -> Path:
    if model_name == "url":
        return args.active_url_model
    if model_name == "html":
        return args.active_html_model
    raise ValueError(f"Unknown model name: {model_name}")


def evaluate_and_promote(
    *,
    model_name: str,
    model_result: dict[str, Any] | None,
    active_path: Path,
    backup_dir: Path,
    timestamp: str,
    dry_run: bool,
    force: bool,
    no_backup: bool,
    min_rows: int,
    min_precision: float,
    min_recall: float,
    min_f1: float,
) -> dict[str, Any]:
    if not model_result:
        return rejected("Candidate not found in registry")
    if model_result.get("status") != "trained":
        return rejected(f"Candidate status is {model_result.get('status')!r}")

    candidate_path = Path(str(model_result.get("model_path") or ""))
    if not candidate_path.exists():
        return rejected(f"Candidate model file not found: {candidate_path}")

    gate_reasons = gate_failures(
        model_result,
        min_rows=min_rows,
        min_precision=min_precision,
        min_recall=min_recall,
        min_f1=min_f1,
    )
    proof = (model_result.get("validation") or {}).get("evaluation") or {}
    if proof.get("model_sha256") != hashlib.sha256(candidate_path.read_bytes()).hexdigest():
        gate_reasons.append("Candidate hash does not match evaluated model")
    if gate_reasons:
        return {
            "status": "rejected",
            "reason": "; ".join(gate_reasons),
            "candidate_model_path": str(candidate_path),
            "validation": model_result.get("validation") or {},
        }

    metadata_path = Path(str(model_result.get("metadata_path") or candidate_path.with_suffix(".metadata.json")))
    active_metadata_path = active_path.with_suffix(".metadata.json")
    try:
        # Reject every alias before backups or either active artifact is touched.
        paths = [candidate_path, active_path, active_metadata_path]
        if metadata_path.exists():
            paths.append(metadata_path)
        for path in paths:
            reject_linked_path(path.absolute())
        validate_training_outputs(*paths)
        if not candidate_path.is_file() or (metadata_path.exists() and not metadata_path.is_file()):
            raise UnsafeArtifactPath("Promotion inputs must be regular files")
    except (OSError, UnsafeArtifactPath) as exc:
        return rejected(str(exc))
    result = {
        "status": "promoted" if not dry_run else "would_promote",
        "promoted_at": datetime.now(timezone.utc).isoformat(),
        "candidate_model_path": str(candidate_path),
        "active_model_path": str(active_path),
        "validation": model_result.get("validation") or {},
        "forced": force,
        "gate_failures": gate_reasons,
    }

    if dry_run:
        return result

    active_path.parent.mkdir(parents=True, exist_ok=True)
    backup_model = backup_existing(active_path, backup_dir, model_name, timestamp, no_backup)
    if backup_model:
        result["backup_model_path"] = str(backup_model)

    copy_atomic(candidate_path, active_path)

    if metadata_path.exists():
        backup_metadata = backup_existing(active_metadata_path, backup_dir, f"{model_name}_metadata", timestamp, no_backup)
        if backup_metadata:
            result["backup_metadata_path"] = str(backup_metadata)
        copy_atomic(metadata_path, active_metadata_path)
        result["active_metadata_path"] = str(active_metadata_path)

    return result


def gate_failures(
    model_result: dict[str, Any],
    *,
    min_rows: int,
    min_precision: float,
    min_recall: float,
    min_f1: float,
) -> list[str]:
    failures: list[str] = []
    validation = model_result.get("validation") or {}
    proof = validation.get("evaluation") or {}
    row_count = int(proof.get("test_rows") or 0)
    precision = float(validation.get("precision") or 0.0)
    recall = float(validation.get("recall") or 0.0)
    f1 = float(validation.get("f1") or 0.0)

    if proof.get("strategy") != "grouped-temporal-v1" or proof.get("verified_labels") is not True or proof.get("refit_on_holdout") is not False:
        failures.append("Independent grouped temporal holdout required")
    if any(proof.get(key) != 0 for key in ("domain_overlap", "template_overlap", "feature_overlap")):
        failures.append("Overlapping or unverified evaluation cohorts")
    if int(proof.get("test_unique_domains") or 0) < 100:
        failures.append("Holdout needs at least 100 distinct domain groups")
    if proof.get("threshold") != 0.5:
        failures.append("Evaluation threshold must match the 0.5 model decision threshold")
    for key in ("dataset_sha256", "model_sha256", "test_identity_sha256"):
        value = proof.get(key)
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            failures.append(f"Missing {key}")
    counts = validation.get("test_label_counts") or {}
    if int(counts.get("0", counts.get(0, 0))) < 300 or int(counts.get("1", counts.get(1, 0))) < 100:
        failures.append("Holdout needs at least 300 clean and 100 phishing samples")
    fpr = float(validation.get("false_positive_rate", 1))
    fpr_upper = float(validation.get("false_positive_rate_upper_95", 1))
    if not all(math.isfinite(value) and 0 <= value <= 1 for value in (precision, recall, f1, fpr, fpr_upper)):
        failures.append("Invalid evaluation metrics")
    if fpr > 0.01 or fpr_upper > 0.02:
        failures.append("False positive rate exceeds 1% or its 95% upper bound exceeds 2%")

    if row_count < max(500, min_rows):
        failures.append(f"row_count {row_count} < min_rows {min_rows}")
    if precision < max(0.98, min_precision):
        failures.append(f"precision {precision} < min_precision {min_precision}")
    if recall < max(0.90, min_recall):
        failures.append(f"recall {recall} < min_recall {min_recall}")
    if f1 < max(0.94, min_f1):
        failures.append(f"f1 {f1} < min_f1 {min_f1}")
    return failures


def backup_existing(
    path: Path,
    backup_dir: Path,
    model_name: str,
    timestamp: str,
    no_backup: bool,
) -> Path | None:
    if no_backup or not path.exists():
        return None

    reject_linked_path(backup_dir.absolute())
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_path = backup_dir / f"{model_name}_{timestamp}{path.suffix}"
    copy_atomic(path, backup_path, overwrite=False)
    return backup_path


def copy_atomic(source: Path, target: Path, *, overwrite: bool = True) -> None:
    reject_linked_path(source.absolute())
    reject_linked_path(target.absolute())
    validate_training_outputs(source, target)
    if not source.is_file() or (target.exists() and not target.is_file()):
        raise UnsafeArtifactPath("Promotion requires regular source and target files")
    if not overwrite and target.exists():
        raise UnsafeArtifactPath("Backup already exists; choose a new timestamp")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=target.parent, prefix=f".{target.name}.", suffix=".tmp", delete=False) as output:
            temporary = Path(output.name)
            with source.open("rb") as input_file:
                shutil.copyfileobj(input_file, output)
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(stat.S_IMODE(source.stat().st_mode))
        reject_linked_path(target.absolute())
        validate_training_outputs(source, target)
        if overwrite:
            temporary.replace(target)
        else:
            # Backups are immutable. Atomic link creation fails if another
            # process has already claimed the destination; never truncate it.
            os.link(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def rejected(reason: str) -> dict[str, Any]:
    return {"status": "rejected", "reason": reason}


def print_status(label: str, result: dict[str, Any]) -> None:
    status = result["status"]
    if status in {"promoted", "would_promote"}:
        print(f"{label}: {status} -> {result['active_model_path']}")
        if result.get("gate_failures"):
            print(f"{label}: forced despite gates: {'; '.join(result['gate_failures'])}")
        return

    print(f"{label}: rejected ({result['reason']})")


if __name__ == "__main__":
    raise SystemExit(main())
