from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = PROJECT_ROOT / "scripts"


def main() -> int:
    args = parse_args()

    commands = [
        [
            sys.executable,
            str(SCRIPT_DIR / "export_training_datasets.py"),
            "--db-path",
            str(args.db_path),
            "--output-dir",
            str(args.dataset_dir),
        ],
        [
            sys.executable,
            str(SCRIPT_DIR / "retrain_models.py"),
            "--dataset-dir",
            str(args.dataset_dir),
            "--model-dir",
            str(args.model_dir),
            "--registry-path",
            str(args.registry_path),
            "--min-samples",
            str(args.min_samples),
            "--test-size",
            str(args.test_size),
            "--threshold",
            str(args.threshold),
        ],
    ]

    if args.include_unapproved:
        commands[0].append("--include-unapproved")

    if args.promote:
        promote_command = [
            sys.executable,
            str(SCRIPT_DIR / "promote_candidate_models.py"),
            "--registry-path",
            str(args.registry_path),
            "--min-rows",
            str(args.min_rows),
            "--min-precision",
            str(args.min_precision),
            "--min-recall",
            str(args.min_recall),
            "--min-f1",
            str(args.min_f1),
        ]
        if args.dry_run_promotion:
            promote_command.append("--dry-run")
        commands.append(promote_command)

    for command in commands:
        print(f"\n$ {' '.join(command)}", flush=True)
        completed = subprocess.run(command, cwd=PROJECT_ROOT, check=False)
        if completed.returncode != 0:
            return completed.returncode

    print("\nTraining cycle finished", flush=True)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run export -> retrain -> optional safe promotion as one training job.")
    parser.add_argument("--db-path", type=Path, default=PROJECT_ROOT / "data" / "phishcatch_training.sqlite3")
    parser.add_argument("--dataset-dir", type=Path, default=PROJECT_ROOT / "generated")
    parser.add_argument("--model-dir", type=Path, default=PROJECT_ROOT / "models" / "candidates")
    parser.add_argument("--registry-path", type=Path, default=PROJECT_ROOT / "models" / "registry.json")
    parser.add_argument("--include-unapproved", action="store_true")
    parser.add_argument("--min-samples", type=int, default=20)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--promote", action="store_true", help="Run safe promotion after retraining.")
    parser.add_argument("--dry-run-promotion", action="store_true", help="Evaluate promotion gates without copying models.")
    parser.add_argument("--min-rows", type=int, default=20)
    parser.add_argument("--min-precision", type=float, default=0.8)
    parser.add_argument("--min-recall", type=float, default=0.6)
    parser.add_argument("--min-f1", type=float, default=0.7)
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(main())
