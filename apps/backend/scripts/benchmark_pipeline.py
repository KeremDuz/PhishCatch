"""Compatibility CLI; the packaged module also runs inside the analyzer image."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.ml.benchmark_cli import main as main
from app.ml.benchmark_cli import _write as _write

if __name__ == "__main__":
    raise SystemExit(main())
