from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import settings
from app.storage import TrainingStore


def main() -> int:
    store = TrainingStore(settings.training_db_path)
    store.init_db()
    counts = store.table_counts()

    print("Training DB initialized")
    print(f"Path: {store.db_path}")
    print(f"url_observations: {counts['url_observations']}")
    print(f"training_samples: {counts['training_samples']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
