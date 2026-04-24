# Artifact Strategy

This repo should keep source code, tests, configuration examples, and small docs in Git. Large datasets, trained models, generated benchmark outputs, virtual environments, IDE state, and local app scaffolds should stay outside Git unless there is a deliberate release process for them.

## Local Only

Keep these local and ignored:

- `apps/backend/Mendeley_dataset/`
- `apps/backend/phishcatch_*.pkl`
- `apps/backend/phishcatch_training_data_*.csv`
- `apps/backend/feed_*_results.csv`
- `.venv/`
- `apps/flutter_app/` while it remains an ignored local scaffold

## Dataset

The raw Mendeley dataset is too large for normal Git. Treat it as a reproducible local input:

1. Download/extract it outside Git or under the ignored `apps/backend/Mendeley_dataset/` path.
2. Regenerate feature CSVs with `python feature_extractor.py`.
3. Do not commit raw HTML dataset parts or generated feature CSVs.

## Model Artifacts

Preferred model packaging is a single sklearn pipeline artifact:

- `ML_MODEL_PATH=phishcatch_url_model.pkl`
- `ML_SCALER_PATH=` left empty
- `feature_schema=url_lexical_v1`

Use `apps/backend/model_manifest.example.json` as the template for published model metadata.

Temporary compatibility mode for old split artifacts is still supported:

- `ML_MODEL_PATH=phishcatch_rf_model_48.pkl`
- `ML_SCALER_PATH=phishcatch_scaler_48.pkl`

If a model needs to be shared, publish it as a release artifact, DVC artifact, Git LFS object, or object-storage download. Do not commit large `.pkl` files directly.

## Generated CSVs

Generated CSV files can be deleted when disk space is tight if the source dataset is still available. They are rebuild outputs, not source of truth.

## Removed Noise

The old `.github/java-upgrade/` output and tracked `.vscode/settings.json` were unrelated to this Python/Flutter project and should not return to Git. Local editor settings can stay private under ignored `.vscode/`.
