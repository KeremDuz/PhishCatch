from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import numpy as np
import pandas as pd
from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.utils.validation import check_is_fitted


@dataclass(frozen=True)
class IncrementalModelConfig:
    alpha: float = 0.0001
    epochs: int = 8
    batch_size: int = 512
    random_state: int = 42


class IncrementalBinaryClassifier:
    """A small sklearn-compatible binary classifier with real partial_fit support."""

    def __init__(
        self,
        feature_names: list[str] | None = None,
        *,
        alpha: float = 0.0001,
        epochs: int = 8,
        batch_size: int = 512,
        random_state: int = 42,
    ) -> None:
        self.feature_names_in_ = np.array(feature_names or [], dtype=object)
        self.config = IncrementalModelConfig(
            alpha=alpha,
            epochs=epochs,
            batch_size=batch_size,
            random_state=random_state,
        )
        self.classes_ = np.array([0, 1], dtype=int)
        self.scaler = StandardScaler()
        self.classifier = self._new_classifier()
        self.n_features_in_: int | None = len(feature_names) if feature_names else None
        self.seen_samples_ = 0

    def fit(
        self,
        features: pd.DataFrame | Iterable[Iterable[float]],
        labels: pd.Series | Iterable[int],
        sample_weight: pd.Series | Iterable[float] | None = None,
    ) -> "IncrementalBinaryClassifier":
        frame = self._feature_frame(features)
        label_array = self._label_array(labels)
        weight_array = self._weight_array(sample_weight)

        self.scaler = StandardScaler()
        self.classifier = self._new_classifier()
        self.seen_samples_ = 0

        self._partial_fit_scaler(frame, weight_array)
        indices = np.arange(len(frame))
        rng = np.random.default_rng(self.config.random_state)

        for _ in range(max(1, self.config.epochs)):
            shuffled = indices.copy()
            rng.shuffle(shuffled)
            for start in range(0, len(shuffled), max(1, self.config.batch_size)):
                batch_indices = shuffled[start : start + max(1, self.config.batch_size)]
                self._partial_fit_classifier(
                    frame.iloc[batch_indices],
                    label_array[batch_indices],
                    weight_array[batch_indices] if weight_array is not None else None,
                )

        self.seen_samples_ = int(len(frame))
        return self

    def partial_fit(
        self,
        features: pd.DataFrame | Iterable[Iterable[float]],
        labels: pd.Series | Iterable[int],
        sample_weight: pd.Series | Iterable[float] | None = None,
    ) -> "IncrementalBinaryClassifier":
        frame = self._feature_frame(features)
        label_array = self._label_array(labels)
        weight_array = self._weight_array(sample_weight)

        self._partial_fit_scaler(frame, weight_array)
        self._partial_fit_classifier(frame, label_array, weight_array)
        self.seen_samples_ += int(len(frame))
        return self

    def predict_proba(self, features: pd.DataFrame | Iterable[Iterable[float]]) -> np.ndarray:
        check_is_fitted(self.classifier)
        frame = self._feature_frame(features)
        transformed = self.scaler.transform(frame)
        return self.classifier.predict_proba(transformed)

    def predict(self, features: pd.DataFrame | Iterable[Iterable[float]]) -> np.ndarray:
        return (self.predict_proba(features)[:, 1] >= 0.5).astype(int)

    def _new_classifier(self) -> SGDClassifier:
        return SGDClassifier(
            loss="log_loss",
            penalty="l2",
            alpha=self.config.alpha,
            random_state=self.config.random_state,
            average=True,
        )

    def _feature_frame(self, features: pd.DataFrame | Iterable[Iterable[float]]) -> pd.DataFrame:
        frame = features.copy() if isinstance(features, pd.DataFrame) else pd.DataFrame(features)

        if len(self.feature_names_in_) == 0:
            self.feature_names_in_ = np.array([str(column) for column in frame.columns], dtype=object)

        feature_names = [str(name) for name in self.feature_names_in_]
        missing = [name for name in feature_names if name not in frame.columns]
        if missing:
            raise ValueError(f"Missing feature columns: {missing[:5]}")

        frame = frame.reindex(columns=feature_names).fillna(0.0).astype(float)
        self.n_features_in_ = int(frame.shape[1])
        return frame

    @staticmethod
    def _label_array(labels: pd.Series | Iterable[int]) -> np.ndarray:
        return np.asarray(list(labels) if not isinstance(labels, pd.Series) else labels.to_list(), dtype=int)

    @staticmethod
    def _weight_array(sample_weight: pd.Series | Iterable[float] | None) -> np.ndarray | None:
        if sample_weight is None:
            return None
        values = sample_weight.to_list() if isinstance(sample_weight, pd.Series) else list(sample_weight)
        return np.asarray(values, dtype=float)

    def _partial_fit_scaler(self, frame: pd.DataFrame, sample_weight: np.ndarray | None) -> None:
        try:
            self.scaler.partial_fit(frame, sample_weight=sample_weight)
        except TypeError:
            self.scaler.partial_fit(frame)

    def _partial_fit_classifier(
        self,
        frame: pd.DataFrame,
        labels: np.ndarray,
        sample_weight: np.ndarray | None,
    ) -> None:
        transformed = self.scaler.transform(frame)
        self.classifier.partial_fit(
            transformed,
            labels,
            classes=self.classes_,
            sample_weight=sample_weight,
        )
