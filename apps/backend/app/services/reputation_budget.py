"""Shared bounded lookup allowance for one analysis, including provider threads."""

from __future__ import annotations

import time
from _thread import LockType
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from threading import Lock

from app.models.schemas import StageResult
from app.services.worker_process import WorkerFailure


@dataclass
class LookupBudget:
    remaining_seconds: float = 10.0
    remaining_calls: int = 6
    lock: LockType = field(default_factory=Lock)
    domain_results: dict[str, tuple[float, StageResult]] = field(default_factory=dict)

    @contextmanager
    def call(self) -> Iterator[float]:
        # Calls consume a shared allowance, including time spent in quota I/O.
        # The same object is propagated to provider threads by copy_context.
        with self.lock:
            if self.remaining_calls <= 0 or self.remaining_seconds < 0.05:
                raise WorkerFailure("lookup_scan_budget_exhausted")
            self.remaining_calls -= 1
            started = time.monotonic()
            try:
                yield min(6.0, self.remaining_seconds)
            finally:
                self.remaining_seconds -= time.monotonic() - started


_budget: ContextVar[LookupBudget | None] = ContextVar("reputation_budget", default=None)


@contextmanager
def lookup_session() -> Iterator[None]:
    token = _budget.set(LookupBudget())
    try:
        yield
    finally:
        _budget.reset(token)
