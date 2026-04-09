from abc import ABC, abstractmethod

from app.models.schemas import StageResult


class BaseScanner(ABC):
    def __init__(self, name: str) -> None:
        self.name = name

    @abstractmethod
    def scan(self, url: str) -> StageResult:
        """Analyze URL and return a standardized stage result."""

    def should_halt(self, result: StageResult) -> bool:
        """Default chain rule: stop only when URL is malicious."""
        return result.verdict == "malicious"
