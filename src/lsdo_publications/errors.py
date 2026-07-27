from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class PublicationError(Exception):
    code: str
    message: str
    retryable: bool = False

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


VALIDATION_EXIT = 2
PROVIDER_EXIT = 3
INTERNAL_EXIT = 4
