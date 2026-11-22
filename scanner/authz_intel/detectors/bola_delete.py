from __future__ import annotations

from ..config import ScannerConfig
from ..reporting import Finding


class DeleteBOLADetector:
    def run(self, config: ScannerConfig) -> list[Finding]:
        if not config.allow_destructive_tests:
            return []
        raise NotImplementedError(
            "Destructive tests require an explicitly designated disposable resource"
        )
