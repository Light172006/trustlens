"""Integration client for the TrustLens Web Security Analyzer Engine."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("trustlens.integrations.web_security")


def _get_analyzer_class() -> Any:
    """Helper to lazily resolve WebSecurityAnalyzer class with type suppression."""
    from analyzer.engine import WebSecurityAnalyzer  # type: ignore

    return WebSecurityAnalyzer


class WebSecurityClient:
    """Client for invoking the TrustLens Web Security Analyzer.

    Mediates between the backend API/worker layers and the WebSecurityAnalyzer engine.
    Safely executes URL validation, live passive telemetry extraction, deterministic rule auditing,
    ML posture prediction, and risk aggregation.
    """

    def __init__(self) -> None:
        self._analyzer: Any | None = None
        self._config_path: Path | None = None
        self._init_analyzer()

    def _init_analyzer(self) -> None:
        """Locate configuration and instantiate the WebSecurityAnalyzer."""
        try:
            repo_root = Path(__file__).resolve().parent.parent.parent.parent
            candidate_config = repo_root / "intelligence" / "web_security_analysis" / "config.yaml"
            if candidate_config.exists():
                self._config_path = candidate_config

            analyzer_cls = _get_analyzer_class()

            if self._config_path:
                self._analyzer = analyzer_cls.from_config(str(self._config_path))
            else:
                self._analyzer = analyzer_cls.from_config()

            logger.info("WebSecurityAnalyzer engine initialized successfully.")
        except Exception as exc:
            logger.warning(f"WebSecurityAnalyzer engine initialization deferred: {exc}")
            self._analyzer = None

    def _ensure_analyzer(self) -> Any:
        """Ensure analyzer instance is available, re-initializing if necessary."""
        if self._analyzer is None:
            self._init_analyzer()
            if self._analyzer is None:
                analyzer_cls = _get_analyzer_class()
                self._analyzer = analyzer_cls.from_config()
        return self._analyzer

    async def analyze_async(self, target_url: str) -> Any:
        """Asynchronously analyze a target website URL and produce a verified security report."""
        try:
            analyzer = self._ensure_analyzer()
            return await analyzer.analyze_async(target_url)
        except Exception as exc:
            logger.exception(f"Web security analysis failed for '{target_url}': {exc}")
            # Fallback error report via analyzer helper
            try:
                import datetime

                analyzer_cls = _get_analyzer_class()
                scan_time = datetime.datetime.now(datetime.UTC).isoformat()
                temp_analyzer = analyzer_cls()
                return temp_analyzer._build_error_report(
                    target_url, f"Analyzer execution failure: {exc}", scan_time
                )
            except Exception:
                raise exc

    def analyze(self, target_url: str) -> Any:
        """Synchronously analyze a target website URL."""
        analyzer = self._ensure_analyzer()
        return analyzer.analyze(target_url)


web_security_client = WebSecurityClient()
