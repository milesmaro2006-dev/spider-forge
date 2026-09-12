from __future__ import annotations


class SpiderForgeError(Exception):
    """Base exception for all SpiderForge errors."""


class ScopeViolation(SpiderForgeError):
    """Raised when an outbound request targets an out-of-scope host."""


class ReconError(SpiderForgeError):
    """Recon-specific failure."""


class FetchError(SpiderForgeError):
    """A URL could not be fetched."""