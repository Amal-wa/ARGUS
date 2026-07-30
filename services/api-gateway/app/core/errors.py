from __future__ import annotations


class OpaUnavailableError(RuntimeError):
    pass


class ScoringUnavailableError(RuntimeError):
    pass


class MfaAlreadyEnrolledError(RuntimeError):
    pass
