"""安全组件：签名校验与防重放。"""

from .protection import install_replay_protection, make_signed_headers
from .replay import (
    AbstractClock,
    AbstractNonceStore,
    HmacKeyRing,
    InMemoryNonceStore,
    NonceConsumption,
    ReplayAuditEntry,
    ReplayAuditLog,
    ReplayError,
    ReplayGuard,
    ReplayRejectReason,
    ReplayResult,
    RequestCanonicalizer,
    Signer,
    SystemClock,
)


__all__ = (
    "AbstractClock",
    "AbstractNonceStore",
    "HmacKeyRing",
    "InMemoryNonceStore",
    "NonceConsumption",
    "ReplayAuditEntry",
    "ReplayAuditLog",
    "ReplayError",
    "ReplayGuard",
    "ReplayRejectReason",
    "ReplayResult",
    "RequestCanonicalizer",
    "Signer",
    "SystemClock",
    "install_replay_protection",
    "make_signed_headers",
)
