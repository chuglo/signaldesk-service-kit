"""Shared, stateless primitives for authenticated SignalDesk services."""

from .auth import (
    ServiceCredential,
    ServiceCredentialSet,
    ServicePrincipal,
    build_service_auth_dependency,
    verify_service_credential,
)
from .http import bounded_timeout

__all__ = [
    "ServiceCredential",
    "ServiceCredentialSet",
    "ServicePrincipal",
    "bounded_timeout",
    "build_service_auth_dependency",
    "verify_service_credential",
]

__version__ = "0.1.0"
