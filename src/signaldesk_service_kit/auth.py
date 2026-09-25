"""Service-to-service authentication primitives."""

from __future__ import annotations

import secrets
from typing import Final

from fastapi import Depends, HTTPException, Request, status
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)


_MIN_CREDENTIAL_LENGTH: Final = 16
_SERVICE_TOKEN_PATTERN: Final = r"^[a-z0-9][a-z0-9-]{0,63}$"
_AUTH_FAILURE: Final = "service authentication failed"
_ACTOR_FAILURE: Final = "service actor not allowed"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ServicePrincipal(_StrictModel):
    """The actor and service audience represented by a credential."""

    actor: str = Field(strict=True, pattern=_SERVICE_TOKEN_PATTERN)
    audience: str = Field(strict=True, pattern=_SERVICE_TOKEN_PATTERN)


class ServiceCredential(_StrictModel):
    """One audience-scoped credential, kept secret in model representations."""

    principal: ServicePrincipal
    credential: SecretStr

    def __init__(self, **data: object) -> None:
        try:
            super().__init__(**data)
        except ValidationError as error:
            # Pydantic includes the original input in validation errors,
            # including the whole input mapping for model-level failures.
            # Rebuild the error with a non-secret marker before it can escape.
            sanitized = []
            for item in error.errors(include_url=False):
                item = dict(item)
                item["input"] = "[redacted]"
                sanitized.append(item)
            raise ValidationError.from_exception_data(type(self).__name__, sanitized) from None

    @field_validator("credential", mode="before")
    @classmethod
    def _protect_credential_input(cls, value: object) -> object:
        # Wrap before Pydantic reports a validation failure, preventing its
        # error context from retaining the caller's raw secret.
        return SecretStr(value) if isinstance(value, str) else value

    @field_validator("credential")
    @classmethod
    def _valid_credential(cls, value: SecretStr) -> SecretStr:
        _validate_credential(value.get_secret_value())
        return value


class ServiceCredentialSet(_StrictModel):
    """An immutable collection of credentials with unique principals and values."""

    credentials: tuple[ServiceCredential, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_principals(self) -> ServiceCredentialSet:
        principals = [item.principal for item in self.credentials]
        if len(set(principals)) != len(principals):
            raise ValueError("duplicate service principal")
        credential_values = [item.credential.get_secret_value() for item in self.credentials]
        for index, credential in enumerate(credential_values):
            if any(secrets.compare_digest(credential, prior) for prior in credential_values[:index]):
                raise ValueError("duplicate service credential")
        return self

    def credential_for(self, actor: str, audience: str) -> SecretStr | None:
        for item in self.credentials:
            if item.principal.actor == actor and item.principal.audience == audience:
                return item.credential
        return None


def _validate_credential(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) < _MIN_CREDENTIAL_LENGTH
        or not value.strip()
        or any(char.isspace() for char in value)
    ):
        raise ValueError("invalid service credential")


def verify_service_credential(
    *,
    actor: str,
    audience: str,
    presented: str,
    configured: str,
    expected_actor: str,
    expected_audience: str,
) -> bool:
    """Verify a credential without leaking its value through errors or output."""

    # Validate both values before comparing. compare_digest is deliberately used
    # even though malformed values are rejected, keeping the comparison path clear.
    try:
        _validate_credential(presented)
        _validate_credential(configured)
    except ValueError:
        return False
    actor_ok = secrets.compare_digest(actor, expected_actor)
    audience_ok = secrets.compare_digest(audience, expected_audience)
    credential_ok = secrets.compare_digest(presented, configured)
    return actor_ok and audience_ok and credential_ok


def build_service_auth_dependency(
    *, credentials: ServiceCredentialSet, audience: str, allowed_actors: set[str] | frozenset[str]
):
    """Build a FastAPI dependency enforcing audience, credential, and actor policy."""

    if not audience.strip():
        raise ValueError("audience must not be blank")
    allowed = frozenset(allowed_actors)

    async def authenticate(request: Request) -> ServicePrincipal:
        actor_values = request.headers.getlist("X-SignalDesk-" + "Service-Actor")
        credential_values = request.headers.getlist("X-SignalDesk-" + "Service-Credential")
        if len(actor_values) != 1 or len(credential_values) != 1:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_AUTH_FAILURE)
        actor = actor_values[0]
        presented = credential_values[0]
        configured = credentials.credential_for(actor, audience)
        if configured is None or not verify_service_credential(
            actor=actor,
            audience=audience,
            presented=presented,
            configured=configured.get_secret_value(),
            expected_actor=actor,
            expected_audience=audience,
        ):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_AUTH_FAILURE)
        if actor not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=_ACTOR_FAILURE)
        return ServicePrincipal(actor=actor, audience=audience)

    # Return the dependency marker itself so callers can use the deliberately
    # narrow API as ``principal: ServicePrincipal = auth``.  Returning an
    # ``Annotated`` type here would make that form a default value rather than
    # a FastAPI dependency on current FastAPI releases.
    return Depends(authenticate)
