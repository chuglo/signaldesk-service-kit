from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from signaldesk_service_kit.auth import (
    ServiceCredential,
    ServiceCredentialSet,
    ServicePrincipal,
    build_service_auth_dependency,
    verify_service_credential,
)


SECRET = "correct-horse-battery-staple"
OTHER_SECRET = "another-correct-horse-secret"


def test_models_are_strict_and_secret_is_not_represented():
    principal = ServicePrincipal(actor="scheduler", audience="control-api")
    credentials = ServiceCredentialSet(
        credentials=(ServiceCredential(principal=principal, credential=SECRET),)
    )

    assert repr(credentials).find(SECRET) == -1
    assert credentials.credentials[0].credential.get_secret_value() == SECRET
    with pytest.raises(ValidationError):
        ServicePrincipal(actor="scheduler", audience="control-api", extra="nope")


@pytest.mark.parametrize(
    ("actor", "audience"),
    [
        (" scheduler", "control-api"),
        ("scheduler ", "control-api"),
        ("Scheduler", "control-api"),
        ("schéduler", "control-api"),
        ("scheduler", " control-api"),
        ("scheduler", "control_api"),
        ("scheduler", "a" * 65),
    ],
)
def test_principal_tokens_are_strict_bounded_lowercase_ascii(actor, audience):
    with pytest.raises(ValidationError):
        ServicePrincipal(actor=actor, audience=audience)


def test_credential_set_rejects_duplicate_secret_values():
    with pytest.raises(ValidationError, match="duplicate service credential") as error:
        ServiceCredentialSet(
            credentials=(
                ServiceCredential(
                    principal=ServicePrincipal(actor="scheduler", audience="control-api"),
                    credential=SECRET,
                ),
                ServiceCredential(
                    principal=ServicePrincipal(actor="worker", audience="other-api"),
                    credential=SECRET,
                ),
            )
        )
    assert SECRET not in str(error.value)


def test_credential_set_allows_distinct_secret_values():
    credentials = ServiceCredentialSet(
        credentials=(
            ServiceCredential(
                principal=ServicePrincipal(actor="scheduler", audience="control-api"),
                credential=SECRET,
            ),
            ServiceCredential(
                principal=ServicePrincipal(actor="worker", audience="other-api"),
                credential=OTHER_SECRET,
            ),
        )
    )

    assert len(credentials.credentials) == 2


@pytest.mark.parametrize(
    "presented, configured",
    [(SECRET, SECRET), ("", SECRET), ("   ", SECRET), ("short", "short"), (SECRET, "different")],
)
def test_constant_time_verifier_accepts_only_valid_credentials(presented, configured):
    result = verify_service_credential(
        actor="scheduler",
        audience="control-api",
        presented=presented,
        configured=configured,
        expected_actor="scheduler",
        expected_audience="control-api",
    )
    assert result is (presented == configured == SECRET)


def make_app(credentials: ServiceCredentialSet) -> FastAPI:
    app = FastAPI()
    auth = build_service_auth_dependency(
        audience="control-api", credentials=credentials, allowed_actors={"scheduler"}
    )

    @app.get("/internal")
    def internal(principal: ServicePrincipal = auth):
        return {"actor": principal.actor, "audience": principal.audience}

    return app


def test_fastapi_auth_success_and_sanitized_failures():
    credentials = ServiceCredentialSet(
        credentials=(
            ServiceCredential(
                principal=ServicePrincipal(actor="scheduler", audience="control-api"),
                credential=SECRET,
            ),
        )
    )
    client = TestClient(make_app(credentials))

    response = client.get(
        "/internal",
        headers={
            "X-SignalDesk-Service-Actor": "scheduler",
            "X-SignalDesk-Service-Credential": SECRET,
        },
    )
    assert response.status_code == 200
    assert response.json() == {"actor": "scheduler", "audience": "control-api"}

    for headers in (
        {},
        {"X-SignalDesk-Service-Actor": "scheduler"},
        {
            "X-SignalDesk-Service-Actor": "scheduler",
            "X-SignalDesk-Service-Credential": "wrong-secret",
        },
        {
            "X-SignalDesk-Service-Actor": "other",
            "X-SignalDesk-Service-Credential": SECRET,
        },
    ):
        failed = client.get("/internal", headers=headers)
        assert failed.status_code == 401
        assert failed.json() == {"detail": "service authentication failed"}
        assert SECRET not in failed.text and "wrong-secret" not in failed.text


def test_authenticated_but_disallowed_actor_is_403_and_cross_audience_fails():
    credentials = ServiceCredentialSet(
        credentials=(
            ServiceCredential(
                principal=ServicePrincipal(actor="other", audience="control-api"),
                credential=SECRET,
            ),
            ServiceCredential(
                principal=ServicePrincipal(actor="scheduler", audience="other-api"),
                credential=OTHER_SECRET,
            ),
        )
    )
    client = TestClient(make_app(credentials))
    forbidden = client.get(
        "/internal",
        headers={
            "X-SignalDesk-Service-Actor": "other",
            "X-SignalDesk-Service-Credential": SECRET,
        },
    )
    assert forbidden.status_code == 403
    assert forbidden.json() == {"detail": "service actor not allowed"}

    cross_service = client.get(
        "/internal",
        headers={
            "X-SignalDesk-Service-Actor": "scheduler",
            "X-SignalDesk-Service-Credential": OTHER_SECRET,
        },
    )
    assert cross_service.status_code == 401


def test_duplicate_header_values_are_rejected():
    credentials = ServiceCredentialSet(
        credentials=(
            ServiceCredential(
                principal=ServicePrincipal(actor="scheduler", audience="control-api"),
                credential=SECRET,
            ),
        )
    )
    client = TestClient(make_app(credentials))
    response = client.request(
        "GET",
        "/internal",
        headers=[
            ("X-SignalDesk-Service-Actor", "scheduler"),
            ("X-SignalDesk-Service-Actor", "other"),
            ("X-SignalDesk-Service-Credential", SECRET),
        ],
    )
    assert response.status_code == 401


def test_timeout_helper_is_bounded():
    from signaldesk_service_kit.http import bounded_timeout

    timeout = bounded_timeout(connect=1.0, read=2.0, write=3.0, pool=4.0)
    assert timeout.connect == 1.0
    assert timeout.read == 2.0
    assert timeout.write == 3.0
    assert timeout.pool == 4.0
    with pytest.raises(ValueError):
        bounded_timeout(connect=0, read=1, write=1, pool=1)
    with pytest.raises(ValueError):
        bounded_timeout(connect=1, read=1, write=1, pool=1, maximum=0.5)
