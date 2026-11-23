"""Behavior matrix: parameters sent without a value, Django server rows.

The same rule as the Flask rows, exercised through the Django integration:
a blank occurrence is treated as omitted (:rfc:`6749#section-3.1`), while
non-blank occurrences keep their existing behavior.

The parameter categories covered here match the Flask matrix:

* required credential parameters (``code``, ``username``/``password``)
* optional protocol parameters (``scope``, ``state``, ``redirect_uri``)
* free-form extension parameters (``token_type_hint``)
"""

import json

import pytest

from authlib.oauth2.rfc6749 import grants

from .models import Client
from .models import CodeGrantMixin
from .models import OAuth2Code
from .oauth2_server import create_basic_auth

authorize_url = "/authorize?response_type=code&client_id=client-id"


@pytest.fixture(autouse=True)
def server(server):
    class AuthorizationCodeGrant(CodeGrantMixin, grants.AuthorizationCodeGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ]

        def save_authorization_code(self, code, request):
            OAuth2Code(
                code=code,
                client_id=request.client.client_id,
                redirect_uri=request.payload.redirect_uri,
                response_type=request.payload.response_type,
                scope=request.payload.scope,
                user=request.user,
            ).save()

    server.register_grant(AuthorizationCodeGrant)
    return server


@pytest.fixture(autouse=True)
def client(user):
    client = Client(
        user_id=user.pk,
        client_id="client-id",
        client_secret="client-secret",
        response_type="code",
        grant_type="authorization_code",
        scope="",
        token_endpoint_auth_method="client_secret_basic",
        default_redirect_uri="https://client.test",
    )
    client.save()
    yield client
    client.delete()


@pytest.fixture
def grant_user(user):
    return user


def _get_code(factory, server, grant_user, extra_url=""):
    request = factory.post(authorize_url + extra_url, data={"user_id": "1"})
    request.user = grant_user
    grant = server.get_consent_grant(request)
    resp = server.create_authorization_response(
        request, grant=grant, grant_user=grant_user
    )
    assert resp.status_code == 302
    assert "code=" in resp["Location"]
    from authlib.common.urls import url_decode
    from authlib.common.urls import urlparse

    return dict(url_decode(urlparse.urlparse(resp["Location"]).query))["code"]


# ---------------------------------------------------------------------------
# Authorization endpoint optional protocol parameters
# ---------------------------------------------------------------------------


def test_authorize_blank_state_is_omitted(factory, server):
    request = factory.get(authorize_url + "&state=")
    # A blank state is omitted, so the consent request still validates.
    grant = server.get_consent_grant(request)
    assert grant is not None


def test_authorize_blank_state_not_echoed(factory, server, grant_user):
    request = factory.post(authorize_url + "&state=", data={"user_id": "1"})
    request.user = grant_user
    grant = server.get_consent_grant(request)
    resp = server.create_authorization_response(
        request, grant=grant, grant_user=grant_user
    )
    assert "state=" not in resp["Location"]


def test_authorize_non_blank_state_is_echoed(factory, server, grant_user):
    request = factory.post(authorize_url + "&state=abc", data={"user_id": "1"})
    request.user = grant_user
    grant = server.get_consent_grant(request)
    resp = server.create_authorization_response(
        request, grant=grant, grant_user=grant_user
    )
    assert "state=abc" in resp["Location"]


def test_authorize_blank_scope_is_omitted(factory, server):
    request = factory.get(authorize_url + "&scope=")
    grant = server.get_consent_grant(request)
    assert grant is not None


def test_authorize_blank_redirect_uri_falls_back_to_default(factory, server):
    request = factory.get(authorize_url + "&redirect_uri=")
    grant = server.get_consent_grant(request)
    assert grant is not None


# ---------------------------------------------------------------------------
# Token endpoint required credential parameters
# ---------------------------------------------------------------------------


def test_token_blank_code_is_missing(factory, server):
    auth = create_basic_auth("client-id", "client-secret")
    request = factory.post(
        "/oauth/token",
        data={"grant_type": "authorization_code", "code": ""},
        HTTP_AUTHORIZATION=auth,
    )
    resp = server.create_token_response(request)
    data = json.loads(resp.content)
    assert data["error"] == "invalid_request"
    assert "Missing" in data["error_description"]


def test_token_blank_code_matches_absent(factory, server):
    auth = create_basic_auth("client-id", "client-secret")
    request = factory.post(
        "/oauth/token",
        data={"grant_type": "authorization_code", "code": ""},
        HTTP_AUTHORIZATION=auth,
    )
    blank = json.loads(server.create_token_response(request).content)

    request = factory.post(
        "/oauth/token",
        data={"grant_type": "authorization_code"},
        HTTP_AUTHORIZATION=auth,
    )
    absent = json.loads(server.create_token_response(request).content)
    assert blank["error"] == absent["error"]


def test_token_non_blank_code_still_issues_token(factory, server, grant_user):
    code = _get_code(factory, server, grant_user)
    auth = create_basic_auth("client-id", "client-secret")
    request = factory.post(
        "/oauth/token",
        data={"grant_type": "authorization_code", "code": code},
        HTTP_AUTHORIZATION=auth,
    )
    resp = server.create_token_response(request)
    assert "access_token" in json.loads(resp.content)


# ---------------------------------------------------------------------------
# Password grant required credential parameters
# ---------------------------------------------------------------------------


@pytest.fixture
def password_server(server, client):
    client.grant_type = "password"
    client.save()

    class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
        def authenticate_user(self, username, password):
            from .models import User

            try:
                user = User.objects.get(username=username)
                if user.check_password(password):
                    return user
            except User.DoesNotExist:
                return None

    server.register_grant(PasswordGrant)
    return server


def test_password_blank_username_is_missing(factory, password_server):
    auth = create_basic_auth("client-id", "client-secret")
    request = factory.post(
        "/oauth/token",
        data={"grant_type": "password", "username": "", "password": "ok"},
        HTTP_AUTHORIZATION=auth,
    )
    resp = password_server.create_token_response(request)
    data = json.loads(resp.content)
    assert data["error"] == "invalid_request"
    assert "username" in data["error_description"]


def test_password_blank_password_is_missing(factory, password_server):
    auth = create_basic_auth("client-id", "client-secret")
    request = factory.post(
        "/oauth/token",
        data={"grant_type": "password", "username": "foo", "password": ""},
        HTTP_AUTHORIZATION=auth,
    )
    resp = password_server.create_token_response(request)
    data = json.loads(resp.content)
    assert data["error"] == "invalid_request"
    assert "password" in data["error_description"]


def test_password_non_blank_still_issues_token(factory, password_server):
    auth = create_basic_auth("client-id", "client-secret")
    request = factory.post(
        "/oauth/token",
        data={"grant_type": "password", "username": "foo", "password": "ok"},
        HTTP_AUTHORIZATION=auth,
    )
    resp = password_server.create_token_response(request)
    assert "access_token" in json.loads(resp.content)


# ---------------------------------------------------------------------------
# Revocation free-form hint parameter
# ---------------------------------------------------------------------------


@pytest.fixture
def revocation_server(server):
    from authlib.integrations.django_oauth2 import RevocationEndpoint

    server.register_endpoint(RevocationEndpoint)
    return server


def test_revocation_blank_hint_is_omitted(
    factory, revocation_server, client, token
):
    auth = create_basic_auth("client-id", "client-secret")
    request = factory.post(
        "/oauth/revoke",
        data={"token": "a1", "token_type_hint": ""},
        HTTP_AUTHORIZATION=auth,
    )
    resp = revocation_server.create_endpoint_response("revocation", request)
    # A blank hint is treated as no hint, so revocation succeeds.
    assert resp.status_code == 200
    assert json.loads(resp.content or b"{}") == {}


def test_revocation_blank_token_is_missing(factory, revocation_server, client, token):
    auth = create_basic_auth("client-id", "client-secret")
    request = factory.post(
        "/oauth/revoke",
        data={"token": ""},
        HTTP_AUTHORIZATION=auth,
    )
    resp = revocation_server.create_endpoint_response("revocation", request)
    data = json.loads(resp.content)
    assert data["error"] == "invalid_request"
