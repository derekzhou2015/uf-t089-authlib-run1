"""Behavior matrix: parameters sent without a value, Flask server rows.

Covers the parameter categories that reach the authorization server through
the Flask integration, across the endpoints that accept them:

* required credential parameters (``code``, ``code_verifier``, ``token``)
* optional protocol parameters (``scope``, ``state``, ``redirect_uri``)
* free-form extension parameters (``prompt``, ``token_type_hint``)

The rule: a blank occurrence is treated as omitted (:rfc:`6749#section-3.1`).
A non-blank occurrence must behave exactly as before.
"""

import pytest
from flask import json

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.integrations.sqla_oauth2 import create_revocation_endpoint
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)

from .models import CodeGrantMixin
from .models import Token
from .models import db
from .models import save_authorization_code
from .oauth2_server import create_basic_header

authorize_url = "/oauth/authorize?response_type=code&client_id=client-id"
token_url = "/oauth/token"


@pytest.fixture(autouse=True)
def server(server):
    class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ]

        def save_authorization_code(self, code, request):
            return save_authorization_code(code, request)

    server.register_grant(AuthorizationCodeGrant)
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def _auth_headers():
    return create_basic_header("client-id", "client-secret")


def _authorize_and_get_code(test_client, extra=""):
    rv = test_client.post(authorize_url + extra, data={"user_id": "1"})
    assert "code=" in rv.location
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    return params["code"]


# ---------------------------------------------------------------------------
# Authorization endpoint optional protocol parameters
# ---------------------------------------------------------------------------


def test_authorize_blank_state_is_omitted(test_client, client):
    # A middleware-emitted blank state must not be echoed back as state=.
    rv = test_client.get(authorize_url + "&state=")
    assert rv.data == b"ok"

    rv = test_client.post(authorize_url + "&state=", data={"user_id": "1"})
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert "code" in params
    assert "state" not in params


def test_authorize_blank_scope_is_omitted(test_client, client):
    # Blank scope means "use the client default", not "request no scope".
    rv = test_client.get(authorize_url + "&scope=")
    assert rv.data == b"ok"


def test_authorize_blank_redirect_uri_falls_back_to_default(test_client, client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "default_redirect_uri": "https://client.test",
            "scope": "profile address",
            "token_endpoint_auth_method": "none",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()

    rv = test_client.get(authorize_url + "&redirect_uri=")
    assert rv.data == b"ok"


def test_authorize_non_blank_state_is_echoed(test_client, client):
    # Regression guard: a real state is still echoed back.
    rv = test_client.post(authorize_url + "&state=abc", data={"user_id": "1"})
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["state"] == "abc"


# ---------------------------------------------------------------------------
# Token endpoint required credential parameters
# ---------------------------------------------------------------------------


def test_token_blank_code_matches_absent(test_client):
    # Blank and absent must produce the same outcome.
    rv_blank = test_client.post(
        token_url,
        data={"grant_type": "authorization_code", "code": ""},
        headers=_auth_headers(),
    )
    rv_absent = test_client.post(
        token_url,
        data={"grant_type": "authorization_code"},
        headers=_auth_headers(),
    )
    assert json.loads(rv_blank.data)["error"] == json.loads(rv_absent.data)["error"]


def test_token_non_blank_code_still_issues_token(test_client):
    code = _authorize_and_get_code(test_client)
    rv = test_client.post(
        token_url,
        data={"grant_type": "authorization_code", "code": code},
        headers=_auth_headers(),
    )
    assert "access_token" in json.loads(rv.data)


# ---------------------------------------------------------------------------
# Free-form extension parameters
# ---------------------------------------------------------------------------


def test_token_blank_scope_matches_absent(test_client):
    # Blank scope must behave exactly like an omitted scope, so the token
    # endpoint succeeds in both cases with the same granted scope.
    code_blank = _authorize_and_get_code(test_client)
    rv_blank = test_client.post(
        token_url,
        data={"grant_type": "authorization_code", "code": code_blank, "scope": ""},
        headers=_auth_headers(),
    )
    resp_blank = json.loads(rv_blank.data)

    code_absent = _authorize_and_get_code(test_client)
    rv_absent = test_client.post(
        token_url,
        data={"grant_type": "authorization_code", "code": code_absent},
        headers=_auth_headers(),
    )
    resp_absent = json.loads(rv_absent.data)

    assert "access_token" in resp_blank
    assert resp_blank.get("scope") == resp_absent.get("scope")


def test_authorize_blank_prompt_is_omitted(test_client, client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "openid profile",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()

    # Blank prompt must not be treated as an invalid prompt value.
    rv = test_client.get(authorize_url + "&scope=openid&prompt=")
    assert rv.data == b"ok"


# ---------------------------------------------------------------------------
# Revocation endpoint: required token and optional hint
# ---------------------------------------------------------------------------


@pytest.fixture
def revocation_server(server, app):
    RevocationEndpoint = create_revocation_endpoint(db.session, Token)
    server.register_endpoint(RevocationEndpoint)

    @app.route("/oauth/revoke", methods=["POST"])
    def revoke_token():
        return server.create_endpoint_response(RevocationEndpoint.ENDPOINT_NAME)

    return server


def test_revocation_blank_token_is_missing(
    test_client, client, db, revocation_server, token
):
    headers = _auth_headers()
    rv = test_client.post("/oauth/revoke", data={"token": ""}, headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"


def test_revocation_blank_hint_is_omitted(
    test_client, client, db, revocation_server, token
):
    headers = _auth_headers()
    rv = test_client.post(
        "/oauth/revoke",
        data={"token": "a1", "token_type_hint": ""},
        headers=headers,
    )
    # A blank hint is treated as no hint, not as an unsupported type.
    assert rv.status_code == 200
    assert token.access_token_revoked_at


# ---------------------------------------------------------------------------
# Device code grant: required device_code credential
# ---------------------------------------------------------------------------


def test_device_code_blank_is_missing():
    from authlib.oauth2.rfc6749 import InvalidRequestError
    from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
    from authlib.oauth2.rfc6749.requests import OAuth2Request
    from authlib.oauth2.rfc8628 import DeviceCodeGrant

    class Grant(DeviceCodeGrant):
        def authenticate_token_endpoint_client(self):  # pragma: no cover
            raise AssertionError("must not authenticate when device_code is absent")

    request = OAuth2Request("POST", "https://server.test/token")
    request.payload = BasicOAuth2Payload(
        {
            "grant_type": DeviceCodeGrant.GRANT_TYPE,
            "device_code": "",
            "client_id": "client-id",
        }
    )
    with pytest.raises(InvalidRequestError):
        Grant(request, server=None).validate_token_request()
