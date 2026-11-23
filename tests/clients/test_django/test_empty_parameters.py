"""Behavior matrix: parameters sent without a value, Django relying-party rows.

Mirrors the Flask client matrix through the Django client integration: a
value-less callback occurrence is treated as omitted, so a middleware that
injects ``state=`` next to the real state does not shadow it.
"""

from unittest import mock

import pytest

from authlib.integrations.base_client.errors import MismatchingStateError
from authlib.integrations.django_client import OAuth
from authlib.oauth2.rfc6749.errors import MissingCodeException

from ..util import get_bearer_token
from ..util import mock_send_value


def _make_client():
    oauth = OAuth()
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
    )
    return client


def _start_flow(factory, client):
    with mock.patch("requests.sessions.Session.send"):
        request = factory.get("/login")
        request.session = factory.session
        resp = client.authorize_redirect(request, "https://client.test/callback")
        from authlib.common.urls import url_decode
        from authlib.common.urls import urlparse

        query = dict(url_decode(urlparse.urlparse(resp["Location"]).query))
        state = query["state"]
        session_data = request.session[f"_state_dev_{state}"]
    return state, session_data


def test_callback_blank_state_does_not_shadow_real_state(factory):
    client = _make_client()
    state, session_data = _start_flow(factory, client)

    request = factory.get(f"/token?state=&state={state}&code=a")
    request.session = factory.session
    request.session[f"_state_dev_{state}"] = session_data
    with mock.patch("requests.sessions.Session.send") as send:
        send.return_value = mock_send_value(get_bearer_token())
        token = client.authorize_access_token(request)
    assert token["access_token"] == "a"


def test_callback_blank_only_state_still_fails_csrf(factory):
    client = _make_client()
    state, session_data = _start_flow(factory, client)

    request = factory.get("/token?code=a&state=")
    request.session = factory.session
    request.session[f"_state_dev_{state}"] = session_data
    with pytest.raises(MismatchingStateError):
        client.authorize_access_token(request)


def test_callback_blank_code_is_missing(factory):
    client = _make_client()
    state, session_data = _start_flow(factory, client)

    request = factory.get(f"/token?code=&state={state}")
    request.session = factory.session
    request.session[f"_state_dev_{state}"] = session_data
    with pytest.raises(MissingCodeException):
        client.authorize_access_token(request)


def test_callback_non_blank_keeps_existing_behavior(factory):
    client = _make_client()
    state, session_data = _start_flow(factory, client)

    request = factory.get(f"/token?code=a&state={state}")
    request.session = factory.session
    request.session[f"_state_dev_{state}"] = session_data
    with mock.patch("requests.sessions.Session.send") as send:
        send.return_value = mock_send_value(get_bearer_token())
        token = client.authorize_access_token(request)
    assert token["access_token"] == "a"
