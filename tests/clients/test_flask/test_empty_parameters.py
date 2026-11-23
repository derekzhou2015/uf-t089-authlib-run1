"""Behavior matrix: parameters sent without a value, Flask relying-party rows.

A front-end middleware or probe may append a parameter with no value to the
callback, for example ``?code=...&state=``.  The client must treat that
occurrence as omitted (:rfc:`6749#section-3.1`) rather than as a state value
that cannot match the stored one.
"""

from unittest import mock

import pytest
from flask import Flask
from flask import session

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.integrations.base_client.errors import MismatchingStateError
from authlib.integrations.flask_client import OAuth
from authlib.oauth2.rfc6749.errors import MissingCodeException

from ..util import get_bearer_token
from ..util import mock_send_value


def _make_client():
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
    )
    return app, client


def _start_flow(app, client):
    with app.test_request_context():
        resp = client.authorize_redirect("https://client.test/callback")
        assert resp.status_code == 302
        query = dict(url_decode(urlparse.urlparse(resp.headers["Location"]).query))
        state = query["state"]
        session_data = session[f"_state_dev_{state}"]
    return state, session_data


# ---------------------------------------------------------------------------
# Callback routing parameters
# ---------------------------------------------------------------------------


def test_callback_blank_state_does_not_shadow_real_state():
    app, client = _make_client()
    state, session_data = _start_flow(app, client)

    # The middleware prepends a value-less state before the real one.  The
    # real state must still be found, exactly as if the blank were absent.
    with app.test_request_context(path=f"/?state=&state={state}&code=a"):
        session[f"_state_dev_{state}"] = session_data
        with mock.patch("requests.sessions.Session.send") as send:
            send.return_value = mock_send_value(get_bearer_token())
            token = client.authorize_access_token()
        assert token["access_token"] == "a"


def test_callback_blank_state_after_real_state():
    app, client = _make_client()
    state, session_data = _start_flow(app, client)

    # Order must not matter: the blank occurrence is simply ignored.
    with app.test_request_context(path=f"/?code=a&state={state}&state="):
        session[f"_state_dev_{state}"] = session_data
        with mock.patch("requests.sessions.Session.send") as send:
            send.return_value = mock_send_value(get_bearer_token())
            token = client.authorize_access_token()
        assert token["access_token"] == "a"


def test_callback_blank_state_post_form():
    app, client = _make_client()
    state, session_data = _start_flow(app, client)

    with app.test_request_context(
        data={"code": "a", "state": state, "probe": ""}, method="POST"
    ):
        session[f"_state_dev_{state}"] = session_data
        with mock.patch("requests.sessions.Session.send") as send:
            send.return_value = mock_send_value(get_bearer_token())
            token = client.authorize_access_token()
        assert token["access_token"] == "a"


def test_callback_blank_only_state_still_fails_csrf():
    app, client = _make_client()
    state, session_data = _start_flow(app, client)

    # A value-less state is omitted; with no value-bearing state the callback
    # cannot be matched to stored state and the existing CSRF error stands.
    with app.test_request_context(path="/?code=a&state="):
        session[f"_state_dev_{state}"] = session_data
        with pytest.raises(MismatchingStateError):
            client.authorize_access_token()


def test_callback_blank_code_is_missing():
    app, client = _make_client()
    state, session_data = _start_flow(app, client)

    # A value-less code is a missing code, whatever the middleware intended.
    with app.test_request_context(path=f"/?code=&state={state}"):
        session[f"_state_dev_{state}"] = session_data
        with pytest.raises(MissingCodeException):
            client.authorize_access_token()


def test_callback_non_blank_state_keeps_existing_behavior():
    app, client = _make_client()
    state, session_data = _start_flow(app, client)

    with app.test_request_context(path=f"/?code=a&state={state}"):
        session[f"_state_dev_{state}"] = session_data
        with mock.patch("requests.sessions.Session.send") as send:
            send.return_value = mock_send_value(get_bearer_token())
            token = client.authorize_access_token()
        assert token["access_token"] == "a"


# ---------------------------------------------------------------------------
# Outgoing builder parameters
# ---------------------------------------------------------------------------


def test_authorize_redirect_omits_blank_parameters():
    app, client = _make_client()
    with app.test_request_context():
        resp = client.authorize_redirect(
            "https://client.test/callback", scope="", login_hint=""
        )
        query = dict(url_decode(urlparse.urlparse(resp.headers["Location"]).query))
    assert "scope" not in query
    assert "login_hint" not in query
    assert query["state"]


def test_authorize_redirect_keeps_non_blank_parameters():
    app, client = _make_client()
    with app.test_request_context():
        resp = client.authorize_redirect(
            "https://client.test/callback", scope="profile", login_hint="u"
        )
        query = dict(url_decode(urlparse.urlparse(resp.headers["Location"]).query))
    assert query["scope"] == "profile"
    assert query["login_hint"] == "u"
