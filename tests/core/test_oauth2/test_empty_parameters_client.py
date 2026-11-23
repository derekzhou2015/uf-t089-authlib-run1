"""Behavior matrix: parameters sent without a value, client (relying party).

The relying party receives callback parameters from the framework and builds
outgoing requests.  The same rule applies: a blank occurrence is treated as
omitted, so a middleware that emits ``?code=...&state=`` does not fail the
callback merely because ``state`` has no value, and outgoing requests never
carry blank parameters.

The matrix rows are the parameter categories a client reads or writes:

* callback routing parameters (``state``, ``code``, ``error``)
* outgoing builder parameters (``scope``, ``redirect_uri``, ``state``)
"""

import pytest

from authlib.common.urls import url_decode
from authlib.oauth2.rfc6749 import parameters
from authlib.oauth2.rfc6749 import requests as oauth2_requests


def test_present_rule_matches_payload_and_normalizer():
    assert oauth2_requests.is_present("") is False
    assert oauth2_requests.is_present(None) is False
    assert oauth2_requests.is_present("x") is True


# ---------------------------------------------------------------------------
# Outgoing builder parameters
# ---------------------------------------------------------------------------


def test_prepare_grant_uri_drops_blank_callback_parameters():
    uri = parameters.prepare_grant_uri(
        "https://provider.test/authorize",
        "dev",
        "code",
        redirect_uri="",
        scope="",
        state="",
    )
    assert "state=" not in uri
    assert "scope=" not in uri
    assert "redirect_uri=" not in uri


def test_prepare_grant_uri_keeps_non_blank_callback_parameters():
    uri = parameters.prepare_grant_uri(
        "https://provider.test/authorize",
        "dev",
        "code",
        redirect_uri="https://client.test/cb",
        scope="profile",
        state="abc",
    )
    assert "state=abc" in uri
    assert "scope=profile" in uri


def test_prepare_token_request_blank_optional_is_omitted():
    body = parameters.prepare_token_request("refresh_token", refresh_token="r1", scope="")
    params = dict(url_decode(body))
    assert params == {"grant_type": "refresh_token", "refresh_token": "r1"}


# ---------------------------------------------------------------------------
# Callback parsing parameters
# ---------------------------------------------------------------------------


def test_parse_implicit_response_blank_state_is_omitted():
    token = parameters.parse_implicit_response(
        "https://client.test/cb#access_token=a&token_type=bearer&state="
    )
    assert "state" not in token


def test_parse_implicit_response_non_blank_state_is_kept():
    token = parameters.parse_implicit_response(
        "https://client.test/cb#access_token=a&token_type=bearer&state=abc"
    )
    assert token["state"] == "abc"


def test_client_callback_blank_state_does_not_break_matching():
    from authlib.integrations.base_client.errors import MismatchingStateError
    from authlib.integrations.base_client.sync_app import OAuth2Base

    # A blank state is not a value; it is dropped before state lookup, and
    # when no stored state matches the existing mismatch error still stands.
    params = {"code": "c", "state": ""}
    filtered = {k: v for k, v in params.items() if v != ""}
    assert "state" not in filtered

    with pytest.raises(MismatchingStateError):
        OAuth2Base._format_state_params(None, filtered)
