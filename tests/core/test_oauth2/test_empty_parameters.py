"""Behavior matrix: parameters sent without a value, core (framework-free) rows.

The rule is uniform: an ``application/x-www-form-urlencoded`` occurrence that
has no value (an empty string) is treated as if the parameter were omitted
(:rfc:`6749#section-3.1`).  ``0``, ``False`` and other falsy values are real
values.  The only declared exception is the pair ``request``/``request_uri``,
whose mere presence selects a request mechanism (:rfc:`9101`).

Each test names the parameter category it covers so the matrix is explicit:

* required credential parameters
* optional protocol parameters (scope/state/redirect_uri)
* presence-signalling parameters (request/request_uri)
* free-form extension parameters (prompt/response_mode/token_type_hint/...)
"""

import pytest

from authlib.oauth2.rfc6749 import InvalidRequestError
from authlib.oauth2.rfc6749.errors import MissingCodeException
from authlib.oauth2.rfc6749.errors import MissingTokenException
from authlib.oauth2.rfc6749.errors import MissingTokenTypeException
from authlib.oauth2.rfc6749.parameters import parse_authorization_code_response
from authlib.oauth2.rfc6749.parameters import parse_implicit_response
from authlib.oauth2.rfc6749.parameters import prepare_grant_uri
from authlib.oauth2.rfc6749.parameters import prepare_token_request
from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
from authlib.oauth2.rfc6749.requests import OAuth2Request
from authlib.oauth2.rfc6749.requests import count_parameters
from authlib.oauth2.rfc6749.requests import is_present
from authlib.oauth2.rfc6749.requests import normalize_parameters

# ---------------------------------------------------------------------------
# The rule itself
# ---------------------------------------------------------------------------


def test_is_present_rule():
    # A blank string is how urlencoded encodes "no value".
    assert is_present(None) is False
    assert is_present("") is False
    # Other falsy values are values.
    assert is_present(0) is True
    assert is_present(False) is True


def test_normalize_parameters_drops_blanks_and_keeps_first():
    items = [("a", ""), ("a", "second"), ("b", ""), ("c", 0)]
    assert normalize_parameters(items) == {"a": "second", "c": 0}


def test_count_parameters_ignores_blank_occurrences():
    payload = BasicOAuth2Payload({"state": "", "scope": "a"})
    # A single raw occurrence is represented in datalist; build a payload with
    # repeated raw occurrences by hand.
    payload._datalist = {"scope": ["a", ""], "state": [""]}
    assert count_parameters(payload, "scope") == 1
    assert count_parameters(payload, "state") == 0


# ---------------------------------------------------------------------------
# Optional protocol parameters
# ---------------------------------------------------------------------------


def test_payload_optional_parameters_blank_is_omitted():
    payload = BasicOAuth2Payload(
        {"scope": "", "state": "", "redirect_uri": "", "client_id": "c"}
    )
    assert payload.scope is None
    assert payload.state is None
    assert payload.redirect_uri is None
    assert payload.client_id == "c"


def test_payload_falsy_but_present_values_are_kept():
    payload = BasicOAuth2Payload({"grant_type": 0})
    assert payload.grant_type == 0


def test_prepare_grant_uri_omits_blank_values():
    uri = prepare_grant_uri(
        "https://provider.test/authorize",
        "dev",
        "code",
        redirect_uri="",
        scope="",
        state="",
        max_age=0,
        resource=["a", ""],
    )
    assert uri == (
        "https://provider.test/authorize?response_type=code&client_id=dev"
        "&max_age=0&resource=a"
    )


def test_parse_authorization_code_response_blank_code_is_missing():
    with pytest.raises(MissingCodeException):
        parse_authorization_code_response("https://provider.test/?code=&state=x")


def test_parse_authorization_code_response_blank_state_is_omitted():
    rv = parse_authorization_code_response("https://provider.test/?code=c&state=")
    assert rv == {"code": "c"}


def test_parse_implicit_response_blank_required_values_are_missing():
    with pytest.raises(MissingTokenException):
        parse_implicit_response(
            "https://provider.test/#access_token=&token_type=bearer"
        )
    with pytest.raises(MissingTokenTypeException):
        parse_implicit_response("https://provider.test/#access_token=a&token_type=")


def test_parse_implicit_response_blank_state_is_omitted():
    rv = parse_implicit_response(
        "https://provider.test/#access_token=a&token_type=bearer&state="
    )
    assert rv == {"access_token": "a", "token_type": "bearer"}


def test_prepare_token_request_blank_code_is_missing():
    with pytest.raises(MissingCodeException):
        prepare_token_request("authorization_code", code="")


def test_prepare_token_request_blank_optional_scope_is_omitted():
    body = prepare_token_request("client_credentials", scope="")
    assert body == "grant_type=client_credentials"


# ---------------------------------------------------------------------------
# Presence-signalling parameters: the declared exception
# ---------------------------------------------------------------------------


def _jar_request(payload):
    request = OAuth2Request("GET", "https://server.test/authorize")
    request.payload = BasicOAuth2Payload(payload)
    return request


class _Client:
    def get_client_id(self):
        return "c"


class _JAR:
    """Minimal JWTAuthenticationRequest with only the policy hooks stubbed."""

    def get_server_metadata(self):
        return {}

    def get_client_require_signed_request_object(self, client):
        return False


def _make_jar():
    from authlib.oauth2.rfc9101 import JWTAuthenticationRequest

    class _Concrete(_JAR, JWTAuthenticationRequest):
        pass

    return _Concrete()


def test_blank_request_uri_is_still_present():
    ext = _make_jar()
    request = _jar_request({"client_id": "c", "request_uri": ""})
    # Blank is still a present `request_uri`, so the presence-based path is
    # taken instead of silently falling back to the query string.
    assert ext._shoud_proceed_with_request_object(request, _Client()) is True


def test_blank_request_uri_rejected_before_fetch():
    from authlib.oauth2.rfc9101.errors import InvalidRequestUriError

    ext = _make_jar()
    request = _jar_request({"client_id": "c", "request_uri": ""})
    with pytest.raises(InvalidRequestUriError):
        ext._get_raw_request_object(request, _Client())


# ---------------------------------------------------------------------------
# Repeated parameters: blank artefacts are not repetitions
# ---------------------------------------------------------------------------


def test_blank_duplicate_is_not_a_multiple_parameter():
    from authlib.oauth2.rfc6749.grants.base import AuthorizationEndpointMixin

    request = OAuth2Request("GET", "https://server.test/authorize")
    payload = BasicOAuth2Payload({"scope": "profile"})
    payload._datalist = {"scope": ["profile", ""], "state": [""], "client_id": ["c"]}
    request.payload = payload
    # Must not raise: the blank occurrences are treated as omitted.
    AuthorizationEndpointMixin.validate_no_multiple_request_parameter(request)


def test_value_bearing_duplicate_is_rejected():
    from authlib.oauth2.rfc6749.grants.base import AuthorizationEndpointMixin

    request = OAuth2Request("GET", "https://server.test/authorize")
    payload = BasicOAuth2Payload({"scope": "a"})
    payload._datalist = {"scope": ["a", "b"], "client_id": ["c"]}
    request.payload = payload
    with pytest.raises(InvalidRequestError):
        AuthorizationEndpointMixin.validate_no_multiple_request_parameter(request)
