from collections import defaultdict
from functools import cached_property

from flask.wrappers import Request
from werkzeug.datastructures import MultiDict

from authlib.oauth2.rfc6749 import JsonPayload
from authlib.oauth2.rfc6749 import JsonRequest
from authlib.oauth2.rfc6749 import OAuth2Payload
from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc6749.requests import is_present


class FlaskOAuth2Payload(OAuth2Payload):
    def __init__(self, request: Request):
        self._request = request

    @cached_property
    def data(self):
        # Blank occurrences are dropped, per RFC 6749 Section 3.1.  A
        # MultiDict is returned, as before, so the merged ``request.values``
        # interface (and its args-over-form precedence) is preserved.
        return MultiDict(
            (key, value)
            for key, value in self._request.values.items(multi=True)
            if is_present(value)
        )

    @cached_property
    def datalist(self):
        values = defaultdict(list)
        for k in self._request.values:
            values[k].extend(self._request.values.getlist(k))
        return values


class FlaskOAuth2Request(OAuth2Request):
    def __init__(self, request: Request):
        super().__init__(
            method=request.method, uri=request.url, headers=request.headers
        )
        self._request = request
        self.payload = FlaskOAuth2Payload(request)

    @property
    def args(self):
        return self._request.args

    @property
    def form(self):
        return self._request.form


class FlaskJsonPayload(JsonPayload):
    def __init__(self, request: Request):
        self._request = request

    @property
    def data(self):
        return self._request.get_json()


class FlaskJsonRequest(JsonRequest):
    def __init__(self, request: Request):
        super().__init__(request.method, request.url, request.headers)
        self.payload = FlaskJsonPayload(request)
