from collections import defaultdict

from authlib.deprecate import deprecate

from .errors import InsecureTransportError


def is_present(value) -> bool:
    """Return whether a parameter occurrence carries a value.

    :rfc:`6749#section-3.1` says parameters sent without a value are treated
    as if they were omitted.  An empty string is how ``application/x-www-form
    -urlencoded`` encodes such a parameter, so it is not a value.  Other falsy
    values such as ``0`` and ``False`` are real values and remain present.

    :param value: a decoded parameter value
    :return: bool
    """
    return value is not None and value != ""


def normalize_parameters(items, keep="first") -> dict:
    """Return the effective parameters for a sequence of ``(key, value)`` pairs.

    Blank occurrences are dropped, as required by :rfc:`6749#section-3.1`.
    Repeated parameters keep the first (``keep="first"``) or last
    (``keep="last"``) value-bearing occurrence.  Use
    :attr:`OAuth2Payload.datalist` when the raw occurrences, including blanks,
    are needed, for example to reject repeated parameters.
    """
    data = {}
    for key, value in items:
        if not is_present(value):
            continue
        if keep == "last" or key not in data:
            data[key] = value
    return data


def has_raw_parameter(payload, key) -> bool:
    """Return whether ``key`` occurs in ``payload``, even without a value.

    A few parameters use their mere presence as a protocol signal.  They are
    listed in :attr:`OAuth2Payload.datalist` documentation and must not be
    normalized away.
    """
    return key in payload.datalist


def get_raw_parameter(payload, key, default=None):
    """Return the first raw occurrence of ``key``, blank value included."""
    values = payload.datalist.get(key)
    if values:
        return values[0]
    return default


def count_parameters(payload, key) -> int:
    """Return the number of value-bearing occurrences of ``key``.

    Value-less occurrences are ignored, consistent with treating them as
    omitted.  This is used to reject a parameter that is genuinely repeated
    without mistaking a blank middleware artefact for a duplicate.
    """
    return sum(1 for value in payload.datalist.get(key, []) if is_present(value))


def get_parameter(payload, key, default=None):
    """Return a payload parameter, treating a value-less value as omitted.

    Works with both :class:`OAuth2Payload` and :class:`JsonPayload`.  A JSON
    ``null`` and an empty string are both "no value"; other falsy values such
    as ``0`` and ``False`` are kept.

    :param payload: an :class:`OAuth2Payload` or :class:`JsonPayload` instance
    :param key: parameter name
    :param default: returned when the parameter is absent or has no value
    """
    value = payload.data.get(key)
    return value if is_present(value) else default


def get_mapping_parameter(mapping, key, default=None):
    """Return a parameter from a framework request mapping.

    A value-less occurrence (empty string) is treated as omitted.  If the
    mapping exposes ``getlist``, the first value-bearing occurrence is
    returned, so a middleware that injects ``state=`` next to the real
    ``state`` does not shadow it.

    :param mapping: a Flask/Werkzeug, Django or Starlette query/form mapping
    :param key: parameter name
    :param default: returned when the parameter is absent or has no value
    """
    getlist = getattr(mapping, "getlist", None)
    if getlist is not None:
        for value in getlist(key):
            if is_present(value):
                return value
        return default
    value = mapping.get(key)
    return value if is_present(value) else default


def get_form_parameter(request, key, default=None):
    """Return a form parameter, treating a value-less occurrence as omitted.

    ``request.form`` is kept raw for application code that needs the framework
    mapping.  Library decisions go through this helper so that
    ``application/x-www-form-urlencoded`` parameters sent without a value are
    handled the same way as missing ones.

    :param request: an :class:`OAuth2Request` instance
    :param key: parameter name
    :param default: returned when the parameter is absent or has no value
    """
    form = request.form
    return get_mapping_parameter(form, key, default)


class OAuth2Payload:
    @property
    def data(self):
        raise NotImplementedError()

    @property
    def datalist(self) -> defaultdict[str, list]:
        """Raw occurrences of each parameter, including blank values."""
        raise NotImplementedError()

    def _get_parameter(self, key):
        value = self.data.get(key)
        return value if is_present(value) else None

    @property
    def client_id(self) -> str:
        """The authorization server issues the registered client a client
        identifier -- a unique string representing the registration
        information provided by the client. The value is extracted from
        request.

        :return: string
        """
        return self._get_parameter("client_id")

    @property
    def response_type(self) -> str:
        rt = self._get_parameter("response_type")
        if rt and " " in rt:
            # sort multiple response types
            return " ".join(sorted(rt.split()))
        return rt

    @property
    def grant_type(self) -> str:
        return self._get_parameter("grant_type")

    @property
    def redirect_uri(self):
        return self._get_parameter("redirect_uri")

    @property
    def scope(self) -> str:
        return self._get_parameter("scope")

    @property
    def state(self):
        return self._get_parameter("state")


class BasicOAuth2Payload(OAuth2Payload):
    def __init__(self, payload):
        self._data = normalize_parameters(payload.items())
        self._datalist = {key: [value] for key, value in payload.items()}

    @property
    def data(self):
        return self._data

    @property
    def datalist(self) -> defaultdict[str, list]:
        return self._datalist


class OAuth2Request(OAuth2Payload):
    def __init__(self, method: str, uri: str, body=None, headers=None):
        InsecureTransportError.check(uri)
        #: HTTP method
        self.method = method
        self.uri = uri
        #: HTTP headers
        self.headers = headers or {}

        # Store body for backward compatibility but issue deprecation warning if used
        if body is not None:
            deprecate(
                "'body' parameter in OAuth2Request is deprecated. "
                "Use the payload system instead.",
                version="1.8",
            )
        self._body = body

        self.payload = None

        self.client = None
        self.auth_method = None
        self.user = None
        self.authorization_code = None
        self.refresh_token = None
        self.credential = None
        self._scope = None

    @property
    def args(self):
        raise NotImplementedError()

    @property
    def form(self):
        if self._body:
            return self._body
        raise NotImplementedError()

    @property
    def data(self):
        deprecate(
            "'request.data' is deprecated in favor of 'request.payload.data'",
            version="1.8",
        )
        return self.payload.data

    @property
    def datalist(self) -> defaultdict[str, list]:
        deprecate(
            "'request.datalist' is deprecated in favor of 'request.payload.datalist'",
            version="1.8",
        )
        return self.payload.datalist

    @property
    def client_id(self) -> str:
        deprecate(
            "'request.client_id' is deprecated in favor of 'request.payload.client_id'",
            version="1.8",
        )
        return self.payload.client_id

    @property
    def response_type(self) -> str:
        deprecate(
            "'request.response_type' is deprecated in favor of 'request.payload.response_type'",
            version="1.8",
        )
        return self.payload.response_type

    @property
    def grant_type(self) -> str:
        deprecate(
            "'request.grant_type' is deprecated in favor of 'request.payload.grant_type'",
            version="1.8",
        )
        return self.payload.grant_type

    @property
    def redirect_uri(self):
        deprecate(
            "'request.redirect_uri' is deprecated in favor of 'request.payload.redirect_uri'",
            version="1.8",
        )
        return self.payload.redirect_uri

    @property
    def scope(self) -> str:
        if self._scope is not None:
            return self._scope
        return self.payload.scope

    @scope.setter
    def scope(self, value: str):
        self._scope = value

    @property
    def state(self):
        deprecate(
            "'request.state' is deprecated in favor of 'request.payload.state'",
            version="1.8",
        )
        return self.payload.state

    @property
    def body(self):
        deprecate(
            "'request.body' is deprecated. Use the payload system instead.",
            version="1.8",
        )
        return self._body


class JsonPayload:
    @property
    def data(self):
        raise NotImplementedError()


class JsonRequest:
    def __init__(self, method, uri, headers=None):
        self.method = method
        self.uri = uri
        self.headers = headers or {}
        self.payload = None

    @property
    def data(self):
        deprecate(
            "'request.data' is deprecated in favor of 'request.payload.data'",
            version="1.8",
        )
        return self.payload.data
