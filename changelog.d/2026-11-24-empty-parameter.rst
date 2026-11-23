Parameters sent without a value are now treated as omitted.

:rfc:`6749#section-3.1` says that request parameters sent without a value
MUST be treated as if they were omitted. Authlib handled such parameters
inconsistently: the authorization and token endpoints mostly treated them
as present, a few helpers (``prepare_grant_uri``, ``prepare_token_request``)
already dropped them, and the response parsers disagreed with each other.
A middleware or probe that appended ``state=`` or ``scope=`` to a request
could therefore fail an otherwise valid login, or trip a callback
validation that compared the blank value with the stored ``state``.

The rule is now uniform across the authorization endpoint, token endpoint,
revocation, introspection, device authorization, dynamic registration,
OpenID Connect and the client integrations: an empty value is no value.
``0`` and ``False`` remain real values. A repeated parameter whose blank
occurrence accompanies a real one keeps the real value and is not reported
as a repeated parameter.

The one declared exception is the ``request``/``request_uri`` pair
(:rfc:`9101`): their presence selects a request mechanism, so a blank
occurrence is still present and an unusable ``request_uri`` is rejected
rather than silently ignored.
