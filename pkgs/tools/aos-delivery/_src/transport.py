"""Connect unary protobuf JSON transport with separate API and GitHub proofs.

The application caller has API authority only. Signed upload URLs never receive
either identity proof, and redirects are disabled for every authenticated hop.
"""

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request


MAX_RESPONSE = 1 << 20
ARTIFACT_MEDIA_TYPE = "application/vnd.oci.image.layout.v1.tar"
OPERATION_NAME = re.compile(r"operations/[0-9a-f]{32}\Z")


class DeliveryError(Exception):
    """Reports a bounded public category without private provider output."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Prevents bearer proofs and signed uploads from following redirects."""

    def redirect_request(self, request, response, code, message, headers, url):
        raise DeliveryError("HTTP redirect is forbidden")


def encoded(value):
    """Encodes canonical JSON shared by declaration hashes and RPC requests."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def checked_https(value):
    """Accepts HTTPS authorities without userinfo, fragment or alternate ports."""
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.port not in (None, 443)
    ):
        raise DeliveryError("HTTPS coordinate is invalid")
    return parsed


def bounded_json(response):
    """Decodes one size-bounded JSON response."""
    content = response.read(MAX_RESPONSE + 1)
    if len(content) > MAX_RESPONSE:
        raise DeliveryError("response exceeds its size boundary")
    try:
        value = json.loads(content)
    except (UnicodeError, ValueError):
        raise DeliveryError("response JSON is invalid") from None
    if not isinstance(value, dict):
        raise DeliveryError("response JSON is not an object")
    return value


def workflow_token(endpoint, opener):
    """Requests GitHub's independently verified, API-audience-bound OIDC proof."""
    value = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    parsed = checked_https(value)
    if not parsed.hostname.lower().endswith(".actions.githubusercontent.com"):
        raise DeliveryError("GitHub OIDC request host is untrusted")
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    if not request_token:
        raise DeliveryError("GitHub OIDC request credential is absent")
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query = [(key, value) for key, value in query if key != "audience"]
    query.append(("audience", endpoint))
    url = urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query)))
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + request_token})
    try:
        with opener.open(request, timeout=30) as response:
            token = bounded_json(response).get("value")
    except urllib.error.HTTPError as error:
        raise DeliveryError("GitHub OIDC request failed: HTTP " + str(error.code)) from None
    except urllib.error.URLError:
        raise DeliveryError("GitHub OIDC transport failed") from None
    if not isinstance(token, str) or not token.strip():
        raise DeliveryError("GitHub OIDC response has no proof")
    return token


class Client:
    """Invokes only the registered delivery and operation API services."""

    def __init__(self, endpoint, opener=None, token_source=None):
        parsed = checked_https(endpoint)
        if parsed.query or parsed.path not in ("", "/"):
            raise DeliveryError("delivery endpoint must be an HTTPS origin")
        self.endpoint = endpoint.rstrip("/")
        self.opener = opener or urllib.request.build_opener(NoRedirect())
        self.token_source = token_source or workflow_token
        self.api_token = os.environ.get("DELIVERY_ID_TOKEN", "")
        if not self.api_token.strip():
            raise DeliveryError("delivery API ID token is absent")

    def rpc(self, method, body, operations=False):
        """Sends a Connect unary request with protobuf JSON encoding."""
        allowed = ("GetOperation",) if operations else (
            "BeginArtifactUpload", "FinalizeArtifactUpload", "ReconcileApplication",
            "ReconcileAnchoredApplication",
        )
        if method not in allowed:
            raise DeliveryError("RPC method is outside the application client contract")
        service = "OperationService" if operations else "DeliveryService"
        url = self.endpoint + "/andyl.infrastructure.delivery.v1." + service + "/" + method
        request = urllib.request.Request(url, data=encoded(body), headers={
            "Authorization": "Bearer " + self.api_token,
            "X-Andyl-Github-Oidc": self.token_source(self.endpoint, self.opener),
            "Content-Type": "application/json",
            "Connect-Protocol-Version": "1",
        })
        try:
            with self.opener.open(request, timeout=45) as response:
                return bounded_json(response)
        except urllib.error.HTTPError as error:
            category = "unknown"
            try:
                code = bounded_json(error).get("code", "unknown")
                if isinstance(code, str) and re.fullmatch(r"[a-z_]{1,40}", code):
                    category = code
            except DeliveryError:
                pass
            message = "delivery RPC failed: " + category + " (HTTP " + str(error.code) + ")"
            raise DeliveryError(message) from None
        except urllib.error.URLError:
            raise DeliveryError("delivery RPC transport failed") from None

    def upload(self, reservation, file, size, digest):
        """Streams exactly one immutable bundle without forwarding API proofs."""
        if (
            str(reservation.get("expectedSizeBytes")) != str(size)
            or reservation.get("expectedDigest") != digest
            or reservation.get("mediaType") != ARTIFACT_MEDIA_TYPE
        ):
            raise DeliveryError("artifact reservation does not match the actual bundle")
        url = reservation.get("uploadUrl", "")
        if not url:
            return  # An idempotent reservation can already be finalized.
        checked_https(url)
        request = urllib.request.Request(url, data=file, method="PUT", headers={
            "Content-Type": ARTIFACT_MEDIA_TYPE,
            "Content-Length": str(size),
            "x-goog-if-generation-match": "0",
        })
        try:
            with self.opener.open(request, timeout=900) as response:
                if not 200 <= response.status < 300:
                    raise DeliveryError("artifact upload failed")
                response.read(64 << 10)
        except urllib.error.HTTPError as error:
            raise DeliveryError("artifact upload failed: HTTP " + str(error.code)) from None
        except urllib.error.URLError:
            raise DeliveryError("artifact upload transport failed") from None

    def wait(self, operation, timeout):
        """Observes one durable operation without resubmitting provider work."""
        name = operation.get("name", "")
        if not OPERATION_NAME.fullmatch(name):
            raise DeliveryError("operation name is invalid")
        deadline = time.monotonic() + timeout
        while True:
            state = operation.get("state")
            if state == "OPERATION_STATE_SUCCEEDED":
                return operation
            if state in ("OPERATION_STATE_FAILED", "OPERATION_STATE_CANCELED"):
                raise DeliveryError("delivery operation failed: " + name + " (" + state + ")")
            if time.monotonic() >= deadline:
                raise DeliveryError("observation deadline expired; resume " + name)
            time.sleep(min(5, max(0, deadline - time.monotonic())))
            current = self.rpc("GetOperation", {"name": name}, operations=True).get("operation", {})
            if current.get("name") != name:
                raise DeliveryError("operation observation crossed its name boundary")
            for field in ("target", "source", "generationAnchor", "artifact"):
                if current.get(field) != operation.get(field):
                    raise DeliveryError("operation observation crossed its source or target boundary")
            operation = current
