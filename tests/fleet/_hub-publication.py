"""Publish the exact signed fixture across short browser-token lifetimes.

Large corpora can outlast the console JWT even when it is obtained immediately
before uploading. The CLI preserves staged publication state on that failure;
the fixture refreshes browser authorization and resumes the unchanged corpus.
"""

import base64
import json
import re
import time


def _expired_principal_refusal(token, error):
    """Recognize an expired bearer refused by Native's later SQL recheck."""
    if ("(403 Forbidden)" not in error or not isinstance(token, str)
            or len(token) > 32768 or not re.fullmatch(
                r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token)):
        return False

    try:
        refusal = json.loads(error[error.rfind("{"):])
        payload = token.split(".")[1]
        claims = json.loads(base64.b64decode(
            payload + "=" * (-len(payload) % 4), altchars=b"-_", validate=True))
    except (ValueError, UnicodeError):
        return False
    if refusal != {"code": "permission_denied", "message": "active authenticated principal required"}:
        return False
    if not isinstance(claims, dict):
        return False

    # This unverified deadline only selects reauthentication. Native still
    # authenticates the replacement token and authorizes the exact publication.
    issued, expires = claims.get("iat"), claims.get("exp")
    return (type(issued) is int and type(expires) is int
        and 0 <= issued < expires <= time.time())


def publish_signed_surface(machine, command, token, refresh_token):
    """Resume proven bearer expiry and require one publication identity."""
    resumed_publication = None
    for attempt in range(3):
        status, stdout, stderr = machine.execute(command(token), timeout=600)
        response = json.loads(stdout)
        if status == 0:
            publication = response["data"]
            assert publication["state"] == "ready", publication
            if resumed_publication is not None:
                assert publication["publication_id"] == resumed_publication, publication
                print("signed publication resumed after browser token expiry:", resumed_publication)
            return publication, token

        error = response.get("error", "")
        resumable = re.search(r"publication ([0-9a-f]{32}) remains resumable;", error)
        expired = ("401 Unauthorized" in error and "JWT has expired" in error)
        expired |= _expired_principal_refusal(token, error)
        assert (
            attempt < 2
            and resumable is not None
            and expired
        ), (status, response, stderr)
        publication_id = resumable.group(1)
        assert resumed_publication in (None, publication_id), response
        resumed_publication = publication_id
        token = refresh_token()

    raise AssertionError("signed publication did not finish within its resume budget")
