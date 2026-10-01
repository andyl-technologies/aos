"""Publish the exact signed fixture across short browser-token lifetimes.

Large corpora can outlast the console JWT even when it is obtained immediately
before uploading. The CLI preserves staged publication state on that failure;
the fixture refreshes browser authorization and resumes the unchanged corpus.
"""

import json
import re


def publish_signed_surface(machine, command, token, refresh_token):
    """Resume only explicit JWT expiry and require one publication identity."""
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
        assert (
            attempt < 2
            and resumable is not None
            and "401 Unauthorized" in error
            and "JWT has expired" in error
        ), (status, response, stderr)
        publication_id = resumable.group(1)
        assert resumed_publication in (None, publication_id), response
        resumed_publication = publication_id
        token = refresh_token()

    raise AssertionError("signed publication did not finish within its resume budget")
