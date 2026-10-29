"""Checks exact publication resumption across browser bearer expiry."""

import base64
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


specification = importlib.util.spec_from_file_location(
    "publication", Path(__file__).with_name("_hub-publication.py"))
publication = importlib.util.module_from_spec(specification)
specification.loader.exec_module(publication)

PUBLICATION_ID = "1" * 32


def bearer(expiry):
    payload = base64.urlsafe_b64encode(json.dumps({"iat": 1, "exp": expiry}).encode())
    return "e30." + payload.decode().rstrip("=") + ".c2ln"


def failure(status, message, code="permission_denied"):
    body = json.dumps({"code": code, "message": message})
    return 1, json.dumps({"error": "publication " + PUBLICATION_ID
        + " remains resumable; upload failed (" + status + "): " + body}), b""


def ready(identifier=PUBLICATION_ID):
    return 0, json.dumps({"data": {"state": "ready", "publication_id": identifier}}), b""


class Machine:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.tokens = []

    def execute(self, token, timeout):
        if timeout != 600:
            raise AssertionError("publication command deadline changed")
        self.tokens.append(token)
        return next(self.replies)


class PublicationExpiryTests(unittest.TestCase):
    def publish(self, replies, token):
        machine = Machine(replies)
        refresh = unittest.mock.Mock(return_value=bearer(2000))
        result = publication.publish_signed_surface(machine, lambda value: value, token, refresh)
        return result, machine, refresh

    def test_expiry_during_current_principal_check_resumes_exact_publication(self):
        with patch("time.time", return_value=1000):
            result, machine, refresh = self.publish([
                failure("403 Forbidden", "active authenticated principal required"), ready(),
            ], bearer(1000))

        self.assertEqual(result[0]["publication_id"], PUBLICATION_ID)
        self.assertEqual(machine.tokens, [bearer(1000), bearer(2000)])
        refresh.assert_called_once_with()

    def test_explicit_jwt_expiry_still_resumes(self):
        _, machine, refresh = self.publish([
            failure("401 Unauthorized", "JWT has expired", "unauthenticated"), ready(),
        ], bearer(1000))
        self.assertEqual(len(machine.tokens), 2)
        refresh.assert_called_once_with()

    def test_live_malformed_or_unrelated_denials_never_refresh(self):
        cases = [
            (bearer(1001), "active authenticated principal required", "permission_denied"),
            ("malformed", "active authenticated principal required", "permission_denied"),
            (bearer(True), "active authenticated principal required", "permission_denied"),
            (bearer(1000), "permission revoked", "permission_denied"),
            (bearer(1000), "provider outcome unknown", "failed_precondition"),
        ]
        for token, message, code in cases:
            with self.subTest(token=token, message=message), patch("time.time", return_value=1000):
                machine = Machine([failure("403 Forbidden", message, code)])
                refresh = unittest.mock.Mock()
                with self.assertRaises(AssertionError):
                    publication.publish_signed_surface(machine, lambda value: value, token, refresh)
                refresh.assert_not_called()
                self.assertEqual(machine.tokens, [token])

    def test_refresh_never_accepts_a_replacement_publication(self):
        with self.assertRaises(AssertionError):
            self.publish([
                failure("401 Unauthorized", "JWT has expired", "unauthenticated"), ready("2" * 32),
            ], bearer(1000))


if __name__ == "__main__":
    unittest.main()
