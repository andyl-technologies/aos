"""Check missing, substituted and expired verification observations."""

import copy
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location("verification_timeout", Path(__file__).with_name(
    "_hub-direct-verification-timeout.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class VerificationTimeoutTests(unittest.TestCase):
    def test_exact_suffix_is_not_reserialized(self):
        body = '{"kind":"started","version":1}'
        self.assertEqual(fixture.verification_observer_records("console prefix " +
            fixture.VERIFICATION_MARKER + body), [body.encode()])

    def test_absence_duplicate_and_overflow_refuse(self):
        marker = fixture.VERIFICATION_MARKER
        for text in ("unrelated success", marker + "{} " + marker + "{}",
                     "\n".join([marker + "{}"] * 33), marker + " " * 65537):
            with self.subTest(text=text[:80]), self.assertRaises(ValueError):
                fixture.verification_observer_records(text)

    def test_sql_selects_exact_real_session_and_complete(self):
        query = fixture.verification_sql_query({"job": {
            "admission": {"sessionId": "session-1"}, "complete": {"operationId": "complete-1"},
            "placementId": "7"}})
        self.assertIn("REPEATABLE READ READ ONLY", query)
        self.assertIn("session.session_id='session-1'", query)
        self.assertIn("complete.operation_id='complete-1'", query)
        self.assertIn("frozen.placement_id=7", query)
        for identity in ("quote'", "../other", "session;DELETE"):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                fixture.verification_sql_query({"job": {"admission": {"sessionId": identity},
                    "complete": {"operationId": "complete-1"}, "placementId": "7"}})

    def test_rendered_guest_blocks_compile(self):
        import ast
        import textwrap

        source = Path(fixture.__file__).read_text()
        for node in ast.walk(ast.parse(source)):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "direct_guest_python"
                    and len(node.args) >= 3 and isinstance(node.args[2], ast.Constant)):
                compile(textwrap.dedent(node.args[2].value), "guest", "exec")

    def test_same_bytes_from_another_publication_refuse(self):
        row = {"registry": {"stable_id": "fresh-registry", "slug": "fresh/read-timeout"},
            "publication": {"publication_id": "new-publication", "default_commit": "a" * 64},
            "session": {"target_kind": "publication_object", "publication_id": "new-publication",
                "object_path": "nar/helper.nar"}}
        projection = {"job": {"admission": {"intent": {"target": {
            "kind": "publication_object", "publicationId": "new-publication"}}}}}
        registry = {"registry": {"stableId": "fresh-registry", "slug": "fresh/read-timeout"}}
        prepared = {"source": {"sourceCommit": "a" * 64}, "original": {"relativePath": "nar/helper.nar"}}
        fixture.check_verification_publication(row, projection, registry, prepared)

        for owner in ("registry", "publication", "session"):
            changed = copy.deepcopy(row)
            if owner == "registry":
                changed[owner]["stable_id"] = "earlier-registry"
            else:
                changed[owner]["publication_id"] = "earlier-publication"
            with self.subTest(owner=owner), self.assertRaises(ValueError):
                fixture.check_verification_publication(changed, projection, registry, prepared)


if __name__ == "__main__":
    unittest.main()
