"""Fixed trigger/identity regressions; real PostgreSQL gates remain separate."""

import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("staged_sql", Path(__file__).with_name("_hub-direct-staged-sql.py"))
sql = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sql)


class SqlTests(unittest.TestCase):
    def selection(self):
        return {"runId": "a" * 32, "deploymentId": "actual-deployment", "sessionId": "actual-session",
                "operationId": "b" * 64, "logicalFingerprint": "c" * 64, "expectedResourceVersion": "7"}

    def definition(self):
        name = "aos_staged_fault_" + "a" * 32
        body = sql.fault_sql(self.selection(), True).split("AS $$", 1)[1].split("$$;", 1)[0]
        return {"relationOid": "100", "function": {
            "oid": "101", "namespace": "public", "name": name, "body": body,
            "arguments": 0, "returnType": "trigger", "language": "plpgsql",
            "securityDefiner": False, "volatility": "v", "configuration": None},
            "triggers": [{"oid": "102", "relationOid": "100", "functionOid": "101", "name": name,
                          "type": 7, "enabled": "O", "internal": False, "constraintOid": "0",
                          "deferrable": False, "initiallyDeferred": False, "argumentCount": 0,
                          "argumentsHex": "", "when": None, "oldTable": None, "newTable": None,
                          "parentOid": "0"}]}

    def test_trigger_is_exact_original_insert_only_and_transactional(self):
        statement = sql.fault_sql(self.selection(), True)
        self.assertIn("BEFORE INSERT ON public.direct_upload_completion_receipts", statement)
        for field, value in (("deployment_id", "actual-deployment"), ("session_id", "actual-session"),
                             ("operation_id", "b" * 64)):
            self.assertIn("NEW." + field + " = '" + value + "'", statement)
        self.assertIn("RETURN NEW;", statement)
        self.assertTrue(statement.startswith("BEGIN;"))
        self.assertTrue(statement.endswith("COMMIT;\n"))
        self.assertNotIn("UPDATE direct_upload_sessions", statement)

    def test_original_identity_cannot_inject_sql(self):
        for value in ("'; DROP TABLE direct_upload_sessions; --", "\n", "x" * 129, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                sql.literal(value)

    def test_complete_catalogue_shape_refuses_changed_function_event_and_predicate(self):
        actual = self.definition()
        sql.validate_definition(self.selection(), actual, "100")
        substitutions = (("functionOid", "999"), ("type", 5), ("type", 23), ("enabled", "D"),
                         ("when", "controlled foreign predicate"), ("argumentCount", 1),
                         ("argumentsHex", "666f726569676e00"), ("relationOid", "999"))
        for field, value in substitutions:
            changed = copy.deepcopy(actual)
            changed["triggers"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                sql.validate_definition(self.selection(), changed, "100")

    def test_replaced_trigger_refuses_cleanup_before_drop(self):
        installed = self.definition()
        for field, value in (("oid", "103"), ("functionOid", "999"), ("type", 5),
                             ("enabled", "A"), ("when", "controlled predicate")):
            changed = copy.deepcopy(installed)
            changed["triggers"][0][field] = value
            owner = sql.ScratchSql.__new__(sql.ScratchSql)
            owner.selection = self.selection()
            owner._fault_attempted = True
            owner._installed_definition = installed
            owner._check_database = lambda cleanup=False: None
            owner._fault_definition = lambda cleanup=False: changed
            owner._query = lambda *_args, **_kwargs: self.fail("changed trigger must refuse before DROP")
            with self.subTest(field=field), self.assertRaises(ValueError):
                owner.remove_fault()

    def test_installed_catalogue_is_validated_and_pinned(self):
        installed = self.definition()
        for changed in (False, True):
            actual = copy.deepcopy(installed)
            if changed:
                actual["triggers"][0]["functionOid"] = "999"
            with tempfile.TemporaryDirectory() as directory:
                os.chmod(directory, 0o700)
                owner = sql.ScratchSql.__new__(sql.ScratchSql)
                owner.selection = self.selection()
                owner.root = Path(directory)
                owner._fault_attempted = False
                owner._installed_definition = None
                owner._check_database = lambda: None
                states = iter([{"relationOid": "100", "function": None, "triggers": []}, actual])
                owner._fault_definition = lambda: next(states)
                statements = []

                def query(statement):
                    statements.append(statement)
                    return ("c" * 64 + "|7|admitted\n").encode() if statement.startswith("SELECT") else b""

                owner._query = query
                if changed:
                    with self.assertRaises(ValueError):
                        owner.install_fault()
                    self.assertIsNone(owner._installed_definition)
                else:
                    owner.install_fault()
                    self.assertEqual(owner._installed_definition, installed)
                self.assertTrue(owner._fault_attempted)
                self.assertEqual(len(statements), 2)

    def test_drop_rechecks_pinned_oid_image_in_same_locked_transaction(self):
        statement = sql.remove_sql(self.selection(), self.definition())
        self.assertTrue(statement.startswith("BEGIN;\nLOCK TABLE"))
        self.assertIn("IS DISTINCT FROM", statement)
        self.assertIn('"functionOid": "101"', statement)
        self.assertIn('"oid": "102"', statement)
        self.assertLess(statement.index("IS DISTINCT FROM"), statement.index("DROP TRIGGER"))
        self.assertTrue(statement.endswith("COMMIT;\n"))

    def test_selected_connection_credentials_are_environment_only(self):
        current = {"HOME": "/controlled/original-home", "UNCHANGED": "value", "PGHOSTADDR": "other", "PGSERVICE": "other"}
        environment = sql.database_environment("postgresql://fixture-user:fixture-pass@localhost:5543/fleet_staged_" + "a" * 32,
                                               current)
        self.assertEqual(environment["PGDATABASE"], "fleet_staged_" + "a" * 32)
        self.assertEqual(environment["PGHOST"], "localhost")
        self.assertEqual(environment["PGPORT"], "5543")
        self.assertEqual(environment["PGUSER"], "fixture-user")
        self.assertEqual(environment["PGPASSWORD"], "fixture-pass")
        self.assertEqual(environment["HOME"], current["HOME"])
        self.assertEqual(environment["UNCHANGED"], "value")
        self.assertNotIn("PGHOSTADDR", environment)
        self.assertNotIn("PGSERVICE", environment)
        self.assertEqual(current["PGSERVICE"], "other")

        owner = sql.ScratchSql.__new__(sql.ScratchSql)
        owner.tools = {"psql": "actual-selected-psql"}
        calls = []
        owner._run = lambda arguments, *args, **kwargs: calls.append(arguments)
        owner._query("SELECT current_database();")
        self.assertEqual(calls, [["actual-selected-psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1"]])
        with tempfile.TemporaryDirectory() as directory:
            owner.root = Path(directory)
            owner.selection = {"databaseName": "fleet_staged_" + "a" * 32}
            owner.tools.update({"pg_dump": "actual-selected-pg-dump", "pg_restore": "actual-selected-pg-restore"})
            owner._check_database = lambda: None
            snapshot = owner.snapshot()
            owner.restore(snapshot)
        self.assertTrue(calls[1][0].endswith("pg-dump"))
        self.assertTrue(calls[2][0].endswith("pg-restore"))
        for arguments in calls:
            self.assertFalse(any("postgresql://" in value or "fixture-pass" in value for value in arguments))
        self.assertIn("--dbname=fleet_staged_" + "a" * 32, calls[2])

    def test_changed_current_fingerprint_or_rv_refuses_before_trigger(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            for row in (b"wrong|7|admitted\n", ("c" * 64 + "|8|admitted\n").encode(),
                        ("c" * 64 + "|7|committed\n").encode(), b""):
                owner = sql.ScratchSql.__new__(sql.ScratchSql)
                owner.selection = self.selection()
                owner.root = Path(directory)
                statements = []
                owner._check_database = lambda: None

                def query(statement):
                    statements.append(statement)
                    return row

                owner._query = query
                with self.subTest(row=row), self.assertRaises(ValueError):
                    owner.install_fault()
                self.assertEqual(len(statements), 1)
                self.assertNotIn("CREATE TRIGGER", statements[0])

    def test_restore_refuses_foreign_or_replaced_snapshot_before_sql(self):
        owner = sql.ScratchSql.__new__(sql.ScratchSql)
        with tempfile.TemporaryDirectory() as directory:
            owner.root = Path(directory)
            for file in ("/unselected/scratch.dump", str(owner.root / "scratch.dump")):
                with self.subTest(file=file), self.assertRaises((ValueError, FileNotFoundError)):
                    owner.restore({"file": file, "sha256": "a" * 64, "byteSize": "1"})


if __name__ == "__main__":
    unittest.main()
