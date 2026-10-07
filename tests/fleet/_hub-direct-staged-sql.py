"""Fault one real completion INSERT in a disposable PostgreSQL database.

The trigger does not alter admission or synthesize receipts. Snapshot/restore
requires the caller to stop the selected scratch Native writers first. Neither
operation touches an issuer journal or a Worker persistence namespace.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from urllib.parse import unquote, urlsplit


MAX_METADATA = 64 * 1024
MAX_DUMP = 256 * 1024 * 1024


def closed(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError("staged SQL fields differ")


def private_bytes(file, maximum):
    descriptor = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or before.st_size > maximum):
            raise ValueError("staged SQL private input custody differs")
        with os.fdopen(os.dup(descriptor), "rb") as reader:
            raw = reader.read(maximum + 1)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) != before.st_size or any(getattr(before, name) != getattr(after, name) for name in fields):
            raise ValueError("staged SQL input changed during read")
        return raw
    finally:
        os.close(descriptor)


def reference(file, maximum):
    descriptor = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or before.st_size > maximum):
            raise ValueError("retained SQL file custody differs")
        digest = hashlib.sha256()
        count = 0
        with os.fdopen(os.dup(descriptor), "rb") as source:
            while block := source.read(65536):
                count += len(block)
                if count > maximum:
                    raise ValueError("retained SQL file exceeds bound")
                digest.update(block)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if count != before.st_size or any(getattr(before, name) != getattr(after, name) for name in fields):
            raise ValueError("retained SQL file changed")
        return {"file": str(file), "sha256": digest.hexdigest(), "byteSize": str(count)}
    finally:
        os.close(descriptor)


def retained(root, name, raw):
    file = root / name
    descriptor = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    return reference(file, MAX_METADATA)


def literal(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value):
        raise ValueError("actual SQL original identity differs")
    return "'" + value.replace("'", "''") + "'"


def fault_sql(selection, install):
    """Builds only the fixed table trigger for the exact retained original."""
    name = "aos_staged_fault_" + selection["runId"]
    deployment, session, operation = (literal(selection[key]) for key in
                                       ("deploymentId", "sessionId", "operationId"))
    if install:
        return f"""BEGIN;
CREATE FUNCTION public.{name}() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.deployment_id = {deployment} AND NEW.session_id = {session}
     AND NEW.operation_id = {operation} THEN
    RAISE EXCEPTION 'aos_staged_selected_receipt_insert_refused' USING ERRCODE = 'P0001';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER {name} BEFORE INSERT ON public.direct_upload_completion_receipts
FOR EACH ROW EXECUTE FUNCTION public.{name}();
COMMIT;
"""
    return f"""BEGIN;
DROP TRIGGER {name} ON public.direct_upload_completion_receipts;
DROP FUNCTION public.{name}();
COMMIT;
"""


def definition_sql(selection):
    """Selects the exact relation, function and trigger catalogue attributes."""
    name = literal("aos_staged_fault_" + selection["runId"])
    return f"""SELECT jsonb_build_object(
  'relationOid', to_regclass('public.direct_upload_completion_receipts')::oid::text,
  'function', (
    SELECT jsonb_build_object(
      'oid', p.oid::text, 'namespace', n.nspname, 'name', p.proname,
      'body', p.prosrc, 'arguments', p.pronargs, 'returnType', p.prorettype::regtype::text,
      'language', l.lanname, 'securityDefiner', p.prosecdef, 'volatility', p.provolatile,
      'configuration', p.proconfig)
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    JOIN pg_language l ON l.oid = p.prolang
    WHERE n.nspname = 'public' AND p.proname = {name} AND p.pronargs = 0),
  'triggers', (
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
      'oid', t.oid::text, 'relationOid', t.tgrelid::text, 'functionOid', t.tgfoid::text,
      'name', t.tgname, 'type', t.tgtype, 'enabled', t.tgenabled, 'internal', t.tgisinternal,
      'constraintOid', t.tgconstraint::text, 'deferrable', t.tgdeferrable,
      'initiallyDeferred', t.tginitdeferred, 'argumentCount', t.tgnargs,
      'argumentsHex', encode(t.tgargs, 'hex'), 'when', t.tgqual::text,
      'oldTable', t.tgoldtable, 'newTable', t.tgnewtable, 'parentOid', t.tgparentid::text)
      ORDER BY t.oid), '[]'::jsonb)
    FROM pg_trigger t
    WHERE t.tgrelid = to_regclass('public.direct_upload_completion_receipts')
      AND t.tgname = {name}));
"""


def validate_definition(selection, definition, relation_oid):
    """Requires the installed INSERT-only trigger to call this exact function."""
    closed(definition, {"relationOid", "function", "triggers"})
    if (not isinstance(relation_oid, str) or not re.fullmatch(r"[1-9][0-9]*", relation_oid)
            or definition["relationOid"] != relation_oid):
        raise ValueError("scratch fault target relation changed")
    function = definition["function"]
    closed(function, {"oid", "namespace", "name", "body", "arguments", "returnType", "language",
                      "securityDefiner", "volatility", "configuration"})
    name = "aos_staged_fault_" + selection["runId"]
    body = fault_sql(selection, True).split("AS $$", 1)[1].split("$$;", 1)[0]
    expected_function = {"oid": function["oid"], "namespace": "public", "name": name, "body": body,
                         "arguments": 0, "returnType": "trigger", "language": "plpgsql",
                         "securityDefiner": False, "volatility": "v", "configuration": None}
    if (not isinstance(function["oid"], str) or not re.fullmatch(r"[1-9][0-9]*", function["oid"])
            or function != expected_function):
        raise ValueError("scratch fault function differs")
    triggers = definition["triggers"]
    if not isinstance(triggers, list) or len(triggers) != 1:
        raise ValueError("scratch fault trigger count differs")
    trigger = triggers[0]
    expected_trigger = {"oid": trigger.get("oid"), "relationOid": relation_oid, "functionOid": function["oid"],
                        "name": name, "type": 7, "enabled": "O", "internal": False,
                        "constraintOid": "0", "deferrable": False, "initiallyDeferred": False,
                        "argumentCount": 0, "argumentsHex": "", "when": None,
                        "oldTable": None, "newTable": None, "parentOid": "0"}
    # PostgreSQL tgtype bits 1|2|4 mean ROW, BEFORE and INSERT respectively.
    # An AFTER/UPDATE trigger, disabled trigger or WHEN predicate is not ours.
    if (not isinstance(trigger.get("oid"), str) or not re.fullmatch(r"[1-9][0-9]*", trigger["oid"])
            or trigger != expected_trigger):
        raise ValueError("scratch fault trigger differs")


def remove_sql(selection, definition):
    """Rechecks the pinned catalogue image in the same transaction as DROP."""
    name = "aos_staged_fault_" + selection["runId"]
    expected = json.dumps(definition, sort_keys=True).replace("'", "''")
    query = definition_sql(selection).removeprefix("SELECT ").rstrip().removesuffix(";")
    return f"""BEGIN;
LOCK TABLE public.direct_upload_completion_receipts IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
  IF ({query}) IS DISTINCT FROM '{expected}'::jsonb THEN
    RAISE EXCEPTION 'aos_staged_fault_definition_changed' USING ERRCODE = 'P0001';
  END IF;
END;
$$;
DROP TRIGGER {name} ON public.direct_upload_completion_receipts;
DROP FUNCTION public.{name}();
COMMIT;
"""


def database_environment(url, current):
    """Supplies the private selected connection without placing it in argv."""
    selected = urlsplit(url)
    environment = dict(current)
    environment["PGDATABASE"] = selected.path.removeprefix("/")
    environment["PGHOST"] = selected.hostname
    # A connection service or hostaddr can override the selected URI's host.
    # Other process settings, including HOME and SSL settings, stay unchanged.
    environment.pop("PGSERVICE", None)
    environment.pop("PGHOSTADDR", None)
    if selected.port is not None:
        environment["PGPORT"] = str(selected.port)
    if selected.username is not None:
        environment["PGUSER"] = unquote(selected.username)
    if selected.password is not None:
        environment["PGPASSWORD"] = unquote(selected.password)
    return environment


class ScratchSql:
    """Owns fixed commands against an explicitly selected scratch database.

    The caller supplies a real prepared original and immutable source-built
    PostgreSQL tools. Constructing this object checks files but executes no SQL.
    """

    def __init__(self, selection, root):
        closed(selection, {"version", "runId", "databaseName", "databaseUrlFile", "postgresBin",
                           "deploymentId", "sessionId", "operationId", "logicalFingerprint",
                           "expectedResourceVersion", "cutoffUnixMs"})
        if (selection["version"] != 1 or isinstance(selection["version"], bool)
                or not re.fullmatch(r"[0-9a-f]{32}", selection["runId"])
                or selection["databaseName"] != "fleet_staged_" + selection["runId"]
                or not isinstance(selection["cutoffUnixMs"], int)
                or isinstance(selection["cutoffUnixMs"], bool)
                or not 0 < selection["cutoffUnixMs"] - int(time.time() * 1000) <= 180000
                or not re.fullmatch(r"[0-9a-f]{64}", selection["operationId"])
                or not re.fullmatch(r"[0-9a-f]{64}", selection["logicalFingerprint"])
                or not re.fullmatch(r"[1-9][0-9]{0,18}", selection["expectedResourceVersion"])):
            raise ValueError("scratch SQL selection differs")
        for key in ("deploymentId", "sessionId", "operationId"):
            literal(selection[key])
        self.selection = dict(selection)
        self.root = Path(root)
        if str(self.root.resolve(strict=True)) != str(self.root):
            raise ValueError("scratch SQL output root is not canonical")
        info = self.root.stat()
        if not self.root.is_dir() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("scratch SQL output custody differs")
        url_file = Path(selection["databaseUrlFile"])
        if url_file.resolve(strict=True) != url_file:
            raise ValueError("scratch URL file is not canonical")
        raw = private_bytes(url_file, 16384)
        self.url = raw.decode("utf-8").strip()
        url = urlsplit(self.url)
        if (url.scheme not in {"postgres", "postgresql"} or url.path != "/" + selection["databaseName"]
                or not url.hostname or url.query or url.fragment):
            raise ValueError("database URL is not the selected scratch database")
        self.url_sha256 = hashlib.sha256(raw).hexdigest()
        self.tools = {}
        self.tool_hashes = {}
        for name in ("psql", "pg_dump", "pg_restore"):
            file = Path(selection["postgresBin"]) / name
            actual = file.resolve(strict=True)
            info = actual.stat()
            if (str(actual) != str(file) or not str(actual).startswith("/nix/store/")
                    or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o222
                    or not os.access(actual, os.X_OK) or info.st_size > 512 * 1024 * 1024):
                raise ValueError("PostgreSQL tool is not an immutable selected executable")
            self.tools[name] = str(actual)
            with actual.open("rb") as source:
                self.tool_hashes[name] = hashlib.file_digest(source, "sha256").hexdigest()
        self.sequence = 0
        self._fault_attempted = False
        self._installed_definition = None

    def _fault_definition(self, cleanup=False):
        raw = self._query(definition_sql(self.selection), cleanup)
        value = json.loads(raw)
        closed(value, {"relationOid", "function", "triggers"})
        return value

    def _run(self, arguments, sql=None, dump=None, cleanup=False):
        self.sequence += 1
        label = f"sql-{self.sequence:02d}"
        stdout = self.root / (label + ".stdout")
        stderr = self.root / (label + ".stderr")
        remaining = self.selection["cutoffUnixMs"] / 1000 - time.time()
        if remaining <= 0 and not cleanup:
            raise ValueError("scratch SQL cutoff elapsed")
        deadline = time.monotonic() + (5 if cleanup else min(remaining, 30))
        child = None
        primary = None
        try:
            with stdout.open("xb") as out, stderr.open("xb") as error:
                os.chmod(stdout, 0o600)
                os.chmod(stderr, 0o600)
                environment = database_environment(self.url, os.environ)
                child = subprocess.Popen(arguments, stdin=subprocess.PIPE if sql is not None else subprocess.DEVNULL,
                                         stdout=out, stderr=error, env=environment)
                if sql is not None:
                    child.stdin.write(sql.encode("utf-8"))
                    child.stdin.close()
                while child.poll() is None:
                    if (time.monotonic() >= deadline or (not cleanup and time.time() * 1000 >= self.selection["cutoffUnixMs"])
                            or stdout.stat().st_size > MAX_METADATA or stderr.stat().st_size > MAX_METADATA
                            or (dump is not None and dump.stat().st_size > MAX_DUMP)):
                        raise RuntimeError("scratch SQL command exceeded its closed bound")
                    time.sleep(0.01)
                if child.returncode != 0:
                    raise RuntimeError("actual scratch SQL command refused; private output retained")
            return private_bytes(stdout, MAX_METADATA)
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                if child is not None and child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=2)
            except BaseException as error:
                if primary is None:
                    raise
                primary.add_note("SQL child cleanup failed: " + type(error).__name__)
            if child is not None:
                try:
                    retained(self.root, label + ".json", json.dumps({
                        "version": 1, "databaseName": self.selection["databaseName"],
                        "databaseUrlSha256": self.url_sha256, "returnCode": child.returncode,
                        "toolHashes": self.tool_hashes,
                        "stdout": reference(stdout, MAX_METADATA), "stderr": reference(stderr, MAX_METADATA),
                        "providerSettlement": None,
                    }, sort_keys=True).encode())
                except BaseException as error:
                    if primary is None:
                        raise
                    primary.add_note("SQL command retention failed: " + type(error).__name__)

    def _query(self, sql, cleanup=False):
        return self._run([self.tools["psql"], "-X", "-qAt", "-v", "ON_ERROR_STOP=1"], sql, cleanup=cleanup)

    def _check_database(self, cleanup=False):
        if self._query("SELECT current_database();\n", cleanup).decode().strip() != self.selection["databaseName"]:
            raise ValueError("connected scratch database identity differs")

    def install_fault(self):
        """Installs the exact receipt trigger; ordinary admission is caller-owned."""
        self._check_database()
        predicate = " AND ".join(f"{column}={literal(self.selection[key])}" for column, key in
                                  (("deployment_id", "deploymentId"), ("session_id", "sessionId")))
        row = self._query("SELECT logical_fingerprint, resource_version, state FROM direct_upload_sessions WHERE "
                          + predicate + ";\n")
        fields = row.decode("utf-8").strip().split("|")
        if (len(fields) != 3 or fields[0] != self.selection["logicalFingerprint"]
                or fields[1] != self.selection["expectedResourceVersion"]
                or fields[2] not in {"admitted", "staged_verified"}):
            raise ValueError("actual current original session differs from prepared fingerprint/RV")
        prior = self._fault_definition()
        relation_oid = prior["relationOid"]
        if (self._fault_attempted or not isinstance(relation_oid, str)
                or not re.fullmatch(r"[1-9][0-9]*", relation_oid)
                or prior != {"relationOid": relation_oid, "function": None, "triggers": []}):
            raise ValueError("scratch fault names are already owned; no replacement attempted")
        self._fault_attempted = True
        self._query(fault_sql(self.selection, True))
        installed = self._fault_definition()
        validate_definition(self.selection, installed, relation_oid)
        self._installed_definition = installed
        retained(self.root, "installed-fault.private.json", json.dumps(installed, sort_keys=True).encode())
        return retained(self.root, "selected-session.private.txt", row)

    def remove_fault(self):
        # DDL cleanup gets a short separate bound; it authorizes no provider
        # effect, target settlement, grant renewal, or mutation retry.
        self._check_database(cleanup=True)
        if not self._fault_attempted:
            raise ValueError("no selected fault installation was attempted; nothing removed")
        definition = self._fault_definition(cleanup=True)
        if definition["function"] is None and definition["triggers"] == []:
            return
        if self._installed_definition is None or definition != self._installed_definition:
            raise ValueError("scratch fault definition changed; nothing removed")
        validate_definition(self.selection, definition, definition["relationOid"])
        self._query(remove_sql(self.selection, definition), cleanup=True)
        absent = self._fault_definition(cleanup=True)
        if absent != {"relationOid": definition["relationOid"], "function": None, "triggers": []}:
            raise ValueError("selected fault objects remain installed or target relation changed")

    def snapshot(self):
        """Captures the selected scratch database while its writers are stopped."""
        self._check_database()
        file = self.root / "scratch.dump"
        descriptor = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        self._run([self.tools["pg_dump"], "--format=custom", "--no-owner", "--no-acl",
                   "--file=" + str(file)], dump=file)
        return reference(file, MAX_DUMP)

    def restore(self, snapshot):
        """Restores only this object's retained snapshot into its selected DB."""
        closed(snapshot, {"file", "sha256", "byteSize"})
        if snapshot["file"] != str(self.root / "scratch.dump") or reference(snapshot["file"], MAX_DUMP) != snapshot:
            raise ValueError("scratch restore does not select the exact retained dump")
        self._check_database()
        self._run([self.tools["pg_restore"], "--clean", "--if-exists", "--single-transaction",
                   "--no-owner", "--no-acl", "--dbname=" + self.selection["databaseName"], snapshot["file"]])
