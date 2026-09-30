"""Provision restricted SQL custody for the Worker-side fixture operator.

Provider material remains on Worker. This helper installs only a separate SQL
login and grants selected metadata reads against the live initialized database.
It grants no storage admission, credential validation or provider acceptance.
"""

import base64
import hashlib
import json
import re
import shlex
import textwrap


HYDRATION_METADATA_TABLES = (
    "schema_version", "hub_schema_identity", "physical_storage_authorities",
    "physical_storage_aliases", "binding_storage_authority_revisions",
    "storage_authority_attestations", "storage_authority_admission_heads",
    "storage_authority_admission_revisions", "bindings", "binding_credential_heads",
    "binding_credential_revisions", "binding_write_revisions",
)


CREDENTIAL_CUSTODY_METADATA_TABLES = HYDRATION_METADATA_TABLES + (
    "topology_operations", "binding_write_state",
    "binding_identity_reservations", "topology_plans",
)


def install_operator_provider_versions(worker, python, material, version_references):
    """Keep actual immutable provider values and their manifest on Worker only."""
    if not isinstance(material, bytes) or not material or len(material) > 65536:
        raise ValueError("provider material has an invalid size")
    references = dict(version_references)
    if not references or not set(references).issubset({"read", "write", "presign", "list", "delete"}):
        raise ValueError("provider credential purposes are invalid")
    if len(set(references.values())) != len(references):
        raise ValueError("immutable provider references must be distinct")
    if any(not isinstance(value, str) or not value.endswith("/v1") for value in references.values()):
        raise ValueError("fixture provider references require explicit first versions")

    encoded_material = base64.b64encode(material).decode()
    encoded_references = base64.b64encode(json.dumps(references).encode()).decode()
    result = json.loads(private_guest_command(worker, textwrap.dedent(f"""
        {shlex.quote(python)} - <<'OPERATOR_PROVIDER_VERSIONS'
        import base64, hashlib, json, os
        from pathlib import Path

        root = Path('/var/lib/hybrid-worker/operator/provider-versions')
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        material = base64.b64decode({encoded_material!r}, validate=True)
        references = json.loads(base64.b64decode({encoded_references!r}, validate=True))
        manifest = {{}}
        for purpose, reference in sorted(references.items()):
            destination = root / (purpose + '.value')
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(material)
                output.flush()
                os.fsync(output.fileno())
            manifest[reference] = str(destination)

        destination = root / 'manifest.json'
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            json.dump(manifest, output, sort_keys=True, separators=(',', ':'))
            output.write('\\n')
            output.flush()
            os.fsync(output.fileno())
        print(json.dumps({{'version': 1, 'manifestFile': str(destination),
            'materialSha256': hashlib.sha256(material).hexdigest(),
            'versionReferences': references, 'machineRole': 'worker_operator'}}))
        OPERATOR_PROVIDER_VERSIONS
    """)))
    if result["materialSha256"] != hashlib.sha256(material).hexdigest():
        raise RuntimeError("Worker retained another provider value")
    if result["versionReferences"] != references:
        raise RuntimeError("Worker retained other immutable provider references")
    return result


def private_guest_command(machine, command, timeout=60):
    """Execute private fixture input without retaining material in error text."""
    # Agent debug logging retains the first sixty bytes. Its failure exceptions
    # can include the whole request, so replace those with an explicit stage
    # refusal before they reach the driver log.
    prefix = "# Private fixture input: command contents and output are not logged.\n"
    try:
        status, stdout, _ = machine.agent.request(
            (prefix + command).encode(), timeout=timeout,
        )
    except Exception:
        raise RuntimeError("private operator fixture command failed in transport") from None
    if status != 0:
        raise RuntimeError(f"private operator fixture command failed with exit {status}")
    return stdout.decode()


def stage_queued_provider_credential(worker, python, bootstrap_executable, operation_id,
                                     purpose, deployment_id, worker_url,
                                     storage_work_key_file, manifest_file):
    """Stage only the genuine queued credential original through the installed tool."""
    if purpose not in {"read", "write", "presign", "list", "delete"}:
        raise ValueError("invalid provider credential purpose")
    output = "/var/lib/hybrid-worker/operator/credential-stage-" + purpose
    arguments = [
        bootstrap_executable, "--database-url-file",
        "/var/lib/hybrid-worker/operator/sql.url", "stage-credential",
        "--operation-id", operation_id, "--deployment-id", deployment_id,
        "--worker-url", worker_url, "--storage-work-key-file", storage_work_key_file,
        "--secret-version-manifest", manifest_file, "--retention-seconds", "86400",
        "--output", output,
    ]
    private_guest_command(worker, shlex.join(arguments), timeout=120)
    receipt_bytes = private_guest_command(worker, (
        f"{shlex.quote(python)} - <<'STAGED_CREDENTIAL_RECEIPT'\n"
        "from pathlib import Path\nimport sys\n"
        f"body=Path({output + '/credential-stage.json'!r}).read_bytes()\n"
        "if len(body)>262144:raise ValueError('credential stage receipt exceeds bound')\n"
        "sys.stdout.buffer.write(body)\nSTAGED_CREDENTIAL_RECEIPT\n"
    )).encode()
    receipt = json.loads(receipt_bytes)
    return {
        "version": 1, "operationId": operation_id, "purpose": purpose,
        "receiptSha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "receiptByteSize": len(receipt_bytes), "receipt": receipt,
        "scope": "Worker material custody only; SQL validation requires actual controller success",
    }


def read_operator_binding_pins(worker, postgres, database_host, binding):
    """Read current numeric identity, validated heads and selected writer through SQL."""
    stable_id = binding["stableId"]
    if not re.fullmatch(r"[A-Za-z0-9:._-]{1,64}", stable_id):
        raise ValueError("invalid fixture binding stable identity")
    if not re.fullmatch(r"[a-z][a-z0-9.-]{0,63}", database_host):
        raise ValueError("invalid operator SQL fixture host")
    query = textwrap.dedent(f"""
        SELECT json_build_object(
          'bindingId', b.id::text,
          'bindingStableId', b.stable_id,
          'bindingResourceVersion', b.resource_version::text,
          'bindingPrefix', b.object_prefix,
          'currentWriteRevision', s.current_write_revision::text,
          'credentials', (
            SELECT json_agg(json_build_object(
              'purpose', h.purpose,
              'generation', r.generation::text,
              'secretVersionRef', r.secret_version_ref,
              'credentialFingerprint', r.credential_fingerprint,
              'validationState', r.validation_state,
              'validatedAt', r.validated_at::text,
              'headResourceVersion', h.resource_version::text
            ) ORDER BY h.purpose)
            FROM binding_credential_heads h
            JOIN binding_credential_revisions r
              ON r.binding_id = h.binding_id AND r.purpose = h.purpose
                AND r.generation = h.current_generation
            WHERE h.binding_id = b.id
          )
        )
        FROM bindings b
        JOIN binding_write_state s ON s.binding_id = b.id
        WHERE b.stable_id = '{stable_id}'
    """).strip()
    arguments = [postgres + "/psql", "-h", database_host,
                 "-U", "fleet_direct_operator", "-d", "postgres",
                 "-v", "ON_ERROR_STOP=1", "-At", "-c", query]
    body = private_guest_command(worker,
        "PGPASSWORD=$(cat /var/lib/hybrid-worker/operator/sql-password) "
        + shlex.join(arguments), timeout=60,
    )
    if len(body.encode()) > 65536:
        raise ValueError("operator SQL binding metadata exceeds bound")
    pins = json.loads(body)
    if (
        pins["bindingStableId"] != stable_id
        or pins["bindingResourceVersion"] != binding["resourceVersion"]
        or pins["bindingPrefix"] != binding["spec"]["s3"]["prefix"]
        or not re.fullmatch(r"[1-9][0-9]*", pins["bindingId"])
        or not re.fullmatch(r"[1-9][0-9]*", pins["currentWriteRevision"])
    ):
        raise ValueError("operator current SQL identity differs from the actual API binding")
    credentials = pins["credentials"]
    if (
        not credentials or len({item["purpose"] for item in credentials}) != len(credentials)
        or not {"read", "write", "presign"}.issubset(item["purpose"] for item in credentials)
        or any(
            item["validationState"] != "valid"
            or not isinstance(item["validatedAt"], str)
            or not re.fullmatch(r"[1-9][0-9]*", item["validatedAt"])
            for item in credentials
        )
    ):
        raise ValueError("operator current SQL credentials have not all passed actual probes")
    return pins


def provision_operator_reader(database_machine, worker, python, postgres, database_host,
                              selected_tables=HYDRATION_METADATA_TABLES):
    """Create a distinct live SQL reader and verify its actual privileges."""
    tables = tuple(selected_tables)
    if not set(HYDRATION_METADATA_TABLES).issubset(tables):
        raise ValueError("operator reader omitted required current metadata tables")
    if len(tables) != len(set(tables)) or any(
        not re.fullmatch(r"[a-z][a-z_]{0,63}", name) for name in tables
    ):
        raise ValueError("operator SQL grant list is invalid")
    if not re.fullmatch(r"[a-z][a-z0-9.-]{0,63}", database_host):
        raise ValueError("operator database fixture host is invalid")

    password = private_guest_command(worker, textwrap.dedent(f"""
        {shlex.quote(python)} - <<'OPERATOR_PRIVATE_PASSWORD'
        import os, secrets
        from pathlib import Path
        root = Path('/var/lib/hybrid-worker/operator')
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        value = secrets.token_hex(32)
        descriptor = os.open(root / 'sql-password', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        print(value)
        OPERATOR_PRIVATE_PASSWORD
    """)).strip()
    if not re.fullmatch(r"[a-f0-9]{64}", password):
        raise RuntimeError("operator SQL password generation returned invalid material")

    grants = ", ".join(tables)
    private_guest_command(database_machine, textwrap.dedent(f"""
        set -eu
        umask 077
        sql_file=/tmp/fleet-operator-reader.sql
        trap 'rm -f "$sql_file"' EXIT
        cat > "$sql_file" <<'OPERATOR_READER_SQL'
        BEGIN;
        SET LOCAL password_encryption = 'scram-sha-256';
        CREATE ROLE fleet_direct_operator LOGIN PASSWORD '{password}'
          NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
        GRANT CONNECT ON DATABASE postgres TO fleet_direct_operator;
        GRANT USAGE ON SCHEMA public TO fleet_direct_operator;
        GRANT SELECT ON {grants} TO fleet_direct_operator;
        COMMIT;
        OPERATOR_READER_SQL
        {shlex.quote(postgres)}/psql -h 127.0.0.1 -U postgres -d postgres \\
          -v ON_ERROR_STOP=1 -f "$sql_file" > /dev/null 2>&1
    """))
    private_guest_command(worker, textwrap.dedent(f"""
        {shlex.quote(python)} - <<'OPERATOR_PRIVATE_URL'
        import os
        from pathlib import Path
        root = Path('/var/lib/hybrid-worker/operator')
        password = (root / 'sql-password').read_text()
        descriptor = os.open(root / 'sql.url', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            output.write('postgres://fleet_direct_operator:' + password + '@{database_host}:5432/postgres')
            output.flush()
            os.fsync(output.fileno())
        OPERATOR_PRIVATE_URL
    """))
    actual = worker.succeed(textwrap.dedent(f"""
        PGPASSWORD=$(cat /var/lib/hybrid-worker/operator/sql-password) \\
          {shlex.quote(postgres)}/psql -h {database_host} -U fleet_direct_operator -d postgres \\
          -v ON_ERROR_STOP=1 -At -F '|' -c \\
          "SELECT has_database_privilege(current_user, current_database(), 'CONNECT'),
           has_schema_privilege(current_user, 'public', 'USAGE'),
           has_table_privilege(current_user, 'bindings', 'SELECT'),
           has_table_privilege(current_user, 'bindings', 'UPDATE'),
           has_table_privilege(current_user, 'bindings', 'INSERT'),
           has_schema_privilege(current_user, 'public', 'CREATE'),
           has_database_privilege(current_user, current_database(), 'CREATE'),
           rolsuper, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = current_user"
    """)).strip().split("|")
    if actual != ["t", "t", "t", "f", "f", "f", "f", "f", "f", "f"]:
        raise AssertionError("actual operator SQL reader privileges differ from required custody")

    # The operator's lifetime checks need two additional history tables. Inspect
    # every selected table so a partial grant cannot masquerade as a usable role.
    selected_values = ", ".join(f"('{table}')" for table in tables)
    privilege_query = (
        "SELECT json_agg(json_build_object('table', name, "
        "'select', has_table_privilege(current_user, name, 'SELECT'), "
        "'mutate', has_table_privilege(current_user, name, "
        "'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')) ORDER BY name) "
        f"FROM (VALUES {selected_values}) AS selected(name)"
    )
    table_privileges = json.loads(private_guest_command(worker,
        "PGPASSWORD=$(cat /var/lib/hybrid-worker/operator/sql-password) "
        + shlex.join([
            postgres + "/psql", "-h", database_host, "-U", "fleet_direct_operator",
            "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-At", "-c", privilege_query,
        ]), timeout=60,
    ))
    if (
        {item["table"] for item in table_privileges} != set(tables)
        or len(table_privileges) != len(tables)
        or any(item["select"] is not True or item["mutate"] is not False
               for item in table_privileges)
    ):
        raise AssertionError("actual operator SQL table grants differ from SELECT-only custody")
    return {
        "version": 1,
        "role": "fleet_direct_operator",
        "selected_tables": list(tables),
        "actual_table_privileges": table_privileges,
        "actual_connect_usage_select": True,
        "actual_write_ddl_superuser_createdb_createrole": False,
        "sql_url_file": "/var/lib/hybrid-worker/operator/sql.url",
    }
