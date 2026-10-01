"""Install the separate issuer from reviewed inputs and genuine SQL export.

The issuer seed and publisher key stay on Native in a private resource outside
the Hub root. Worker receives public installation metadata, the renewal key and
the SQL-derived publication. Export and hydration run with its restricted SQL
role; none of these steps produces runtime acceptance.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import textwrap


def provision_external_issuer(native, worker, python, openssl, installation,
                              timing_profile, clock_uncertainty, clock_commit_latency,
                              signing_key_id, renewal_key, certificate_file,
                              private_key_file, expected_server_name):
    """Generate Native-only keys under an independently selected installation."""
    if set(installation) != {
        "format_version", "authority", "issuer_resource_id", "runtime_identity",
        "executor_identity",
    } or installation["format_version"] != 1:
        raise ValueError("issuer installation differs from the shared closed schema")
    if set(timing_profile) != {
        "profile_id", "review_digest", "maximum_lifetime", "maximum_clock_uncertainty",
    } or not re.fullmatch(r"[0-9a-f]{64}", timing_profile["review_digest"]):
        raise ValueError("issuer requires an explicit independently reviewed timing profile")
    if (
        type(clock_uncertainty) is not int or clock_uncertainty < 0
        or type(clock_commit_latency) is not int or clock_commit_latency < 1
        or not isinstance(renewal_key, bytes) or not 32 <= len(renewal_key) <= 65536
    ):
        raise ValueError("issuer clock or renewal input is invalid")
    if not signing_key_id or not expected_server_name or any(not path.startswith("/") for path in (
        certificate_file, private_key_file,
    )):
        raise ValueError("issuer requires explicit signing and TLS identities")

    root = "/var/lib/hybrid-authority"
    configuration = {
        "format_version": 1, "listen": "127.0.0.1:8444",
        "journal_file": root + "/journal.sqlite", "installation": installation,
        "hub_root": "/var/lib/aos-hub", "hub_sqlite_file": None,
        "policy": {"timing_profile": timing_profile},
        "clock_uncertainty": str(clock_uncertainty),
        "clock_commit_latency": str(clock_commit_latency), "issuance_enabled": True,
        "publisher_key_file": root + "/publisher.key",
        "renewal_key_file": root + "/renewal.key",
        "signing_seed_file": root + "/signing-seed.key",
        "signing_key_id": signing_key_id,
        "tls": {"certificate_file": certificate_file,
                "private_key_file": private_key_file,
                "expected_server_name": expected_server_name},
    }
    encoded_configuration = base64.b64encode(json.dumps(configuration).encode()).decode()
    encoded_renewal = base64.b64encode(renewal_key).decode()
    result = json.loads(private_guest_command(native, textwrap.dedent(f"""
        {shlex.quote(python)} - <<'NATIVE_ISSUER_RESOURCE'
        import base64, hashlib, json, os, subprocess
        from pathlib import Path

        root = Path({root!r})
        root.mkdir(mode=0o700, exist_ok=False)
        configuration = json.loads(base64.b64decode({encoded_configuration!r}, validate=True))
        certificate_check = subprocess.run([{openssl!r}, 'x509', '-noout',
            '-in', configuration['tls']['certificate_file'], '-checkhost',
            configuration['tls']['expected_server_name']], capture_output=True, check=False)
        if certificate_check.returncode:
            raise ValueError('installed issuer leaf does not cover selected TLS hostname')
        seed = os.urandom(32)
        # RFC 8410 PKCS#8 encodes the same Ed25519 seed consumed by the issuer.
        private_der = bytes.fromhex('302e020100300506032b657004220420') + seed
        command = [{openssl!r}, 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER']
        derived = subprocess.run(command, input=private_der, capture_output=True, check=False)
        public_prefix = bytes.fromhex('302a300506032b6570032100')
        if derived.returncode or not derived.stdout.startswith(public_prefix) or len(derived.stdout) != 44:
            raise ValueError('source-built Ed25519 public verifier derivation failed')
        public_key = derived.stdout[len(public_prefix):].hex()
        renewal = base64.b64decode({encoded_renewal!r}, validate=True)
        values = {{'signing-seed.key': seed.hex().encode(),
            'publisher.key': os.urandom(32).hex().encode(), 'renewal.key': renewal,
            'issuer-public-key.hex': public_key.encode(),
            'configuration.json': json.dumps(configuration, sort_keys=True,
                separators=(',', ':')).encode()}}
        for name, body in values.items():
            descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(body)
                output.flush()
                os.fsync(output.fileno())
        print(json.dumps({{'configuration': configuration, 'publicKey': public_key,
            'configurationSha256': hashlib.sha256(values['configuration.json']).hexdigest(),
            'seedCustody': 'native_issuer_only', 'publisherCustody': 'native_issuer_only'}}))
        NATIVE_ISSUER_RESOURCE
    """)))
    if result["configuration"] != configuration or not re.fullmatch(r"[0-9a-f]{64}", result["publicKey"]):
        raise RuntimeError("issuer provisioning returned different public metadata")
    metadata = {
        "issuer.json": json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode(),
        "issuer-public-key.hex": result["publicKey"].encode(),
        "issuer-renewal.key": renewal_key,
    }
    encoded_metadata = base64.b64encode(json.dumps({
        name: base64.b64encode(body).decode() for name, body in metadata.items()
    }).encode()).decode()
    private_guest_command(worker, textwrap.dedent(f"""
        {shlex.quote(python)} - <<'WORKER_ISSUER_METADATA'
        import base64, json, os
        from pathlib import Path

        root = Path('/var/lib/hybrid-worker/operator/issuer')
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        values = json.loads(base64.b64decode({encoded_metadata!r}, validate=True))
        for name, encoded in values.items():
            body = base64.b64decode(encoded, validate=True)
            descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(body)
                output.flush()
                os.fsync(output.fileno())
        WORKER_ISSUER_METADATA
    """))
    return result


def export_external_authority(worker, native, python, bootstrap_executable,
                              authority_executable, authority_id, association_id,
                              deployment_id, admitted_prefix):
    """Export live SQL pins on Worker and initialize that exact Native publication."""
    operator = "/var/lib/hybrid-worker/operator"
    destination = operator + "/authority-export"
    arguments = [
        bootstrap_executable, "--database-url-file", operator + "/sql.url", "export",
        "--authority-id", authority_id, "--association-id", association_id,
        "--deployment-id", deployment_id, "--issuer-configuration", operator + "/issuer/issuer.json",
        "--issuer-public-key-file", operator + "/issuer/issuer-public-key.hex",
        "--admitted-prefix", admitted_prefix, "--output", destination,
    ]
    private_guest_command(worker, shlex.join(arguments), timeout=120)
    documents = {}
    for name in ("publication.json", "bootstrap.json"):
        body = private_guest_command(worker, textwrap.dedent(f"""
            {shlex.quote(python)} - <<'ACTUAL_AUTHORITY_EXPORT'
            from pathlib import Path
            import sys
            body = Path({destination + '/' + name!r}).read_bytes()
            if len(body) > 1048576:
                raise ValueError('actual authority export exceeds shared bound')
            sys.stdout.buffer.write(body)
            ACTUAL_AUTHORITY_EXPORT
        """)).encode()
        documents[name] = body

    bootstrap = json.loads(documents["bootstrap.json"])
    if bootstrap["publication"] != json.loads(documents["publication.json"]):
        raise RuntimeError("operator export contains different publications")
    encoded_publication = base64.b64encode(documents["publication.json"]).decode()
    private_guest_command(native, textwrap.dedent(f"""
        {shlex.quote(python)} - <<'NATIVE_ACTUAL_PUBLICATION'
        import base64, os
        body = base64.b64decode({encoded_publication!r}, validate=True)
        descriptor = os.open('/var/lib/hybrid-authority/publication.json',
            os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
        NATIVE_ACTUAL_PUBLICATION
    """))
    private_guest_command(native, shlex.join([
        authority_executable, "initialize", "--configuration",
        "/var/lib/hybrid-authority/configuration.json", "--publication",
        "/var/lib/hybrid-authority/publication.json",
    ]), timeout=120)

    root = Path("external-direct-authority")
    root.mkdir(mode=0o700)
    for name, body in documents.items():
        descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
    return {"bootstrap": bootstrap, "workerDirectory": destination,
            "documentSha256": {name: hashlib.sha256(body).hexdigest()
                               for name, body in documents.items()}}


def start_external_issuer(native, python, authority_executable):
    """Launch the initialized issuer and retain its actual process identity."""
    return json.loads(private_guest_command(native, textwrap.dedent(f"""
        {shlex.quote(python)} - <<'NATIVE_ISSUER_PROCESS'
        import hashlib, json, os, subprocess, time
        from pathlib import Path

        root = Path('/var/lib/hybrid-authority')
        descriptor = os.open(root / 'serve.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as log:
            process = subprocess.Popen([{authority_executable!r}, 'serve',
                '--configuration', str(root / 'configuration.json')],
                stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        time.sleep(0.2)
        if process.poll() is not None:
            raise ValueError('initialized issuer exited before process observation')
        status = Path('/proc/' + str(process.pid))
        executable = os.readlink(status / 'exe')
        executable_digest = hashlib.file_digest(open(status / 'exe', 'rb'), 'sha256').hexdigest()
        start_ticks = (status / 'stat').read_text().rsplit(')', 1)[1].split()[19]
        receipt = {{'version': 1, 'pid': process.pid, 'startTicks': start_ticks,
            'executable': executable, 'executableSha256': executable_digest,
            'machineRole': 'native_metadata_issuer', 'listener': '127.0.0.1:8444',
            'scope': 'process startup only; authenticated lease observations pending'}}
        descriptor = os.open(root / 'process.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            json.dump(receipt, output, sort_keys=True, separators=(',', ':'))
            output.flush()
            os.fsync(output.fileno())
        print(json.dumps(receipt))
        NATIVE_ISSUER_PROCESS
    """)))


def hydrate_external_authority(worker, python, bootstrap_executable, exported,
                               worker_url, storage_work_key_file, manifest_file):
    """Run the genuine current-SQL hydration on Worker after consumer installation."""
    operator = "/var/lib/hybrid-worker/operator"
    destination = operator + "/authority-hydration"
    arguments = [
        bootstrap_executable, "--database-url-file", operator + "/sql.url", "hydrate",
        "--bootstrap", exported["workerDirectory"] + "/bootstrap.json",
        "--worker-url", worker_url, "--storage-work-key-file", storage_work_key_file,
        "--secret-version-manifest", manifest_file, "--output", destination,
    ]
    private_guest_command(worker, shlex.join(arguments), timeout=120)
    body = private_guest_command(worker, textwrap.dedent(f"""
        {shlex.quote(python)} - <<'ACTUAL_HYDRATION_RECEIPT'
        from pathlib import Path
        import sys
        body = Path({destination + '/hydration.json'!r}).read_bytes()
        if len(body) > 1048576:
            raise ValueError('actual hydration receipt exceeds shared bound')
        sys.stdout.buffer.write(body)
        ACTUAL_HYDRATION_RECEIPT
    """)).encode()
    receipt = json.loads(body)
    bootstrap = exported["bootstrap"]
    if (
        receipt["version"] != 1 or receipt["deployment_id"] != bootstrap["deployment_id"]
        or receipt["executor_public_origin"] != worker_url
        or receipt["publication_digest"] != bootstrap["write_cohort"]["publication_digest"]
        or receipt["binding_hydrated"] is not True
        or receipt["provider_readiness_evaluated"] is not False
    ):
        raise RuntimeError("actual hydration acknowledgement differs from exported metadata")
    destination = Path("external-direct-authority/hydration.json")
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    return {"receipt": receipt, "receiptSha256": hashlib.sha256(body).hexdigest()}


def reconcile_external_authority(native, hub_executable, database_url_file,
                                 storage_work_key_file, exported, worker_url):
    """Reconcile current SQL with fresh signed Worker watermarks on Native."""
    bootstrap = exported["bootstrap"]
    publication = bootstrap["publication"]
    authority = publication["authority"]
    arguments = [
        hub_executable, "--root", "/var/lib/aos-hub", "--database-url-file",
        database_url_file, "authority-control-sync", "--authority-id",
        authority["authority_id"], "--guard-namespace-id", authority["guard_namespace_id"],
        "--executor-identity", bootstrap["issuer_installation"]["executor_identity"],
        "--worker-url", worker_url, "--deployment-id", bootstrap["deployment_id"],
        "--storage-work-key-file", storage_work_key_file,
    ]
    body = private_guest_command(native, shlex.join(arguments), timeout=120).encode()
    if len(body) > 262144:
        raise ValueError("actual authority reconciliation exceeds the control bound")
    receipt = json.loads(body)
    if (
        set(receipt) != {
            "authority_id", "desired_generation", "desired_digest",
            "control_synchronized", "provider_readiness_evaluated",
        }
        or receipt["authority_id"] != authority["authority_id"]
        or receipt["desired_generation"] != publication["generation"]
        or receipt["desired_digest"] != publication["digest"]
        or receipt["control_synchronized"] is not True
        or receipt["provider_readiness_evaluated"] is not False
    ):
        raise RuntimeError("fresh authority acknowledgement differs from the SQL export")

    # This is one metadata bootstrap exchange. Ordinary object operations use
    # the existing Native issuer and authenticated binding refresh paths.
    destination = Path("external-direct-authority/control-synchronization.json")
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    return {"receipt": receipt, "receiptSha256": hashlib.sha256(body).hexdigest()}
