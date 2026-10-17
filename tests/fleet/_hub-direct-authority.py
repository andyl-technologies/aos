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


def validate_direct_clock_recovery_policy(policy, signing_key_id, uncertainty,
                                          commit_latency, timing_profile):
    """Check public selected structure; deployment qualification stays independent."""
    fields = ("version", "reviewer_key_id", "reviewer_public_key",
        "resource_qualification_digest", "clock_qualification_digest",
        "maximum_review_seconds", "clock_uncertainty", "clock_commit_latency")
    if not isinstance(policy, dict) or set(policy) != set(fields):
        raise ValueError("clock recovery policy differs from the closed source schema")
    if (type(policy["version"]) is not int or policy["version"] != 1
            or not isinstance(policy["reviewer_key_id"], str)
            or not 0 < len(policy["reviewer_key_id"].encode()) <= 255
            or policy["reviewer_key_id"] == signing_key_id):
        raise ValueError("clock recovery requires a distinct pinned independent reviewer")
    for name in fields[2:5]:
        if not isinstance(policy[name], str) or not re.fullmatch(r"[0-9a-f]{64}", policy[name]):
            raise ValueError("clock recovery requires explicit qualification and verifier pins")
    for name in fields[5:]:
        value = policy[name]
        if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,18}", value):
            raise ValueError("clock recovery time must use canonical nonnegative decimal strings")
        if int(value) > 2**63 - 1:
            raise ValueError("clock recovery time exceeds the shared integer range")
    total = uncertainty + commit_latency + 1
    if (not 1 <= int(policy["maximum_review_seconds"]) <= 30
            or int(policy["clock_uncertainty"]) != uncertainty
            or int(policy["clock_commit_latency"]) != commit_latency
            or commit_latency < 1 or total > 2**63 - 1
            or total > int(timing_profile["maximum_clock_uncertainty"])):
        raise ValueError("clock recovery time differs from the installed qualified interval")
    # This order matches ClockRecoveryPolicy's typed serde encoding. Rust still
    # validates the actual verifier and all signed documents at their boundaries.
    return {name: policy[name] for name in fields}


def provision_external_issuer(native, worker, python, openssl, installation,
                              timing_profile, clock_uncertainty, clock_commit_latency,
                              signing_key_id, renewal_key, certificate_file,
                              private_key_file, expected_server_name, *,
                              issuer_root="/var/lib/hybrid-authority",
                              worker_operator_root="/var/lib/hybrid-worker/operator",
                              listen="127.0.0.1:8444", hub_root="/var/lib/aos-hub",
                              clock_recovery_policy=None):
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

    if (issuer_root != "/var/lib/hybrid-authority" and re.fullmatch(
            r"/var/lib/hybrid-native/external-oci/[0-9a-f]{32}/issuer", issuer_root) is None
            or worker_operator_root != "/var/lib/hybrid-worker/operator" and re.fullmatch(
                r"/var/lib/hybrid-worker/external-oci/[0-9a-f]{32}/operator", worker_operator_root) is None
            or listen not in {"127.0.0.1:8444", "127.0.0.1:4680"}
            or hub_root != "/var/lib/aos-hub" and re.fullmatch(
                r"/var/lib/hybrid-native/external-oci/[0-9a-f]{32}/hub", hub_root) is None):
        raise ValueError("issuer fixture root or fixed listener differs")
    root = issuer_root
    configuration = {
        "format_version": 1, "listen": listen,
        "journal_file": root + "/journal/journal.sqlite", "installation": installation,
        "hub_root": hub_root, "hub_sqlite_file": None,
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
    if clock_recovery_policy is not None:
        configuration["clock_recovery"] = validate_direct_clock_recovery_policy(
            clock_recovery_policy, signing_key_id, clock_uncertainty,
            clock_commit_latency, timing_profile)
        # Only a new resource gets format 2 configuration / format 3 journal.
        # The create-only root and genuine initializer forbid legacy adoption.
        configuration["format_version"] = 2
    encoded_configuration = base64.b64encode(json.dumps(configuration).encode()).decode()
    encoded_renewal = base64.b64encode(renewal_key).decode()
    result = json.loads(private_guest_command(native, textwrap.dedent(f"""
        {shlex.quote(python)} - <<'NATIVE_ISSUER_RESOURCE'
        import base64, hashlib, json, os, subprocess
        from pathlib import Path

        root = Path({root!r})
        root.mkdir(mode=0o700, exist_ok=False)
        # Initialization requires an empty dedicated parent, separate from keys.
        (root / 'journal').mkdir(mode=0o700, exist_ok=False)
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

        root = Path({worker_operator_root + '/issuer'!r})
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


def initialize_external_issuer(native, python, authority_executable,
                               configuration_file, publication_file):
    """Retain bounded private initialization diagnostics before reporting failure.

    Only the fixed phase, category, exit status and collection bounds reach the
    driver. Raw stderr remains in a create-only owner-private issuer file.
    """
    result = json.loads(private_guest_command(native, textwrap.dedent(f"""
        {shlex.quote(python)} - <<'NATIVE_ISSUER_INITIALIZATION'
        import json, os, selectors, subprocess, time
        from pathlib import Path

        root = Path({configuration_file!r}).parent
        stderr_descriptor = os.open(root / 'initialize.stderr',
            os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        result_descriptor = os.open(root / 'initialize-result.json',
            os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        arguments = [{authority_executable!r}, 'initialize', '--configuration',
            {configuration_file!r}, '--publication', {publication_file!r}]
        body = bytearray()
        overflow = timed_out = eof = False
        with os.fdopen(stderr_descriptor, 'wb') as private_stderr:
            with subprocess.Popen(arguments, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as process:
                deadline = time.monotonic() + 110
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stderr, selectors.EVENT_READ)
                    while not eof:
                        if time.monotonic() >= deadline:
                            timed_out = True
                            break
                        if not selector.select(timeout=0.1):
                            continue
                        chunk = os.read(process.stderr.fileno(), 8192)
                        if not chunk:
                            eof = True
                            break
                        remaining = 65536 - len(body)
                        body.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            overflow = True
                            break
                if overflow or timed_out:
                    process.kill()
                try:
                    exit_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    timed_out = True
                    process.kill()
                    exit_code = process.wait(timeout=5)
            private_stderr.write(body)
            private_stderr.flush()
            os.fsync(private_stderr.fileno())

        category = 'success' if exit_code == 0 else 'other_failure'
        if overflow:
            category = 'stderr_bound_exceeded'
        elif timed_out:
            category = 'initialization_timeout'
        elif exit_code != 0:
            # Exact source error text selects a category; it never reaches the driver.
            for message, known in (
                    (b'issuer journal requires a dedicated private directory', 'journal_directory'),
                    (b'noncanonical initial publication', 'publication_encoding'),
                    (b'clock uncertainty exceeds reviewed profile', 'clock_profile')):
                if message in body:
                    category = known
                    break
        result = {{'phase': 'issuer_initialize', 'category': category,
            'exitCode': exit_code, 'stderrBytes': len(body), 'stderrComplete': eof,
            'stderrOverflow': overflow, 'timedOut': timed_out}}
        with os.fdopen(result_descriptor, 'wb') as output:
            output.write(json.dumps(result, separators=(',', ':')).encode())
            output.flush()
            os.fsync(output.fileno())
        print(json.dumps(result))
        NATIVE_ISSUER_INITIALIZATION
    """), timeout=120))
    label = "issuer-initialize-" + hashlib.sha256(os.fsencode(configuration_file)).hexdigest()[:16]
    retain_direct_flow(label + ".json", result)
    if (result["exitCode"] != 0 or result["stderrOverflow"] or result["timedOut"]
            or not result["stderrComplete"]):
        raise RuntimeError("issuer initialization failed: " + result["category"]
                           + " (exit " + str(result["exitCode"]) + ")")
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
    initialize_external_issuer(native, python, authority_executable,
        "/var/lib/hybrid-authority/configuration.json",
        "/var/lib/hybrid-authority/publication.json")

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


def start_external_issuer(native, python, authority_executable, *,
                          issuer_root="/var/lib/hybrid-authority",
                          qualification_observation_file=None, clock_resolution_file=None,
                          startup_label=None, recovery_expires_at=None,
                          recovery_uncertainty=None):
    """Retain a safe startup result before requiring actual process observation."""
    arguments = [authority_executable, "serve", "--configuration",
                 issuer_root + "/configuration.json"]
    if startup_label is not None and not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", startup_label):
        raise ValueError("issuer startup label differs from its fixed filename bound")
    if clock_resolution_file is not None:
        if (startup_label is None or clock_resolution_file != issuer_root + "/cold-recovery/resolution.json"
                or type(recovery_expires_at) is not int or type(recovery_uncertainty) is not int
                or recovery_uncertainty < 1):
            raise ValueError("recovered startup requires an exact receipt and original review deadline")
        arguments += ["--clock-resolution", clock_resolution_file]
    elif recovery_expires_at is not None or recovery_uncertainty is not None:
        raise ValueError("recovery deadline without explicit resolution")
    prefix = startup_label + "-" if startup_label is not None else ""
    log_name, summary_name, process_name = (prefix + name for name in
        ("serve.log", "startup-result.json", "process.json"))
    if qualification_observation_file is not None:
        arguments += ["--qualification-observation", qualification_observation_file]
    result = json.loads(private_guest_command(native, textwrap.dedent(f"""
        {shlex.quote(python)} - <<'NATIVE_ISSUER_PROCESS'
        import hashlib, json, os, subprocess, time
        from pathlib import Path

        root = Path({issuer_root!r})
        process = None
        receipt = None
        log_created = False
        phase, category = 'launch', 'launch_failure'
        try:
            if {clock_resolution_file is not None!r} and int(time.time()) + {recovery_uncertainty!r} >= {recovery_expires_at!r}:
                raise ValueError('original clock recovery deadline elapsed before successor launch')
            descriptor = os.open(root / {log_name!r}, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            log_created = True
            with os.fdopen(descriptor, 'wb') as log:
                process = subprocess.Popen({arguments!r}, stdin=subprocess.DEVNULL,
                    stdout=log, stderr=log, start_new_session=True)
            time.sleep(0.2)
            if process.poll() is not None:
                phase, category = 'early_exit', 'other_failure'
            else:
                phase, category = 'process_observation', 'observation_failure'
                status = Path('/proc/' + str(process.pid))
                executable = os.readlink(status / 'exe')
                with open(status / 'exe', 'rb') as executable_file:
                    executable_digest = hashlib.file_digest(executable_file, 'sha256').hexdigest()
                start_ticks = (status / 'stat').read_text().rsplit(')', 1)[1].split()[19]
                if process.poll() is None:
                    receipt = {{'version': 1, 'pid': process.pid, 'startTicks': start_ticks,
                        'executable': executable, 'executableSha256': executable_digest,
                        'machineRole': 'native_metadata_issuer', 'listener': '127.0.0.1:8444',
                        'scope': 'process startup only; authenticated lease observations pending'}}
                    if {clock_resolution_file is not None!r}:
                        receipt['clockResolutionFile'] = {clock_resolution_file!r}
                        if int(time.time()) + {recovery_uncertainty!r} >= {recovery_expires_at!r}:
                            receipt = None
                            raise ValueError('successor observation missed original review deadline')
                    phase, category = 'observed', 'process_observed'
        except (OSError, ValueError, IndexError):
            # Exception text and private logs never cross the guest boundary.
            pass

        exit_code = process.poll() if process is not None else None
        if receipt is not None and exit_code is not None:
            receipt = None
            phase, category = 'early_exit', 'other_failure'
        log_bytes, diagnostic, overflow = None, None, None
        try:
            if not log_created:
                raise OSError('startup log was not created')
            with open(root / {log_name!r}, 'rb') as log:
                log_bytes = os.fstat(log.fileno()).st_size
                diagnostic = log.read(65536)
            overflow = log_bytes > 65536
        except OSError:
            receipt = None
            if log_created:
                phase, category = 'log_inspection', 'log_inspection_failure'
        if phase == 'early_exit' and diagnostic is not None and not overflow:
            if b'grants group/other permissions' in diagnostic:
                category = 'permissions'
            elif any(message in diagnostic for message in (
                    b'TLS certificate file is empty',
                    b'TLS private-key file contains no supported key',
                    b'TLS certificate and private key are incompatible',
                    b'opening TLS certificate', b'opening TLS private key')):
                category = 'tls'
            elif any(message in diagnostic for message in (
                    b'unresolved clock session', b'configured issuer policy differs',
                    b'clock commit latency', b'clock observation')):
                category = 'clock'
        summary = {{'version': 1, 'phase': phase, 'category': category,
            'exitCode': exit_code, 'logBytes': log_bytes,
            'inspectedLogBytes': len(diagnostic) if diagnostic is not None else None,
            'logOverflow': overflow,
            'logComplete': exit_code is not None and diagnostic is not None and not overflow}}

        def retain(name, value):
            descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w') as output:
                json.dump(value, output, sort_keys=True, separators=(',', ':'))
                output.flush()
                os.fsync(output.fileno())

        retain({summary_name!r}, summary)
        if receipt is not None:
            retain({process_name!r}, receipt)
        print(json.dumps({{'summary': summary, 'process': receipt}}))
        NATIVE_ISSUER_PROCESS
    """), timeout=120))
    label = "issuer-startup-" + hashlib.sha256(os.fsencode(issuer_root)).hexdigest()[:16]
    if startup_label is not None:
        label += "-" + startup_label
    retain_direct_flow(label + ".json", result["summary"])
    if result["process"] is None:
        raise RuntimeError("issuer startup failed: " + result["summary"]["category"])
    return result["process"]


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


def _run_authority_control_sync(native, python, arguments, expected_receipt, *,
                                diagnostics_root="/var/lib/hybrid-authority/control-sync",
                                timeout_seconds=120):
    """Collect bounded private command output without exporting failure text."""
    if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 120:
        raise ValueError("authority synchronization collection deadline differs")
    result = json.loads(private_guest_command(native, textwrap.dedent(f"""
        {shlex.quote(python)} - <<'NATIVE_AUTHORITY_CONTROL_SYNC'
        import base64, json, os, selectors, subprocess, time
        from pathlib import Path

        root = Path({diagnostics_root!r})
        root.mkdir(mode=0o700, exist_ok=False)
        descriptors = {{name: os.open(root / (name + '.private'),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600) for name in ('stdout', 'stderr')}}
        buffers = {{name: bytearray() for name in descriptors}}
        limits = {{'stdout': 262144, 'stderr': 65536}}
        eof = {{name: False for name in descriptors}}
        overflow = {{name: False for name in descriptors}}
        process = None
        exit_code = None
        timed_out = False
        category = 'launch_failure'
        deadline = time.monotonic() + {timeout_seconds!r}
        try:
            process = subprocess.Popen({arguments!r}, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError:
            # Launch exceptions may contain sensitive paths; retain only a category.
            pass
        if process is not None:
            category = 'other_failure'
            with selectors.DefaultSelector() as selector:
                for name in descriptors:
                    selector.register(getattr(process, name), selectors.EVENT_READ, name)
                while selector.get_map():
                    if time.monotonic() >= deadline:
                        timed_out = True
                        break
                    for selected, _ in selector.select(timeout=0.1):
                        name = selected.data
                        chunk = os.read(selected.fd, 8192)
                        if not chunk:
                            eof[name] = True
                            selector.unregister(selected.fileobj)
                            continue
                        remaining = limits[name] - len(buffers[name])
                        buffers[name].extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            overflow[name] = True
                    if any(overflow.values()):
                        break
            if timed_out or any(overflow.values()):
                process.kill()
            try:
                exit_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                exit_code = process.wait(timeout=5)
            finally:
                process.stdout.close()
                process.stderr.close()
        for name, descriptor in descriptors.items():
            with os.fdopen(descriptor, 'wb') as private_output:
                private_output.write(buffers[name])
                private_output.flush()
                os.fsync(private_output.fileno())

        receipt_body = None
        if any(overflow.values()):
            category = 'output_bound_exceeded'
        elif timed_out:
            category = 'synchronization_timeout'
        elif process is not None and exit_code != 0:
            for message, known in (
                    (b'authority control returned status 503', 'authority_control_unavailable'),
                    (b'authority control returned status 401', 'authority_control_authentication'),
                    (b'authority control returned status 400', 'authority_control_domain'),
                    (b'authority control returned status 409', 'authority_control_reconciliation'),
                    (b'authority remote watermark differs from desired state or exact predecessor', 'authority_history'),
                    (b'authority latest remote watermark differs from reviewed desired generation', 'authority_watermark'),
                    (b'authority facts changed during control preflight', 'authority_changed'),
                    (b'authority response signature is missing', 'authority_response_authentication'),
                    (b'requesting fresh authority control evidence', 'authority_transport'),
                    (b'reading native database URL credential file', 'database_input'),
                    (b'grants group/other permissions', 'permissions')):
                if message in buffers['stderr']:
                    category = known
                    break
        elif exit_code == 0 and all(eof.values()):
            try:
                receipt = json.loads(buffers['stdout'])
                if receipt == {expected_receipt!r}:
                    category = 'success'
                    receipt_body = base64.b64encode(buffers['stdout']).decode()
                else:
                    category = 'receipt_mismatch'
            except (ValueError, UnicodeError):
                category = 'receipt_encoding'
        elif process is not None:
            category = 'incomplete_output'
        summary = {{'version': 1, 'phase': 'authority_control_sync',
            'category': category, 'exitCode': exit_code, 'timedOut': timed_out,
            'stdoutBytes': len(buffers['stdout']), 'stderrBytes': len(buffers['stderr']),
            'stdoutComplete': eof['stdout'], 'stderrComplete': eof['stderr'],
            'stdoutOverflow': overflow['stdout'], 'stderrOverflow': overflow['stderr']}}
        descriptor = os.open(root / 'result.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            json.dump(summary, output, separators=(',', ':'))
            output.flush()
            os.fsync(output.fileno())
        print(json.dumps({{'summary': summary, 'receiptBody': receipt_body}}))
        NATIVE_AUTHORITY_CONTROL_SYNC
    """), timeout=150))
    label = "authority-control-sync-" + hashlib.sha256(os.fsencode(diagnostics_root)).hexdigest()[:16]
    retain_direct_flow(label + ".json", result["summary"])
    if result["summary"]["category"] != "success":
        raise RuntimeError("authority synchronization failed: " + result["summary"]["category"]
                           + " (exit " + str(result["summary"]["exitCode"]) + ")")
    return base64.b64decode(result["receiptBody"], validate=True)


def reconcile_external_authority(native, hub_executable, database_url_file,
                                 storage_work_key_file, exported, worker_url, *, python):
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
    expected_receipt = {
        "authority_id": authority["authority_id"], "desired_generation": publication["generation"],
        "desired_digest": publication["digest"], "control_synchronized": True,
        "provider_readiness_evaluated": False,
    }
    body = _run_authority_control_sync(native, python, arguments, expected_receipt)
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
