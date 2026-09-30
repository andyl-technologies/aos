"""Install private Worker controls before measuring an External fixture.

Keys are generated on Worker and remain separate from provider material and the
Native issuer seed. Consumer updates preserve the exact configured namespace
and artifact. Callers stop their own recorded runner before replacing its
configuration; this module neither restarts processes nor installs acceptance.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import textwrap


DIRECT_WORKER_PRIVATE_KEYS = (
    "HUB_STORAGE_WORK_KEY",
    "HUB_DIRECT_UPLOAD_GUARD_KEY", "HUB_DIRECT_UPLOAD_CONFORMANCE_KEY",
    "HUB_DIRECT_UPLOAD_JOURNAL_KEY", "HUB_EXTERNAL_OBJECT_GUARD_KEY",
    "HUB_EXTERNAL_STAGE_KEY", "HUB_AUTHORITY_RENEWAL_KEY",
)


def direct_guest_python(machine, python, body, document, timeout=60):
    """Run a bounded private guest action with explicit JSON inputs."""
    encoded = base64.b64encode(json.dumps(document, separators=(",", ":")).encode()).decode()
    command = (
        f"{shlex.quote(python)} - <<'DIRECT_PRIVATE_ACTION'\n"
        "import base64, json\n"
        f"selected = json.loads(base64.b64decode({encoded!r}, validate=True))\n"
        + textwrap.dedent(body) + "\nDIRECT_PRIVATE_ACTION\n"
    )
    return private_guest_command(machine, command, timeout=timeout)


def start_direct_worker(worker, tools, configuration, generation):
    """Start the selected immutable runner and retain its actual process lifetime."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", generation):
        raise ValueError("Worker generation label is invalid")
    return json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, os, subprocess, time
        from pathlib import Path

        root = Path('/var/lib/hybrid-worker')
        root.mkdir(mode=0o700, exist_ok=True)
        arguments = [selected['node'], selected['runner'], selected['miniflare'], selected['configuration']]
        environment = dict(os.environ)
        environment.update(NODE_EXTRA_CA_CERTS='/etc/ssl/certs/ca-certificates.crt',
            SSL_CERT_FILE='/etc/ssl/certs/ca-certificates.crt',
            MINIFLARE_WORKERD_PATH=selected['workerd'])
        log_path = root / (selected['generation'] + '.log')
        descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as log:
            process = subprocess.Popen(arguments, env=environment, stdin=subprocess.DEVNULL,
                stdout=log, stderr=log, start_new_session=True)
        time.sleep(0.2)
        if process.poll() is not None:
            raise ValueError('selected Worker runner exited before observation')
        directory = Path('/proc') / str(process.pid)
        metadata = directory.stat()
        command = (directory / 'cmdline').read_bytes().split(b'\\x00')[:-1]
        if command != [os.fsencode(value) for value in arguments] or metadata.st_uid != os.getuid():
            raise ValueError('actual Worker process differs from selected runner')
        lifetime = (directory / 'stat').read_text().rpartition(') ')[2].split()[19]
        receipt = {'version': 1, 'pid': process.pid, 'ownerUid': metadata.st_uid,
            'startTicks': lifetime, 'arguments': arguments, 'logFile': str(log_path),
            'configurationFile': selected['configuration'],
            'configurationSha256': hashlib.sha256(Path(selected['configuration']).read_bytes()).hexdigest(),
            'generation': selected['generation']}
        descriptor = os.open(root / (selected['generation'] + '.process.json'),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            json.dump(receipt, output, sort_keys=True, separators=(',', ':'))
            output.flush()
            os.fsync(output.fileno())
        # Existing observers use this selected process. Its immutable receipt
        # remains available across a deliberate configuration reload.
        (root / 'worker.pid').write_text(str(process.pid))
        print(json.dumps(receipt))
    """, {**{name: tools[name] for name in ("node", "runner", "miniflare", "workerd")},
            "configuration": configuration, "generation": generation}))


def stop_direct_worker(worker, python, process):
    """Stop only this recorded runner, allowing Miniflare to flush and dispose."""
    return json.loads(direct_guest_python(worker, python, """
        import os, signal, time
        from pathlib import Path

        directory = Path('/proc') / str(selected['pid'])
        def matches():
            fields = (directory / 'stat').read_text().rpartition(') ')[2].split()
            command = (directory / 'cmdline').read_bytes().split(b'\\x00')[:-1]
            return (fields[19] == selected['startTicks']
                and directory.stat().st_uid == selected['ownerUid']
                and command == [os.fsencode(value) for value in selected['arguments']])
        if not matches():
            raise ValueError('Worker lifetime changed before disposal')
        os.kill(selected['pid'], signal.SIGTERM)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                fields = (directory / 'stat').read_text().rpartition(') ')[2].split()
            except FileNotFoundError:
                break
            if fields[19] != selected['startTicks'] or fields[0] == 'Z':
                break
            time.sleep(0.1)
        else:
            raise ValueError('recorded Worker disposal did not complete; no broad kill issued')
        socket_path = Path('/var/lib/hybrid-worker/acceptance-control.sock')
        if socket_path.exists():
            metadata = socket_path.lstat()
            import stat
            if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise ValueError('disposed runner socket custody changed')
            socket_path.unlink()
        print(json.dumps({'version': 1, 'pid': selected['pid'],
            'startTicks': selected['startTicks'], 'status': 'recorded_runner_disposed',
            'persistenceRemoved': False}))
    """, process, timeout=45))


def direct_namespace_readback(worker, python, process):
    """Capture actual selected namespace IDs from the exact live runner peer."""
    return json.loads(direct_guest_python(worker, python, """
        import os, socket, struct
        from pathlib import Path

        directory = Path('/proc') / str(selected['pid'])
        before = (directory / 'stat').read_text().rpartition(') ')[2].split()[19]
        if before != selected['startTicks'] or directory.stat().st_uid != selected['ownerUid']:
            raise ValueError('namespace runner identity changed')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(15)
            peer.connect('/var/lib/hybrid-worker/acceptance-control.sock')
            pid, uid, _ = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if pid != selected['pid'] or uid != selected['ownerUid']:
                raise ValueError('namespace observer connected to another runner')
            peer.sendall(b'{"version":1,"kind":"namespace-readback"}')
            peer.shutdown(socket.SHUT_WR)
            body = bytearray()
            while block := peer.recv(4096):
                body.extend(block)
                if len(body) > 131072:
                    raise ValueError('namespace readback exceeds bound')
        actual = json.loads(body)
        after = (directory / 'stat').read_text().rpartition(') ')[2].split()[19]
        if (before != after or actual['runnerPid'] != selected['pid']
                or actual['runnerStartTicks'] != before
                or actual['configurationSha256'] != selected['configurationSha256']):
            raise ValueError('namespace readback changed runtime identity')
        print(json.dumps(actual, sort_keys=True, separators=(',', ':')))
    """, process, timeout=30))


def initialize_direct_worker_controls(worker, python, reviewer_executable,
                                      original_configuration, reviewer_public_key):
    """Create distinct private controls with the selected independent verifier."""
    if not re.fullmatch(r"[0-9a-f]{64}", reviewer_public_key):
        raise ValueError("Worker requires the independently selected public reviewer")
    result = json.loads(private_guest_command(worker, textwrap.dedent(f"""
        {shlex.quote(python)} - <<'INSTALL_WORKER_CONTROLS'
        import hashlib, json, os, secrets, subprocess
        from pathlib import Path

        root = Path('/var/lib/hybrid-worker/controls')
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        configuration = json.loads(Path({original_configuration!r}).read_bytes())
        binding = configuration['bindings']
        keys = {{name: secrets.token_hex(32) for name in {DIRECT_WORKER_PRIVATE_KEYS!r}
                if name != 'HUB_STORAGE_WORK_KEY'}}
        keys['HUB_STORAGE_WORK_KEY'] = binding['HUB_STORAGE_WORK_KEY']
        if len(set(keys.values())) != len(keys):
            raise ValueError('Worker control keys are not independent')
        for name, value in keys.items():
            descriptor = os.open(root / (name + '.key'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w') as output:
                output.write(value)
                output.flush()
                os.fsync(output.fileno())
            binding[name] = value
        binding['HUB_DIRECT_UPLOAD_QUALIFICATION_PUBLIC_KEY'] = {reviewer_public_key!r}
        clock = subprocess.run([{reviewer_executable!r}, 'clock-policy', '--uncertainty-seconds',
            binding['HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS']],
            capture_output=True, check=False, timeout=60)
        if clock.returncode:
            raise ValueError('installed shared clock-policy encoder refused')
        policy = json.loads(clock.stdout)
        if policy['commitment'] != binding['HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION']:
            raise ValueError('configured clock commitment differs from the installed shared encoder')
        documents = {{'clock-policy.json': clock.stdout,
            'configuration-bootstrap.json': json.dumps(configuration, sort_keys=True,
                separators=(',', ':')).encode()}}
        for name, body in documents.items():
            descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(body)
                output.flush()
                os.fsync(output.fileno())
        print(json.dumps({{'version': 1, 'configurationFile': str(root / 'configuration-bootstrap.json'),
            'configurationSha256': hashlib.sha256(documents['configuration-bootstrap.json']).hexdigest(),
            'clockPolicy': policy, 'keyFiles': {{name: str(root / (name + '.key')) for name in keys}},
            'scope': 'private control provisioning only; no runtime or provider acceptance'}}))
        INSTALL_WORKER_CONTROLS
    """), timeout=90))
    if set(result["keyFiles"]) != set(DIRECT_WORKER_PRIVATE_KEYS):
        raise RuntimeError("Worker installed another control key set")
    return result


def install_direct_worker_consumers(worker, python, previous_configuration,
                                    consumer_bindings, issuer_binding):
    """Write reviewed consumer inputs while preserving persistence and artifact."""
    if set(consumer_bindings) != {"HUB_EXTERNAL_OBJECT_CONSUMER", "HUB_EXTERNAL_STAGING_CONSUMER"}:
        raise ValueError("Worker consumer inputs differ from the closed fixture projection")
    update = {"consumerBindings": consumer_bindings, "issuerBinding": issuer_binding}
    encoded = base64.b64encode(json.dumps(update, separators=(",", ":")).encode()).decode()
    return json.loads(private_guest_command(worker, textwrap.dedent(f"""
        {shlex.quote(python)} - <<'INSTALL_WORKER_CONSUMERS'
        import base64, hashlib, json, os
        from pathlib import Path

        root = Path('/var/lib/hybrid-worker/controls')
        original = Path({previous_configuration!r}).read_bytes()
        configuration = json.loads(original)
        update = json.loads(base64.b64decode({encoded!r}, validate=True))
        identity = {{name: configuration.get(name) for name in (
            'name', 'scriptPath', 'resourcePersistencePath', 'durableObjects',
            'kvNamespaces', 'queueProducers', 'queueConsumers')}}
        for name, value in update['consumerBindings'].items():
            configuration['bindings'][name] = json.dumps(value, sort_keys=True, separators=(',', ':'))
        configuration.setdefault('serviceBindings', {{}})['HUB_AUTHORITY_ISSUER'] = update['issuerBinding']
        if any(configuration.get(name) != value for name, value in identity.items()):
            raise ValueError('consumer installation changed namespace, artifact or queue identity')
        body = json.dumps(configuration, sort_keys=True, separators=(',', ':')).encode()
        destination = root / 'configuration-consumers.json'
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
        print(json.dumps({{'version': 1, 'configurationFile': str(destination),
            'previousConfigurationSha256': hashlib.sha256(original).hexdigest(),
            'configurationSha256': hashlib.sha256(body).hexdigest(),
            'scope': 'consumer configuration only; restart, hydration and actual leases pending'}}))
        INSTALL_WORKER_CONSUMERS
    """), timeout=60))


def inspect_direct_external_deployment(worker, python, hub_executable, exported,
                                       worker_url, native_origin_url, worker_name,
                                       emulator_bucket, guard_key_file):
    """Capture the installed CLI's authenticated full actual External profile."""
    bootstrap = exported["bootstrap"]
    root = "/var/lib/hybrid-worker/operator/deployment-inspection"
    encoded = base64.b64encode(json.dumps([bootstrap["selector"]]).encode()).decode()
    arguments = [
        hub_executable, "worker", "inspect-hybrid-direct-upload", "--name", worker_name,
        "--bucket", emulator_bucket, "--deployment-id", bootstrap["deployment_id"],
        "--external-url", worker_url, "--native-origin-url", native_origin_url,
        "--direct-upload-guard-key-file", guard_key_file,
        "--direct-upload-external-selectors-file", root + "/selectors.json",
    ]
    body = private_guest_command(worker, textwrap.dedent(f"""
        {shlex.quote(python)} - <<'AUTHENTICATED_EXTERNAL_INSPECTION'
        import base64, os, subprocess, sys
        from pathlib import Path

        root = Path({root!r})
        root.mkdir(mode=0o700, exist_ok=False)
        descriptor = os.open(root / 'selectors.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(base64.b64decode({encoded!r}, validate=True))
            output.flush()
            os.fsync(output.fileno())
        environment = dict(os.environ)
        environment['SSL_CERT_FILE'] = '/etc/ssl/certs/ca-certificates.crt'
        result = subprocess.run({arguments!r}, env=environment, capture_output=True,
            check=False, timeout=60)
        if result.returncode:
            raise ValueError('installed authenticated External discovery refused')
        if len(result.stdout) > 262144:
            raise ValueError('actual External identity exceeds its shared bound')
        descriptor = os.open(root / 'identity.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(result.stdout)
            output.flush()
            os.fsync(output.fileno())
        sys.stdout.buffer.write(result.stdout)
        AUTHENTICATED_EXTERNAL_INSPECTION
    """), timeout=90).encode()
    identity = json.loads(body)
    if (
        identity["version"] != 1 or identity["deploymentId"] != bootstrap["deployment_id"]
        or identity["publicOrigin"] != worker_url or identity["managedProfile"] is not None
        or len(identity["externalProfiles"]) != 1
        or not re.fullmatch(r"[0-9a-f]{64}", identity["sourceDigest"])
        or identity["scriptVersion"] != "emulated-" + identity["sourceDigest"]
    ):
        raise RuntimeError("actual authenticated deployment differs from the External fixture")
    destination = Path("external-direct-authority/deployment-identity.json")
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    return {"identity": identity, "identityFile": root + "/identity.json",
            "identitySha256": hashlib.sha256(body).hexdigest(),
            "scope": "authenticated installed profile capture; no acceptance"}
