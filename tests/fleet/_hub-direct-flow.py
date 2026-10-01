"""Run the explicit External fixture through independent review checkpoints.

The entry point uses genuine public decisions, Worker-side provider custody,
Native-side metadata issuance and the installed signed publisher. Observations
are retained before assertions. A pending independent review, unknown provider
effect or failed gate stops the original flow without replay or cleanup.
"""

import base64
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import textwrap
import time


def retain_direct_flow(name, value):
    """Retain new private evidence bytes and return their exact commitment."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,127}", name):
        raise ValueError("External evidence name is invalid")
    root = Path("external-direct-flow")
    root.mkdir(mode=0o700, exist_ok=True)
    body = value if isinstance(value, bytes) else (
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    return hashlib.sha256(body).hexdigest()


def direct_selected_bytes(reference, maximum_bytes):
    """Read only the explicitly reviewed immutable file under private custody."""
    if set(reference) != {"path", "sha256"} or not re.fullmatch(r"[0-9a-f]{64}", reference["sha256"]):
        raise ValueError("independent selected file reference differs from its schema")
    descriptor = os.open(reference["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_mode & 0o077 or before.st_nlink != 1 or before.st_size > maximum_bytes):
            raise ValueError("independent selected file has invalid custody or size")
        body = source.read(maximum_bytes + 1)
        after = os.fstat(source.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (len(body) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in fields)
            or hashlib.sha256(body).hexdigest() != reference["sha256"]):
        raise ValueError("independent selected bytes changed")
    return body


def install_direct_guest_file(machine, python, path, body):
    """Transfer selected private bytes once without logging material."""
    if not path.startswith("/") or not isinstance(body, bytes):
        raise ValueError("private fixture file input is invalid")
    return json.loads(direct_guest_python(machine, python, """
        import hashlib, os
        from pathlib import Path

        destination = Path(selected['path'])
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        body = base64.b64decode(selected['body'], validate=True)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
        print(json.dumps({'file': str(destination), 'sha256': hashlib.sha256(body).hexdigest(),
            'byteSize': len(body)}))
    """, {"path": path, "body": base64.b64encode(body).decode()}))


def read_direct_guest_file(machine, python, path, maximum_bytes):
    """Capture an actual bounded regular file while preserving its private bytes."""
    captured = json.loads(direct_guest_python(machine, python, """
        import hashlib, os, stat
        from pathlib import Path

        descriptor = os.open(selected['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > selected['maximumBytes']:
                raise ValueError('actual capture is not a bounded regular file')
            body = source.read(selected['maximumBytes'] + 1)
            after = os.fstat(source.fileno())
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if len(body) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in fields):
            raise ValueError('actual capture changed while reading')
        print(json.dumps({'sha256': hashlib.sha256(body).hexdigest(),
            'body': base64.b64encode(body).decode()}))
    """, {"path": path, "maximumBytes": maximum_bytes}))
    body = base64.b64decode(captured["body"], validate=True)
    if len(body) > maximum_bytes or hashlib.sha256(body).hexdigest() != captured["sha256"]:
        raise ValueError("actual guest file capture changed in transport")
    return body


def capture_direct_artifacts(worker, tools):
    """Dump the exact realized source/distribution and hash actual installed files."""
    return json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, os, subprocess
        from pathlib import Path

        root = Path('/var/lib/hybrid-worker/installation')
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        files = {name: selected[name] for name in ('wasm', 'shim', 'runner', 'workerd')}
        files.update({name: selected[name] for name in (
            'nginx', 'nativeObservationProxyConfiguration', 'workerObservationProxyConfiguration')})
        files.update({name: selected[tool] for name, tool in (
            ('nativeHub', 'hub'), ('authority', 'authority'),
            ('authorityBootstrap', 'authorityBootstrap'), ('reviewer', 'reviewer'),
            ('providerConformance', 'providerConformance'), ('client', 'aos'), ('publisher', 'apr'))})
        for name, path in (('sourceNar', selected['workerSourcePath']),
                           ('distributionNar', selected['workerDistribution'])):
            destination = root / (name + '.nar')
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                result = subprocess.run([selected['nixStore'], '--dump', path],
                    stdout=output, stderr=subprocess.PIPE, check=False, timeout=120)
                output.flush()
                os.fsync(output.fileno())
            if result.returncode:
                raise ValueError('actual immutable NAR capture refused')
            files[name] = str(destination)
        observations = {}
        for name, path in files.items():
            with open(path, 'rb') as source:
                digest = hashlib.file_digest(source, 'sha256').hexdigest()
            observations[name] = {'file': path, 'sha256': digest, 'byteSize': str(Path(path).stat().st_size)}
        print(json.dumps({'version': 1, 'sourceStorePath': selected['workerSourcePath'],
            'distributionStorePath': selected['workerDistribution'], 'files': observations,
            'buildDerivedSourceDigest': hashlib.sha256(os.fsencode(selected['workerSourcePath'])).hexdigest(),
            'scope': 'actual immutable artifact bytes; protected identity and runtime pending'}))
    """, tools, timeout=300))


def observe_direct_native_trust(native, tools, artifacts, label):
    """Retain the live ordinary Native process and its installed trust inputs."""
    if not re.fullmatch(r"[a-z0-9-]{1,32}", label):
        raise ValueError("Native trust observation label is invalid")
    observed = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, pwd, re, ssl, stat, subprocess
        from pathlib import Path

        result = subprocess.run(['systemctl', 'show', '--property=MainPID', '--value',
            'aos-hub.service'], capture_output=True, check=True, timeout=10)
        pid = int(result.stdout)
        if pid <= 1:
            raise ValueError('ordinary Native service has no live process')
        process = Path('/proc') / str(pid)
        before = (process / 'stat').read_text().rsplit(')', 1)[1].split()
        if before[0] == 'Z' or process.stat().st_uid != pwd.getpwnam('aos-hub').pw_uid:
            raise ValueError('ordinary Native process owner or lifetime differs')
        with (process / 'exe').open('rb') as executable:
            executable_sha = hashlib.file_digest(executable, 'sha256').hexdigest()
        if executable_sha != selected['executableSha256']:
            raise ValueError('ordinary Native process differs from installed package')

        root = Path('/var/lib/hybrid-native-trust') / selected['label']
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        with (process / 'environ').open('rb') as source:
            environment = source.read(65537)
        with (process / 'cmdline').open('rb') as source:
            arguments = source.read(65537)
        if len(environment) > 65536 or len(arguments) > 65536:
            raise ValueError('Native process input observation exceeds its bound')
        unit = subprocess.run(['systemctl', 'cat', 'aos-hub.service'],
            capture_output=True, check=True, timeout=10).stdout
        if len(unit) > 1048576:
            raise ValueError('Native service configuration observation exceeds its bound')
        private_inputs = {}
        for name, body in (('environment', environment), ('arguments', arguments), ('unit', unit)):
            descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(body)
                output.flush()
                os.fsync(output.fileno())
            private_inputs[name] = {'sha256': hashlib.sha256(body).hexdigest(), 'byteSize': len(body)}
        variables = {}
        for field in environment.split(b'\\0'):
            if not field:
                continue
            name, value = field.split(b'=', 1)
            if name in variables:
                raise ValueError('Native process environment has duplicate names')
            variables[name] = value
        default_bundle = '/etc/ssl/certs/ca-certificates.crt'
        bundle_path = os.fsdecode(variables.get(b'SSL_CERT_FILE', os.fsencode(default_bundle)))
        if not bundle_path.startswith('/'):
            raise ValueError('Native trust bundle path is not absolute')
        with open(bundle_path, 'rb') as source:
            metadata = os.fstat(source.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 2097152
                    or metadata.st_uid != 0 or metadata.st_mode & 0o022):
                raise ValueError('Native trust bundle type or bound differs')
            bundle = source.read(2097153)
            after_bundle = os.fstat(source.fileno())
        if (len(bundle) != metadata.st_size or any(getattr(metadata, name) != getattr(after_bundle, name)
                for name in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))):
            raise ValueError('Native trust bundle changed during observation')
        def certificates(body):
            return {hashlib.sha256(ssl.PEM_cert_to_DER_cert(match.decode())).hexdigest()
                for match in re.findall(br'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
                    body, flags=re.S)}
        installed = certificates(bundle)
        required = certificates(selected['fleetCaPem'].encode()) | certificates(
            Path(selected['s3PublicTrust']).read_bytes())
        if len(required) != 2 or not required <= installed:
            raise ValueError('installed Native trust lacks the selected fixture roots')
        after = (process / 'stat').read_text().rsplit(')', 1)[1].split()
        if before[19] != after[19] or after[0] == 'Z':
            raise ValueError('Native lifetime changed during trust observation')
        print(json.dumps({'version': 1, 'pid': pid, 'startTicks': before[19],
            'ownerUid': process.stat().st_uid, 'executableSha256': executable_sha,
            'privateInputs': private_inputs, 'installedBundleSha256': hashlib.sha256(bundle).hexdigest(),
            'installedBundlePathSha256': hashlib.sha256(os.fsencode(bundle_path)).hexdigest(),
            'installedBundleBytes': len(bundle), 'requiredCertificateDerSha256': sorted(required),
            'sslCertFileOverride': b'SSL_CERT_FILE' in variables,
            'sslCertDirectoryOverride': b'SSL_CERT_DIR' in variables,
            'proxyEnvironmentPresent': any(name in variables for name in
                (b'HTTP_PROXY', b'HTTPS_PROXY', b'ALL_PROXY', b'http_proxy', b'https_proxy', b'all_proxy')),
            'scope': 'actual ordinary Native process/trust inputs; execution TLS still requires handler joins'}))
    """, {"label": label, "executableSha256": artifacts["files"]["nativeHub"]["sha256"],
        "fleetCaPem": tools["fleetCaPem"], "s3PublicTrust": tools["s3PublicTrust"]}, timeout=45))
    return retain_direct_flow("native-trust-" + label + ".json", observed)


def observe_direct_initial_state(native, worker, s3, tools, process):
    """Capture real inventory, namespace and clocks before a new provider original."""
    namespace = direct_namespace_readback(worker, tools["python"], process)
    namespace_sha = retain_direct_flow("initial-runtime-namespace.json", namespace)
    if namespace["objectIds"]:
        raise RuntimeError("selected new guard namespace already contains objects")
    inventory = {
        "version": 1, "observedAt": datetime.now(timezone.utc).isoformat(),
        "bucketInfo": private_guest_command(s3, tools["garage"] + " bucket info fleet-s3"),
        "keyInventory": private_guest_command(s3, tools["garage"] + " key list"),
        "selectedKeyInfo": private_guest_command(s3, tools["garage"] + " key info fleet-s3-key"),
        "guardNamespaceSha256": namespace_sha,
        "operatorMachineRole": "worker", "providerMachineRole": "s3",
        "knownMutationPaths": ["isolated ordinary operator conformance", "protected isolated qualification",
            "authenticated credential write probe", "physical guard-backed production direct publication"],
        "scope": "actual inventory; writer closure and physical authority require independent review",
    }
    inventory_sha = retain_direct_flow("initial-provider-inventory.json", inventory)
    clocks = {"version": 1, "samples": [], "scope": "actual VM UTC within host request brackets"}
    for role, machine in (("native", native), ("worker", worker)):
        before = time.time_ns()
        actual = json.loads(direct_guest_python(machine, tools["python"], """
            import time
            print(json.dumps({'unixTimeNs': str(time.time_ns()), 'monotonicNs': str(time.monotonic_ns())}))
        """, {}))
        after = time.time_ns()
        clocks["samples"].append({"role": role, "hostBeforeUnixNs": str(before),
            "hostAfterUnixNs": str(after), "guest": actual})
    clock_sha = retain_direct_flow("initial-clock-brackets.json", clocks)
    return {"providerInventory": inventory_sha, "guardNamespace": namespace_sha,
            "clockObservations": clock_sha}


def direct_provider_observations(worker, s3, tools, selected):
    """Run one independently selected ordinary provider original on Worker only."""
    review = direct_selected_bytes(selected["providerReviewFile"], 262144)
    policy = selected["privateStagePolicy"]
    prefix = selected["providerPrefix"]
    if not prefix.endswith("/.aos-direct-upload") or ".aos-direct-qualification" not in prefix.split("/"):
        raise ValueError("provider conformance requires its isolated reviewed prefix")
    key_info = private_guest_command(s3, tools["garage"] + " key info --show-secret fleet-s3-key")
    access = re.search(r"Key ID:\s*(\S+)", key_info)
    secret = re.search(r"Secret key:\s*(\S+)", key_info)
    if not access or not secret:
        raise RuntimeError("actual Garage material capture failed")
    root = "/var/lib/hybrid-worker/provider-observation"
    documents = {
        "credential.json": json.dumps({"access_key": access.group(1), "secret_key": secret.group(1),
            "region": "garage"}).encode(),
        "private-policy.json": json.dumps(policy).encode(), "policy-review.json": review,
        "configuration.json": json.dumps({"version": 1, "endpoint": "https://s3.fleet.test",
            "bucket": "fleet-s3", "staging_prefix": prefix, "credential_file": root + "/credential.json",
            "private_policy_file": root + "/private-policy.json", "policy_review_file": root + "/policy-review.json",
            "policy_review_sha256": hashlib.sha256(review).hexdigest(),
            "tls_ca_file": tools["s3Ca"]}).encode(),
    }
    for name, body in documents.items():
        install_direct_guest_file(worker, tools["python"], root + "/" + name, body)
    arguments = [tools["providerConformance"], "run", "--config-file", root + "/configuration.json",
        "--journal-directory", root + "/journal", "--output", root + "/observations.json"]
    outcome = json.loads(direct_guest_python(worker, tools["python"], """
        import os, subprocess
        from pathlib import Path
        root = Path(selected['root'])
        descriptor = os.open(root / 'run.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as log:
            try:
                result = subprocess.run(selected['arguments'], stdout=log, stderr=log,
                    stdin=subprocess.DEVNULL, check=False, timeout=900)
                outcome = {'exitCode': result.returncode, 'timedOut': False}
            except subprocess.TimeoutExpired:
                outcome = {'exitCode': None, 'timedOut': True}
        journal = root / 'journal'
        captures = []
        if journal.is_dir():
            for path in sorted(journal.iterdir()):
                if not path.is_file() or path.is_symlink() or path.stat().st_size > 1048576:
                    raise ValueError('provider journal capture exceeds bounds')
                captures.append({'name': path.name, 'body': base64.b64encode(path.read_bytes()).decode()})
        outcome['journalFiles'] = captures
        print(json.dumps(outcome))
    """, {"root": root, "arguments": arguments}, timeout=930))
    # Unknown mutations retain their original and intent even when the command
    # fails. There is no second dispatch, implicit abort or cleanup here.
    for document in outcome.pop("journalFiles"):
        if not re.fullmatch(r"[a-zA-Z0-9_.-]+", document["name"]):
            raise ValueError("provider journal filename escaped its capture")
        retain_direct_flow("provider-journal-" + document["name"], base64.b64decode(document["body"], validate=True))
    retain_direct_flow("provider-invocation.json", outcome)
    retain_direct_flow("provider-run.log", read_direct_guest_file(worker, tools["python"], root + "/run.log", 1048576))
    if outcome["exitCode"] != 0:
        raise RuntimeError("new provider original failed; retained journal requires independent inspection")
    body = read_direct_guest_file(worker, tools["python"], root + "/observations.json", 1048576)
    sha = retain_direct_flow("provider-observations.json", body)
    material = (access.group(1) + ":" + secret.group(1) + ":garage").encode()
    return body, sha, material


def observe_direct_runtime_process(worker, tools, generation):
    """Observe the exact live workerd child using the existing bounded sampler."""
    arguments = [tools["python"], tools["processSampler"], "--pid-file",
        "/var/lib/hybrid-worker/worker.pid", "--node-exe", tools["node"],
        "--workerd-exe", tools["workerd"]]
    actual = json.loads(private_guest_command(worker, shlex.join(arguments)))
    pid = actual["processes"]["workerd"]["pid"]
    path = "/var/lib/hybrid-worker/installation/" + generation + "-workerd.pid"
    install_direct_guest_file(worker, tools["python"], path, str(pid).encode())
    retain_direct_flow(generation + "-process-counters.json", actual)
    return actual, path


def run_direct_observer(worker, tools, executable, arguments, destination):
    """Run a source-built observer, then retain its actual closed report bytes."""
    private_guest_command(worker, shlex.join([tools["python"], executable, *arguments]), timeout=180)
    body = read_direct_guest_file(worker, tools["python"], destination, 262144)
    return json.loads(body), retain_direct_flow(Path(destination).name, body)


def observe_direct_installed_runtime(worker, tools, artifacts, process, identity):
    """Bind the protected identity to live executable, NAR and queue readbacks."""
    _, pid_file = observe_direct_runtime_process(worker, tools, process["generation"])
    root = "/var/lib/hybrid-worker/installation"
    installation_file = root + "/installation-report.json"
    selected = {
        "identity-file": identity["identityFile"],
        "source-nar-file": artifacts["files"]["sourceNar"]["file"],
        "distribution-nar-file": artifacts["files"]["distributionNar"]["file"],
        "wasm-file": tools["wasm"], "shim-file": tools["shim"],
        "runner-file": tools["runner"], "runtime-file": tools["workerd"],
        "runtime-bindings-file": process["configurationFile"],
        "process-pid-file": pid_file, "report-file": installation_file,
    }
    arguments = [value for name, path in selected.items() for value in ("--" + name, path)]
    installation, installation_sha = run_direct_observer(
        worker, tools, tools["installationObserver"], arguments, installation_file,
    )
    queues = {}
    for queue_class, queue_name in (("bulk", "fleet-direct-verify-bulk"),
                                    ("metadata", "fleet-direct-verify-metadata")):
        output = root + "/" + queue_class + "-configuration.json"
        arguments = ["--startup-file", "/var/lib/hybrid-worker/queue-startup." + str(process["pid"]) + ".json",
            "--installation-file", installation_file, "--configuration-file", process["configurationFile"],
            "--runner-file", tools["runner"], "--queue-name", queue_name, "--queue-class", queue_class,
            "--output-file", output]
        report, digest = run_direct_observer(worker, tools, tools["queueObserver"], arguments, output)
        queues[queue_class] = {"report": report, "sha256": digest, "file": output}
    return {"installation": installation, "installationSha256": installation_sha,
            "installationFile": installation_file, "queues": queues}


def expose_direct_review_inputs(worker, tools, artifacts, process):
    """Retain independently usable files matching the actual guest installation."""
    root = Path("external-direct-flow")
    references = {}
    for name, path in (("sourceNar", tools["workerSourcePath"]),
                       ("distributionNar", tools["workerDistribution"])):
        destination = root / (name + ".nar")
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            result = subprocess.run([tools["nixStore"], "--dump", path], stdout=output,
                stderr=subprocess.PIPE, check=False, timeout=180)
            output.flush()
            os.fsync(output.fileno())
        if result.returncode:
            raise ValueError("actual host immutable NAR capture refused")
        with destination.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        if digest != artifacts["files"][name]["sha256"]:
            raise ValueError("host and guest immutable artifact bytes differ")
        references[name] = {"path": str(destination.resolve()), "sha256": digest}
    for name in ("wasm", "shim", "runner", "workerd"):
        with open(tools[name], "rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        if digest != artifacts["files"][name]["sha256"]:
            raise ValueError("selected host file differs from the installed guest artifact")
        references[name] = {"path": tools[name], "sha256": digest}
    configuration = read_direct_guest_file(worker, tools["python"], process["configurationFile"], 1048576)
    sha = retain_direct_flow("installed-runtime-bindings.json", configuration)
    if sha != process["configurationSha256"]:
        raise ValueError("actual runtime binding bytes changed after installation")
    references["runtimeBindings"] = {"path": str((root / "installed-runtime-bindings.json").resolve()), "sha256": sha}
    retain_direct_flow("actual-review-installed-file-references.json", {
        "version": 1, "files": references,
        "scope": "actual host files independently matched to the installed guest; no acceptance",
    })
    return references


def install_direct_reviewed_acceptance(native, worker, tools, process, identity,
                                       controls, observation_hashes):
    """Install only the independently signed exact measured artifact on both runtimes."""
    selected = await_direct_review("external-runtime-acceptance", observation_hashes, {
        "signedArtifact", "independentReview", "reviewerKeyId",
    })
    artifact_bytes = direct_selected_bytes(selected["selection"]["signedArtifact"], 65536)
    review_bytes = direct_selected_bytes(selected["selection"]["independentReview"], 262144)
    artifact = _closed_review_json(artifact_bytes)
    actual = identity["identity"]
    if any(artifact[name] != actual[name] for name in ("deploymentId", "publicOrigin", "sourceDigest", "scriptVersion")):
        raise ValueError("selected signed artifact differs from the actual installed runtime")
    if artifact["executionKind"] != "emulated_external" or artifact["reviewerKeyId"] != selected["selection"]["reviewerKeyId"]:
        raise ValueError("selected artifact has another execution or independent reviewer")
    retain_direct_flow("selected-runtime-review.json", review_bytes)
    artifact_sha = retain_direct_flow("selected-signed-artifact.json", artifact_bytes)
    destination = "/var/lib/hybrid-worker/controls/independently-accepted.json"
    install_direct_guest_file(worker, tools["python"], destination, artifact_bytes)
    registry = private_guest_command(worker, shlex.join([
        tools["reviewer"], "registry-key", "--deployment-id", actual["deploymentId"],
        "--source-digest", actual["sourceDigest"], "--script-version", actual["scriptVersion"],
    ])).encode()
    key_file = "/var/lib/hybrid-worker/controls/registry-key"
    install_direct_guest_file(worker, tools["python"], key_file, registry)
    receipt = json.loads(private_guest_command(worker, shlex.join([
        tools["python"], tools["acceptanceInstaller"], "--socket-file",
        "/var/lib/hybrid-worker/acceptance-control.sock", "--artifact-file", destination,
        "--registry-key-file", key_file, "--runner-pid-file", "/var/lib/hybrid-worker/worker.pid",
        "--output-directory", "/var/lib/hybrid-worker/acceptance-installation",
    ]), timeout=60))
    retain_direct_flow("worker-acceptance-installation.json", receipt)
    if receipt["status"] != "installed" or receipt["artifactSha256"] != artifact_sha:
        raise RuntimeError("actual KV installation did not retain the selected signed artifact")

    native_root = "/var/lib/hybrid-native-direct"
    review_keys = json.dumps({selected["selection"]["reviewerKeyId"]:
        controls["reviewerPublicKey"]}).encode()
    install_direct_guest_file(native, tools["python"], native_root + "/acceptance.json", artifact_bytes)
    install_direct_guest_file(native, tools["python"], native_root + "/reviewers.json", review_keys)
    guard_key = read_direct_guest_file(worker, tools["python"], controls["keyFiles"]["HUB_DIRECT_UPLOAD_GUARD_KEY"], 65536)
    install_direct_guest_file(native, tools["python"], native_root + "/guard.key", guard_key)
    native.succeed("chown -R aos-hub:aos-hub " + shlex.quote(native_root))
    dropin = (
        "[Service]\nEnvironment=HUB_DIRECT_UPLOAD_ACCEPTANCE_FILE=" + native_root + "/acceptance.json\n"
        "Environment=HUB_DIRECT_UPLOAD_REVIEW_KEYS_FILE=" + native_root + "/reviewers.json\n"
        "Environment=HUB_DIRECT_UPLOAD_GUARD_KEY_FILE=" + native_root + "/guard.key\n"
    ).encode()
    install_direct_guest_file(native, tools["python"],
        "/etc/systemd/system/aos-hub.service.d/external-direct.conf", dropin)
    native.succeed("systemctl daemon-reload; systemctl restart aos-hub.service", timeout=90)
    native.wait_for_unit("aos-hub.service", timeout=90)
    return {"artifactSha256": artifact_sha, "workerReceipt": receipt,
            "scope": "actual separate verifier installation; live production capabilities pending"}


def direct_log_position(machine, python, path):
    """Record a file inode and byte position for a distinct measurement window."""
    return json.loads(direct_guest_python(machine, python, """
        import os, stat
        from pathlib import Path

        metadata = Path(selected['path']).stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError('measurement log is not regular')
        print(json.dumps({'path': selected['path'], 'device': str(metadata.st_dev),
            'inode': str(metadata.st_ino), 'byteSize': metadata.st_size}))
    """, {"path": path}))


def retain_direct_log_window(machine, python, before, name):
    """Capture a fixed observed log prefix in bounded transport chunks."""
    after = direct_log_position(machine, python, before["path"])
    if any(before[key] != after[key] for key in ("device", "inode")) or after["byteSize"] < before["byteSize"]:
        raise ValueError("measurement log rotated or shrank")
    size = after["byteSize"] - before["byteSize"]
    if size > 512 * 1024 * 1024:
        raise ValueError("measurement window exceeded its retained capture bound")
    root = Path("external-direct-flow")
    root.mkdir(mode=0o700, exist_ok=True)
    destination = root / name
    digest = hashlib.sha256()
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        offset = before["byteSize"]
        while offset < after["byteSize"]:
            length = min(1024 * 1024, after["byteSize"] - offset)
            block = json.loads(direct_guest_python(machine, python, """
                import os, stat
                descriptor = os.open(selected['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, 'rb') as source:
                    metadata = os.fstat(source.fileno())
                    if (not stat.S_ISREG(metadata.st_mode) or str(metadata.st_dev) != selected['device']
                            or str(metadata.st_ino) != selected['inode']
                            or metadata.st_size < selected['end']):
                        raise ValueError('measurement log identity changed')
                    source.seek(selected['offset'])
                    body = source.read(selected['length'])
                    if len(body) != selected['length']:
                        raise ValueError('measurement log prefix truncated')
                print(json.dumps({'body': base64.b64encode(body).decode()}))
            """, {**before, "offset": offset, "length": length, "end": after["byteSize"]}))["body"]
            body = base64.b64decode(block, validate=True)
            if len(body) != length:
                raise ValueError("measurement log chunk changed in transport")
            output.write(body)
            digest.update(body)
            offset += length
        output.flush()
        os.fsync(output.fileno())
    receipt = {"version": 1, "before": before, "after": after,
        "sha256": digest.hexdigest(), "capturedBytes": size,
        "scope": "actual fixed file window; missing or later events remain outside this capture"}
    retain_direct_flow(name + ".window.json", receipt)
    return destination, receipt


def direct_page_samples(client, tools, count):
    """Collect genuine fresh TLS page requests with their own response spans."""
    return json.loads(direct_guest_python(client, tools["python"], """
        import hashlib, subprocess, time
        arguments = selected['curl'] + ['-fsS', '--max-time', '30', '-o', '/dev/null',
            '-b', '/var/lib/hybrid-client/browser-session/cookies',
            '-H', 'cf-connecting-ip: 192.0.2.10', '-w', selected['writeout'],
            'https://aos.andyl.org/-/instance']
        probes, samples = [], []
        for _ in range(selected['count']):
            started = time.time_ns()
            try:
                result = subprocess.run(arguments, capture_output=True, check=False, timeout=35)
                stdout, stderr = result.stdout, result.stderr
                exit_code, timed_out = result.returncode, False
            except subprocess.TimeoutExpired as error:
                stdout, stderr = error.stdout or b'', error.stderr or b''
                exit_code, timed_out = None, True
            probes.append({'startedUnixNs': str(started), 'finishedUnixNs': str(time.time_ns()),
                'exitCode': exit_code, 'timedOut': timed_out,
                'writeout': stdout.decode(), 'stderrSha256': hashlib.sha256(stderr).hexdigest(),
                'stderrBytes': len(stderr)})
            if exit_code == 0:
                samples.append(stdout.decode())
        print(json.dumps({'version': 1, 'samples': ''.join(samples), 'probes': probes}))
    """, {"curl": shlex.split(tools["curl"]), "writeout": PAGE_PERF_WRITEOUT,
            "count": count}, timeout=count * 35 + 30))


def prepare_direct_client_provider_policy(client, tools, credentials):
    """Authorize only the actual disposable provider address and public CA."""
    endpoint = credentials["binding"]["spec"]["s3"]["endpoint"]
    if endpoint["scheme"] != "https" or endpoint["port"] != 443:
        raise ValueError("the selected disposable provider is not the reviewed HTTPS origin")
    policy = json.loads(direct_guest_python(client, tools["python"], """
        import hashlib, ipaddress, os, socket
        from pathlib import Path

        root = Path('/var/lib/hybrid-client/provider-policy')
        root.mkdir(mode=0o700, exist_ok=False)
        addresses = sorted({record[4][0] for record in socket.getaddrinfo(
            selected['host'], 443, family=socket.AF_INET, type=socket.SOCK_STREAM)})
        if not addresses or any(not ipaddress.ip_address(address).is_private for address in addresses):
            raise ValueError('the selected disposable provider did not resolve to private IPv4 addresses')
        certificate = Path(selected['publicTrust']).read_bytes()
        document = {'version': 1, 'privateEndpoints': [{
            'origin': 'https://' + selected['host'],
            'privateCidrs': [address + '/32' for address in addresses]}],
            'rootCertificateFiles': [str(root / 'public-ca.pem')]}
        for name, body in (('public-ca.pem', certificate),
                ('policy.json', json.dumps(document, separators=(',', ':')).encode())):
            descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(body)
                output.flush()
                os.fsync(output.fileno())
        print(json.dumps({'version': 1, 'policyFile': str(root / 'policy.json'),
            'policy': document, 'publicCaSha256': hashlib.sha256(certificate).hexdigest(),
            'scope': 'explicit local network reachability and public TLS trust; no provider readiness'}))
    """, {"host": endpoint["dnsName"], "publicTrust": tools["s3PublicTrust"]}))
    retain_direct_flow("actual-client-provider-policy.json", policy)
    return {**tools, "providerPolicyFile": policy["policyFile"]}


def run_external_direct_publication(client, native, worker, s3, tools, controls, credentials,
                                   authority, process, identity, acceptance):
    """Publish the real signed business corpus and retain runtime gates separately."""
    tools = prepare_direct_client_provider_policy(client, tools, credentials)
    sources = {}
    for label, name in (("a", "external-direct"), ("b", "external-overlap")):
        sources[label] = prepare_direct_signed_surface(client, tools["python"], tools["apr"], tools["git"],
            tools["opensshBin"], tools["nixBin"], tools["helperStorePath"],
            tools["workerUrl"] + "/fleet-direct/objects", authoring_name=name)
    corpus = prepare_direct_publication_corpus(client, tools["python"], sources["a"]["surfaceRoot"])
    retain_direct_flow("actual-publication-source-corpus.json", corpus)
    corpus_a, corpus_b = split_direct_publication_sources(client, tools, sources["a"], sources["b"], corpus)
    registries = {}
    for label, name in (("a", "external-direct"), ("b", "external-overlap")):
        registries[label] = controls.create_external_registry(
            credentials["organization"], credentials["binding"], name,
            [sources[label]["trustKey"]], "primary",
            credentials["binding"]["spec"]["s3"]["prefix"] + "/registry-" + label,
            credentials["currentSqlPins"]["currentWriteRevision"], False)
        retain_direct_flow("actual-registry-placement-" + label + ".json", registries[label])
    token = direct_root_browser_token(client, tools["curl"], tools["python"], private_guest_command, reuse_session=True)
    assert_direct_fifo_checkpoint(client, tools, registries["b"]["registry"]["slug"], sources["b"], token)
    observe_direct_boundary_lifetimes(native, worker, tools, "baseline-start")
    baseline_report = direct_page_samples(client, tools, 100)
    retain_direct_flow("baseline-page-probes.json", baseline_report)
    baseline_raw = baseline_report["samples"]
    retain_direct_flow("baseline-pages.txt", baseline_raw.encode())
    assert all(probe["exitCode"] == 0 for probe in baseline_report["probes"]), baseline_report
    baseline = parse_page_observations(baseline_raw, 100)
    report_page_observations("External baseline", baseline)
    baseline_first = page_cumulative_values(baseline, "time_starttransfer")
    native_executable = observe_direct_native_executable(native, tools,
        tools["installedNativeExecutableSha256"])
    provider_callers = observe_direct_provider_callers(s3, tools)
    workload_started = time.monotonic_ns()
    before_worker = direct_log_position(worker, tools["python"], process["logFile"])
    before_native = direct_log_position(native, tools["python"], "/var/lib/hybrid-native-observations/requests.jsonl")
    before_provider = direct_log_position(s3, tools["python"], "/var/lib/hybrid-s3/provider-observations.jsonl")
    before_native_storage = direct_log_position(native, tools["python"],
        "/var/lib/hybrid-native-outbound/requests.jsonl")
    before_worker_storage = direct_log_position(worker, tools["python"],
        "/var/lib/hybrid-worker-boundary/requests.jsonl")
    observe_direct_boundary_lifetimes(native, worker, tools, "loaded-start")
    try:
        publications, concurrent = run_direct_concurrent_publications(client, worker, tools,
            sources, registries, before_worker, identity["identity"]["sourceDigest"], corpus_a)
        index_freshness = wait_direct_registry_indexes(controls, registries, sources)
    finally:
        worker_log, worker_window = retain_direct_log_window(worker, tools["python"], before_worker, "publication-worker.log")
        native_log, native_window = retain_direct_log_window(native, tools["python"], before_native, "publication-native.jsonl")
        provider_log, provider_window = retain_direct_log_window(s3, tools["python"], before_provider, "publication-provider-private.jsonl")
        native_storage_log, native_storage_window = retain_direct_log_window(native, tools["python"],
            before_native_storage, "publication-native-storage.jsonl")
        worker_storage_log, worker_storage_window = retain_direct_log_window(worker, tools["python"],
            before_worker_storage, "publication-worker-storage.jsonl")
        proxy_lifetimes = observe_direct_boundary_lifetimes(native, worker, tools, "loaded-finish")
    workload_finished = time.monotonic_ns()
    workload_interval = {"clock": "controller_monotonic",
        "startedNanoseconds": str(workload_started), "finishedNanoseconds": str(workload_finished),
        "elapsedNanoseconds": str(workload_finished - workload_started)}

    # Retain every measured gate before asserting. Parsing errors and incomplete
    # telemetry remain failures even if the public publisher says ready.
    assert_direct_publication_objects(publications["a"], corpus_a)
    assert_direct_publication_objects(publications["b"], corpus_b)
    checkpoints = observe_direct_absolute_checkpoints(client, tools, sources)
    counters = [counter for invocation in concurrent["invocations"]
                if invocation["terminalCountersAvailable"]
                for counter in direct_client_observations(invocation["stderr"])]
    aggregate = {name: sum(counter[name] for counter in counters) for name in DIRECT_CLIENT_COUNTERS}
    aggregate["max_provider_active"] = max(counter["max_provider_active"] for counter in counters)
    events = direct_runtime_observations(worker_log.read_text(), identity["identity"]["sourceDigest"])
    runtime = summarize_direct_runtime(events)
    native_observations = native_control_observations(native_log.read_text())
    native_observations, native_bodies = capture_direct_native_bodies(native, tools, native_observations)
    native_control_joins = join_direct_native_control_bodies(native_bodies, events)
    retain_direct_flow("actual-native-verified-control-joins.json", native_control_joins)
    provider_boundary = provider_boundary_observations(provider_log.read_text(), provider_callers)
    retain_direct_flow("actual-provider-byte-receipts.json", provider_boundary)
    originals_path, originals_receipt = capture_direct_native_originals(native, tools, publications)
    original_mapping = direct_provider_original_mapping(originals_path, publications,
        credentials["binding"]["spec"]["s3"]["bucket"], events)
    same_registry = direct_same_registry_parallel_reads(events, original_mapping,
        publications["a"]["publication_id"], DIRECT_LARGE_OBJECT_BYTES)
    retain_direct_flow("actual-same-registry-parallel-integrity.json", same_registry)
    storage_boundary = capture_direct_storage_boundary(native, worker, tools,
        native_storage_log.read_text(), worker_storage_log.read_text(), worker_log.read_text(),
        identity["identity"]["sourceDigest"], tools["storageBoundaryInstallation"]["routing"]["nativeAddress"])
    provider_classification = classify_direct_provider_object_receipts(provider_boundary, original_mapping)
    throughput = summarize_direct_provider_throughput(provider_boundary, provider_classification,
        original_mapping, corpus, workload_interval)
    retain_direct_flow("actual-production-transfer-throughput.json", throughput)
    native_summary = summarize_native_control_bytes(native_observations, sum(len(publication["objects"]) for publication in publications.values()))
    loaded_raw = concurrent["pageSamples"]
    loaded_count = len(loaded_raw.splitlines())
    loaded_p95 = None
    loaded_p99 = None
    if loaded_count:
        loaded = parse_page_observations(loaded_raw, loaded_count)
        report_page_observations("External during actual publication", loaded)
        loaded_first = page_cumulative_values(loaded, "time_starttransfer")
        loaded_p95 = loaded_first[math.ceil(loaded_count * 0.95) - 1]
        loaded_p99 = loaded_first[math.ceil(loaded_count * 0.99) - 1]
    positive_integrity = sum(item["consumed_bytes"] for item in runtime["production_read_bytes"]
        if item["outcome"] == "positive" and item["read_kind"] == "full_integrity")
    summary = {
        "version": 1, "acceptance": acceptance, "workerLogWindow": worker_window,
        "nativeLogWindow": native_window, "clientInvocations": counters,
        "providerLogWindow": provider_window, "providerBoundary": provider_boundary,
        "productionTransferThroughput": throughput,
        "nativeVerifiedControlJoins": native_control_joins,
        "nativeOriginalsSnapshot": originals_receipt, "providerObjectClassification": provider_classification,
        "nativeBulkAssessment": None,
        "nativeStorageBoundary": storage_boundary,
        "nativeStorageLogWindow": native_storage_window,
        "workerStorageLogWindow": worker_storage_window,
        "boundaryProxyLifetimes": proxy_lifetimes,
        "clientAggregate": aggregate, "clientMetricsCoverage": concurrent["metricsCoverage"],
        "sparseRecovery": concurrent["sparseRecovery"],
        "runtime": runtime, "nativeBoundary": native_summary,
        "baselinePageP95Seconds": baseline_first[94], "loadedPageP95Seconds": loaded_p95,
        "baselinePageP99Seconds": baseline_first[98], "loadedPageP99Seconds": loaded_p99,
        "loadedPageSampleCount": loaded_count,
        "loadedPublisherOverlapSamples": len(concurrent["pageIntervals"]),
        "failedPageProbeExitCodes": concurrent["failedPageProbeExitCodes"],
        "publicationOriginals": {label: publication["publication_id"] for label, publication in publications.items()},
        "largeOriginalDistribution": {"a": corpus_a["large_objects"], "b": corpus_b["large_objects"]},
        "providerPacing": concurrent["pacing"],
        "actualBusinessCorpus": {"largeObjects": 3, "largeObjectBytes": DIRECT_LARGE_OBJECT_BYTES,
            "mutableJsonPointers": DIRECT_METADATA_OBJECT_COUNT, "dependencyPhase": "visibility"},
        "providerPositiveIntegrityConsumedBytes": positive_integrity,
        "sameRegistryParallelIntegrity": same_registry,
        "authoritativeIndexFreshness": index_freshness,
        "absoluteCheckpoints": checkpoints,
        "scope": "actual External emulator publication; independent hosted qualification remains separate",
    }
    retain_direct_flow("actual-publication-measurements.json", summary)
    if concurrent["sparseRecovery"]["terminalCountersUnavailable"]:
        summary["recoveredActivityEvidence"] = assert_direct_recovered_activity(
            aggregate, corpus, concurrent["sparseRecovery"], original_mapping,
            provider_classification, native_observations)
    else:
        assert_direct_client_activity([aggregate], corpus)
    assert baseline_first[94] < 0.5 and baseline_first[98] < 1.0, summary
    assert loaded_count >= 25 and summary["loadedPublisherOverlapSamples"] >= 25, summary
    assert not summary["failedPageProbeExitCodes"], summary
    assert loaded_p95 < 0.5 and loaded_p95 <= baseline_first[94] * 1.25, summary
    assert loaded_p99 < 1.0, summary
    assert native_summary["legacy_request_body_limit_passed"], native_summary
    assert native_summary["direct_body_limit_passed"], native_summary
    assert native_summary["publication_inventory_transport_limit_passed"], native_summary
    assert runtime["production_phase_originals"].get("visibility", 0) >= DIRECT_METADATA_OBJECT_COUNT, runtime
    assert positive_integrity >= 3 * DIRECT_LARGE_OBJECT_BYTES + corpus["metadata_source_bytes"], runtime
    assert same_registry["samePublicationOverlaps"], same_registry
    assert runtime["queue_overlap"]["positive_metadata_completions_during_bulk"], runtime
    for kind in ("queue_attempts", "production_read_attempts", "control_attempts"):
        assert not runtime[kind]["missing_finish_attempts"] and not runtime[kind]["unmatched_finish_attempts"], runtime
        assert not runtime[kind]["duplicate_boundary_attempts"], runtime
    assert not runtime["unknown_control_replies"], runtime
    summary["businessIndexParity"] = qualify_direct_business_indexes(
        client, native, worker, tools, registries["a"], sources["a"])
    retain_direct_flow("actual-publication-with-index-parity.json", summary)
    bootstrap = authority["exported"]["bootstrap"]
    native_bulk = assess_direct_native_bodies(native_bodies, native_control_joins,
        provider_classification, original_mapping, identity["identity"]["sourceDigest"],
        {"keyId": bootstrap["issuer_key_id"], "publicKeyHex": bootstrap["issuer_public_key"]},
        native_executable, storage_work_boundary=storage_boundary,
        release_placements=[{"registrySlug": registries[label]["registry"]["slug"],
            "release": "1.0.0", "sourceCommit": sources[label]["sourceCommit"],
            "placement": registries[label]["placement"]} for label in ("a", "b")])
    assert native_bulk["nativeBulkBytes"] == 0, native_bulk
    summary["nativeBulkAssessment"] = native_bulk
    retain_direct_flow("actual-publication-assessed.json", summary)
    # The HTTP byte totals and consumed stream counters are independent actual
    # measurements. Their distinction remains explicit in the retained ledger.
    print("Actual External publication measurements and scoped Native bulk assessment retained:",
          str(Path('external-direct-flow/actual-publication-assessed.json').resolve()), flush=True)
    return summary


def run_external_direct_fleet(client, native, worker, s3, database_machine, tools,
                              database_host, original_configuration):
    """Execute the genuine External path with no legacy snapshot/material shortcut."""
    private_guest_command(worker, "umask 077; install -d -m 0700 /var/lib/hybrid-worker")
    artifacts = capture_direct_artifacts(worker, tools)
    tools = {**tools, "installedNativeExecutableSha256": artifacts["files"]["nativeHub"]["sha256"]}
    artifact_sha = retain_direct_flow("immutable-artifacts.json", artifacts)
    native_trust = observe_direct_native_trust(native, tools, artifacts, "bootstrap")
    initial_review = await_direct_review("external-installation-inputs", {
        "installedArtifacts": artifact_sha, "nativeProcessTrust": native_trust,
    }, {
        "reviewerPublicKey", "privateStagePolicy", "providerPrefix", "providerReviewFile", "bindingPrefix",
    })
    inputs = initial_review["selection"]
    shared_controls = install_direct_shared_controls(native, tools, artifacts)
    prebody = run_direct_native_prebody_probes(native, tools, shared_controls)
    retain_direct_flow("actual-native-prebody-window.json", prebody)
    worker_controls = initialize_direct_worker_controls(
        worker, tools["python"], tools["reviewer"], original_configuration, inputs["reviewerPublicKey"],
    )
    worker_controls["reviewerPublicKey"] = inputs["reviewerPublicKey"]
    namespace_file = "/var/lib/hybrid-worker/installation/new-namespace.json"
    run_direct_observer(worker, tools, tools["namespaceObserver"], [
        "--configuration-file", worker_controls["configurationFile"],
        "--persistence-root", "/var/lib/hybrid-worker/state", "--source-store-path", tools["workerSourcePath"],
        "--source-nar-file", artifacts["files"]["sourceNar"]["file"],
        "--distribution-nar-file", artifacts["files"]["distributionNar"]["file"],
        "--wasm-file", tools["wasm"], "--shim-file", tools["shim"],
        "--runner-file", tools["runner"], "--runtime-file", tools["workerd"],
        "--report-file", namespace_file,
    ], namespace_file)
    process = start_direct_worker(worker, tools, worker_controls["configurationFile"], "bootstrap")
    wait_worker_transport(worker, tools["curl"], tools["python"], True,
                          observation_label="worker-bootstrap")
    runtime, _ = observe_direct_runtime_process(worker, tools, "bootstrap")
    installation_sha = retain_direct_flow("preauthority-runtime-context.json", {
        "version": 1, "artifacts": artifacts, "runner": process, "runtime": runtime,
        "scope": "actual installed artifact/process context before protected External profile exists",
    })
    observations = observe_direct_initial_state(native, worker, s3, tools, process)
    provider_review = await_direct_review("external-provider-original", {
        **observations, "installation": installation_sha,
    }, {"privateStagePolicy", "providerPrefix", "providerReviewFile"})
    for field in ("privateStagePolicy", "providerPrefix", "providerReviewFile"):
        if provider_review["selection"][field] != inputs[field]:
            raise ValueError("reviewed provider inputs changed after preinstallation")
    provider_body, provider_sha, material = direct_provider_observations(worker, s3, tools, inputs)
    binding_prefix = inputs["bindingPrefix"]
    if (not isinstance(binding_prefix, str) or ".aos-direct-qualification" not in binding_prefix.split("/")
            or any(part in {"", ".", ".."} for part in binding_prefix.split("/"))
            or inputs["providerPrefix"].startswith(binding_prefix + "/")):
        raise ValueError("operator-only mutations must remain outside the selected production binding")
    tools = {**tools, "storageWorkKeyFile": worker_controls["keyFiles"]["HUB_STORAGE_WORK_KEY"]}
    controls, credentials, credential_sha = bootstrap_external_direct(
        client, worker, database_machine, tools, database_host, material, {
            "bucket": "fleet-s3", "prefix": binding_prefix,
            "endpoint": {"scheme": "https", "dnsName": "s3.fleet.test", "port": 443},
            "signingRegion": "garage", "accessMode": "private",
        },
    )
    # Re-enumerate immediately before physical review. Credential controllers
    # may have executed their actual isolated write probes since startup.
    fresh_namespace = direct_namespace_readback(worker, tools["python"], process)
    namespace_sha = retain_direct_flow("namespace-before-physical-authority.json", fresh_namespace)
    observations.update(guardNamespace=namespace_sha, credentialBootstrap=credential_sha,
        providerObservations=provider_sha, installation=installation_sha)
    renewal = read_direct_guest_file(worker, tools["python"], worker_controls["keyFiles"]["HUB_AUTHORITY_RENEWAL_KEY"], 65536)
    authority = prepare_external_authority(controls, credentials, worker, native, tools,
        observations, provider_body, renewal)
    address = private_guest_command(worker, tools["python"] + " -c " + shlex.quote(
        "import socket; print(socket.gethostbyname('native'))")).strip()
    service = issuer_service_binding(address, 8443, tools["fleetCaPem"], tools["issuerCertificateHost"])
    installed = install_direct_worker_consumers(worker, tools["python"], process["configurationFile"],
        authority["consumerBindings"], service)
    retain_direct_flow("bootstrap-runner-disposal.json", stop_direct_worker(worker, tools["python"], process))
    process = start_direct_worker(worker, tools, installed["configurationFile"], "qualified")
    wait_worker_transport(worker, tools["curl"], tools["python"], True,
                          observation_label="worker-qualified")
    hydration = hydrate_external_authority(worker, tools["python"], tools["authorityBootstrap"],
        authority["exported"], tools["workerUrl"], tools["storageWorkKeyFile"],
        credentials["operatorVersions"]["manifestFile"])
    synchronized = reconcile_external_authority(native, tools["hub"], tools["nativeDatabaseUrlFile"],
        tools["nativeStorageWorkKeyFile"], authority["exported"], tools["workerUrl"])
    identity = inspect_direct_external_deployment(worker, tools["python"], tools["hub"],
        authority["exported"], tools["workerUrl"], tools["nativeOriginUrl"], "hub-hybrid-fleet",
        "hybrid-fleet-r2", worker_controls["keyFiles"]["HUB_DIRECT_UPLOAD_GUARD_KEY"])
    bulk = prepare_direct_qualification_bulk(worker, tools["python"], "/var/lib/hybrid-worker/qualification-bulk")
    metadata = prepare_direct_qualification_metadata(worker, tools["python"], "/var/lib/hybrid-worker/qualification-metadata")
    queue_restart, process = run_direct_queue_restart(worker, tools, process, identity,
        worker_controls["keyFiles"]["HUB_DIRECT_UPLOAD_CONFORMANCE_KEY"],
        authority["exported"]["bootstrap"]["selector"], bulk[0])
    # The measured installation and review captures describe the new live
    # runner, with the same artifact/configuration and retained persistent state.
    measured = observe_direct_installed_runtime(worker, tools, artifacts, process, identity)
    expose_direct_review_inputs(worker, tools, artifacts, process)
    qualification = run_direct_prequalification(worker, tools["python"], tools["node"], tools["qualificationDriver"],
        tools["workerUrl"], worker_controls["keyFiles"]["HUB_DIRECT_UPLOAD_CONFORMANCE_KEY"],
        identity["identityFile"], authority["exported"]["bootstrap"]["selector"], bulk, metadata)
    qualification_sha = retain_direct_flow("actual-prequalification.json", qualification)
    acceptance = install_direct_reviewed_acceptance(native, worker, tools, process, identity, worker_controls, {
        **observations, "protectedIdentity": identity["identitySha256"],
        "installation": measured["installationSha256"], "prequalification": qualification_sha,
        "bulkConfiguration": measured["queues"]["bulk"]["sha256"],
        "metadataConfiguration": measured["queues"]["metadata"]["sha256"],
        "hydration": hydration["receiptSha256"], "authoritySynchronization": synchronized["receiptSha256"],
    })
    observe_direct_native_trust(native, tools, artifacts, "accepted-runtime")
    publication = run_external_direct_publication(client, native, worker, s3, tools, controls, credentials,
        authority, process, identity, acceptance)
    issuer_lifecycle = run_direct_issuer_lifecycle(native, worker, tools, shared_controls, authority)
    issuer_cutoff = run_direct_issuer_cutoff(native, worker, tools, shared_controls, controls, authority)
    failures = run_direct_dependency_outages(client, native, worker, database_machine, tools, process)
    browser = run_direct_browser_session(client, native, worker, tools,
        failures["scenarios"]["executor"]["restart"])
    # Cold startup has no supported reviewed clock-session resolution. Observe
    # its real refusal last so the live issuer supports the other scenarios.
    cold_refusal = run_direct_issuer_terminal_refusal(native, worker, tools, shared_controls, authority)
    return {"publication": publication, "queueRestart": queue_restart, "nativePrebody": prebody,
            "issuerLifecycle": issuer_lifecycle, "issuerCutoff": issuer_cutoff,
            "dependencyFailures": failures, "browserSession": browser,
            "terminalColdRefusal": cold_refusal}
