"""Actual signed publisher workloads and bounded direct client observations.

The source corpus lives on the client VM's persistent disk. These helpers retain
source identities and numeric client counters; provider or Native effects need
their own independently observed evidence.
"""

import hashlib
import json
import re
import shlex
import textwrap


DIRECT_LARGE_OBJECT_BYTES = 2 * 1024 ** 3
DIRECT_LARGE_OBJECT_COUNT = 3
DIRECT_METADATA_OBJECT_COUNT = 12_535
DIRECT_QUALIFICATION_NARINFO_BYTES = 256 * 1024
DIRECT_QUALIFICATION_NARINFO_COUNT = 4
DIRECT_CLIENT_COUNTERS = (
    "caps", "begin", "status", "grant", "report", "complete", "abort",
    "identity", "manifest_begin", "manifest_append", "manifest_seal",
    "commit", "metadata_read", "provider_attempts", "provider_successes",
    "acknowledged_bytes", "max_provider_active",
)


def assert_direct_fifo_checkpoint(client, tools, registry, signed, token):
    """Exercise the real publisher's admission checkpoint refusal on the client VM."""
    arguments = [tools["aos"], "--json", "hub", "registry", "publish", "upload", registry,
        "--root", signed["surfaceRoot"], "--hub", tools["workerUrl"], "--token", token,
        "--direct-provider-policy", tools["providerPolicyFile"],
        "--direct-upload-journal", signed["publisherHome"] + "/fifo-checkpoint.sqlite"]
    observed = json.loads(direct_guest_python(client, tools["python"], """
        import os, stat, subprocess, time
        from pathlib import Path

        journal = Path(selected['journal'])
        fifo = journal.with_name(journal.name + '.admission')
        os.mkfifo(fifo, 0o600)
        before = fifo.lstat()
        if not stat.S_ISFIFO(before.st_mode) or Path('/').stat().st_uid != 0:
            raise ValueError('FIFO admission fixture lacks actual trusted-root custody')
        environment = dict(os.environ)
        environment.update(HOME=selected['home'], SSL_CERT_FILE='/etc/ssl/certs/ca-certificates.crt')
        started = time.time_ns()
        try:
            result = subprocess.run(selected['arguments'], env=environment, capture_output=True,
                check=False, timeout=60)
            stdout, stderr = result.stdout, result.stderr
            exit_code, timed_out = result.returncode, False
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b'', error.stderr or b''
            exit_code, timed_out = None, True
        after = fifo.lstat()
        print(json.dumps({'version': 1, 'exitCode': exit_code, 'timedOut': timed_out,
            'startedUnixNs': str(started), 'finishedUnixNs': str(time.time_ns()),
            'stdout': stdout.decode(), 'stderr': stderr.decode(), 'rootOwnerUid': Path('/').stat().st_uid,
            'unchangedFifo': stat.S_ISFIFO(after.st_mode) and before.st_dev == after.st_dev
                and before.st_ino == after.st_ino, 'ordinaryJournalCreated': journal.exists(),
            'scope': 'actual installed publisher admission checkpoint FIFO refusal; no foreign-root substitute'}))
    """, {"arguments": arguments, "journal": arguments[-1], "home": signed["publisherHome"]}, timeout=90))
    retain_direct_flow("actual-fifo-checkpoint-refusal.json", observed)
    assert observed["exitCode"] not in {None, 0} and not observed["timedOut"], observed
    assert observed["unchangedFifo"] and not observed["ordinaryJournalCreated"], observed
    error = json.loads(observed["stdout"]).get("error", "")
    assert "direct upload checkpoint is unavailable" in error, observed
    counters = direct_client_observations(observed["stderr"])
    assert len(counters) == 1 and counters[0]["manifest_begin"] == 0, counters
    assert counters[0]["provider_attempts"] == 0 and counters[0]["acknowledged_bytes"] == 0, counters


def observe_direct_absolute_checkpoints(client, tools, sources):
    """Read genuine completed absolute journals without exposing retained capabilities."""
    observed = json.loads(direct_guest_python(client, tools["python"], """
        import hashlib, os, sqlite3, stat
        from pathlib import Path

        files = []
        for label, home in selected['homes'].items():
            for suffix in ('', '.admission'):
                path = Path(home) / ('direct-upload.sqlite' + suffix)
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, 'rb') as source:
                    metadata = os.fstat(source.fileno())
                    if (not path.is_absolute() or not stat.S_ISREG(metadata.st_mode)
                            or metadata.st_uid != os.getuid() or metadata.st_mode & 0o7777 != 0o600
                            or metadata.st_nlink != 1 or source.read(16) != b'SQLite format 3\\x00'):
                        raise ValueError('actual completed absolute checkpoint has invalid custody or format')
                    source.seek(0)
                    digest = hashlib.file_digest(source, 'sha256').hexdigest()
                connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
                try:
                    counts = dict(connection.execute('SELECT kind, count(*) FROM direct_records GROUP BY kind'))
                finally:
                    connection.close()
                after = path.stat()
                if any(getattr(metadata, name) != getattr(after, name) for name in
                        ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
                    raise ValueError('completed checkpoint changed during readonly observation')
                files.append({'label': label, 'kind': 'admission' if suffix else 'object',
                    'sha256': digest, 'byteSize': metadata.st_size, 'recordCounts': counts})
        print(json.dumps({'version': 1, 'rootOwnerUid': Path('/').stat().st_uid, 'journals': files,
            'scope': 'actual completed absolute client-VM checkpoints; readonly numeric projection'}))
    """, {"homes": {label: source["publisherHome"] for label, source in sources.items()}}))
    retain_direct_flow("actual-absolute-checkpoints.json", observed)
    assert observed["rootOwnerUid"] == 0 and len(observed["journals"]) == 4, observed
    assert all(journal["recordCounts"] for journal in observed["journals"]), observed
    return observed


def prepare_direct_signed_surface(client, python, apr, git, openssh, nix,
                                  helper_store_path, cache_url, authoring_name="external-direct"):
    """Author an actual APR release before extending its signed publication surface."""
    result = json.loads(private_guest_command(client, textwrap.dedent(f"""
        {shlex.quote(python)} - <<'DIRECT_SIGNED_SURFACE'
        import json, os, re, subprocess
        from pathlib import Path

        name = {authoring_name!r}
        if not re.fullmatch(r'[a-z][a-z0-9-]{{0,31}}', name):
            raise ValueError('publisher authoring name is invalid')
        home = Path('/var/lib/hybrid-client/' + name + '-publisher-home')
        home.mkdir(mode=0o700, parents=True, exist_ok=False)
        surface = '/var/lib/hybrid-client/' + name + '-surface'
        environment = dict(os.environ)
        environment.update(HOME=str(home), USER='fleet-publisher', NIX_REMOTE='',
            NIX_CONF_DIR=str(home / '.config/nix'))
        environment['PATH'] = ':'.join([{git.rsplit('/', 1)[0]!r},
            {openssh!r}, {nix!r}, environment.get('PATH', '')])
        configuration = home / '.config/nix'
        configuration.mkdir(mode=0o700, parents=True)
        (configuration / 'nix.conf').write_text(
            'experimental-features = nix-command\\nsandbox = false\\nbuild-users-group =\\n')
        os.umask(0o077)

        def run(arguments):
            result = subprocess.run(arguments, env=environment, capture_output=True,
                timeout=180, check=False)
            if result.returncode:
                raise ValueError('actual signed publisher preparation refused')
            return result.stdout + result.stderr

        run([{git!r}, 'config', '--global', 'user.name', 'Hybrid Fleet Publisher'])
        run([{git!r}, 'config', '--global', 'user.email', 'fleet-publisher@example.test'])
        generated = run([{apr!r}, 'keys', 'generate', 'initial', '--registry', name])
        keys = re.findall(rb'Public key:\\s*(' + name.encode() + rb':Ed25519:[A-Za-z0-9+/=]+)', generated)
        if len(keys) != 1:
            raise ValueError('actual APR publisher trust anchor is ambiguous')
        trust_key = keys[0].decode()
        key = home / ('.config/apm/keys/' + name + '-initial.key')
        run([{apr!r}, 'create', name, '--trust-key', trust_key,
            '--trust-key-id', 'initial', '--key', str(key)])
        registry = home / ('.local/share/apm/registries/' + name)
        configuration = home / '.config/apm/registries.d'
        configuration.mkdir(mode=0o700, parents=True, exist_ok=True)
        (configuration / (name + '.toml')).write_text(
            '[registry]\\nname = "' + name + '"\\nurl = "file://' + str(registry)
            + '"\\n\\n[registry.signing_keys]\\ninitial = "' + str(key) + '"\\n')
        run([{apr!r}, 'release', '1.0.0', '--registry', name,
            '--store-path', {helper_store_path!r}, '--name', 'hub-helper',
            '--description', 'External direct signed publication qualification',
            '--license', 'MIT', '--maintainer', 'fleet-publisher@example.test',
            '--key-id', 'initial', '--channel', 'stable', '--init-channel',
            '--cache-url', {cache_url!r},
            '--upload-url', 'file://' + surface])
        run([{apr!r}, 'verify', '--registry', name])
        if not (Path(surface) / 'HEAD').is_file():
            raise ValueError('actual APR release did not produce its signed HEAD')
        source_commit = run([{git!r}, '-C', str(registry), 'rev-parse', 'HEAD']).decode().strip()
        if not re.fullmatch(r'[0-9a-f]{{64}}', source_commit):
            raise ValueError('actual signed publisher source commit differs')
        print(json.dumps({{'version': 1, 'trustKey': trust_key, 'sourceCommit': source_commit,
            'surfaceRoot': surface, 'publisherHome': str(home),
            'scope': 'actual APR release and verifier; provider admission pending'}}))
        DIRECT_SIGNED_SURFACE
    """), timeout=900))
    if not result["trustKey"].startswith(authoring_name + ":Ed25519:"):
        raise RuntimeError("signed publisher returned another registry anchor")
    return result


def prepare_direct_qualification_metadata(machine, python, directory):
    """Create one mixed and three pure metadata originals at the parser ceiling."""
    script = textwrap.dedent("""
        import hashlib
        import json
        import os
        from pathlib import Path

        root = Path(ROOT)
        if not root.is_absolute():
            raise ValueError("qualification inputs require an absolute private directory")
        root.mkdir(mode=0o700)
        originals = []
        for number in range(COUNT):
            body = (
                f"StorePath: /nix/store/0123456789abcdfghijklmnpqrsvwxy{number}-qualification\\n"
                f"URL: nar/qualification-{number}.nar\\n"
                "NarHash: sha256:0000000000000000000000000000000000000000000000000000\\n"
                "NarSize: 1\\nFileSize: 1\\nCompression: none\\nReferences: \\n"
                "UnknownField: "
            ).encode()
            body += bytes([65 + number]) * (BYTE_SIZE - len(body) - 1) + b"\\n"
            path = root / f"qualification-{number}.narinfo"
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(body)
                output.flush()
                os.fsync(output.fileno())
            originals.append({
                "file": str(path), "metadata": True,
                "byte_size": len(body), "sha256": hashlib.sha256(body).hexdigest(),
            })
        print(json.dumps(originals, sort_keys=True))
    """)
    configuration = (
        f"ROOT = {directory!r}\n"
        f"BYTE_SIZE = {DIRECT_QUALIFICATION_NARINFO_BYTES}\n"
        f"COUNT = {DIRECT_QUALIFICATION_NARINFO_COUNT}\n"
    )
    originals = json.loads(machine.succeed(
        f"{shlex.quote(python)} - <<'QUALIFICATION_NARINFO'\n"
        + configuration + script + "\nQUALIFICATION_NARINFO\n",
        timeout=60,
    ))
    assert len(originals) == DIRECT_QUALIFICATION_NARINFO_COUNT, originals
    assert all(
        item["metadata"] is True
        and item["byte_size"] == DIRECT_QUALIFICATION_NARINFO_BYTES
        and re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
        for item in originals
    ), originals
    assert len({item["sha256"] for item in originals}) == len(originals), originals
    return originals


def prepare_direct_publication_corpus(client, python, surface_root):
    """Extend an APR-authored signed surface with real disk-backed objects."""
    script = textwrap.dedent("""
        import hashlib
        import json
        import os
        from pathlib import Path

        root = Path(ROOT)
        if not root.is_absolute() or not (root / "HEAD").is_file():
            raise ValueError("the signed publication surface is absent")
        os.chmod(root, 0o700)
        content = root / "web" / "direct-content"
        metadata = root / "web" / "packages"
        content.mkdir(parents=True, exist_ok=True)
        metadata.mkdir(parents=True, exist_ok=True)

        originals = []
        for number in range(LARGE_COUNT):
            path = content / f"qualification-{number}.bin"
            digest = hashlib.sha256()
            block = bytes([number + 1]) * (1024 * 1024)
            remaining = LARGE_BYTES
            with path.open("xb") as output:
                while remaining:
                    chunk = block[:min(remaining, len(block))]
                    output.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
                output.flush()
                os.fsync(output.fileno())
            originals.append({
                "path": path.relative_to(root).as_posix(),
                "byte_size": path.stat().st_size,
                "sha256": digest.hexdigest(),
            })

        metadata_catalogue = hashlib.sha256()
        metadata_bytes = 0
        for number in range(METADATA_COUNT):
            path = metadata / f"direct-qualification-{number:05d}.json"
            body = json.dumps({
                "name": f"direct-qualification-{number:05d}",
                "version": "1.0.0",
                "qualificationSequence": number,
            }, sort_keys=True, separators=(",", ":")).encode() + b"\\n"
            with path.open("xb") as output:
                output.write(body)
            metadata_bytes += len(body)
            identity = {
                "path": path.relative_to(root).as_posix(),
                "byte_size": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
            }
            metadata_catalogue.update(
                json.dumps(identity, sort_keys=True, separators=(",", ":"))
                .encode() + b"\\n"
            )

        report = {
            "large_objects": originals,
            "metadata_objects": METADATA_COUNT,
            "metadata_source_bytes": metadata_bytes,
            "metadata_catalogue_sha256": metadata_catalogue.hexdigest(),
        }
        print(json.dumps(report, sort_keys=True))
    """)
    configuration = (
        f"ROOT = {surface_root!r}\n"
        f"LARGE_BYTES = {DIRECT_LARGE_OBJECT_BYTES}\n"
        f"LARGE_COUNT = {DIRECT_LARGE_OBJECT_COUNT}\n"
        f"METADATA_COUNT = {DIRECT_METADATA_OBJECT_COUNT}\n"
    )
    report = json.loads(client.succeed(
        f"{shlex.quote(python)} - <<'DIRECT_CORPUS'\n"
        + configuration + script + "\nDIRECT_CORPUS\n",
        timeout=600,
    ))
    assert len(report["large_objects"]) == DIRECT_LARGE_OBJECT_COUNT, report
    assert all(
        item["byte_size"] == DIRECT_LARGE_OBJECT_BYTES
        and re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
        for item in report["large_objects"]
    ), report
    assert len({item["sha256"] for item in report["large_objects"]}) == DIRECT_LARGE_OBJECT_COUNT, report
    assert report["metadata_objects"] == DIRECT_METADATA_OBJECT_COUNT, report
    assert re.fullmatch(r"[0-9a-f]{64}", report["metadata_catalogue_sha256"]), report
    return report


def direct_client_observations(stderr):
    """Retain complete numeric summaries emitted by the actual publisher."""
    observations = []
    for line in stderr.splitlines():
        if not line.startswith("Direct upload client: "):
            continue
        payload = line.removeprefix("Direct upload client: ")
        fields = payload.split()
        if len(fields) != len(DIRECT_CLIENT_COUNTERS):
            raise ValueError("the direct client observation is incomplete")
        observation = {}
        for expected, field in zip(DIRECT_CLIENT_COUNTERS, fields):
            match = re.fullmatch(r"([a-z_]+)=([0-9]+)", field)
            if not match or match.group(1) != expected:
                raise ValueError("the direct client observation changed shape")
            observation[expected] = int(match.group(2))
        if observation["provider_successes"] > observation["provider_attempts"]:
            raise ValueError("the direct client success count exceeds attempts")
        observations.append(observation)
    if not observations:
        raise ValueError("the actual direct publisher emitted no observations")
    return observations


def assert_direct_client_activity(observations, source_report):
    """Require actual multipart overlap and batch controls from the real client."""
    assert len(observations) == 1, "each preserved invocation has its own counters"
    actual = observations[0]
    object_count = DIRECT_METADATA_OBJECT_COUNT + DIRECT_LARGE_OBJECT_COUNT
    minimum_bytes = (
        DIRECT_LARGE_OBJECT_COUNT * DIRECT_LARGE_OBJECT_BYTES
        + source_report["metadata_source_bytes"]
    )
    assert actual["acknowledged_bytes"] >= minimum_bytes, actual
    assert actual["provider_successes"] >= object_count, actual
    assert actual["max_provider_active"] >= 2, actual
    assert actual["caps"] >= 1 and actual["identity"] >= 1, actual
    assert actual["manifest_begin"] >= 1 and actual["manifest_append"] > 1, actual
    assert actual["manifest_seal"] >= 1 and actual["commit"] >= 1, actual
    for phase in ("begin", "grant", "report", "complete"):
        assert 0 < actual[phase] < object_count, (phase, actual)


def assert_direct_publication_objects(publication, source_report):
    """Compare actual terminal publication originals with the client sources."""
    assert publication["state"] == "ready", publication
    objects = {item["path"]: item for item in publication["objects"]}
    assert len(objects) == len(publication["objects"]), "duplicate publication paths"
    for expected in source_report["large_objects"]:
        actual = objects[expected["path"]]
        assert actual["verified"], actual
        assert int(actual["byte_size"]) == expected["byte_size"], actual
        assert actual["sha256"] == expected["sha256"], actual
        assert actual["kind"] == "immutable", actual

    metadata = [
        item for path, item in objects.items()
        if re.fullmatch(r"web/packages/direct-qualification-[0-9]{5}\.json", path)
    ]
    assert len(metadata) == source_report["metadata_objects"], len(metadata)
    assert all(item["verified"] and item["kind"] == "mutable_pointer" for item in metadata)
    catalogue = hashlib.sha256()
    for item in sorted(metadata, key=lambda item: item["path"]):
        identity = {
            "path": item["path"],
            "byte_size": int(item["byte_size"]),
            "sha256": item["sha256"],
        }
        catalogue.update(
            json.dumps(identity, sort_keys=True, separators=(",", ":"))
            .encode() + b"\n"
        )
    assert catalogue.hexdigest() == source_report["metadata_catalogue_sha256"]
