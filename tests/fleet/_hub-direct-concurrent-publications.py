"""Schedule genuine independent publication phases without changing barriers.

Publication A contains two large Content originals and the full Visibility JSON
corpus. Publication B contains the third large Content original under its own
signed registry and admitted placement. An actual A Visibility enqueue starts B;
production queue intervals determine whether real overlap occurred.
"""

import base64
import hashlib
import json
import shlex
import textwrap
import time


def login_direct_publisher(client, tools, signed):
    """Approve the ordinary CLI device login and retain its renewable profile."""
    observed = json.loads(direct_guest_python(client, tools["python"], """
        import os, re, subprocess, time, urllib.parse
        from pathlib import Path

        os.umask(0o077)
        home = Path(selected['home'])
        root = home / 'device-login'
        root.mkdir(mode=0o700, exist_ok=False)
        environment = dict(os.environ)
        environment.update(AOS_CONFIG_HOME=str(home / '.config/aos'),
            XDG_CONFIG_HOME=str(home / '.config'),
            XDG_DATA_HOME=str(home / '.local/share'), XDG_CACHE_HOME=str(home / '.cache'),
            SSL_CERT_FILE='/etc/ssl/certs/ca-certificates.crt')
        origin = selected['origin']
        cookie = '/var/lib/hybrid-client/browser-session/cookies'

        def request(label, path, arguments=()):
            result = subprocess.run(selected['curl'] + ['-sS', '--max-time', '20',
                '--max-filesize', '262144', '--cookie', cookie,
                '--output', str(root / (label + '.body')), '--write-out', '%{http_code}']
                + list(arguments) + [origin + path], capture_output=True, check=False, timeout=25)
            (root / (label + '.stderr')).write_bytes(result.stderr)
            if result.returncode or result.stderr:
                raise ValueError('device approval transport failed; private originals retained')
            return result.stdout, (root / (label + '.body')).read_bytes()

        with (root / 'stdout').open('xb') as stdout, (root / 'stderr').open('xb') as stderr:
            login = subprocess.Popen([selected['aos'], 'hub', 'login', '--hub', origin],
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=environment)
            try:
                deadline = time.monotonic() + 45
                while True:
                    output = (root / 'stdout').read_bytes() + (root / 'stderr').read_bytes()
                    if len(output) > 65536:
                        raise ValueError('device login output exceeded its bound')
                    codes = set(re.findall(re.escape(origin.encode())
                        + rb'/activate\\?user_code=([A-Z0-9-]{4,32})', output))
                    if len(codes) == 1:
                        break
                    if codes or login.poll() is not None or time.monotonic() > deadline:
                        raise ValueError('ordinary CLI did not publish a unique device approval code')
                    time.sleep(0.05)
                code = next(iter(codes)).decode()
                status, page = request('activate', '/activate?user_code=' + code)
                csrf = re.findall(rb'name="csrf" value="([0-9a-f]{64})"', page)
                if status != b'200' or len(set(csrf)) != 1:
                    raise ValueError('authenticated device approval has no unique CSRF value')
                payload = urllib.parse.urlencode({'csrf': csrf[0].decode(),
                    'user_code': code, 'decision': 'approve'}).encode()
                payload_file = root / 'approval.request'
                payload_file.write_bytes(payload)
                status, _ = request('approve', '/activate', ['--header', 'Origin: ' + origin,
                    '--header', 'Content-Type: application/x-www-form-urlencoded',
                    '--data-binary', '@' + str(payload_file)])
                if status != b'303' or login.wait(timeout=30) != 0:
                    raise ValueError('ordinary CLI device login did not complete successfully')
                profile = home / '.config/aos/hub-profiles.json'
                if not profile.is_file() or profile.stat().st_mode & 0o077:
                    raise ValueError('ordinary CLI did not retain a private renewable profile')
                print(json.dumps({'version': 1, 'loginExitCode': login.returncode,
                    'approvalStatus': 303, 'privateProfileStored': True}))
            finally:
                if login.poll() is None:
                    login.kill()
                    login.wait(timeout=5)
    """, {"home": signed["publisherHome"], "origin": tools["workerUrl"],
            "aos": tools["aos"], "curl": shlex.split(tools["curl"])}, timeout=100))
    retain_direct_flow("publisher-" + signed["publisherHome"].rsplit("/", 1)[-1]
        + "-device-login.json", observed)


def split_direct_publication_sources(client, tools, signed_a, signed_b, corpus):
    """Move one actual disk-backed original into the second signed surface."""
    moved = json.loads(direct_guest_python(client, tools["python"], """
        import hashlib, os
        from pathlib import Path

        original = selected['original']
        source = Path(selected['surfaceA']) / original['path']
        destination = Path(selected['surfaceB']) / original['path']
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if destination.exists():
            raise ValueError('second publication already contains the selected original')
        with source.open('rb') as input_file:
            digest = hashlib.file_digest(input_file, 'sha256').hexdigest()
        if source.stat().st_size != original['byte_size'] or digest != original['sha256']:
            raise ValueError('selected disk-backed source changed before distribution')
        os.rename(source, destination)
        if source.exists() or destination.stat().st_size != original['byte_size']:
            raise ValueError('actual publication source distribution failed')
        print(json.dumps({'original': original, 'sourceSurface': selected['surfaceA'],
            'destinationSurface': selected['surfaceB'], 'sha256': digest,
            'scope': 'same original bytes distributed across independent signed publications'}))
    """, {"surfaceA": signed_a["surfaceRoot"], "surfaceB": signed_b["surfaceRoot"],
            "original": corpus["large_objects"][-1]}, timeout=180))
    retain_direct_flow("actual-large-original-distribution.json", moved)
    return ({**corpus, "large_objects": corpus["large_objects"][:-1]},
            {"large_objects": [corpus["large_objects"][-1]], "metadata_objects": 0,
             "metadata_source_bytes": 0, "metadata_catalogue_sha256": hashlib.sha256(b"").hexdigest()})


def start_direct_publication(client, tools, registry_slug, signed, token, label, attempt):
    """Start one retained invocation with a bounded result-recording supervisor."""
    if label not in {"a", "b"} or type(attempt) is not int or not 1 <= attempt <= 3:
        raise ValueError("publication invocation identity is invalid")
    arguments = [tools["aos"], "--json", "hub", "registry", "publish", "upload", registry_slug,
        "--root", signed["surfaceRoot"], "--hub", tools["workerUrl"],
        "--direct-provider-policy", tools["providerPolicyFile"],
        "--direct-upload-journal", signed["publisherHome"] + "/direct-upload.sqlite"]
    if token is not None:
        arguments += ["--token", token]
    supervisor = textwrap.dedent("""
        import json, os, subprocess, sys, time
        from pathlib import Path

        root = Path(__file__).parent

        def retain_receipt(name, document):
            temporary = root / (name + '.pending')
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w') as output:
                json.dump(document, output, sort_keys=True, separators=(',', ':'))
                output.flush()
                os.fsync(output.fileno())
            os.link(temporary, root / name)
            temporary.unlink()
            # The VM may be stopped immediately after an observer fails. Make
            # the terminal result's directory entry durable before exiting.
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

        fields = Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()
        pin = {'supervisorPid': os.getpid(), 'supervisorUid': os.getuid(),
            'supervisorStartTicks': fields[19], 'supervisorExecutable': os.readlink('/proc/self/exe'),
            'supervisorArguments': [sys.executable, str(root / 'supervisor.py')]}
        retain_receipt('process.json', pin)
        selected = json.loads((root / 'input.json').read_bytes())
        environment = dict(os.environ)
        environment.update(AOS_CONFIG_HOME=selected['publisherHome']+'/.config/aos',
            XDG_CONFIG_HOME=selected['publisherHome']+'/.config',
            XDG_DATA_HOME=selected['publisherHome']+'/.local/share',
            XDG_CACHE_HOME=selected['publisherHome']+'/.cache', SSL_CERT_FILE='/etc/ssl/certs/ca-certificates.crt')
        started = time.time_ns()
        with open(root / 'stdout', 'xb') as stdout, open(root / 'stderr', 'xb') as stderr:
            os.chmod(root / 'stdout', 0o600)
            os.chmod(root / 'stderr', 0o600)
            try:
                result = subprocess.run(selected['arguments'], stdin=subprocess.DEVNULL,
                    stdout=stdout, stderr=stderr, env=environment, check=False, timeout=1800)
                outcome = {'exitCode': result.returncode, 'timedOut': False}
            except subprocess.TimeoutExpired:
                outcome = {'exitCode': None, 'timedOut': True}
            os.fsync(stdout.fileno())
            os.fsync(stderr.fileno())
        outcome.update(version=1, startedUnixNs=str(started), finishedUnixNs=str(time.time_ns()),
            publicationLabel=selected['label'], attempt=selected['attempt'])
        retain_receipt('result.json', outcome)
    """)
    return json.loads(direct_guest_python(client, tools["python"], """
        import hashlib, os, subprocess, time
        from pathlib import Path

        root = Path('/var/lib/hybrid-client/concurrent-' + selected['label'] + '-' + str(selected['attempt']))
        root.mkdir(mode=0o700, exist_ok=False)
        descriptor = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        inputs = {name: selected[name] for name in ('arguments', 'publisherHome', 'label', 'attempt')}
        files = {'input.json': json.dumps(inputs, separators=(',', ':')).encode(),
            'supervisor.py': base64.b64decode(selected['supervisor'], validate=True)}
        for name, body in files.items():
            descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(body)
                output.flush()
                os.fsync(output.fileno())
        descriptor = os.open(root / 'supervisor.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as log:
            process = subprocess.Popen([selected['python'], str(root / 'supervisor.py')],
                stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        deadline = time.monotonic() + 5
        while not (root / 'process.json').is_file():
            if process.poll() is not None or time.monotonic() > deadline:
                raise ValueError('actual publication supervisor failed before its identity receipt')
            time.sleep(0.05)
        pin = json.loads((root / 'process.json').read_bytes())
        if pin['supervisorPid'] != process.pid or pin['supervisorUid'] != os.getuid():
            raise ValueError('actual publication supervisor identity changed at startup')
        print(json.dumps({'version': 1, 'directory': str(root), **pin,
            'supervisorSha256': hashlib.sha256(files['supervisor.py']).hexdigest(),
            'label': selected['label'], 'attempt': selected['attempt']}))
    """, {"arguments": arguments, "publisherHome": signed["publisherHome"], "label": label,
            "attempt": attempt, "python": tools["python"],
            "supervisor": base64.b64encode(supervisor.encode()).decode()}))


def poll_direct_publication(client, tools, process):
    """Read an actual retained terminal result; absence remains pending."""
    return json.loads(direct_guest_python(client, tools["python"], """
        import os
        from pathlib import Path
        path = Path(selected['directory']) / 'result.json'
        if path.is_file():
            body = path.read_bytes()
            if len(body) > 4096:
                raise ValueError('publication process result exceeds its bound')
            print(body.decode())
        else:
            directory = Path('/proc') / str(selected['supervisorPid'])
            try:
                fields = (directory / 'stat').read_text().rsplit(')', 1)[1].split()
                arguments = (directory / 'cmdline').read_bytes().split(b'\\x00')[:-1]
                if (fields[19] != selected['supervisorStartTicks']
                        or directory.stat().st_uid != selected['supervisorUid']
                        or os.readlink(directory / 'exe') != selected['supervisorExecutable']
                        or [argument.decode() for argument in arguments] != selected['supervisorArguments']):
                    raise ValueError('publication supervisor lifetime identity changed')
            except FileNotFoundError:
                if path.is_file():
                    print(path.read_text())
                else:
                    raise ValueError('publication supervisor disappeared without a retained result')
            else:
                print('null')
    """, process))


def direct_visibility_rendezvous(worker, tools, cursor, expected_source):
    """Read genuine production events since A started, before B is dispatched."""
    captured = json.loads(direct_guest_python(worker, tools["python"], """
        import os
        with open(selected['path'], 'rb') as source:
            metadata = os.fstat(source.fileno())
            if str(metadata.st_dev) != selected['device'] or str(metadata.st_ino) != selected['inode']:
                raise ValueError('Worker log identity changed during rendezvous')
            source.seek(selected['offset'])
            body = source.read(1048576)
        boundary = body.rfind(b'\\n')
        if boundary < 0:
            body = b''
        else:
            body = body[:boundary + 1]
        print(json.dumps({'body': base64.b64encode(body).decode(), 'offset': selected['offset'] + len(body)}))
    """, cursor))
    body = base64.b64decode(captured["body"], validate=True)
    cursor["offset"] = captured["offset"]
    if DIRECT_RUNTIME_PREFIX not in body.decode():
        return None
    events = direct_runtime_observations(body.decode(), expected_source)
    for event in events:
        if (event["scope"] == "production_queue" and event["kind"] == "queue_enqueue"
                and event["object"]["dependencyPhase"] == "visibility"):
            return {"version": 1, "event": event,
                "capturedChunkSha256": hashlib.sha256(body).hexdigest(), "cursor": dict(cursor),
                "scope": "actual A Visibility enqueue before B exists; no phase or permission hold"}
    return None


def run_direct_concurrent_publications(client, worker, tools, sources, registries,
                                       before_worker, expected_source, corpus_a):
    """Start B from A's genuine Visibility event and retain every invocation."""
    processes, completed, originals, invocations = {}, {}, {}, []
    pages, page_intervals, failed_probes = [], [], []
    sparse = {"interruption": None, "changedSource": None, "continuity": None,
        "terminalCountersUnavailable": []}
    cursor = {**before_worker, "offset": before_worker["byteSize"]}
    for signed in sources.values():
        login_direct_publisher(client, tools, signed)

    def start(label, attempt):
        process = start_direct_publication(client, tools, registries[label]["registry"]["slug"],
            sources[label], None, label, attempt)
        processes[label] = process
        retain_direct_flow("publisher-" + label + "-" + str(attempt) + ".process.json", process)

    start("a", 1)
    deadline = time.monotonic() + 5400
    while len(completed) != 2:
        if time.monotonic() > deadline:
            raise RuntimeError("actual concurrent publications exceeded their retained invocation budget")
        if sparse["interruption"] is None and "a" not in completed:
            process = processes["a"]
            observation = observe_direct_sparse_publisher(client, tools, process, sources["a"], corpus_a)
            if observation["sparse"]:
                if process["attempt"] >= 3:
                    raise ValueError("actual sparse interruption has no remaining retained resume attempt")
                interrupted = interrupt_direct_sparse_publisher(
                    client, tools, process, sources["a"], corpus_a, observation)
                if interrupted is not None:
                    publication_id = interrupted["admission"]["publication"]["admission"]["publicationId"]
                    if "a" in originals and originals["a"] != publication_id:
                        raise ValueError("sparse interruption changed the actual admitted publication")
                    originals["a"] = publication_id
                    # SIGKILL has no terminal JSON or counter report. Do not parse
                    # its partial stdout or reconstruct its unavailable metrics.
                    partial_stderr = read_direct_guest_file(client, tools["python"],
                        process["directory"] + "/stderr", 1048576)
                    invocations.append({"label": "a", "result": interrupted["result"],
                        "stderr": partial_stderr.decode(), "terminalCountersAvailable": False,
                        "metricsScope": "actual killed original; terminal counters unavailable"})
                    sparse["terminalCountersUnavailable"].append({"label": "a", "attempt": process["attempt"]})
                    sparse["interruption"] = interrupted
                    source = next(item for item in corpus_a["large_objects"]
                        if any(session["path"] == item["path"] and session["sparseGaps"]
                            for session in interrupted["checkpoint"]["sessions"]))
                    sparse["changedSource"] = probe_direct_changed_source(
                        client, tools, process, sources["a"], source, None)
                    start("a", process["attempt"] + 1)
        if "b" not in processes:
            rendezvous = direct_visibility_rendezvous(worker, tools, cursor, expected_source)
            if rendezvous is not None:
                retain_direct_flow("actual-publication-rendezvous.json", rendezvous)
                start("b", 1)
        for label, process in list(processes.items()):
            if label in completed:
                continue
            result = poll_direct_publication(client, tools, process)
            if result is None:
                continue
            prefix = "publisher-" + label + "-" + str(process["attempt"])
            stdout = read_direct_guest_file(client, tools["python"], process["directory"] + "/stdout", 8 * 1024 * 1024)
            stderr = read_direct_guest_file(client, tools["python"], process["directory"] + "/stderr", 1048576)
            retain_direct_flow(prefix + ".stdout.json", stdout)
            retain_direct_flow(prefix + ".stderr.log", stderr)
            retain_direct_flow(prefix + ".invocation.json", result)
            reply = json.loads(stdout)
            invocations.append({"label": label, "result": result, "stderr": stderr.decode(),
                "terminalCountersAvailable": True,
                "metricsScope": "actual completed invocation; only its fresh transfers"})
            if result["exitCode"] == 0:
                publication = reply["data"]
                if label in originals and originals[label] != publication["publication_id"]:
                    raise ValueError("publication JWT resume changed its original")
                completed[label] = publication
                if label == "a":
                    if sparse["interruption"] is None:
                        raise RuntimeError("A completed without an observed sparse gap; no interruption fabricated")
                    checkpoint = observe_direct_sparse_completion(client, tools, sources["a"], corpus_a)
                    sparse["continuity"] = assert_direct_sparse_resume(
                        sparse["interruption"], checkpoint, publication)
                    retain_direct_flow("actual-sparse-publication-continuity.json", sparse["continuity"])
                continue
            raise RuntimeError("actual concurrent publisher failed; no mutation replay or cleanup")
        if "a" in completed and "b" not in processes:
            raise RuntimeError("A completed without an observed Visibility rendezvous; no overlap fabricated")
        if len(completed) == 2:
            break
        started = time.time_ns()
        sample = direct_page_samples(client, tools, 1)
        page_intervals.append({"startedUnixNs": str(started), "finishedUnixNs": str(time.time_ns()),
            "pendingPublicationLabels": sorted(set(processes) - set(completed)), "probes": sample["probes"]})
        failed_probes.extend(probe["exitCode"] for probe in sample["probes"] if probe["exitCode"] != 0)
        pages.append(sample["samples"])
        time.sleep(0.2)
    observation = {"version": 1, "invocations": invocations, "pageSamples": "".join(pages),
        "pageIntervals": page_intervals, "failedPageProbeExitCodes": failed_probes,
        "pacing": "none", "sparseRecovery": sparse,
        "metricsCoverage": "terminal summaries cover completed invocations only; the killed original is explicitly unavailable",
        "scope": "two genuine admitted publications with unchanged dependency barriers; actual A interruption and same-original resume costs included"}
    retain_direct_flow("actual-concurrent-publisher.json", observation)
    return completed, observation
