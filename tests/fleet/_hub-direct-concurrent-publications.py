"""Schedule genuine independent publication phases without changing barriers.

Publication A contains two large Content originals and the full Visibility JSON
corpus. Publication B contains the third large Content original under its own
signed registry and admitted placement. An actual A Visibility enqueue starts B;
production queue intervals determine whether real overlap occurred.
"""

import base64
import hashlib
import json
import re
import shlex
import textwrap
import time


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
        "--root", signed["surfaceRoot"], "--hub", tools["workerUrl"], "--token", token,
        "--direct-provider-policy", tools["providerPolicyFile"],
        "--direct-upload-journal", signed["publisherHome"] + "/direct-upload.sqlite"]
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

        fields = Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()
        pin = {'supervisorPid': os.getpid(), 'supervisorUid': os.getuid(),
            'supervisorStartTicks': fields[19], 'supervisorExecutable': os.readlink('/proc/self/exe'),
            'supervisorArguments': [sys.executable, str(root / 'supervisor.py')]}
        retain_receipt('process.json', pin)
        selected = json.loads((root / 'input.json').read_bytes())
        environment = dict(os.environ)
        environment.update(HOME=selected['publisherHome'], SSL_CERT_FILE='/etc/ssl/certs/ca-certificates.crt')
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
        outcome.update(version=1, startedUnixNs=str(started), finishedUnixNs=str(time.time_ns()),
            publicationLabel=selected['label'], attempt=selected['attempt'])
        retain_receipt('result.json', outcome)
    """)
    return json.loads(direct_guest_python(client, tools["python"], """
        import hashlib, os, subprocess, time
        from pathlib import Path

        root = Path('/var/lib/hybrid-client/concurrent-' + selected['label'] + '-' + str(selected['attempt']))
        root.mkdir(mode=0o700, exist_ok=False)
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

    def start(label, attempt):
        token = direct_root_browser_token(client, tools["curl"], tools["python"], private_guest_command, reuse_session=True)
        process = start_direct_publication(client, tools, registries[label]["registry"]["slug"],
            sources[label], token, label, attempt)
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
                fresh_token = direct_root_browser_token(client, tools["curl"], tools["python"],
                    private_guest_command, reuse_session=True)
                sparse["changedSource"] = probe_direct_changed_source(
                    client, tools, process, sources["a"], source, fresh_token)
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
            error = reply.get("error", "")
            retained = re.search(r"publication ([0-9a-f]{32}) remains resumable;", error)
            if (result["timedOut"] or process["attempt"] >= 3 or retained is None
                    or "401 Unauthorized" not in error or "JWT has expired" not in error):
                raise RuntimeError("actual concurrent publisher failed; no mutation replay or cleanup")
            if label in originals and originals[label] != retained.group(1):
                raise ValueError("publication JWT resume changed its retained original")
            originals[label] = retained.group(1)
            start(label, process["attempt"] + 1)
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
