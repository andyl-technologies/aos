"""Select a small signed-publication workload after the ordinary fleet setup.

This module is injected only by _hub-direct-development.nix. The full fleet's
authority, prequalification, provider limit and production queues stay intact.
The development workload omits interruption and later fault windows, and never
establishes full fleet qualification.
"""

from collections import defaultdict


DIRECT_LARGE_OBJECT_BYTES = 16 * 1024 ** 2
DIRECT_METADATA_OBJECT_COUNT = 64
DEVELOPMENT_PUBLICATION_SECONDS = 180


class _DevelopmentPublicationComplete(Exception):
    """Ends this explicit development target after its publication assertions."""


_ordinary_external_direct_fleet = run_external_direct_fleet
_ordinary_publication_sources = prepare_external_direct_publication_sources


def prepare_external_direct_publication_sources(client, tools):
    """Author a genuine helper release without the unrelated CLI/Native inventory."""
    project = Path(DEVELOPMENT_PUBLICATION_PROJECT).read_text()
    if project.count(DEVELOPMENT_PUBLICATION_INVENTORY) != 1:
        raise ValueError("small publication project has an ambiguous inventory")
    project = project.replace(DEVELOPMENT_PUBLICATION_INVENTORY, "./inventory.json")
    inventory = Path(DEVELOPMENT_PUBLICATION_INVENTORY).read_bytes()
    directory = "/var/lib/hybrid-client/direct-development-project"
    direct_guest_python(client, tools["python"], """
        import base64, os
        from pathlib import Path

        root = Path(selected['directory'])
        root.mkdir(mode=0o700, exist_ok=False)
        for name in ('default.nix', 'inventory.json'):
            descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(base64.b64decode(selected[name], validate=True))
    """, {"directory": directory, "default.nix": base64.b64encode(project.encode()).decode(),
          "inventory.json": base64.b64encode(inventory).decode()})
    return _ordinary_publication_sources(client, {**tools, "publicationProject": directory})


def run_external_direct_fleet(*arguments, **keywords):
    """Run ordinary setup and stop before unrelated full qualification windows."""
    try:
        _ordinary_external_direct_fleet(*arguments, **keywords)
    except _DevelopmentPublicationComplete:
        return
    raise RuntimeError("development publication did not reach its completion boundary")


def _development_timing_summary(body):
    """Report fixed timing categories and numeric queue latency aggregates."""
    samples = defaultdict(list)
    enqueued, started = {}, {}
    queue_events = defaultdict(int)
    for phase, millis in re.findall(
            r"direct_stage_timing phase=([a-z_]+) elapsed_millis=(\d+) success=true", body):
        if phase in {"provider_response_headers", "provider_response_body", "stage_provider",
                     "provider_foreground_capacity", "provider_bulk_capacity", "provider_metadata_capacity"}:
            samples[phase].append(int(millis))
    for line in body.splitlines():
        if "direct_upload_observation " not in line:
            continue
        row = json.loads(line.split("direct_upload_observation ", 1)[1])
        item = row.get("object")
        if not isinstance(item, dict):
            continue
        phase = item["dependencyPhase"]
        if phase not in {"content", "visibility", "discovery"}:
            continue
        session = item["session"]["sessionDigest"]
        attempt = row["attemptDigest"]
        at = row["atMillis"]
        kind, outcome = row.get("kind"), row.get("outcome")
        if kind in {"queue_enqueue", "queue_start", "queue_finish", "queue_retry", "queue_ack"}:
            queue_events[phase + ":" + kind + ":" + outcome] += 1
        if kind == "queue_enqueue" and outcome == "positive":
            enqueued.setdefault(session, at)
        elif kind == "queue_start":
            started[attempt] = at
            if session in enqueued:
                samples[phase + "_enqueue_to_start"].append(at - enqueued[session])
        elif kind == "queue_finish" and attempt in started:
            samples[phase + "_active"].append(at - started.pop(attempt))

    result = {}
    for phase, values in sorted(samples.items()):
        values.sort()
        result[phase] = {"count": len(values), "medianMillis": statistics.median(values),
                         "p95Millis": values[int(.95 * (len(values) - 1))],
                         "maximumMillis": values[-1]}
    return {"timings": result, "queueEvents": dict(queue_events)}


def run_external_direct_publication(client, native, worker, s3, tools, controls, credentials,
                                   authority, process, identity, acceptance, database_machine,
                                   publication_inputs):
    """Run two genuine signed publishers with the original Visibility rendezvous."""
    sources = publication_inputs["sources"]
    registries = {}
    for label, name in (("a", "external-direct"), ("b", "external-overlap")):
        registries[label] = controls.create_external_registry(
            credentials["organization"], credentials["binding"], name,
            [sources[label]["trustKey"]], "primary",
            credentials["binding"]["spec"]["s3"]["prefix"] + "/registry-" + label,
            credentials["currentSqlPins"]["currentWriteRevision"], False,
            label_prefix="development-publication-" + label)
        login_direct_publisher(client, tools, sources[label])

    before_worker = direct_log_position(worker, tools["python"], process["logFile"])
    before_native = direct_log_position(native, tools["python"],
                                        "/var/lib/hybrid-native-observations/requests.jsonl")
    before_provider = direct_log_position(s3, tools["python"],
                                          "/var/lib/hybrid-s3/provider-observations.jsonl")
    cursor = {**before_worker, "offset": before_worker["byteSize"]}
    processes, completed, terminals, timings = {}, {}, {}, {}
    started_at = time.monotonic()
    failure = None

    def start(label):
        processes[label] = start_direct_publication(client, tools,
            registries[label]["registry"]["slug"], sources[label], None, label, 1)

    try:
        start("a")
        last_progress = started_at
        while len(completed) != 2:
            if time.monotonic() - started_at > DEVELOPMENT_PUBLICATION_SECONDS:
                raise RuntimeError("small concurrent publication exceeded its 180-second deadline")
            if "b" not in processes:
                rendezvous = direct_visibility_rendezvous(worker, tools, cursor,
                    identity["identity"]["sourceDigest"], timings)
                if rendezvous is not None:
                    retain_direct_flow("development-rendezvous.json", rendezvous)
                    start("b")
            for label, publisher in list(processes.items()):
                if label in completed:
                    continue
                result = poll_direct_publication(client, tools, publisher)
                if result is None:
                    continue
                stdout = read_direct_guest_file(client, tools["python"],
                    publisher["directory"] + "/stdout", 8 * 1024 * 1024)
                retain_direct_flow("development-" + label + ".stdout.private.json", stdout)
                retain_direct_flow("development-" + label + ".result.json", result)
                if result["timedOut"] or result["exitCode"] != 0:
                    raise RuntimeError("small signed publisher failed; private output retained")
                publication = json.loads(stdout)["data"]
                assert_direct_publication_objects(publication, publication_inputs["corpora"][label])
                completed[label] = publication
                terminals[label] = result
            if "a" in completed and "b" not in processes:
                raise RuntimeError("small publication completed without a Visibility rendezvous")
            if time.monotonic() - last_progress >= 15:
                print(json.dumps({"developmentPublicationSeconds": round(time.monotonic() - started_at),
                                  "publishersStarted": len(processes), "publishersReady": len(completed)}), flush=True)
                last_progress = time.monotonic()
            if len(completed) != 2:
                time.sleep(.2)
        if int(terminals["b"]["startedUnixNs"]) >= int(terminals["a"]["finishedUnixNs"]):
            raise RuntimeError("small publishers did not actually overlap")
    except BaseException as error:
        failure = error
        raise
    finally:
        with preserve_direct_workload_failure(failure):
            worker_log, _ = retain_direct_log_window(worker, tools["python"], before_worker,
                                                     "development-worker.private.log")
            retain_direct_log_window(native, tools["python"], before_native, "development-native.private.jsonl")
            retain_direct_log_window(s3, tools["python"], before_provider, "development-provider.private.jsonl")
            for label, publisher in processes.items():
                stderr = read_direct_guest_file(client, tools["python"],
                    publisher["directory"] + "/stderr", 1024 * 1024)
                retain_direct_flow("development-" + label + ".stderr.private.log", stderr)
            summary = {"version": 1, "developmentOnly": True, "fullQualification": False,
                       "metadataObjects": DIRECT_METADATA_OBJECT_COUNT,
                       "largeObjectBytes": DIRECT_LARGE_OBJECT_BYTES,
                       "publishersStarted": len(processes), "publishersReady": len(completed),
                       "overlapConfirmed": len(terminals) == 2 and
                           int(terminals["b"]["startedUnixNs"]) < int(terminals["a"]["finishedUnixNs"]),
                       "seconds": round(time.monotonic() - started_at, 3),
                       **_development_timing_summary(worker_log.read_text())}
            retain_direct_flow("development-summary.json", summary)
            print(json.dumps(summary), flush=True)
    raise _DevelopmentPublicationComplete()
