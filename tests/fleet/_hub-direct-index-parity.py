"""Compare genuine signed business indexes across three runtime topologies.

Companions publish the exact signed APR corpus after the loaded business window.
Their ordinary Worker emulator is not an accepted managed Direct profile. Each
process has a distinct root and port; only its recorded lifetime is stopped.
"""

import hashlib
import json
import time


def wait_direct_registry_indexes(controls, registries, sources, timeout=240):
    """Wait for actual fresh indexes at each publisher's exact signed commit."""
    result = {}
    for label, publication in registries.items():
        deadline = time.monotonic() + timeout
        attempts = []
        while True:
            registry = controls.call("RegistryService", "GetRegistry", {
                "slug": publication["registry"]["slug"],
            })["registry"]
            attempts.append({"indexState": registry.get("indexState"),
                "indexError": registry.get("indexError"),
                "lastIndexedCommit": registry.get("lastIndexedCommit")})
            if (registry.get("indexState") == "fresh"
                    and registry.get("lastIndexedCommit") == sources[label]["sourceCommit"]):
                break
            if time.monotonic() >= deadline:
                retain_direct_flow("actual-registry-index-wait-" + label + ".json", attempts)
                raise ValueError("actual registry index did not reach its retained signed commit")
            time.sleep(2)
        result[label] = {"registrySlug": registry["slug"],
            "sourceCommit": sources[label]["sourceCommit"], "observations": attempts}
    retain_direct_flow("actual-registry-index-freshness.json", result)
    return result


def assert_direct_registry_index_parity(readers, slug, *, source_commit, container_index_digest=None):
    """Compare every authoritative projection and require nonempty release data."""
    if set(readers) != {"hybrid", "native_only", "worker_only"} or container_index_digest is not None:
        raise ValueError("business parity readers or selected corpus scope differ")
    snapshots = {mode: registry_index_observations(query, slug) for mode, query in readers.items()}
    selected = snapshots["hybrid"]
    index = selected["index"]
    if len(index) != 1 or index[0][:3] != ["fresh", None, source_commit]:
        raise ValueError("actual authoritative index is not fresh at the signed source commit")
    releases = selected["releases"]
    if len(releases) != 1 or releases[0][0] != "1.0.0":
        raise ValueError("actual signed business release inventory differs")
    for table in ("packages", "versions", "platforms", "keys", "release_records",
                  "catalog_artifacts", "artifact_snapshots", "release_artifacts", "channels"):
        if not selected[table]:
            raise ValueError("actual signed business index lacks required " + table)
    if selected["channel_floors"] != [["stable", "1.0.0"]] or len(selected["channel_partitions"]) != 256:
        raise ValueError("actual signed business channel frontier differs")
    for snapshot in selected["artifact_snapshots"]:
        if snapshot[1] != source_commit or snapshot[4] != "complete" or snapshot[5] != snapshot[6]:
            raise ValueError("actual release artifact head lacks a complete exact-source snapshot")
    differences = {mode: [table for table in selected if snapshot[table] != selected[table]]
        for mode, snapshot in snapshots.items()}
    private = {"version": 1, "registrySlug": slug, "sourceCommit": source_commit,
        "snapshots": snapshots, "differences": differences}
    retain_direct_flow("actual-authoritative-index-snapshots-private.json", private)
    if any(differences.values()):
        raise ValueError("actual same-corpus authoritative projections differ; snapshots retained")
    encoded = json.dumps(selected, sort_keys=True, separators=(",", ":")).encode()
    result = {"version": 1, "modes": sorted(readers), "sourceCommit": source_commit,
        "snapshotSha256": hashlib.sha256(encoded).hexdigest(),
        "rowsByTable": {name: len(rows) for name, rows in selected.items()},
        "optionalAbsentProjections": [name for name, rows in selected.items() if not rows],
        "scope": "all authoritative tables compared from the same genuine signed APR release; absent docs/OCI are not content-route qualification"}
    retain_direct_flow("actual-authoritative-index-parity.json", result)
    return result


class DirectPrivateParityMachine:
    """Keep real companion commands and authentication output in private evidence."""

    def __init__(self, machine, role):
        self.machine = machine
        self.agent = machine.agent
        self.role = role
        self.sequence = 0

    def execute(self, command, timeout=60):
        prefix = "# Private parity command and output; numeric receipts only.\n"
        try:
            status, stdout, stderr = self.agent.request((prefix + command).encode(), timeout=timeout)
        except Exception:
            raise RuntimeError("private parity command transport failed") from None
        name = "parity-" + self.role + "-" + str(self.sequence)
        self.sequence += 1
        retain_direct_flow(name + ".stdout.private", stdout)
        retain_direct_flow(name + ".stderr.private", stderr)
        retain_direct_flow(name + ".receipt.json", {"status": status,
            "commandSha256": hashlib.sha256(command.encode()).hexdigest(),
            "stdoutBytes": len(stdout), "stderrBytes": len(stderr)})
        return status, stdout.decode(), "private parity diagnostics retained" if status else ""

    def succeed(self, command, timeout=60):
        status, stdout, _ = self.execute(command, timeout)
        if status:
            raise RuntimeError("private parity command failed with exit " + str(status))
        return stdout

    def wait_until_succeeds(self, command, timeout=60):
        deadline = time.monotonic() + timeout
        while True:
            status, stdout, _ = self.execute(command, min(60, timeout))
            if status == 0:
                return stdout
            if time.monotonic() >= deadline:
                raise RuntimeError("private parity readiness deadline exceeded")
            time.sleep(1)


def direct_parity_process(machine, tools, root, pid_file, executable, stop=None):
    """Read or stop only an exact companion PID, owner, argv and start identity."""
    return json.loads(direct_guest_python(machine, tools["python"], """
        import hashlib, os, signal, time
        from pathlib import Path

        pid = int((Path(selected['root']) / selected['pidFile']).read_text())
        process = Path('/proc') / str(pid)
        fields = (process / 'stat').read_text().rpartition(') ')[2].split()
        argv = (process / 'cmdline').read_bytes().split(b'\\x00')[:-1]
        executable = os.readlink(process / 'exe')
        if process.stat().st_uid != os.getuid() or executable != os.path.realpath(selected['executable']):
            raise ValueError('companion owner or actual executable differs')
        with (process / 'exe').open('rb') as source:
            digest = hashlib.file_digest(source, 'sha256').hexdigest()
        receipt = {'version': 1, 'pid': pid, 'ownerUid': os.getuid(),
            'startTicks': fields[19], 'executable': executable,
            'executableSha256': digest, 'argvSha256': hashlib.sha256(b'\\x00'.join(argv)).hexdigest(),
            'root': selected['root'], 'pidFile': selected['pidFile']}
        if selected['stop'] is not None:
            if receipt != selected['stop']:
                raise ValueError('companion lifetime changed before stop')
            os.kill(pid, signal.SIGTERM)
            for _ in range(100):
                if not process.exists() or (process / 'stat').read_text().rpartition(') ')[2].split()[0] == 'Z':
                    break
                time.sleep(0.1)
            else:
                raise ValueError('recorded companion did not stop after SIGTERM')
        print(json.dumps(receipt))
    """, {"root": root, "pidFile": pid_file, "executable": executable, "stop": stop}, timeout=30))


def qualify_direct_business_indexes(client, native, worker, tools, registry, source):
    """Publish identical semantic source into genuine ordinary companion runtimes."""
    selected_tools = {**tools["parityTools"], "python": tools["python"], "curl": tools["curl"],
        "aos": tools["aos"], "hub": tools["hub"], "node": tools["node"],
        "miniflare": tools["miniflare"], "postgres": tools["postgres"]}
    result = qualify_registry_runtime_parity(
        DirectPrivateParityMachine(client, "client"), DirectPrivateParityMachine(native, "native"),
        DirectPrivateParityMachine(worker, "worker"), tools=selected_tools,
        fixture=tools["parityFixture"], corpus_fixture={
            "surfaceRoot": source["surfaceRoot"], "trustKey": source["trustKey"],
            "sourceCommit": source["sourceCommit"], "registrySlug": registry["registry"]["slug"]},
        snapshot_assert=lambda readers, slug, **options: assert_direct_registry_index_parity(
            readers, slug, source_commit=source["sourceCommit"], **options),
        process_observer=lambda machine, root, pid_file, executable: direct_parity_process(
            machine, selected_tools, root, pid_file, executable),
        process_stop=lambda machine, receipt: direct_parity_process(machine, selected_tools,
            receipt["root"], receipt["pidFile"], receipt["executable"], stop=receipt),
    )
    retain_direct_flow("actual-business-runtime-index-parity.json", result)
    return result
