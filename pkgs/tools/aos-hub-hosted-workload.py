"""Supervise the ordinary hosted publisher and retain incomplete measurements.

This runner creates no deployment, acceptance, registry or provider credential.
An operator selects two existing signed surfaces and authorized registries. The
same production CLI and fleet measurement parsers own upload and validation.
Publisher restart is a separate explicit invocation, never an effect retry.
Missing application-hop captures remain unknown, even after successful upload.
Optional clientObserver pins an independently measured immutable package context,
its producer source pair and the actual underlying publisher ELF. Legacy inputs
still run; their loaded pages remain observations without offering-overlap proof.
Version 3 retained windows preserve each invocation separately across resume.
Local offered-chunk spans do not prove provider receipt or Worker read overlap.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import runpy
import selectors
import signal
import sqlite3
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit


LARGE_BYTES = 2 * 1024 ** 3
METADATA_COUNT = 12_535
MAX_CAPTURE_BYTES = 512 * 1024 * 1024


def closed_json(body):
    """Read JSON without duplicate fields or nonfinite numbers."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON field")
            result[key] = value
        return result

    return json.loads(body, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))


def private_bytes(path, maximum):
    """Read a bounded owned regular input without following its final symlink."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_mode & 0o077 or before.st_size > maximum):
            raise ValueError("Input lacks bounded private custody")
        body = source.read(maximum + 1)
        after = os.fstat(source.fileno())
    if len(body) != before.st_size or any(getattr(before, field) != getattr(after, field)
                                         for field in ("st_ino", "st_dev", "st_size", "st_mtime_ns")):
        raise ValueError("Input changed while reading")
    return body


class Evidence:
    """Keep create-only evidence under an owned held directory descriptor."""

    def __init__(self, path, fresh=True):
        path = Path(path)
        if fresh:
            path.mkdir(mode=0o700)
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(self.fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            os.close(self.fd)
            raise ValueError("Output directory lacks private custody")
        self.path = Path(f"/proc/self/fd/{self.fd}")
        self.original_path = path.resolve(strict=True)
        self.identity = {"path": str(self.original_path), "device": str(info.st_dev), "inode": str(info.st_ino)}

    def save(self, name, value):
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,127}", name):
            raise ValueError("Invalid evidence filename")
        body = value if isinstance(value, bytes) else json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=self.fd)
        with os.fdopen(descriptor, "wb") as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
        return {"file": name, "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)}

    def close(self):
        os.close(self.fd)


def libraries(directory):
    """Load unchanged fleet parsers; VM transport functions are never invoked."""
    result = {}
    for name in ("_hub-direct-publisher.py", "_hub-perf.py",
                 "_hub-direct-runtime-observations.py", "_hub-direct-observations.py"):
        result.update(runpy.run_path(str(Path(directory) / name)))
    sparse = runpy.run_path(str(Path(directory) / "_hub-direct-sparse-publisher.py"))
    namespace = {}
    exec(sparse["SPARSE_GUEST_LIBRARY"], namespace)
    result["read_checkpoint"] = namespace["_read_checkpoint"]
    result["preserve_originals"] = namespace["_preserve_originals"]
    return result


def exact_fields(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError("Configuration differs from its closed schema")


def immutable_executable(path):
    """Pin a canonical resolved executable inside the immutable AOS store."""
    if not isinstance(path, str):
        raise ValueError("Select a canonical source-built AOS store executable")
    selected = Path(path)
    pattern = r"^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/]+/"
    if (not isinstance(path, str) or str(selected) != path
            or any(part in {".", ".."} for part in selected.parts)
            or not re.match(pattern, path)):
        raise ValueError("Select a canonical source-built AOS store executable")
    resolved = selected.resolve(strict=True)
    if not re.match(pattern, str(resolved)):
        raise ValueError("Tool resolved outside the immutable store")
    descriptor = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_mode & 0o6222
                or not before.st_mode & 0o111):
            raise ValueError("Selected executable lacks immutable file custody")
        digest = hashlib.file_digest(source, "sha256").hexdigest()
        after = os.fstat(source.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_mode", "st_uid")
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise ValueError("Selected executable changed while hashing")
    return {"file": str(resolved), "sha256": digest}


def selected_tool(tool):
    """Validate the selected hash as well as canonical store custody."""
    exact_fields(tool, {"file", "sha256"})
    observed = immutable_executable(tool["file"])
    if observed["sha256"] != tool["sha256"]:
        raise ValueError("Selected source-built executable changed")
    return observed


def binding(path):
    """Select existing operator inputs, without synthesizing runtime authority."""
    raw = private_bytes(path, 256 * 1024)
    selected = closed_json(raw)
    exact_fields(selected, {"version", "origin", "pagePath", "region", "timeoutSeconds",
                            "tools", "tokenFile", "pageCookieFile", "providerPolicyFile",
                            "publishers", "captures", "workerSourceDigest"}
                 | ({"clientObserver"} if "clientObserver" in selected else set()))
    origin = urlsplit(selected["origin"])
    if (selected["version"] != 1 or origin.scheme != "https" or not origin.netloc
            or origin.username or origin.password or origin.path or origin.query or origin.fragment
            or not selected["pagePath"].startswith("/")
            or selected["pagePath"].startswith("//") or "#" in selected["pagePath"]):
        raise ValueError("Use an exact HTTPS origin and same-origin page path")
    if (type(selected["timeoutSeconds"]) is not int
            or not 60 <= selected["timeoutSeconds"] <= 7200
            or not isinstance(selected["region"], str) or not selected["region"]
            or not re.fullmatch(r"[0-9a-f]{64}", selected["workerSourceDigest"])):
        raise ValueError("Missing bounded window or measured audience")
    exact_fields(selected["tools"], {"aos", "curl"})
    for tool in selected["tools"].values():
        selected_tool(tool)
    if set(selected["publishers"]) != {"a", "b"}:
        raise ValueError("Two independent publishers are required")
    for publication in selected["publishers"].values():
        exact_fields(publication, {"registry", "surfaceRoot", "publisherHome", "journal"})
        if (not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", publication["registry"])
                or any(not Path(publication[name]).is_absolute()
                       for name in ("surfaceRoot", "publisherHome", "journal"))):
            raise ValueError("Publisher coordinates are invalid")
    for name in ("registry", "surfaceRoot", "publisherHome", "journal"):
        if selected["publishers"]["a"][name] == selected["publishers"]["b"][name]:
            raise ValueError("Publisher selections must be independent")
    exact_fields(selected["captures"], {"workerRuntime", "nativeBoundary"})
    for ref in selected["captures"].values():
        if ref is not None:
            exact_fields(ref, {"file"})
            if not Path(ref["file"]).is_absolute():
                raise ValueError("Capture path must be absolute")
    if "clientObserver" in selected:
        client_observer(selected["clientObserver"], selected["tools"]["aos"])
    private_bytes(selected["tokenFile"], 16 * 1024)
    private_bytes(selected["pageCookieFile"], 256 * 1024)
    private_bytes(selected["providerPolicyFile"], 256 * 1024)
    return selected, hashlib.sha256(raw).hexdigest()


def provider_probe(selection_file, evidence):
    """Invoke one selected production probe once, without acceptance."""
    selected = closed_json(private_bytes(selection_file, 256 * 1024))
    exact_fields(selected, {"version", "kind", "tool", "inputs", "timeoutSeconds"})
    if selected["version"] != 1 or type(selected["timeoutSeconds"]) is not int or not 1 <= selected["timeoutSeconds"] <= 3600:
        raise ValueError("Invalid bounded probe selection")
    tool = selected["tool"]
    selected_tool(tool)
    inputs = selected["inputs"]
    fields = {
        "provider": {"config-file", "journal-directory", "output"},
        "sdk": {"endpoint", "account-id", "bucket", "control-key-file", "output-dir", "browser-origin"},
        "qualification": {"origin", "control-key-file", "identity-file", "manifest-file", "output-dir", "run-id"},
        "staged": {"selection-file", "output-dir"},
    }
    if selected["kind"] not in fields:
        raise ValueError("Unknown production probe")
    exact_fields(inputs, fields[selected["kind"]])
    if any(not isinstance(value, str) or not value for value in inputs.values()):
        raise ValueError("Probe inputs must be explicit strings")
    if selected["kind"] == "staged" and (
            Path(tool["file"]).name != "aos-hub-direct-staged-races"
            or Path(tool["file"]).parent.name != "bin"):
        raise ValueError("Staged observations require the selected packaged driver")
    for name, value in inputs.items():
        if name.endswith("-file"):
            private_bytes(value, 64 * 1024 if selected["kind"] == "staged" else 4 * 1024 * 1024)
    output = Path(inputs["output-dir"] if "output-dir" in inputs else inputs["output"])
    if not output.is_absolute() or output.exists():
        raise ValueError("Probe evidence output must be fresh")
    if "journal-directory" in inputs and Path(inputs["journal-directory"]).exists():
        raise ValueError("Provider journal must be fresh; unknown effects cannot be replayed")
    command = [tool["file"]] + (["run"] if selected["kind"] == "provider" else [])
    if selected["kind"] == "staged":
        # The existing driver has a positional closed-selection contract. It
        # returns exit 2 for retained observations with missing acceptance joins.
        command.extend([inputs["selection-file"], inputs["output-dir"]])
    else:
        for name, value in inputs.items():
            command.extend(["--" + name, value])
    evidence.save("probe-pending.json", {"kind": selected["kind"], "tool": tool,
                                        "selectionSha256": hashlib.sha256(private_bytes(selection_file, 256 * 1024)).hexdigest()})
    with os.fdopen(os.open("probe-stdout", os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                          0o600, dir_fd=evidence.fd), "wb") as stdout, os.fdopen(os.open(
                              "probe-stderr", os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                              0o600, dir_fd=evidence.fd), "wb") as stderr:
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                    timeout=selected["timeoutSeconds"], check=False)
        except subprocess.TimeoutExpired:
            return {"state": "probe_unknown", "automaticReplay": False, "acceptance": "not_granted"}
    if selected["kind"] == "staged":
        state = "probe_observed_incomplete" if result.returncode == 2 else "probe_failed_or_unknown"
    else:
        state = "probe_observed" if result.returncode == 0 else "probe_failed_or_unknown"
    return {"state": state, "exitCode": result.returncode,
            "automaticReplay": False, "acceptance": "not_granted"}


def corpus(selected):
    """Rehash the actual full fleet corpus, partitioned two bulk plus one bulk."""
    reports = {}
    for label, publication in selected["publishers"].items():
        root = Path(publication["surfaceRoot"])
        if not (root / "HEAD").is_file():
            raise ValueError("Supply an APR-authored signed surface")
        large = []
        for number in ((0, 1) if label == "a" else (2,)):
            relative = f"web/direct-content/qualification-{number}.bin"
            path = root / relative
            with path.open("rb") as source:
                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size != LARGE_BYTES:
                    raise ValueError("Full 2GiB source geometry differs")
                digest = hashlib.file_digest(source, "sha256").hexdigest()
            large.append({"path": relative, "byte_size": LARGE_BYTES, "sha256": digest})
        catalogue = hashlib.sha256()
        metadata_bytes = 0
        for number in range(METADATA_COUNT if label == "a" else 0):
            relative = f"web/packages/direct-qualification-{number:05d}.json"
            body = (root / relative).read_bytes()
            expected = json.dumps({"name": f"direct-qualification-{number:05d}", "version": "1.0.0",
                                   "qualificationSequence": number}, sort_keys=True,
                                  separators=(",", ":")).encode() + b"\n"
            if body != expected:
                raise ValueError("Metadata source differs from the fleet corpus")
            metadata_bytes += len(body)
            identity = {"path": relative, "byte_size": len(body),
                        "sha256": hashlib.sha256(body).hexdigest()}
            catalogue.update(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        reports[label] = {"large_objects": large, "metadata_objects": METADATA_COUNT if label == "a" else 0,
                          "metadata_source_bytes": metadata_bytes,
                          "metadata_catalogue_sha256": catalogue.hexdigest()}
    if len({item["sha256"] for report in reports.values() for item in report["large_objects"]}) != 3:
        raise ValueError("Bulk originals must be distinct")
    return reports


def prepare_corpus(selected, lib):
    """Run the unchanged disk-backed fleet authoring script on two signed roots."""
    roots = [Path(selected["publishers"][label]["surfaceRoot"]) for label in ("a", "b")]
    if any(not (root / "HEAD").is_file() for root in roots):
        raise ValueError("APR must author both signed surfaces before corpus preparation")

    class LocalCorpus:
        def succeed(self, command, timeout):
            # Adapt only this fixed generated corpus heredoc, not arbitrary VM
            # commands or a caller-selected shell. Use the running AOS Python.
            prefix = sys.executable + " - <<'DIRECT_CORPUS'\n"
            suffix = "\nDIRECT_CORPUS\n"
            if not command.startswith(prefix) or not command.endswith(suffix):
                raise ValueError("Fleet corpus command shape changed")
            result = subprocess.run([sys.executable, "-c", command[len(prefix):-len(suffix)]],
                                    stdin=subprocess.DEVNULL, capture_output=True,
                                    timeout=timeout, check=False)
            if result.returncode:
                raise ValueError("Corpus preparation failed; retain partial originals without overwriting")
            return result.stdout.decode()

    report = lib["prepare_direct_publication_corpus"](LocalCorpus(), sys.executable, str(roots[0]))
    original = roots[0] / report["large_objects"][-1]["path"]
    destination = roots[1] / report["large_objects"][-1]["path"]
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Create the new name without overwriting an existing original. Keep failed
    # preparations available for operator inspection rather than cleaning up.
    os.link(original, destination)
    original.unlink()
    return corpus(selected)


def checkpoint(publication, sources, lib):
    """Observe a bounded consistent SQL transaction without exposing grants."""
    journal = Path(publication["journal"])
    if not journal.exists() and not Path(str(journal) + ".admission").exists():
        return None
    # Preserve live WAL semantics: hash the projected transaction, not a copied
    # main database file that could omit committed WAL pages.
    result = {}
    for name, path in (("object", journal), ("admission", Path(str(journal) + ".admission"))):
        if not path.exists():
            result[name] = None
            continue
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > MAX_CAPTURE_BYTES):
            raise ValueError("Checkpoint lacks bounded private custody")
        connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=0.2)
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            result[name] = lib["read_checkpoint"](connection, sources)
            after = path.lstat()
            if (info.st_dev, info.st_ino) != (after.st_dev, after.st_ino):
                raise ValueError("Checkpoint path identity changed")
        finally:
            connection.close()
    return result


def publisher_arguments(selected, publication):
    token = private_bytes(selected["tokenFile"], 16 * 1024).decode().strip()
    if not token or "\n" in token:
        raise ValueError("Application session token is malformed")
    return [selected["tools"]["aos"]["file"], "--json", "hub", "registry", "publish", "upload",
            publication["registry"], "--root", publication["surfaceRoot"], "--hub", selected["origin"],
            "--token", token, "--direct-provider-policy", selected["providerPolicyFile"],
            "--direct-upload-journal", publication["journal"]]


def process_pin(process):
    directory = Path("/proc") / str(process.pid)
    return {"pid": process.pid, "uid": directory.stat().st_uid,
            "startTicks": (directory / "stat").read_text().rsplit(")", 1)[1].split()[19],
            "executable": os.readlink(directory / "exe"),
            "argumentsSha256": hashlib.sha256((directory / "cmdline").read_bytes()).hexdigest()}


def process_owner(pin):
    """Separate stable child ownership from executable and argument observations."""
    return {name: pin[name] for name in ("pid", "uid", "startTicks")}


def publisher_executables(path):
    """Pin a script interpreter and its single explicit store ELF exec target."""
    path = Path(path).resolve(strict=True)
    with path.open("rb") as source:
        prefix = source.read(65537)
    if prefix.startswith(b"\x7fELF"):
        return [immutable_executable(str(path))]
    if len(prefix) > 65536 or not prefix:
        raise ValueError("Publisher wrapper exceeds its inspection bound")
    first = prefix.splitlines()[0].decode()
    if not first.startswith("#!/nix/store/") or " " in first:
        raise ValueError("Publisher interpreter lacks source-built custody")
    executables = [immutable_executable(first[2:])]
    targets = re.findall(rb'^exec (?:"(/nix/store/[^"\n]+)"|(/nix/store/[^ \n"$]+))(?: |$)', prefix, re.MULTILINE)
    if len(targets) > 1:
        raise ValueError("Publisher wrapper has ambiguous exec targets")
    for quoted, literal in targets:
        target = immutable_executable((quoted or literal).decode())
        with open(target["file"], "rb") as source:
            if source.read(4) != b"\x7fELF":
                raise ValueError("Publisher wrapper target is not an ELF")
        if target != executables[-1]:
            executables.append(target)
    return executables


CLIENT_FIELDS = {"version", "purpose", "observerSourceSha256", "processId", "attemptOrdinal",
                 "startedAtMillis", "completedAtMillis", "sessionSha256", "originalSha256",
                 "clientOperationSha256", "placementSha256", "partSha256", "providerOriginSha256",
                 "providerPathSha256", "offered", "reply", "status", "etagSha256", "outcome",
                 "monotonicElapsedNs", "offeredFirstElapsedNs", "offeredLastElapsedNs"}
CLIENT_MARKER = "direct_upload_part_application_observation "


def immutable_bytes(path, maximum):
    """Read a bounded canonical immutable store input without following its leaf."""
    selected = Path(path)
    if (str(selected) != path or selected.resolve(strict=True) != selected
            or not re.match(r"^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/]+/", path)):
        raise ValueError("Observer input is not a canonical immutable file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o222 or before.st_size > maximum:
            raise ValueError("Observer input lacks immutable custody")
        body = source.read(maximum + 1)
        after = os.fstat(source.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_uid")
    if len(body) != before.st_size or any(getattr(before, name) != getattr(after, name) for name in fields):
        raise ValueError("Observer input changed")
    return body


def client_observer(selected, tool):
    """Join independently selected package provenance, compiled source and ELF."""
    exact_fields(selected, {"sourceSha256", "executableSha256", "packageContext"})
    exact_fields(selected["packageContext"], {"file", "sha256"})
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
           for value in (selected["sourceSha256"], selected["executableSha256"],
                         selected["packageContext"]["sha256"])):
        raise ValueError("Observer pin differs")
    raw = immutable_bytes(selected["packageContext"]["file"], 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != selected["packageContext"]["sha256"]:
        raise ValueError("Observer package context changed")
    context = closed_json(raw)
    exact_fields(context, {"version", "runtimeSource", "runtime", "runtimeProvenance", "sourceTree",
                          "nativeAuth", "observerExecutable", "captureImplementationSha256",
                          "producerSha256", "clientExecutable"})
    if type(context["version"]) is not int or context["version"] != 1:
        raise ValueError("Observer package version differs")
    exact_fields(context["producerSha256"], {"sdk", "client"})
    client = context["clientExecutable"]
    exact_fields(client, {"file", "sha256", "byteSize"})
    wrapper = selected_tool(tool)
    if (client["file"] != wrapper["file"] or client["sha256"] != wrapper["sha256"]
            or client["byteSize"] != str(Path(wrapper["file"]).stat().st_size)):
        raise ValueError("Observer package selected another CLI")
    executable = publisher_executables(wrapper["file"])[-1]
    with open(executable["file"], "rb") as source:
        if source.read(4) != b"\x7fELF":
            raise ValueError("Observer publisher lacks a selected underlying ELF")
    if executable["sha256"] != selected["executableSha256"]:
        raise ValueError("Observer underlying ELF differs")
    source = hashlib.sha256()
    for name in ("provider.rs", "provider_observation.rs"):
        source.update(immutable_bytes(str(Path(context["runtimeSource"]) /
                         "crates/aos-net/src/direct_upload" / name), 1024 * 1024))
    if source.hexdigest() != selected["sourceSha256"] or context["producerSha256"]["client"] != source.hexdigest():
        raise ValueError("Observer compiled source commitment differs")
    return {**selected, "executable": executable, "runtimeSource": context["runtimeSource"]}


def elapsed_integer(value):
    if (not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,19}", value)
            or int(value) > 2**64 - 1):
        raise ValueError("Observer elapsed time differs")
    return int(value)


def client_record(encoded):
    """Validate a bounded closed v2 record without printing arbitrary log text."""
    if len(encoded.encode()) > 4096:
        raise ValueError("Observer record exceeds bound")
    value, end = json.JSONDecoder().raw_decode(encoded)
    if encoded[end:] and not encoded[end:].startswith(" span="):
        raise ValueError("Observer record suffix differs")
    value = closed_json(encoded[:end])
    exact_fields(value, CLIENT_FIELDS)
    if (type(value["version"]) is not int or value["version"] != 2
            or value["purpose"] != "upload_part"
            or type(value["processId"]) is not int or not 0 < value["processId"] <= 2**32 - 1
            or type(value["attemptOrdinal"]) is not int or not 0 <= value["attemptOrdinal"] <= 2**64 - 1
            or value["outcome"] not in {"pending", "accepted", "refused", "unknown"}):
        raise ValueError("Observer record identity differs")
    for name in ("observerSourceSha256", "sessionSha256", "originalSha256", "clientOperationSha256",
                 "placementSha256", "partSha256", "providerOriginSha256", "providerPathSha256", "etagSha256"):
        if value[name] is None and name in {"placementSha256", "partSha256", "etagSha256"}:
            continue
        if not isinstance(value[name], str) or not re.fullmatch(r"[0-9a-f]{64}", value[name]):
            raise ValueError("Observer commitment differs")
    for name in ("startedAtMillis", "completedAtMillis", "status"):
        if value[name] is not None and (type(value[name]) is not int or not 0 <= value[name] <= 2**64 - 1):
            raise ValueError("Observer integer differs")
    if value["status"] is not None and value["status"] > 65535:
        raise ValueError("Observer status differs")
    for name in ("offered", "reply"):
        prefix = value[name]
        if prefix is None:
            continue
        exact_fields(prefix, {"bytes", "sha256", "eof", "failed", "overflow"})
        if (type(prefix["bytes"]) is not int or not 0 <= prefix["bytes"] <= 2**64 - 1
                or not isinstance(prefix["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", prefix["sha256"])
                or any(type(prefix[field]) is not bool for field in ("eof", "failed", "overflow"))):
            raise ValueError("Observer prefix differs")
        if name == "reply" and prefix["bytes"] > 8192:
            raise ValueError("Observer reply exceeds its production bound")
    for name in ("monotonicElapsedNs", "offeredFirstElapsedNs", "offeredLastElapsedNs"):
        if value[name] is not None:
            elapsed_integer(value[name])
    return value


class OfferingObserver:
    """Read the owned child's bounded emitted records; missing facts stay unknown."""

    def __init__(self, source, pid, started):
        self.source, self.pid, self.started = source, pid, started
        self.position, self.buffer, self.origin_upper = 0, b"", None
        self.attempts, self.spans = {}, []
        clock = time.get_clock_info("monotonic")
        supported = sys.platform == "linux" and clock.implementation == "clock_gettime(CLOCK_MONOTONIC)"
        self.state = "observed" if source is not None and supported else "unavailable"

    def read(self, descriptor):
        if self.state != "observed":
            return
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1
                    or not self.position <= info.st_size <= 4 * 1024 * 1024):
                raise ValueError("Observer output custody differs")
            # pread shares the actual held writer inode, without following a path
            # or disturbing the child's write offset. No additional stream poll.
            chunk = os.pread(descriptor, info.st_size - self.position, self.position)
            received = time.monotonic_ns()
            self.position += len(chunk)
            self.buffer += chunk
            lines = self.buffer.split(b"\n")
            self.buffer = lines.pop()
            if len(self.buffer) > 65536:
                raise ValueError("Observer incomplete line exceeds bound")
            for line in lines:
                marker = CLIENT_MARKER.encode()
                if marker not in line:
                    continue
                record = client_record(line.split(marker, 1)[1].decode())
                if record["observerSourceSha256"] != self.source or record["processId"] != self.pid:
                    raise ValueError("Observer process or source differs")
                elapsed = record["monotonicElapsedNs"]
                if elapsed is None:
                    continue
                upper = received - elapsed_integer(elapsed)
                if upper < self.started:
                    raise ValueError("Observer clocks cannot be joined")
                self.origin_upper = upper if self.origin_upper is None else min(self.origin_upper, upper)
                key = record["attemptOrdinal"]
                old = self.attempts.get(key)
                if old is None:
                    if record["outcome"] != "pending" or len(self.attempts) >= 32768:
                        raise ValueError("Observer pending record is missing")
                    self.attempts[key] = record
                    continue
                stable = CLIENT_FIELDS - {"completedAtMillis", "monotonicElapsedNs", "offeredFirstElapsedNs",
                                           "offeredLastElapsedNs", "offered", "reply", "status", "etagSha256", "outcome"}
                if old["outcome"] != "pending" or record["outcome"] == "pending" or any(old[name] != record[name] for name in stable):
                    raise ValueError("Observer attempt correlation differs")
                self.attempts[key] = record
                first, last = record["offeredFirstElapsedNs"], record["offeredLastElapsedNs"]
                prefix = record["offered"]
                if first is None or last is None or prefix is None or prefix["bytes"] == 0 or prefix["failed"] or prefix["overflow"]:
                    continue
                first, last = elapsed_integer(first), elapsed_integer(last)
                if not elapsed_integer(old["monotonicElapsedNs"]) <= first <= last <= elapsed_integer(elapsed):
                    raise ValueError("Observer offering order differs")
                self.spans.append((first, last))
        except (OSError, ValueError, UnicodeError, TypeError):
            self.state = "unavailable"
            self.spans.clear()

    def summary(self, pages):
        proven = []
        if self.state == "observed" and self.origin_upper is not None:
            for page in pages:
                start, finish = page.get("startedMonotonicNs"), page.get("finishedMonotonicNs")
                if start is None or finish is None:
                    continue
                if any(self.origin_upper + first <= int(start) <= int(finish) <= self.started + last
                       for first, last in self.spans):
                    proven.append(page)
        state = self.state if self.origin_upper is not None else "unavailable"
        return {"state": state, "sourceSha256": self.source,
                "controllerOriginLowerNs": str(self.started),
                "controllerOriginUpperNs": str(self.origin_upper) if self.origin_upper is not None else None,
                "matchedAttemptOfferingSpans": len(self.spans) if state == "observed" else None, "provenPages": proven,
                "providerReceivedBytes": None, "workerVerificationOverlap": None}


class Publisher:
    """Own one child and its exact checkpoint; kill never means provider drain."""

    def __init__(self, selected, publication, evidence, label):
        self.label = label
        self.outputs = []
        self.process = None
        self.evidence = evidence
        try:
            self.executables = publisher_executables(selected["tools"]["aos"]["file"])
            for stream in ("stdout", "stderr"):
                fd = os.open(f"{label}-{stream}", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=evidence.fd)
                self.outputs.append(os.fdopen(fd, "wb"))
            environment = dict(os.environ)
            home = publication["publisherHome"]
            environment.update(XDG_CONFIG_HOME=home + "/.config", XDG_DATA_HOME=home + "/.local/share",
                               XDG_CACHE_HOME=home + "/.cache")
            self.started = time.monotonic_ns()
            self.process = subprocess.Popen(publisher_arguments(selected, publication), stdin=subprocess.DEVNULL,
                                            stdout=self.outputs[0], stderr=self.outputs[1], env=environment,
                                            start_new_session=True)
            self.pin = process_pin(self.process)
            self.execution_index = self.execution_stage(self.pin)
            observer = selected.get("clientObserver")
            self.offering = OfferingObserver(observer["sourceSha256"] if observer else None,
                                            self.process.pid, self.started)
            evidence.save(label + "-process.json", {"version": 1, **self.pin,
                          "startedMonotonicNs": str(self.started), "allowedExecutables": self.executables})
        except Exception:
            # This Popen handle owns an unreaped child even if /proc observation
            # raced its exit. Never signal a separately discovered PID.
            if self.process is not None:
                try:
                    if self.process.poll() is None:
                        self.process.kill()
                    self.process.wait(timeout=5)
                finally:
                    for output in self.outputs:
                        output.close()
            else:
                for output in self.outputs:
                    output.close()
            raise

    def execution_stage(self, pin):
        paths = [item["file"] for item in self.executables]
        if pin["executable"] not in paths:
            raise ValueError("Publisher executed an unselected program")
        return paths.index(pin["executable"])

    def observe(self):
        pin = process_pin(self.process)
        if process_owner(pin) != process_owner(self.pin):
            raise ValueError("Publisher lifetime ownership changed")
        stage = self.execution_stage(pin)
        if stage < self.execution_index:
            raise ValueError("Publisher reversed its selected wrapper transition")
        if stage > self.execution_index:
            self.evidence.save(self.label + "-exec-transition.json", {
                "version": 1, **pin, "previousExecutable": self.executables[self.execution_index],
                "selectedExecutable": self.executables[stage]})
            self.execution_index = stage
        return pin

    def stop(self):
        killed = False
        observation_error = None
        try:
            if self.process.poll() is None:
                try:
                    self.observe()
                except Exception as error:
                    observation_error = error
                # An unexpected exec is a failed measurement, but this unreaped
                # Popen child remains owned. Exec changes neither PID nor parent.
                if self.process.poll() is None:
                    self.process.kill()
                    killed = True
            self.process.wait(timeout=5)
            self.offering.read(self.outputs[1].fileno())
        finally:
            for output in self.outputs:
                output.close()
        if observation_error is not None:
            raise observation_error
        return killed


def cleanup(children, captures, evidence):
    """Attempt every owned stop and capture independently, retaining failures."""
    stops, texts, errors = {}, {}, []
    for label, child in children.items():
        try:
            killed = child.stop()
            stops[label] = {"killedOwnedProcess": killed, "exitCode": child.process.returncode,
                            "finishedMonotonicNs": str(time.monotonic_ns()), "providerDrain": "unknown"}
        except Exception as error:
            stops[label] = {"exitCode": child.process.returncode, "providerDrain": "unknown",
                            "cleanupErrorType": type(error).__name__}
            errors.append({"role": "publisher", "label": label, "errorType": type(error).__name__})
    for name, capture in captures.items():
        try:
            texts[name] = capture_finish(capture, evidence, capture_filename(name))
        except Exception as error:
            texts[name] = None
            errors.append({"role": "capture", "label": name, "errorType": type(error).__name__})
    evidence.save("publisher-exits.json", stops)
    evidence.save("cleanup-errors.json", errors)
    if errors:
        raise ValueError("Owned cleanup or capture failed; retained effects remain unknown")
    return stops, texts


def original_cutoff(timeout_seconds, resumed=None):
    """Preserve the initial wall and same-boot monotonic cutoffs across resume."""
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot):
        raise ValueError("Controller boot identity is unavailable")
    if resumed is None:
        return {"originalCutoffUnixNs": str(time.time_ns() + int(timeout_seconds * 1e9)),
                "originalCutoffMonotonicNs": str(time.monotonic_ns() + int(timeout_seconds * 1e9)),
                "controllerBootId": boot}
    cutoff = {name: resumed[name] for name in
              ("originalCutoffUnixNs", "originalCutoffMonotonicNs", "controllerBootId")}
    if cutoff["controllerBootId"] != boot:
        raise ValueError("Original monotonic clock belongs to another boot")
    for name in ("originalCutoffUnixNs", "originalCutoffMonotonicNs"):
        if (not isinstance(cutoff[name], str) or not re.fullmatch(r"[0-9]{1,19}", cutoff[name])
                or str(int(cutoff[name])) != cutoff[name] or not 0 < int(cutoff[name]) <= 2**63 - 1):
            raise ValueError("Original cutoff is noncanonical")
    remaining_cutoff(cutoff)
    return cutoff


def remaining_cutoff(cutoff):
    """Use the stricter remaining interval; wall rollback cannot extend it."""
    remaining = min(int(cutoff["originalCutoffUnixNs"]) - time.time_ns(),
                    int(cutoff["originalCutoffMonotonicNs"]) - time.monotonic_ns()) / 1e9
    if remaining <= 0:
        raise TimeoutError("Original workload cutoff elapsed")
    return remaining


def page_probe(selected, evidence, sequence, deadline, lib, cutoff=None):
    remaining = deadline - time.monotonic()
    if cutoff is not None:
        remaining = min(remaining, remaining_cutoff(cutoff))
    if remaining <= 0:
        raise TimeoutError("Original workload cutoff elapsed")
    command = [selected["tools"]["curl"]["file"], "--disable", "--cookie", selected["pageCookieFile"],
               "--silent", "--show-error", "--fail", "--max-time", str(min(30, remaining)),
               "--output", "/dev/null", "--write-out", lib["PAGE_PERF_WRITEOUT"],
               selected["origin"] + selected["pagePath"]]
    started = time.monotonic_ns()
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=min(35, remaining), check=False)
    except subprocess.TimeoutExpired:
        evidence.save(f"page-{sequence}.json", {"state": "unknown", "cause": "original_cutoff"})
        raise
    finished = time.monotonic_ns()
    evidence.save(f"page-{sequence}.json", {"exitCode": result.returncode,
                    "startedMonotonicNs": str(started), "finishedMonotonicNs": str(finished),
                    "stderrSha256": hashlib.sha256(result.stderr).hexdigest(), "stderrBytes": len(result.stderr),
                    "writeout": result.stdout.decode()})
    if result.returncode:
        raise ValueError("Authenticated page probe failed; private receipt retained")
    return {**lib["parse_page_observations"](result.stdout.decode(), 1)[0],
            "startedMonotonicNs": str(started), "finishedMonotonicNs": str(finished)}


def latency(baseline, loaded):
    """Apply the existing fleet's nearest-rank latency gates to both windows."""
    def quantiles(samples):
        values = sorted(float(item["curl_cumulative_raw"]["time_starttransfer"]) for item in samples)
        if not values:
            raise ValueError("Latency sample window is absent")
        return {f"p{p}": values[math.ceil(len(values) * p / 100) - 1] for p in (50, 95, 99)}

    before, during = quantiles(baseline), quantiles(loaded)
    passed = (len(baseline) >= 100 and len(loaded) >= 25 and before["p95"] < 0.5
              and before["p99"] < 1 and during["p95"] < 0.5 and during["p99"] < 1
              and during["p95"] <= before["p95"] * 1.25)
    return {"baseline": before, "loaded": during, "baselineSamples": len(baseline),
            "loadedSamples": len(loaded), "passed": passed}


def capture_begin(reference):
    if reference is None:
        return None
    descriptor = os.open(reference["file"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        os.close(descriptor)
        raise ValueError("Exported capture lacks private custody")
    return descriptor, info


def capture_finish(capture, evidence, name):
    if capture is None:
        return None
    descriptor, before = capture
    try:
        after = os.fstat(descriptor)
        if after.st_size < before.st_size or after.st_size - before.st_size > MAX_CAPTURE_BYTES:
            raise ValueError("Capture window truncated or exceeded bounds")
        os.lseek(descriptor, before.st_size, os.SEEK_SET)
        remaining = after.st_size - before.st_size
        chunks = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError("Capture window lost bytes")
            chunks.append(chunk)
            remaining -= len(chunk)
        body = b"".join(chunks)
        reference = evidence.save(name + ".jsonl", body)
        evidence.save(name + "-window.json", {**reference, "device": str(before.st_dev),
                                               "inode": str(before.st_ino), "start": before.st_size,
                                               "end": after.st_size})
        return body.decode()
    finally:
        os.close(descriptor)


def capture_filename(name):
    """Map the two closed capture roles to owned evidence filenames."""
    return {"workerRuntime": "worker-runtime", "nativeBoundary": "native-boundary"}[name]


def output_reference(evidence, name, maximum):
    """Commit one already retained owned file without disclosing its bytes."""
    body = private_bytes(evidence.path / name, maximum)
    return {"file": name, "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)}


def clock_sample():
    """Bracket one controller wall-clock observation with its monotonic clock."""
    before = time.monotonic_ns()
    observed = time.time_ns()
    after = time.monotonic_ns()
    return {"monotonicBeforeNs": str(before), "observedUnixNs": str(observed),
            "monotonicAfterNs": str(after)}


def validate_clock_bridge(bridge, cutoff, started, finished):
    """Validate local clock observations without asserting remote UTC accuracy."""
    exact_fields(bridge, {"bootId", "loadedStart", "loadedFinish"})
    if bridge["bootId"] != cutoff["controllerBootId"]:
        raise ValueError("Loaded clock bridge belongs to another boot")
    observed = []
    for label, boundary in (("loadedStart", started), ("loadedFinish", finished)):
        sample = bridge[label]
        exact_fields(sample, {"monotonicBeforeNs", "observedUnixNs", "monotonicAfterNs"})
        for value in sample.values():
            if (not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,18}", value)
                    or int(value) > 2**63 - 1):
                raise ValueError("Loaded clock bridge is noncanonical")
        before, after = int(sample["monotonicBeforeNs"]), int(sample["monotonicAfterNs"])
        if not before <= boundary <= after:
            raise ValueError("Loaded clock bridge misses its monotonic boundary")
        observed.append(int(sample["observedUnixNs"]))
    if observed[1] < observed[0]:
        raise ValueError("Loaded clock bridge observes wall-clock rollback")


def retain_window(evidence, cutoff, started, finished, baseline, loaded, memory, counters, captures,
                  clock_bridge=None, offering=None):
    """Retain the first loaded interval and references needed by explicit resume."""
    logs = {label + "-" + stream: output_reference(evidence, label + "-" + stream, maximum)
            for label in ("a", "b") for stream, maximum in
            (("stdout", 64 * 1024 * 1024), ("stderr", 4 * 1024 * 1024))}
    refs = {name: output_reference(evidence, capture_filename(name) + ".jsonl", MAX_CAPTURE_BYTES)
            if text is not None else None for name, text in captures.items()}
    window = {"version": 1, "cutoff": cutoff, "startedMonotonicNs": str(started),
              "finishedMonotonicNs": str(finished), "elapsedNs": str(finished - started),
              "baseline": baseline, "loaded": loaded, "clientMemory": memory,
              "clientCounters": counters, "logs": logs, "captures": refs}
    if clock_bridge is not None:
        validate_clock_bridge(clock_bridge, cutoff, started, finished)
        window.update(version=2, clockBridge=clock_bridge)
    if offering is not None:
        if clock_bridge is None:
            raise ValueError("Offering window lacks a retained controller clock")
        window.update(version=3, clientOffering=offering)
    body = json.dumps(window, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    if len(body) > 16 * 1024 * 1024:
        raise ValueError("Retained loaded window exceeded its bound")
    reference = evidence.save("workload-window.json", body)
    return {"directory": evidence.identity, "reference": reference}


def retained_window(reference, cutoff):
    """Validate prior interval, log and capture hashes under its original directory."""
    exact_fields(reference, {"directory", "reference"})
    exact_fields(reference["directory"], {"path", "device", "inode"})
    previous = Evidence(reference["directory"]["path"], fresh=False)
    try:
        if previous.identity != reference["directory"]:
            raise ValueError("Original evidence directory changed")
        ref = reference["reference"]
        exact_fields(ref, {"file", "sha256", "bytes"})
        if ref["file"] != "workload-window.json" or output_reference(previous, ref["file"], 16 * 1024 * 1024) != ref:
            raise ValueError("Original loaded window changed")
        window = closed_json(private_bytes(previous.path / ref["file"], 16 * 1024 * 1024))
        fields = {"version", "cutoff", "startedMonotonicNs", "finishedMonotonicNs", "elapsedNs",
                  "baseline", "loaded", "clientMemory", "clientCounters", "logs", "captures"}
        if type(window.get("version")) is not int or window["version"] not in (1, 2, 3):
            raise ValueError("Original loaded window version differs")
        if window["version"] >= 2:
            fields.add("clockBridge")
        if window["version"] == 3:
            fields.add("clientOffering")
        exact_fields(window, fields)
        if window["version"] == 3:
            exact_fields(window["clientOffering"], {"a", "b"})
            for observation in window["clientOffering"].values():
                exact_fields(observation, {"state", "sourceSha256", "controllerOriginLowerNs",
                    "controllerOriginUpperNs", "matchedAttemptOfferingSpans", "provenPages",
                    "providerReceivedBytes", "workerVerificationOverlap"})
                if (observation["state"] not in {"observed", "unavailable"}
                        or observation["providerReceivedBytes"] is not None
                        or observation["workerVerificationOverlap"] is not None
                        or (observation["matchedAttemptOfferingSpans"] is not None
                            and (type(observation["matchedAttemptOfferingSpans"]) is not int
                              or not 0 <= observation["matchedAttemptOfferingSpans"] <= 32768))
                        or not isinstance(observation["provenPages"], list)
                        or any(page not in window["loaded"] for page in observation["provenPages"])):
                    raise ValueError("Retained offering summary differs")
                elapsed_integer(observation["controllerOriginLowerNs"])
                if observation["controllerOriginUpperNs"] is not None:
                    if elapsed_integer(observation["controllerOriginUpperNs"]) < int(observation["controllerOriginLowerNs"]):
                        raise ValueError("Retained observer clock order differs")
                if observation["state"] == "unavailable" and (observation["provenPages"]
                        or observation["matchedAttemptOfferingSpans"] is not None):
                    raise ValueError("Unavailable offering has qualified pages")
        if window["cutoff"] != cutoff:
            raise ValueError("Original loaded window cutoff changed")
        times = [window[name] for name in ("startedMonotonicNs", "finishedMonotonicNs", "elapsedNs")]
        if any(not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,18}", value)
               or int(value) > 2**63 - 1 for value in times):
            raise ValueError("Original loaded interval is noncanonical")
        start, finish, elapsed = map(int, times)
        if finish - start != elapsed or elapsed < 0 or finish > time.monotonic_ns():
            raise ValueError("Original loaded interval changed")
        if window["version"] >= 2:
            validate_clock_bridge(window["clockBridge"], cutoff, start, finish)
        exact_fields(window["logs"], {label + "-" + stream for label in ("a", "b") for stream in ("stdout", "stderr")})
        exact_fields(window["captures"], {"workerRuntime", "nativeBoundary"})
        for name, ref in window["logs"].items():
            maximum = 64 * 1024 * 1024 if name.endswith("stdout") else 4 * 1024 * 1024
            exact_fields(ref, {"file", "sha256", "bytes"})
            if ref["file"] != name or output_reference(previous, name, maximum) != ref:
                raise ValueError("Original publisher log changed")
        for name, ref in window["captures"].items():
            if ref is not None:
                exact_fields(ref, {"file", "sha256", "bytes"})
                if (ref["file"] != capture_filename(name) + ".jsonl"
                        or output_reference(previous, ref["file"], MAX_CAPTURE_BYTES) != ref):
                    raise ValueError("Original capture window changed")
        return window
    finally:
        previous.close()


def assessment_input(reference, maximum):
    """Hold an owned private input while checking its selected byte commitment."""
    exact_fields(reference, {"file", "sha256", "byteSize"})
    path = reference["file"]
    if (not isinstance(path, str) or not Path(path).is_absolute()
            or not isinstance(reference["sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", reference["sha256"])
            or not isinstance(reference["byteSize"], str)
            or not re.fullmatch(r"0|[1-9][0-9]{0,19}", reference["byteSize"])
            or int(reference["byteSize"]) > maximum):
        raise ValueError("Assessment input reference differs")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_mode & 0o077 or before.st_nlink != 1
                or before.st_size != int(reference["byteSize"])):
            raise ValueError("Assessment input lacks private custody")
        with os.fdopen(os.dup(descriptor), "rb") as source:
            raw = source.read(maximum + 1)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_uid", "st_nlink")
        if (len(raw) != before.st_size or hashlib.sha256(raw).hexdigest() != reference["sha256"]
                or any(getattr(before, name) != getattr(after, name) for name in fields)):
            raise ValueError("Assessment input changed")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor, raw
    except BaseException:
        os.close(descriptor)
        raise


def assessment_process(command, inherited, timeout=60):
    """Collect one owned offline adapter within fixed output and time bounds."""
    started = time.monotonic_ns()
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, pass_fds=tuple(inherited), start_new_session=True)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    bounds = {"stdout": 16 * 1024 * 1024, "stderr": 64 * 1024}
    timed_out, overflow, cancelled, collection_failed = False, False, False, False
    cleanup = {"processGroup": process.pid, "isolatedSession": True,
               "termSent": False, "killSent": False, "state": "unknown"}
    try:
        with selectors.DefaultSelector() as pending:
            for name in buffers:
                pending.register(getattr(process, name), selectors.EVENT_READ, name)
            deadline = time.monotonic() + timeout
            while pending.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                for selected, _ in pending.select(min(remaining, 0.1)):
                    name = selected.data
                    chunk = os.read(selected.fileobj.fileno(), 64 * 1024)
                    if not chunk:
                        pending.unregister(selected.fileobj)
                        continue
                    room = bounds[name] - len(buffers[name])
                    buffers[name].extend(chunk[:room])
                    if len(chunk) > room:
                        overflow = True
                        break
                if overflow:
                    break
            if not timed_out and not overflow:
                while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                    if time.monotonic() >= deadline:
                        timed_out = True
                        break
                    time.sleep(0.01)
    except BaseException as error:
        cancelled = isinstance(error, (InterruptedError, KeyboardInterrupt))
        collection_failed = not cancelled
    finally:
        try:
            # Do not reap the leader before the last group signal: its reserved
            # PID prevents this freshly created PGID from being reused. The
            # reviewed observer inherits this group rather than escaping it.
            try:
                os.killpg(process.pid, signal.SIGTERM)
                cleanup["termSent"] = True
                grace = time.monotonic() + 0.5
                while (os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None
                       and time.monotonic() < grace):
                    time.sleep(0.01)
            except ProcessLookupError:
                pass
            except OSError:
                cleanup["signalFailed"] = True
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    cleanup["killSent"] = True
                except ProcessLookupError:
                    pass
                except OSError:
                    cleanup["signalFailed"] = True
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cleanup["leaderWaitFailed"] = True
            # Signal delivery alone is not group termination. Give inherited
            # helpers and the system reaper a bounded chance to settle; once
            # the leader is reaped, only probe and never signal the PGID again.
            settle = time.monotonic() + 0.5
            while True:
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    cleanup["state"] = "group_absent"
                    break
                except OSError:
                    break
                if time.monotonic() >= settle:
                    break
                time.sleep(0.01)
        finally:
            process.stdout.close()
            process.stderr.close()
    return {"exitCode": process.returncode, "pid": process.pid,
            "startedMonotonicNs": str(started), "finishedMonotonicNs": str(time.monotonic_ns()),
            "timedOut": timed_out, "overflow": overflow,
            "cancelled": cancelled, "collectionFailed": collection_failed, "cleanup": cleanup,
            **{name: bytes(body) for name, body in buffers.items()}}


def assess_workload(selection_file, evidence):
    """Retain an optional offline assessment as incomplete observation only."""
    raw = private_bytes(selection_file, 1024 * 1024)
    specification = closed_json(raw)
    exact_fields(specification, {"version", "python", "adapter", "selection"})
    if type(specification["version"]) is not int or specification["version"] != 1:
        raise ValueError("Assessment invocation version differs")
    specification_ref = evidence.save("assessment-selected-invocation.json", raw)
    python = selected_tool(specification["python"])
    adapter_fd, _ = assessment_input(specification["adapter"], 1024 * 1024)
    selection_fd = None
    try:
        selection_fd, original = assessment_input(specification["selection"], 1024 * 1024)
        selection = closed_json(original)
        fields = {"version", "runtime", "runtimeProvenance", "bodyManifest", "observerExecutable",
                  "authSidecar", "capturePolicy", "captureExport", "sdkApplicationLog",
                  "clientApplicationLog", "indexSnapshots", "workloadWindows", "wireMetrics"}
        if "nativeInventory" in selection:
            fields.add("nativeInventory")
        exact_fields(selection, fields)
        inventory = selection.get("nativeInventory")
        if inventory is not None:
            # Forward the existing adapter selection; its reader owns custody,
            # authentication and coverage. Missing/null never means zero.
            fields = {"policy", "sidecar"}
            if isinstance(inventory, dict) and "sqlReaderObservation" in inventory:
                fields.add("sqlReaderObservation")
            exact_fields(inventory, fields)
            for name, reference in inventory.items():
                if name == "sqlReaderObservation" and reference is None:
                    continue
                exact_fields(reference, {"file", "sha256", "byteSize"})
                if (not isinstance(reference["file"], str) or not Path(reference["file"]).is_absolute()
                        or not isinstance(reference["sha256"], str)
                        or not re.fullmatch(r"[0-9a-f]{64}", reference["sha256"])
                        or not isinstance(reference["byteSize"], str)
                        or not re.fullmatch(r"0|[1-9][0-9]{0,19}", reference["byteSize"])
                        or int(reference["byteSize"]) > 2**64 - 1):
                    raise ValueError("Native inventory selected reference differs")
        measurements = closed_json(private_bytes(evidence.path / "measurements.json", 16 * 1024 * 1024))
        windows = []
        for window in measurements["loadedWindowReferences"]:
            retained_window(window, measurements["originalCutoff"])
            reference = window["reference"]
            windows.append({"file": str(Path(window["directory"]["path"]) / reference["file"]),
                            "sha256": reference["sha256"], "byteSize": str(reference["bytes"])})
        if selection["workloadWindows"] not in ([], windows):
            raise ValueError("Assessment selected a different workload window")
        selection["workloadWindows"] = windows
        original_ref = evidence.save("assessment-original-selection.json", original)
        invocation_ref = evidence.save("assessment-invocation-selection.json", selection)
        derived = {"file": str(evidence.original_path / invocation_ref["file"]),
                   "sha256": invocation_ref["sha256"], "byteSize": str(invocation_ref["bytes"])}
        derived_fd, _ = assessment_input(derived, 1024 * 1024)
        try:
            # The adapter's private reader rejects final symlinks, so it opens
            # a regular selection beneath the inherited owned directory fd.
            command = [python["file"], "-B", "-E", f"/proc/self/fd/{adapter_fd}",
                       str(evidence.path / invocation_ref["file"])]
            before = {fd: os.fstat(fd) for fd in (adapter_fd, selection_fd, derived_fd)}
            try:
                result = assessment_process(command, [adapter_fd, evidence.fd])
            except Exception:
                result = {"exitCode": None, "pid": None, "startedMonotonicNs": None,
                          "finishedMonotonicNs": str(time.monotonic_ns()), "timedOut": False,
                          "overflow": False, "stdout": b"", "stderr": b"",
                          "collectionFailed": True}
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_uid", "st_nlink")
            changed = any(any(getattr(info, field) != getattr(os.fstat(fd), field) for field in fields)
                          for fd, info in before.items())
            result["inputsChanged"] = changed
        finally:
            os.close(derived_fd)
        stdout = evidence.save("assessment-stdout", result.pop("stdout"))
        stderr = evidence.save("assessment-stderr", result.pop("stderr"))
        receipt = {"version": 1, "state": "invalid_or_unknown", **result,
                   "selectedInvocation": specification_ref, "python": python,
                   "adapter": specification["adapter"],
                   "originalSelection": {"selected": specification["selection"], "retained": original_ref},
                   "invocationSelection": derived, "workloadWindows": windows,
                   "stdout": stdout, "stderr": stderr,
                   "harnessSourceSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   "hostedAcceptance": "incomplete", "providerSettlement": "unknown"}
        report = None
        if (result["exitCode"] == 2 and not result["timedOut"]
                and not result["overflow"] and not result["inputsChanged"]
                and not result.get("cancelled", False) and not result.get("collectionFailed", False)
                and result.get("cleanup", {}).get("state") == "group_absent"):
            try:
                report = closed_json(private_bytes(evidence.path / stdout["file"], 16 * 1024 * 1024))
                exact_fields(report, {"version", "hostedAcceptance", "applicationBodyAssessment",
                                      "applicationProviderLedger", "indexParity", "wireMetrics",
                                      "loadedWindowReferences", "runtime"})
                expected_windows = [{"sha256": item["sha256"], "byteSize": item["byteSize"]} for item in windows]
                body = report["applicationBodyAssessment"]
                if (type(report["version"]) is not int or report["version"] != 1
                        or report["hostedAcceptance"] != "incomplete" or report["runtime"] != selection["runtime"]
                        or report["loadedWindowReferences"] != expected_windows
                        or body["state"] != "incomplete" or body["nativeBulkBytes"] is not None
                        or body["nativeCapturedObjectPayloadBytes"] is not None
                        or report["applicationProviderLedger"]["state"] != "incomplete"):
                    raise ValueError("Assessment promoted or changed selected observations")
                receipt["state"] = "incomplete_observation"
            except (ValueError, KeyError, TypeError):
                report = None
        receipt_ref = evidence.save("assessment-receipt.json", receipt)
        if report is None:
            raise ValueError("Offline assessment invalid or unknown; private result retained")
        return {"state": "incomplete_observation", "exitCode": result["exitCode"], "receipt": receipt_ref}
    finally:
        if selection_fd is not None:
            os.close(selection_fd)
        os.close(adapter_fd)


def run(selected, binding_hash, evidence, lib, resume=None):
    """Dispatch each initial publisher once; sparse interruption stops the run."""
    cutoff = original_cutoff(selected["timeoutSeconds"], resume)
    deadline = time.monotonic() + remaining_cutoff(cutoff)
    first_window = None
    reports = corpus(selected)
    evidence.save("selection.json", {"version": 1, "bindingSha256": binding_hash,
                                      "region": selected["region"], "origin": selected["origin"],
                                      "tools": selected["tools"], "corpus": reports,
                                      "clientObserver": selected.get("clientObserver")})
    if resume is not None:
        exact_fields(resume, {"version", "phase", "bindingSha256", "corpus", "checkpoints",
                              "completed", "originalCutoffUnixNs", "originalCutoffMonotonicNs",
                              "controllerBootId", "firstWindow"})
        if (resume["version"] != 2 or resume["phase"] != "interrupted_sparse_checkpoint"
                or set(resume["checkpoints"]) != {"a", "b"}
                or resume["completed"]):
            raise ValueError("Resume must preserve the exact interrupted two-publisher phase")
        first_window = retained_window(resume["firstWindow"], cutoff)
        original = resume["checkpoints"]["a"]
        if (not original or not original["object"] or not original["admission"]
                or not any(row["sparseGaps"] and row["completeSha256"] is None
                           for row in original["object"]["sessions"])):
            raise ValueError("Resume lacks the retained interrupted sparse original")
        if resume["bindingSha256"] != binding_hash or resume["corpus"] != reports:
            raise ValueError("Resume changed the original binding or source")
        for label, old in resume["checkpoints"].items():
            current = checkpoint(selected["publishers"][label], reports[label]["large_objects"], lib)
            if old != current:
                raise ValueError("Retained interrupted checkpoint changed before explicit resume")
    else:
        for publication in selected["publishers"].values():
            if Path(publication["journal"]).exists() or Path(publication["journal"] + ".admission").exists():
                raise ValueError("Initial run requires fresh exclusive checkpoint paths")

    baseline = [page_probe(selected, evidence, f"baseline-{index}", deadline, lib, cutoff)
                for index in range(100)]
    captures = {}
    children, loaded, completed, client_counters = {}, [], {}, {}
    start_clock = clock_sample()
    started = int(start_clock["monotonicAfterNs"])
    interrupted = None
    memory = []
    try:
        for name, reference in selected["captures"].items():
            captures[name] = capture_begin(reference)
        for label, publication in selected["publishers"].items():
            if resume is None or label not in resume["completed"]:
                remaining_cutoff(cutoff)
                children[label] = Publisher(selected, publication, evidence, label)
        while any(child.process.poll() is None for child in children.values()):
            remaining_cutoff(cutoff)
            for child in children.values():
                child.offering.read(child.outputs[1].fileno())
            for label in children:
                for stream, maximum in (("stdout", 64 * 1024 * 1024), ("stderr", 4 * 1024 * 1024)):
                    if (evidence.path / f"{label}-{stream}").stat().st_size > maximum:
                        raise ValueError("Publisher diagnostic output exceeded its retained bound")
            if resume is None and children["a"].process.poll() is None:
                current = checkpoint(selected["publishers"]["a"], reports["a"]["large_objects"], lib)
                if current and current["object"] and any(row["sparseGaps"] and row["completeSha256"] is None
                                   for row in current["object"]["sessions"]):
                    interrupted = current
                    break
            for label, child in children.items():
                if child.process.poll() is None:
                    try:
                        child.observe()
                        fields = (Path("/proc") / str(child.process.pid) / "status").read_text()
                        match = re.search(r"^VmRSS:\s+([0-9]+) kB$", fields, re.MULTILINE)
                        memory.append({"label": label, "monotonicNs": str(time.monotonic_ns()),
                                       "residentBytes": int(match.group(1)) * 1024 if match else None})
                    except FileNotFoundError:
                        memory.append({"label": label, "residentBytes": None, "state": "exit_race"})
            sample = page_probe(selected, evidence, f"loaded-{len(loaded)}", deadline, lib, cutoff)
            # Preserve the existing observed publisher window. Being alive
            # alone does not qualify overlap with actual offered chunks.
            if any(child.process.poll() is None for child in children.values()):
                loaded.append(sample)
        if interrupted is None:
            for label, child in children.items():
                if child.process.wait() != 0:
                    raise ValueError("Publisher failed; effects unknown and no automatic retry")
                raw = private_bytes(evidence.path / (label + "-stdout"), 64 * 1024 * 1024)
                reply = closed_json(raw)
                publication = reply["data"]
                lib["assert_direct_publication_objects"](publication, reports[label])
                counters = lib["direct_client_observations"](
                    private_bytes(evidence.path / (label + "-stderr"), 4 * 1024 * 1024).decode())
                evidence.save(label + "-counters.json", counters)
                client_counters[label] = counters
                completed[label] = publication
    finally:
        # Cleanup visits every owned child and capture even if one fails.
        stops, texts = cleanup(children, captures, evidence)

    finish_clock = clock_sample()
    finished = int(finish_clock["monotonicBeforeNs"])
    bridge = {"bootId": cutoff["controllerBootId"], "loadedStart": start_clock,
              "loadedFinish": finish_clock}
    offering = {label: child.offering.summary(loaded) for label, child in children.items()}
    current_window = retain_window(evidence, cutoff, started, finished, baseline, loaded, memory,
                                   client_counters, texts, clock_bridge=bridge, offering=offering)
    if interrupted is not None:
        if not stops["a"]["killedOwnedProcess"] or stops["a"]["exitCode"] != -signal.SIGKILL:
            raise ValueError("Sparse rendezvous missed actual owned process interruption")
        checkpoints = {label: checkpoint(selected["publishers"][label], report["large_objects"], lib)
                       for label, report in reports.items()}
        lib["preserve_originals"](interrupted["object"], checkpoints["a"]["object"])
        if not any(row["sparseGaps"] and row["completeSha256"] is None
                   for row in checkpoints["a"]["object"]["sessions"]):
            raise ValueError("Stopped publisher has no retained sparse gap")
        evidence.save("resume.json", {"version": 2, "phase": "interrupted_sparse_checkpoint",
                     "bindingSha256": binding_hash, "corpus": reports, "checkpoints": checkpoints,
                     "completed": {}, **cutoff, "firstWindow": current_window})
        return {"state": "interrupted", "providerSettlement": "unknown",
                "nextAction": "Explicit resume with exact binding/checkpoints before original cutoff"}

    if resume is not None:
        completed.update(resume["completed"])
        for label, old in resume["checkpoints"].items():
            if old is not None:
                current = checkpoint(selected["publishers"][label], reports[label]["large_objects"], lib)
                if old["object"] is not None:
                    lib["preserve_originals"](old["object"], current["object"])
                if old["admission"] is not None:
                    lib["preserve_originals"](old["admission"], current["admission"])
                if (old["admission"] is not None
                        and old["admission"]["publication"].get("headerSha256")
                            != current["admission"]["publication"].get("headerSha256")):
                    raise ValueError("Resume changed original publication header")
    whole_baseline = first_window["baseline"] if first_window is not None else baseline
    whole_loaded = (first_window["loaded"] if first_window is not None else []) + loaded
    whole_started = int(first_window["startedMonotonicNs"]) if first_window is not None else started
    offering_windows = ([first_window["clientOffering"]]
                        if first_window is not None and "clientOffering" in first_window else []) + [offering]
    proven = []
    for window in offering_windows:
        for observed in window.values():
            for page in observed["provenPages"]:
                if page not in proven:
                    proven.append(page)
    observed_latency = {**latency(whole_baseline, whole_loaded), "scope": "observed_publisher_window"}
    measurements = {"latency": observed_latency,
                    "offeringOverlap": {"clientWindows": offering_windows, "provenPageCount": len(proven),
                        "latency": latency(whole_baseline, proven) if proven else None,
                        "workerVerificationOverlap": None, "providerDispatchOverlap": None},
                    "publications": completed,
                    "clientMemory": (first_window["clientMemory"] if first_window is not None else []) + memory,
                    "clientCounters": client_counters,
                    "workloadElapsedNs": str(finished - whole_started),
                    "invocationLoadedElapsedNs": str(finished - started),
                    "firstWindowElapsedNs": first_window["elapsedNs"] if first_window is not None else None,
                    "loadedWindowReferences": ([resume["firstWindow"]] if resume is not None else []) + [current_window],
                    "originalCutoff": cutoff,
                    "nativeBulkBytes": None, "hostedAcceptance": "incomplete",
                    "missing": ["complete authenticated application-hop body/codec/provider original ledger",
                                "full fresh-transfer client/provider byte and batch accounting across interrupted invocation",
                                "three-mode authoritative index parity and stale-placement refusal",
                                "actual queued consumer restart/current runtime measurements",
                                "SQL pool, Worker CPU/duration, cache hits and billed provider wire telemetry"]}
    if texts["workerRuntime"] is not None:
        events = lib["direct_runtime_observations"](texts["workerRuntime"], selected["workerSourceDigest"])
        measurements["runtime"] = lib["summarize_direct_runtime"](events)
    else:
        measurements["missing"].append("Worker runtime original-window exporter")
    if texts["nativeBoundary"] is not None:
        observed = lib["native_control_observations"](texts["nativeBoundary"])
        measurements["nativeBoundary"] = lib["summarize_native_control_bytes"](observed, METADATA_COUNT + 3)
    else:
        measurements["missing"].append("Native application boundary original-window exporter")
    evidence.save("measurements.json", measurements)
    return {"state": "workload_complete", "hostedAcceptance": "incomplete",
            "latencyPassed": measurements["latency"]["passed"],
            "latencyScope": "observed_publisher_window",
            "clientOfferingOverlapPages": len(proven) if any(
                row["state"] == "observed" for window in offering_windows for row in window.values()) else None,
            "workerVerificationOverlap": None, "nativeBulkBytes": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binding-file")
    parser.add_argument("--probe-selection-file")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--library-dir", required=True)
    parser.add_argument("--resume-file")
    parser.add_argument("--assessment-selection-file")
    parser.add_argument("--prepare-corpus", action="store_true")
    options = parser.parse_args()
    def cancelled(_signal, _frame):
        raise InterruptedError("Operator cancellation; original effects remain unknown")

    signal.signal(signal.SIGTERM, cancelled)
    signal.signal(signal.SIGINT, cancelled)
    evidence = Evidence(options.output_dir)
    try:
        if bool(options.binding_file) == bool(options.probe_selection_file):
            raise ValueError("Select exactly one workload binding or production probe")
        if options.probe_selection_file:
            if options.resume_file or options.prepare_corpus or options.assessment_selection_file:
                raise ValueError("Production probes do not permit workload resume or preparation")
            outcome = provider_probe(options.probe_selection_file, evidence)
            evidence.save("outcome.json", outcome)
            print(json.dumps(outcome))
            if outcome["state"] == "probe_observed_incomplete":
                return 2
            return 0 if outcome["state"] == "probe_observed" else 1
        selected, digest = binding(options.binding_file)
        lib = libraries(options.library_dir)
        if options.prepare_corpus:
            if options.resume_file or options.assessment_selection_file:
                raise ValueError("Corpus preparation cannot accompany resume")
            evidence.save("corpus.json", prepare_corpus(selected, lib))
            evidence.save("outcome.json", {"state": "corpus_prepared", "publicationDispatched": False})
            return 0
        resumed = closed_json(private_bytes(options.resume_file, 16 * 1024 * 1024)) if options.resume_file else None
        outcome = run(selected, digest, evidence, lib, resumed)
        if options.assessment_selection_file and outcome["state"] == "workload_complete":
            outcome["assessment"] = assess_workload(options.assessment_selection_file, evidence)
        evidence.save("outcome.json", outcome)
        print(json.dumps(outcome))
        return 2  # Workload measurements are not the complete hosted launch gate.
    except Exception as error:
        evidence.save("outcome.json", {"state": "failed_or_unknown", "errorType": type(error).__name__,
                                       "providerSettlement": "unknown", "automaticReplay": False})
        print("Hosted workload stopped; private original evidence retained.")
        return 1
    finally:
        evidence.close()


if __name__ == "__main__":
    raise SystemExit(main())
