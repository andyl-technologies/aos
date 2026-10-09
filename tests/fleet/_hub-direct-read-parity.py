"""Exercise fixed signed-corpus reads and the real hybrid Cache API.

The caller supplies independently retained publication files and installed
runtime identities. All HTTP requests go through the selected public origins,
with strict TLS and no redirect, retry or alternate storage path. Capture files
remain private; these observations do not establish Native bulk-byte absence.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import time
from urllib.parse import urlsplit


READ_BODY_LIMIT = 4 * 1024 * 1024
HEADER_LIMIT = 64 * 1024
READ_CLASSES = ("git", "package", "metadata", "document", "container")
READ_MODES = ("hybrid", "native_only", "worker_only")


def _digest(body):
    return hashlib.sha256(body).hexdigest()


def _json(body):
    def unique_fields(pairs):
        value = {}
        for name, field in pairs:
            if name in value:
                raise ValueError("read observation repeats a JSON field")
            value[name] = field
        return value

    def invalid_constant(_):
        raise ValueError("read observation contains a nonfinite JSON value")

    return json.loads(body, object_pairs_hook=unique_fields, parse_constant=invalid_constant)


def _private_write(root, name, body):
    descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return root / name


def _read_source(path, maximum=READ_BODY_LIMIT, private=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid() or before.st_size > maximum
                or private and before.st_mode & 0o077):
            raise ValueError("selected read input lacks bounded regular-file custody")
        body = source.read(maximum + 1)
        after = os.fstat(source.fileno())
    if len(body) > maximum or len(body) != before.st_size or any(
            getattr(before, field) != getattr(after, field) for field in
            ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")):
        raise ValueError("selected read input changed")
    return body


def _origin(value):
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment):
        raise ValueError("selected read origin is not an exact HTTPS origin")
    return value


def select_direct_read_corpus(selection):
    """Require five independently retained objects from one signed publication."""
    if (not isinstance(selection, dict) or set(selection) != {
            "version", "sourceCommit", "registrySlug", "packageName", "origins", "objects"}
            or selection["version"] != 1
            or not re.fullmatch(r"[0-9a-f]{64}", selection["sourceCommit"])
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}/[a-z][a-z0-9-]{0,63}", selection["registrySlug"])
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", selection["packageName"])
            or set(selection["origins"]) != set(READ_MODES)
            or set(selection["objects"]) != set(READ_CLASSES)):
        raise ValueError("signed read corpus is incomplete or unsupported")
    if len(set(selection["origins"].values())) != 3:
        raise ValueError("read parity requires three distinct installed origins")
    for origin in selection["origins"].values():
        _origin(origin)
    bodies = {}
    patterns = {
        "git": r"objects/[0-9a-f]{2}/[0-9a-f]{62}",
        "package": r"nar/[A-Za-z0-9._-]+\.nar(?:\.(?:xz|zst|bz2|gz))?",
        "metadata": r"[0-9a-z]{32}\.narinfo",
        "document": r"-/api/v1/documentation/sha256:[0-9a-f]{64}",
        "container": r"v2/[a-z0-9][a-z0-9._/-]{0,255}/blobs/sha256:[0-9a-f]{64}",
    }
    for kind in READ_CLASSES:
        row = selection["objects"][kind]
        if (not isinstance(row, dict) or set(row) != {"relativePath", "file", "sha256", "byteSize"}
                or not re.fullmatch(patterns[kind], row["relativePath"])
                or any(part in {".", "..", ""} for part in row["relativePath"].split("/"))
                or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                or type(row["byteSize"]) is not int or not 16 <= row["byteSize"] <= READ_BODY_LIMIT):
            raise ValueError("selected " + kind + " object differs from its fixed route grammar")
        body = _read_source(row["file"])
        if len(body) != row["byteSize"] or _digest(body) != row["sha256"]:
            raise ValueError("independent signed-corpus object bytes differ")
        if kind == "document":
            value = _json(body)
            if value.get("schema") != "aos.module.documentation" or not value.get("options"):
                raise ValueError("selected document lacks genuine package option content")
            if row["relativePath"].rsplit(":", 1)[-1] != row["sha256"]:
                raise ValueError("documentation route differs from its canonical content hash")
        if kind == "container" and row["relativePath"].rsplit(":", 1)[-1] != row["sha256"]:
            raise ValueError("OCI blob route differs from its exact digest")
        bodies[kind] = body
    return bodies


class DirectReadHttp:
    """Capture one actual bounded curl request without retries or redirects."""

    def __init__(self, curl, output_directory):
        if not isinstance(curl, list) or not curl or not re.fullmatch(
                r"/nix/store/[0-9a-z]{32}-[^/]+/bin/curl", curl[0]):
            raise ValueError("read transport must select the source-built curl")
        # The selected trust/fixture routing may add these value options only.
        # An extra URL, config file or combined short flag can change dispatch.
        if (len(curl) % 2 != 1 or any(curl[index] not in {"--cacert", "--resolve", "--noproxy"}
                or not isinstance(curl[index + 1], str) or not curl[index + 1]
                or len(curl[index + 1]) > 4096 or "\n" in curl[index + 1] or "\r" in curl[index + 1]
                for index in range(1, len(curl), 2))):
            raise ValueError("read transport must retain strict TLS and one dispatch")
        self.curl = curl
        self.root = Path(output_directory)
        self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.observations = []

    def request(self, label, url, *, method="GET", request_headers=(), expected_size=READ_BODY_LIMIT,
                request_body=None):
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,95}", label) or method not in {"GET", "HEAD", "POST"}:
            raise ValueError("read case label or method differs")
        if method == "POST":
            if (urlsplit(url).path != "/aos.hub.v1.DocumentationService/GetDocumentationArtifact"
                    or request_body is None or len(request_body) > 4096):
                raise ValueError("read POST is not the fixed documentation procedure")
        elif request_body is not None:
            raise ValueError("read-only GET/HEAD carries an unexpected body")
        if not 0 <= expected_size <= READ_BODY_LIMIT:
            raise ValueError("read response exceeds the per-object bound")
        body_path = _private_write(self.root, label + ".body", b"")
        headers_path = _private_write(self.root, label + ".headers", b"")
        request_bytes = (method + " " + url + "\n" + "\n".join(request_headers)).encode()
        _private_write(self.root, label + ".request", request_bytes)
        arguments = self.curl + ["-sS", "--max-time", "25", "--max-filesize", str(READ_BODY_LIMIT),
            "--output", str(body_path), "--dump-header", str(headers_path), "--write-out", "%{http_code}",
            "--header", "Accept: */*", "--header", "Accept-Encoding: identity"]
        if method == "HEAD":
            # curl's --head writes headers to its ordinary output stream.
            # Preserve those in --dump-header and leave the body capture empty.
            arguments += ["--head", "--output", "/dev/null"]
        elif method == "POST":
            request_path = _private_write(self.root, label + ".request-body", request_body)
            arguments += ["--request", "POST", "--data-binary", "@" + str(request_path),
                "--header", "Content-Type: application/json", "--header", "Connect-Protocol-Version: 1"]
        for header in request_headers:
            if "\r" in header or "\n" in header:
                raise ValueError("read request header contains a line break")
            arguments += ["--header", header]
        started_utc, started = time.time_ns(), time.monotonic_ns()
        timed_out = False
        try:
            result = subprocess.run(arguments + [url], stdin=subprocess.DEVNULL,
                capture_output=True, check=False, timeout=30)
            stdout, stderr, exit_code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr, exit_code = error.stdout or b"", error.stderr or b"", None
            timed_out = True
        body = _read_source(body_path, private=True)
        headers = _read_source(headers_path, HEADER_LIMIT, private=True)
        _private_write(self.root, label + ".stderr", stderr)
        status = int(stdout) if re.fullmatch(rb"[0-9]{3}", stdout) else None
        row = {"label": label, "method": method, "urlSha256": _digest(url.encode()),
            "requestSha256": _digest(request_bytes), "status": status, "exitCode": exit_code,
            "timedOut": timed_out, "bodySha256": _digest(body), "bodyBytes": len(body),
            "headersSha256": _digest(headers), "headerBytes": len(headers),
            "stderrSha256": _digest(stderr), "stderrBytes": len(stderr),
            "startedAtUnixNs": str(started_utc), "completedAtUnixNs": str(time.time_ns()),
            "elapsedNanoseconds": str(time.monotonic_ns() - started)}
        self.observations.append(row)
        _private_write(self.root, label + ".json", json.dumps(row, sort_keys=True).encode())
        if timed_out or exit_code != 0 or stderr or status is None or len(body) > expected_size:
            raise RuntimeError("actual read transport is unknown; originals retained")
        return row, body, parse_direct_read_headers(headers)


def parse_direct_read_headers(body):
    """Require one final HTTP response and unambiguous selected header fields."""
    blocks = body.strip().split(b"\r\n\r\n")
    if len(blocks) != 1 or not re.fullmatch(rb"HTTP/(?:1\.[01]|2|3) [1-5][0-9]{2}(?: [^\r\n]*)?", blocks[0].split(b"\r\n")[0]):
        raise ValueError("read response has an unsupported redirect/interim/header shape")
    selected = {}
    for line in blocks[0].split(b"\r\n")[1:]:
        name, separator, value = line.partition(b":")
        if not separator or not re.fullmatch(rb"[A-Za-z0-9-]+", name):
            raise ValueError("read response header is malformed")
        key = name.decode().lower()
        if key in {"content-length", "content-range", "etag", "content-type", "cache-control",
                "x-aos-front-cache", "x-aos-front-cache-expires", "set-cookie", "content-encoding"}:
            if key in selected:
                raise ValueError("read response selected header is duplicated")
            selected[key] = value.strip().decode("ascii")
    if selected.get("content-encoding", "identity") != "identity":
        raise ValueError("read parity response changed representation encoding")
    return selected


def _read_url(selection, mode, kind):
    relative = selection["objects"][kind]["relativePath"]
    # Distribution routes are selected by the real OCI repository route;
    # machine registry objects and browse documentation live under the slug.
    prefix = "" if kind == "container" else selection["registrySlug"] + "/"
    return selection["origins"][mode] + "/" + prefix + relative


def run_direct_read_parity(selection, transport):
    """Read exact Git, NAR, narinfo, documentation and OCI bytes in all modes."""
    bodies = select_direct_read_corpus(selection)
    rows = []
    for mode in READ_MODES:
        for kind in READ_CLASSES:
            expected = bodies[kind]
            url = _read_url(selection, mode, kind)
            full, body, _ = transport.request(mode.replace("_", "-") + "-" + kind + "-full", url,
                expected_size=len(expected))
            if full["status"] != 200 or body != expected:
                raise ValueError("actual " + mode + " " + kind + " bytes differ from signed source")
            rows.append(full)
            # Canonical documentation is a bounded Native query projection;
            # its JSON API does not advertise an object-range contract.
            if kind == "document":
                continue
            head, body, headers = transport.request(mode.replace("_", "-") + "-" + kind + "-head", url,
                method="HEAD", expected_size=0)
            if head["status"] != 200 or body or headers.get("content-length") != str(len(expected)):
                raise ValueError("actual object HEAD differs from full representation")
            ranged, body, headers = transport.request(mode.replace("_", "-") + "-" + kind + "-range", url,
                request_headers=("Range: bytes=6-13",), expected_size=8)
            if (ranged["status"] != 206 or body != expected[6:14]
                    or headers.get("content-range") != "bytes 6-13/" + str(len(expected))
                    or headers.get("content-length") != "8"):
                raise ValueError("actual object range is unsupported or differs from exact source")
            rows.extend((head, ranged))
    return {"version": 1, "sourceCommit": selection["sourceCommit"], "observations": rows,
        "classes": list(READ_CLASSES), "modes": list(READ_MODES), "nativeBulkBytes": None,
        "scope": "actual fixed-corpus reads; docs are bounded query content, complete body/provider joins remain separate"}


def run_direct_semantic_read_parity(selection, transport):
    """Compare four fixed indexed browse APIs without dropping response fields."""
    select_direct_read_corpus(selection)
    routes = {"packages": "-/api/packages",
        "package": "-/api/packages/" + selection["packageName"],
        "channels": "-/api/channels", "releases": "-/api/releases"}
    values, observations = {}, []
    for mode in READ_MODES:
        actual = {}
        for name, route in routes.items():
            url = selection["origins"][mode] + "/" + selection["registrySlug"] + "/" + route
            row, body, headers = transport.request(mode.replace("_", "-") + "-indexed-" + name, url)
            observations.append(row)
            if row["status"] != 200 or headers.get("content-type", "").split(";", 1)[0] != "application/json":
                raise ValueError("actual indexed browse route is unsupported or not JSON")
            actual[name] = _json(body)
        if (any(not isinstance(actual[name], list) or not actual[name]
                for name in ("packages", "channels", "releases"))
                or not isinstance(actual["package"], dict)
                or actual["package"].get("name") != selection["packageName"]
                or not actual["package"].get("versions")
                or sum(isinstance(row, dict) and row.get("name") == selection["packageName"]
                    for row in actual["packages"]) != 1):
            raise ValueError("actual indexed package/release/channel content is incomplete")
        values[mode] = actual
    if any(value != values["hybrid"] for value in values.values()):
        raise ValueError("actual indexed browse semantics differ across runtime modes")
    return {"version": 1, "sourceCommit": selection["sourceCommit"], "observations": observations,
        "responseSemanticsSha256": _digest(json.dumps(values["hybrid"], sort_keys=True,
            separators=(",", ":")).encode()), "nativeBulkBytes": None,
        "scope": "complete fixed browse JSON equality; authoritative source/index and body/provider joins remain required"}


def assert_direct_full_index_parity(snapshots, source_commit):
    """Refuse missing document/container projections or divergent actual indexes."""
    if set(snapshots) != set(READ_MODES) or not re.fullmatch(r"[0-9a-f]{64}", source_commit):
        raise ValueError("full index parity topology or source differs")
    selected = snapshots["hybrid"]
    required = ("packages", "versions", "platforms", "keys", "releases", "release_records", "channels",
        "channel_floors", "channel_partitions", "catalog_artifacts", "artifact_snapshots", "release_artifacts",
        "documentation", "container_roots", "container_closure_members", "container_evidence",
        "container_provenance", "container_layers", "browse_catalogs", "browse_nodes")
    if len(selected.get("index", [])) != 1 or selected["index"][0][:3] != ["fresh", None, source_commit]:
        raise ValueError("full parity source index is not fresh")
    for name in required:
        if not selected.get(name):
            raise ValueError("actual full index lacks " + name)
    for mode, actual in snapshots.items():
        if actual != selected:
            raise ValueError("actual " + mode + " authoritative indexes diverge")
    body = json.dumps(selected, sort_keys=True, separators=(",", ":")).encode()
    return {"version": 1, "sourceCommit": source_commit, "snapshotSha256": _digest(body),
        "rowsByTable": {name: len(rows) for name, rows in selected.items()}}


def capture_direct_full_index_parity(readers, slug, source_commit):
    """Query actual authoritative tables using the existing fixed SQL projector."""
    if set(readers) != set(READ_MODES):
        raise ValueError("actual authoritative index readers are missing")
    snapshots = {mode: registry_index_observations(query, slug) for mode, query in readers.items()}
    retain_direct_flow("full-read-index-snapshots-private.json", snapshots)
    result = assert_direct_full_index_parity(snapshots, source_commit)
    retain_direct_flow("full-read-index-parity.json", result)
    return result


def direct_document_cache_control(socket_path, kind, output_root, label):
    """Retain a request and actual response on the owner-private runner socket."""
    if kind not in {"public-document-cache-readback", "public-document-cache-evict"}:
        raise ValueError("cache control kind is unsupported")
    metadata = Path(socket_path).lstat()
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise ValueError("cache control socket lacks owner-private custody")
    body = json.dumps({"version": 1, "kind": kind}, separators=(",", ":")).encode()
    _private_write(output_root, label + ".request", body)
    before_utc = time.time_ns() // 1_000_000
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(10)
        connection.connect(socket_path)
        peer_pid, peer_uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET,
            socket.SO_PEERCRED, struct.calcsize("3i")))
        if peer_uid != os.getuid():
            raise ValueError("cache control peer owner differs")
        start_ticks = Path("/proc", str(peer_pid), "stat").read_text().rpartition(") ")[2].split()[19]
        connection.sendall(body)
        connection.shutdown(socket.SHUT_WR)
        chunks, size = [], 0
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > 16384:
                raise ValueError("cache control reply exceeded its closed bound")
    raw = b"".join(chunks)
    _private_write(output_root, label + ".reply", raw)
    after_utc = (time.time_ns() + 999_999) // 1_000_000
    reply = _json(raw)
    fields = {"version", "observationScope", "kind", "runnerPid", "runnerStartTicks", "configurationSha256",
        "cacheObserverSha256", "miniflareVersion", "miniflareModuleSha256", "cacheWorkerSha256",
        "cacheEntrySha256", "shimSha256", "workerName", "documentUrlSha256", "cacheKeySha256",
        "observedAtUnixMillis", "before", "deleted", "after"}
    if (not isinstance(reply, dict) or set(reply) != fields or reply["version"] != 1
            or reply.get("observationScope") != "selected_public_document_cache_api" or reply.get("kind") != kind
            or reply.get("runnerPid") != peer_pid or reply.get("runnerStartTicks") != start_ticks
            or not isinstance(reply.get("observedAtUnixMillis"), str)
            or not re.fullmatch(r"[1-9][0-9]{0,19}", reply["observedAtUnixMillis"])
            or not before_utc <= int(reply["observedAtUnixMillis"]) <= after_utc):
        raise ValueError("actual cache control was refused or changed scope")
    return reply


def _cache_observation(reply, selected, kind, document):
    identity_fields = {"runnerPid", "runnerStartTicks", "configurationSha256", "cacheObserverSha256",
        "miniflareVersion", "miniflareModuleSha256", "cacheWorkerSha256", "cacheEntrySha256",
        "shimSha256", "workerName", "documentUrlSha256", "cacheKeySha256"}
    if (not isinstance(selected, dict) or set(selected) != identity_fields
            or type(selected["runnerPid"]) is not int or selected["runnerPid"] <= 0
            or not re.fullmatch(r"[1-9][0-9]{0,19}", selected["runnerStartTicks"])
            or any(not re.fullmatch(r"[0-9a-f]{64}", selected[field])
                for field in identity_fields if field.endswith("Sha256"))
            or selected["miniflareVersion"] != "5.20260801.0-alpha"
            or not isinstance(selected["workerName"], str) or not selected["workerName"]):
        raise ValueError("independently selected cache installation facts are missing")
    fields = identity_fields | {"version", "observationScope", "kind", "observedAtUnixMillis",
        "before", "deleted", "after"}
    if (not isinstance(reply, dict) or set(reply) != fields or type(reply["version"]) is not int
            or reply["version"] != 1 or reply["observationScope"] != "selected_public_document_cache_api"
            or reply["kind"] != kind or any(reply[field] != selected[field] for field in identity_fields)
            or not re.fullmatch(r"[1-9][0-9]{0,19}", reply["observedAtUnixMillis"])):
        raise ValueError("actual cache installation/configuration/process changed")
    for value in (reply["before"], reply["after"]):
        if value is not None and (not isinstance(value, dict)
                or set(value) != {"bodySha256", "byteSize", "expiresAtUnixSeconds"}
                or value["bodySha256"] != _digest(document) or value["byteSize"] != str(len(document))
                or not re.fullmatch(r"[1-9][0-9]{0,19}", value["expiresAtUnixSeconds"])):
            raise ValueError("actual cache content differs from the independent document")
    if kind == "public-document-cache-readback":
        if reply["deleted"] is not None or reply["after"] != reply["before"]:
            raise ValueError("readback unexpectedly changed cache state")
    elif reply["before"] is None or reply["deleted"] is not True or reply["after"] is not None:
        raise ValueError("actual exact-key cache deletion is unknown")
    return reply


def run_direct_document_cache(selection, transport, control, bearer_header_file, cookie_header_file,
                              private_registry_slug, cache_identity):
    """Observe real public cache fill/hit/expiry/eviction and credential bypass."""
    bodies = select_direct_read_corpus(selection)
    expected = bodies["document"]
    if len(expected) > 256 * 1024:
        raise ValueError("selected genuine documentation exceeds cache admission limit")
    url = _read_url(selection, "hybrid", "document")
    controls, rows = [], []
    if cache_identity.get("documentUrlSha256") != _digest(url.encode()):
        raise ValueError("cache case URL differs from the selected installed identity")

    def observe(kind, label):
        result = _cache_observation(control(kind, label), cache_identity, kind, expected)
        controls.append(result)
        return result

    cold = observe("public-document-cache-readback", "cache-cold")
    if cold["before"] is not None:
        raise ValueError("fresh selected document namespace is not cold")

    def request(label, request_url=url, headers=(), expected_status=200):
        row, body, response_headers = transport.request(label, request_url,
            request_headers=headers, expected_size=256 * 1024)
        rows.append(row)
        if row["status"] != expected_status or expected_status == 200 and body != expected:
            raise ValueError("actual cache case differs from the selected document/status")
        if "x-aos-front-cache-expires" in response_headers:
            raise ValueError("internal cache expiry escaped to the public response")
        return response_headers

    if request("cache-fill").get("x-aos-front-cache") == "hit":
        raise ValueError("first selected public document request was not a cache miss")
    filled = observe("public-document-cache-readback", "cache-filled")
    if filled["before"] is None or request("cache-hit").get("x-aos-front-cache") != "hit":
        raise ValueError("actual Cache API admission/hit is absent")
    bearer_header = None
    for label, file, prefix in (("cache-bearer-bypass", bearer_header_file, "Authorization: Bearer "),
            ("cache-cookie-bypass", cookie_header_file, "Cookie: ")):
        header = _read_source(file, HEADER_LIMIT, private=True).decode().strip()
        if not header.startswith(prefix) or "\n" in header or "\r" in header:
            raise ValueError("selected cache bypass credential header differs")
        if prefix.startswith("Authorization"):
            bearer_header = header
        if request(label, headers=(header,)).get("x-aos-front-cache") == "hit":
            raise ValueError("authenticated request reused shared cache content")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}/[a-z][a-z0-9-]{0,63}", private_registry_slug):
        raise ValueError("selected private registry slug differs")
    private_document, reply_body, _ = transport.request("cache-private-known-positive",
        selection["origins"]["hybrid"] + "/aos.hub.v1.DocumentationService/GetDocumentationArtifact",
        method="POST", request_headers=(bearer_header,),
        request_body=json.dumps({"registry": private_registry_slug,
            "documentSha256": "sha256:" + _digest(expected)}, separators=(",", ":")).encode())
    rows.append(private_document)
    reply = _json(reply_body)
    if (private_document["status"] != 200 or set(reply) != {"identity", "canonicalJson", "etag"}
            or base64.b64decode(reply["canonicalJson"], validate=True) != expected
            or reply["etag"] != "sha256:" + _digest(expected)):
        raise ValueError("private document has no authenticated existing-object positive")
    private_url = url.replace("/" + selection["registrySlug"] + "/", "/" + private_registry_slug + "/", 1)
    if request("cache-private-bypass", private_url, expected_status=404).get("x-aos-front-cache") == "hit":
        raise ValueError("hidden private document reused public cache")

    expiry = int(filled["before"]["expiresAtUnixSeconds"])
    remaining = expiry - time.time()
    if not 0 < remaining <= 61:
        raise ValueError("actual cache expiry is missing or outside the production TTL")
    # Real passage of UTC: do not forge a cache timestamp or a Worker clock.
    deadline = time.monotonic() + 65
    while time.time() <= expiry:
        if time.monotonic() >= deadline:
            raise ValueError("real cache expiry wait exceeded its bound")
        time.sleep(min(0.5, max(0.01, expiry + 0.01 - time.time())))
    if request("cache-expired-refetch").get("x-aos-front-cache") == "hit":
        raise ValueError("expired Cache API content was served as a hit")
    refilled = observe("public-document-cache-readback", "cache-refilled")
    if refilled["before"] is None:
        raise ValueError("expired document was not freshly admitted")
    evicted = observe("public-document-cache-evict", "cache-evicted")
    if evicted["deleted"] is not True or evicted["after"] is not None:
        raise ValueError("actual exact-key Cache API eviction is unknown")
    if request("cache-evicted-refetch").get("x-aos-front-cache") == "hit":
        raise ValueError("evicted Cache API entry was still served")
    if request("cache-rebuilt-hit").get("x-aos-front-cache") != "hit":
        raise ValueError("evicted public content did not rebuild through Native")
    return {"version": 1, "observations": rows, "cacheObservations": controls,
        "nativeBulkBytes": None, "scope": "actual public documentation Cache API and credential/private bypass; no outage permission inferred"}


def run_direct_full_read_window(selection, transport, control, bearer_header_file, cookie_header_file,
                                private_registry_slug, cache_identity, index_readers):
    """Run the fixed production reads after genuine same-source indexing."""
    indexes = capture_direct_full_index_parity(index_readers, selection["registrySlug"], selection["sourceCommit"])
    # The selected public document must still be cold when the cache case starts.
    # Reading it for parity first would erase the actual cache admission baseline.
    cache = run_direct_document_cache(selection, transport, control, bearer_header_file, cookie_header_file,
        private_registry_slug, cache_identity)
    reads = run_direct_read_parity(selection, transport)
    semantic = run_direct_semantic_read_parity(selection, transport)
    result = {"version": 1, "sourceCommit": selection["sourceCommit"], "indexParity": indexes,
        "cache": cache, "objectReads": reads, "indexedReads": semantic, "nativeBulkBytes": None,
        "scope": "actual indexed signed-corpus read/cache window; complete authenticated byte accounting remains separate"}
    retain_direct_flow("actual-full-read-window.json", result)
    return result


def prepare_direct_documented_surface(client, tools):
    """Author genuine option documentation in a separate signed APR release."""
    # The extra release belongs to its own registry/root. The main three large
    # objects and 12,535 pointers keep their existing publisher and counters.
    signed = prepare_direct_signed_surface(client, tools["python"], tools["apr"], tools["git"],
        tools["openssh"], tools["nix"], tools["helperStorePath"], tools["cacheUrl"],
        authoring_name="external-direct-docs")
    result = json.loads(direct_guest_python(client, tools["python"], r"""
        import hashlib, json, os, re, stat, subprocess, tomllib
        from pathlib import Path

        publisher_root = Path(selected['publisherRoot'])
        registry = publisher_root / '.local/share/apm/registries/external-direct-docs'
        environment = dict(os.environ)
        # APR's user-scoped registry and signing paths honor these XDG roots.
        # Retain the inherited home and use the actual prepared registry.
        environment.update(XDG_CONFIG_HOME=str(publisher_root / '.config'),
            XDG_DATA_HOME=str(publisher_root / '.local/share'),
            XDG_CACHE_HOME=str(publisher_root / '.cache'), NIX_REMOTE='',
            NIX_CONF_DIR=str(publisher_root / '.config/nix'))
        environment['PATH'] = ':'.join(selected['toolDirectories'] + [environment.get('PATH', '')])
        commands = [
            [selected['apr'], 'publish', selected['hubPackage'], '--registry', 'external-direct-docs',
                '--name', 'aos-hub', '--version', selected['hubVersion'],
                '--description', 'Native and Worker registry Hub service.', '--license', 'Apache-2.0',
                '--maintainer', 'fleet-publisher@example.test',
                '--key-id', 'initial'],
            [selected['apr'], 'release', '1.0.1', '--registry', 'external-direct-docs', '--key-id', 'initial',
                '--channel', 'stable', '--cache-url', selected['cacheUrl'],
                '--upload-url', 'file://' + selected['surface']],
            [selected['apr'], 'verify', '--registry', 'external-direct-docs'],
        ]
        root = publisher_root / 'documentation-source'
        root.mkdir(mode=0o700, exist_ok=False)
        os.umask(0o077)
        for number, field in enumerate(('name', 'email')):
            completed = subprocess.run([selected['git'], '-C', str(registry), 'config', '--local', '--get', 'user.' + field],
                env=environment, stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=30)
            if (completed.returncode or not 1 <= len(completed.stdout) <= 512
                    or completed.stderr or not completed.stdout.endswith(b'\n')
                    or b'\n' in completed.stdout[:-1]):
                raise ValueError('actual prepared publisher commit identity is unavailable')
            value = completed.stdout[:-1].decode()
            environment['GIT_AUTHOR_' + field.upper()] = value
            environment['GIT_COMMITTER_' + field.upper()] = value
            descriptor = os.open(root / ('git-identity-' + field), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(completed.stdout); output.flush(); os.fsync(output.fileno())
        for number, arguments in enumerate(commands):
            descriptors = [os.open(root / (str(number) + '.' + suffix),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600) for suffix in ('stdout', 'stderr')]
            with os.fdopen(descriptors[0], 'wb') as stdout, os.fdopen(descriptors[1], 'wb') as stderr:
                completed = subprocess.run(arguments, env=environment, stdin=subprocess.DEVNULL,
                    stdout=stdout, stderr=stderr, check=False, timeout=300)
                for output in (stdout, stderr):
                    output.flush(); os.fsync(output.fileno())
                    if os.fstat(output.fileno()).st_size > 1048576:
                        raise ValueError('actual APR output exceeded its retained inspection bound')
            if completed.returncode:
                raise ValueError('actual APR documentation preparation refused; source retained')
        catalog = tomllib.loads((registry / 'packages/a/aos-hub.toml').read_text())
        matching = [entry['platforms'][selected['platform']]['module_documentation']
            for entry in catalog['versions'] if entry['version'] == selected['hubVersion']]
        if len(matching) != 1:
            raise ValueError('actual signed package documentation identity is ambiguous')
        identity = matching[0]
        descriptor = os.open(Path(identity['store_path']) / 'options.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or not 1 <= metadata.st_size <= 262144:
                raise ValueError('actual APR documentation exceeds cache bounds')
            document = source.read(262145)
        if len(document) != metadata.st_size or len(document) > 262144:
            raise ValueError('actual APR documentation size changed')
        digest = hashlib.sha256(document).hexdigest()
        if (identity['document_sha256'] != 'sha256:' + digest
                or identity['document_size'] != len(document) or len(document) > 262144
                or not json.loads(document)['options']):
            raise ValueError('actual APR documentation is absent or outside cache bounds')
        descriptor = os.open(root / 'document.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(document); output.flush(); os.fsync(output.fileno())
        completed = subprocess.run([selected['git'], '-C', str(registry), 'rev-parse', 'HEAD'],
            env=environment, capture_output=True, check=False, timeout=30)
        commit = completed.stdout.decode().strip()
        if completed.returncode or not re.fullmatch(r'[0-9a-f]{64}', commit):
            raise ValueError('actual documented release source commit differs')
        print(json.dumps({'version': 1, 'sourceCommit': commit, 'release': '1.0.1',
            'document': {'file': str(root / 'document.json'), 'sha256': digest,
                'byteSize': len(document), 'relativePath': '-/api/v1/documentation/sha256:' + digest},
            'documentationIdentity': identity}))
    """, {"publisherRoot": signed["publisherHome"], "surface": signed["surfaceRoot"],
        "apr": tools["apr"], "hubPackage": tools["hubPackage"], "hubVersion": tools["hubVersion"],
        "cacheUrl": tools["cacheUrl"], "git": tools["git"],
        "platform": "x86_64-linux", "toolDirectories": [tools["git"].rsplit("/", 1)[0],
            tools["openssh"], tools["nix"]]}, timeout=1000))
    return {**signed, **result}


def assert_direct_read_refusals(observations):
    """Check retained fault evidence without inferring immediate lease revocation."""
    if set(observations) != {"provider_timeout", "stale_placement", "worker_revision"}:
        raise ValueError("required real read refusal cases are incomplete")
    result = {}
    fields = {"originalRequestSha256", "receivedRequestSha256", "replySha256", "replyBytes",
        "status", "startedAtUnixNs", "completedAtUnixNs", "providerWindow",
        "sqlBeforeSha256", "sqlAfterSha256", "actualSourceDigest", "selectedSourceDigest"}
    for name, row in observations.items():
        selected_fields = fields | ({"placementBefore", "placementAfter"} if name == "stale_placement" else set())
        if not isinstance(row, dict) or set(row) != selected_fields:
            raise ValueError("read refusal observation shape differs")
        for field in ("originalRequestSha256", "receivedRequestSha256", "replySha256",
                "sqlBeforeSha256", "sqlAfterSha256", "actualSourceDigest", "selectedSourceDigest"):
            if not re.fullmatch(r"[0-9a-f]{64}", row[field]):
                raise ValueError("read refusal original/source commitment is absent")
        if (row["originalRequestSha256"] != row["receivedRequestSha256"]
                or row["sqlBeforeSha256"] != row["sqlAfterSha256"]
                or type(row["replyBytes"]) is not int or not 1 <= row["replyBytes"] <= 256 * 1024
                or type(row["status"]) is not int or not 400 <= row["status"] <= 599
                or not re.fullmatch(r"[1-9][0-9]{0,19}", row["startedAtUnixNs"])
                or not re.fullmatch(r"[1-9][0-9]{0,19}", row["completedAtUnixNs"])
                or int(row["completedAtUnixNs"]) <= int(row["startedAtUnixNs"])):
            raise ValueError("read fault is unknown, successful, mutated SQL or has incomplete capture")
        window = row["providerWindow"]
        if (not isinstance(window, dict) or set(window) != {"file", "sha256", "capturedBytes", "before", "after"}
                or not re.fullmatch(r"[0-9a-f]{64}", window["sha256"])):
            raise ValueError("actual provider observation window is absent")
        before, after = window["before"], window["after"]
        position_fields = {"path", "device", "inode", "byteSize"}
        if (set(before) != position_fields or set(after) != position_fields
                or any(before[key] != after[key] for key in ("path", "device", "inode"))
                or type(before["byteSize"]) is not int or type(after["byteSize"]) is not int
                or not 0 <= before["byteSize"] <= after["byteSize"]
                or after["byteSize"] - before["byteSize"] != window["capturedBytes"]):
            raise ValueError("provider observation log rotated, shrank or has an incomplete prefix")
        raw = _read_source(window["file"], 128 * 1024, private=True)
        if len(raw) != window["capturedBytes"] or _digest(raw) != window["sha256"]:
            raise ValueError("actual retained provider observation prefix differs")
        receipts = [_json(line) for line in raw.splitlines()]
        if not isinstance(receipts, list) or len(receipts) > 32:
            raise ValueError("read fault provider observations are invalid")
        if name == "provider_timeout":
            event_fields = {"version", "kind", "sequence", "runDigest", "keyDigest", "versionDigest", "etagDigest",
                "atUnixMillis", "elapsedNanoseconds", "method", "status", "responseOfferedBytes"}
            if (len(receipts) != 2 or any(set(event) != event_fields for event in receipts)
                    or receipts[0]["kind"] != "read_started"
                    or receipts[1]["kind"] not in {"peer_closed", "fixture_timeout"}):
                raise ValueError("provider timeout lacks an actual request and terminal socket observation")
            for number, event in enumerate(receipts):
                if (event["version"] != 1 or event["sequence"] != number or event["method"] != "GET"
                        or event["status"] is not None or event["responseOfferedBytes"] != "0"
                        or any(not re.fullmatch(r"[0-9a-f]{64}", event[field])
                            for field in ("runDigest", "keyDigest", "versionDigest", "etagDigest"))
                        or not re.fullmatch(r"[1-9][0-9]{0,19}", event["atUnixMillis"])
                        or not re.fullmatch(r"0|[1-9][0-9]{0,19}", event["elapsedNanoseconds"])):
                    raise ValueError("provider timeout was replaced by an ordinary HTTP error/success")
            if (any(receipts[0][field] != receipts[1][field]
                    for field in ("runDigest", "keyDigest", "versionDigest", "etagDigest"))
                    or int(receipts[1]["elapsedNanoseconds"]) <= int(receipts[0]["elapsedNanoseconds"])
                    or any(not int(row["startedAtUnixNs"]) // 1_000_000 <= int(event["atUnixMillis"])
                        <= (int(row["completedAtUnixNs"]) + 999_999) // 1_000_000 for event in receipts)):
                raise ValueError("provider timeout terminal does not join the original actual request")
        elif name == "worker_revision" and receipts:
            raise ValueError("revision mismatch dispatched selected provider work")
        if name == "stale_placement":
            placement_before, placement_after = row["placementBefore"], row["placementAfter"]
            for value in (placement_before, placement_after):
                if (not isinstance(value, dict) or set(value) != {"placementId", "resourceVersion"}
                        or any(not re.fullmatch(r"[1-9][0-9]{0,19}", value[field]) for field in value)):
                    raise ValueError("actual stale placement revision observations are missing")
            if (placement_before["placementId"] != placement_after["placementId"]
                    or int(placement_after["resourceVersion"]) <= int(placement_before["resourceVersion"])):
                raise ValueError("the actual selected placement revision did not advance")
            # A valid previously admitted read may dispatch through its lease
            # cutoff. This case fences Native's index commit, not provider I/O.
        if name == "worker_revision":
            if row["selectedSourceDigest"] == row["actualSourceDigest"]:
                raise ValueError("revision mismatch did not select a different actual Worker revision")
        elif row["selectedSourceDigest"] != row["actualSourceDigest"]:
            raise ValueError("read fault unexpectedly changed runtime source")
        result[name] = {"status": row["status"], "originalRequestSha256": row["originalRequestSha256"],
            "replySha256": row["replySha256"],
            "providerRequests": None if name == "stale_placement" else 1 if receipts else 0,
            "providerObservationSha256": window["sha256"], "nativeBulkBytes": None,
            "scope": "retained original/authoritative-index/provider-window consistency only; stale placement fences Native commit, current auth/handler/source joins remain required"}
    return result
