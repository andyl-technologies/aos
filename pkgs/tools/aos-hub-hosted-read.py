"""Read an existing signed hosted corpus and retain bounded observations.

The run command issues only fixed HTTPS reads. The assess command consumes later
installation and capture readbacks without replaying traffic. Neither command
creates authority, changes a deployment, or establishes whole-provider coverage.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import time
from urllib.parse import urlsplit


HERE = Path(__file__).resolve().parent
HOSTED = runpy.run_path(str(next(path for path in (
    HERE / "hosted-workload.py", HERE / "aos-hub-hosted-workload.py") if path.is_file())))
MODES = ("hybrid", "native_only", "worker_only")
MAX_JSON = 1024 * 1024
MAX_BODY = 4 * 1024 * 1024
RUNTIME_FIELDS = {"runtimeCodecRevision", "workerSourceDigest", "sourceArchiveSha256", "nativeExecutableSha256"}
FIELDS = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def closed(value, fields):
    HOSTED["exact_fields"](value, fields)


def reference_bytes(reference, maximum=MAX_JSON):
    """Use the existing held private reference reader, without accepting aliases."""
    fd, raw = HOSTED["assessment_input"](reference, maximum)
    os.close(fd)
    return raw


def parsed(reference, maximum=MAX_JSON):
    return HOSTED["closed_json"](reference_bytes(reference, maximum))


def load_parity(directory, expected):
    path = Path(directory) / "_hub-direct-read-parity.py"
    if digest(path.read_bytes()) != expected:
        raise ValueError("Selected signed-read comparator source differs")
    return runpy.run_path(str(path))


def runtime(value):
    closed(value, RUNTIME_FIELDS)
    if (not re.fullmatch(r"[0-9a-f]{40}", value["runtimeCodecRevision"])
            or any(not re.fullmatch(r"[0-9a-f]{64}", value[name])
                   for name in RUNTIME_FIELDS - {"runtimeCodecRevision"})):
        raise ValueError("Measured runtime commitment differs")


def readback(value, selected, mode, *, earliest, latest):
    """Compare retained installation facts; their independent authority stays open."""
    closed(value, {"version", "mode", "origin", "deploymentId", "moduleSha256", "configurationSha256",
                   "processEpoch", "runtime", "sourceTree", "observedAtUnixNs"})
    pin = selected["deployments"][mode]
    if (type(value["version"]) is not int or value["version"] != 1
            or value["mode"] != mode or value["origin"] != selected["corpus"]["origins"][mode]
            or value["runtime"] != selected["runtime"] or value["sourceTree"] != selected["sourceTree"]
            or any(value[name] != pin[name] for name in
                   ("deploymentId", "moduleSha256", "configurationSha256", "processEpoch"))
            or not isinstance(value["observedAtUnixNs"], str)
            or not re.fullmatch(r"[1-9][0-9]{0,19}", value["observedAtUnixNs"])
            or not earliest <= int(value["observedAtUnixNs"]) <= latest):
        raise ValueError("Actual installation readback belongs to another epoch or window")
    return value


def select(reference, parity):
    raw = reference_bytes(reference)
    value = HOSTED["closed_json"](raw)
    closed(value, {"version", "corpusId", "windowId", "startsAt", "expiresAt", "runtime", "sourceTree",
                   "paritySourceSha256", "hostedWorkloadSourceSha256", "signedPublication", "corpus", "deployments",
                   "curl", "trustFile", "bearerHeaderFile", "cookieHeaderFile", "privateRegistrySlug"})
    runtime(value["runtime"])
    if (type(value["version"]) is not int or value["version"] != 1
            or any(not re.fullmatch(r"[0-9a-f]{32}", value[name]) for name in ("corpusId", "windowId"))
            or not re.fullmatch(r"[0-9a-f]{40}", value["sourceTree"])
            or value["hostedWorkloadSourceSha256"] != digest(Path(HOSTED["__file__"]).read_bytes())
            or type(value["startsAt"]) is not int or type(value["expiresAt"]) is not int
            or not value["startsAt"] <= time.time() < value["expiresAt"] <= value["startsAt"] + 600
            or set(value["deployments"]) != set(MODES)
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}/[a-z][a-z0-9-]{0,63}", value["privateRegistrySlug"])
            or value["privateRegistrySlug"] == value["corpus"]["registrySlug"]):
        raise ValueError("Hosted read selection or original cutoff differs")
    parity["select_direct_read_corpus"](value["corpus"])
    reference_bytes(value["signedPublication"], 64 * MAX_JSON)
    HOSTED["selected_tool"](value["curl"])
    for mode, pin in value["deployments"].items():
        closed(pin, {"deploymentId", "moduleSha256", "configurationSha256", "processEpoch", "before"})
        if (any(not isinstance(pin[name], str) or not 1 <= len(pin[name]) <= 256
                for name in ("deploymentId", "processEpoch"))
                or not re.fullmatch(r"[0-9a-f]{64}", pin["configurationSha256"])
                or not (mode == "native_only" and pin["moduleSha256"] is None
                        or isinstance(pin["moduleSha256"], str)
                        and re.fullmatch(r"[0-9a-f]{64}", pin["moduleSha256"]))):
            raise ValueError("Installation pin differs")
        readback(parsed(pin["before"]), value, mode,
                 earliest=value["startsAt"] * 10**9, latest=time.time_ns())
    return value, raw


def location(headers):
    values = [line.partition(b":")[2].strip() for line in headers.split(b"\r\n")
              if line.partition(b":")[0].lower() == b"cf-ray"]
    if len(values) > 1:
        raise ValueError("Hosted response repeats its edge observation")
    if not values:
        return None
    match = re.fullmatch(rb"[0-9a-fA-F]{16,32}-([A-Z]{3})", values[0])
    return match[1].decode() if match else None


class HostedReadHttp:
    """Use one source-built curl per fixed read with existing bounded supervision."""

    def __init__(self, selected, parity, evidence):
        self.selected, self.parity, self.evidence = selected, parity, evidence
        self.observations = []
        remaining = selected["expiresAt"] - time.time()
        self.cutoff = HOSTED["original_cutoff"](remaining)
        self.cutoff["originalCutoffUnixNs"] = str(selected["expiresAt"] * 10**9)

    def request(self, label, url, *, method="GET", request_headers=(), expected_size=MAX_BODY,
                request_body=None, credential=None):
        parsed_url = urlsplit(url)
        origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
        if (not re.fullmatch(r"[a-z][a-z0-9-]{0,95}", label) or method not in {"GET", "HEAD", "POST"}
                or origin not in self.selected["corpus"]["origins"].values()
                or parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment
                or not 0 <= expected_size <= MAX_BODY):
            raise ValueError("Read dispatch leaves the selected HTTPS corpus")
        if method == "POST":
            if (origin != self.selected["corpus"]["origins"]["hybrid"]
                    or parsed_url.path != "/aos.hub.v1.DocumentationService/GetDocumentationArtifact"
                    or request_body is None or len(request_body) > 4096):
                raise ValueError("POST leaves the fixed documentation query")
        elif request_body is not None:
            raise ValueError("GET/HEAD unexpectedly carries a body")
        if any(header != "Range: bytes=6-13" for header in request_headers):
            raise ValueError("Read request changes its fixed range geometry")
        remaining = min(25, HOSTED["remaining_cutoff"](self.cutoff))
        args = [self.selected["curl"]["file"], "--disable", "--silent", "--show-error", "--proto", "=https",
                "--noproxy", "*", "--max-time", str(remaining), "--max-filesize", str(MAX_BODY),
                "--include", "--output", "-", "--write-out", "\naos-read-status:%{http_code}",
                "--header", "Accept: */*", "--header", "Accept-Encoding: identity"]
        if method == "HEAD":
            args += ["--head"]
        elif method == "POST":
            ref = self.evidence.save(label + ".request-body", request_body)
            args += ["--request", "POST", "--data-binary", "@" + str(self.evidence.path / ref["file"]),
                     "--header", "Content-Type: application/json", "--header", "Connect-Protocol-Version: 1"]
        for header in request_headers:
            args += ["--header", header]
        descriptors, before = [], {}
        try:
            if self.selected["trustFile"] is not None:
                fd, _ = HOSTED["assessment_input"](self.selected["trustFile"], MAX_JSON)
                descriptors.append(fd)
                args += ["--cacert", f"/proc/self/fd/{fd}"]
            if credential is not None:
                if credential not in {"bearer", "cookie"}:
                    raise ValueError("Credential selector differs")
                # Curl consumes the private header file. Do not decode, hash,
                # retain or log bearer/cookie values in the observation process.
                path = self.selected[credential + "HeaderFile"]
                if (not isinstance(path, str) or not Path(path).is_absolute()
                        or str(Path(path)) != path or ".." in Path(path).parts):
                    raise ValueError("Opaque credential header path is not canonical and absolute")
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                descriptors.append(fd)
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != 0o600 or not 1 <= info.st_size <= 65536):
                    raise ValueError("Opaque private credential header file custody differs")
                args += ["--header", f"@/proc/self/fd/{fd}"]
            before = {fd: os.fstat(fd) for fd in descriptors}
            remaining = min(25, HOSTED["remaining_cutoff"](self.cutoff))
            args[args.index("--max-time") + 1] = str(remaining)
            started = time.time_ns()
            result = HOSTED["assessment_process"](args + [url], [self.evidence.fd, *descriptors], timeout=remaining)
            changed = any(any(getattr(info, field) != getattr(os.fstat(fd), field) for field in FIELDS)
                          for fd, info in before.items())
        finally:
            for fd in descriptors:
                os.close(fd)
        stdout, stderr = result.pop("stdout"), result.pop("stderr")
        # The existing supervisor bounds stdout at 16 MiB and stderr at 64 KiB,
        # including headers with no Content-Length. Curl never writes an
        # unbounded header or body file. Preserve the actual prefix first.
        transcript = self.evidence.save(label + ".response-prefix", stdout)
        stderr_ref = self.evidence.save(label + ".stderr", stderr)
        marker = b"\naos-read-status:"
        status = int(stdout[-3:]) if (stdout[-len(marker)-3:-3] == marker
                                    and re.fullmatch(rb"[1-5][0-9]{2}", stdout[-3:])) else None
        raw_response = stdout[:-len(marker)-3] if status is not None else stdout
        prefix, separator, body = raw_response.partition(b"\r\n\r\n")
        headers = prefix + separator
        shape = bool(separator) and len(headers) <= 65536 and len(body) <= MAX_BODY
        body_ref = self.evidence.save(label + ".body", body) if shape else None
        header_ref = self.evidence.save(label + ".headers", headers) if shape else None
        eof = (result["exitCode"] == 0 and not any(result.get(name, False) for name in
               ("timedOut", "overflow", "cancelled", "collectionFailed"))
               and result["cleanup"]["state"] == "group_absent" and not changed and shape)
        row = {"label": label, "method": method, "urlSha256": digest(url.encode()), "status": status,
               "requestBodySha256": None if request_body is None else digest(request_body),
               "requestBodyBytes": 0 if request_body is None else len(request_body), "credentialClass": credential,
               "startedAtUnixNs": str(started), "completedAtUnixNs": str(time.time_ns()),
               "bodySha256": digest(body) if shape else None, "bodyBytes": len(body) if shape else None, "responseEof": eof,
               "headersSha256": digest(headers) if shape else None, "headerBytes": len(headers) if shape else None,
               "edgeLocation": location(headers) if shape else None, "responsePrefix": transcript,
               "bodyFile": None if body_ref is None else str(self.evidence.original_path / body_ref["file"]),
               "headersFile": None if header_ref is None else str(self.evidence.original_path / header_ref["file"]), "stderr": stderr_ref,
               "transport": result, "credentialInputsChanged": changed,
               "receiverCustody": None, "authenticatedActor": None}
        self.observations.append(row)
        self.evidence.save(label + ".json", row)
        if not eof or stderr or status is None or len(body) > expected_size:
            raise RuntimeError("Actual read did not complete within its original bound; prefix retained")
        HOSTED["remaining_cutoff"](self.cutoff)
        return row, body, self.parity["parse_direct_read_headers"](headers)


def cache_reads(selected, parity, transport):
    """Assert observed document fill/hit and credential/private separation."""
    corpus = selected["corpus"]
    expected = parity["select_direct_read_corpus"](corpus)["document"]
    if len(expected) > 256 * 1024:
        raise ValueError("Selected documentation exceeds public cache admission")
    url = parity["_read_url"](corpus, "hybrid", "document")
    rows = []

    def public(label, credential=None, *, hit=None):
        row, body, headers = transport.request(label, url, expected_size=len(expected), credential=credential)
        rows.append(row)
        if row["status"] != 200 or body != expected or "x-aos-front-cache-expires" in headers:
            raise ValueError("Public document differs from retained canonical bytes")
        observed = headers.get("x-aos-front-cache") == "hit"
        if hit is not None and observed != hit:
            raise ValueError("Actual document cache hit/bypass assertion failed")
        return observed

    first_hit = public("document-fill", hit=False)
    public("document-warm", hit=True)
    public("document-bearer-bypass", "bearer", hit=False)
    public("document-cookie-bypass", "cookie", hit=False)
    body = json.dumps({"registry": selected["privateRegistrySlug"],
                       "documentSha256": "sha256:" + digest(expected)}, separators=(",", ":")).encode()
    row, raw, headers = transport.request("private-document-positive",
        corpus["origins"]["hybrid"] + "/aos.hub.v1.DocumentationService/GetDocumentationArtifact",
        method="POST", request_body=body, credential="bearer")
    rows.append(row)
    reply = HOSTED["closed_json"](raw)
    closed(reply, {"identity", "canonicalJson", "etag"})
    if (row["status"] != 200 or base64.b64decode(reply["canonicalJson"], validate=True) != expected
            or reply["etag"] != "sha256:" + digest(expected) or headers.get("x-aos-front-cache") == "hit"):
        raise ValueError("Private document lacks its actual positive existing-object query")
    private_url = url.replace("/" + corpus["registrySlug"] + "/", "/" + selected["privateRegistrySlug"] + "/", 1)
    row, _, headers = transport.request("private-document-anonymous", private_url, expected_size=256 * 1024)
    rows.append(row)
    if row["status"] != 404 or headers.get("x-aos-front-cache") == "hit":
        raise ValueError("Private document reused shared cache or escaped anonymous refusal")
    pops = {row["edgeLocation"] for row in rows}
    return {"state": "observed" if len(pops) == 1 and None not in pops else "location_unknown_or_changed",
            "firstRequestWasHit": first_hit, "coldCacheState": None, "cacheApiContents": None,
            "eviction": None, "observations": rows, "authority": "independent_actor_and_installation_joins_required"}


def run(reference, directory, evidence):
    initial = parsed(reference)
    parity = load_parity(directory, initial["paritySourceSha256"])
    selected, raw = select(reference, parity)
    original = evidence.save("selection.json", raw)
    transport = HostedReadHttp(selected, parity, evidence)
    try:
        cache = cache_reads(selected, parity, transport)
        reads = parity["run_direct_read_parity"](selected["corpus"], transport)
        queries = parity["run_direct_semantic_read_parity"](selected["corpus"], transport)
        result = {"version": 1, "state": "reads_observed_acceptance_incomplete", "selection": original,
                  "harnessSha256": digest(Path(__file__).read_bytes()), "runtime": selected["runtime"],
                  "sourceTree": selected["sourceTree"], "corpusId": selected["corpusId"], "windowId": selected["windowId"],
                  "startsAt": selected["startsAt"], "expiresAt": selected["expiresAt"],
                  "cache": cache, "objectReads": reads, "indexedQueries": queries,
                  "observations": transport.observations, "cutoff": transport.cutoff,
                  "afterInstallationReadbacks": None, "fanout": None, "outage": None,
                  "signedPublicationVerification": None,
                  "indexReaderAuthority": None, "providerState": None, "nativeBulkBytes": None,
                  "qualification": None}
        evidence.save("report.json", result)
        return result
    except Exception as error:
        evidence.save("read-failure.json", {"state": "unknown", "errorClass": type(error).__name__,
                      "observations": transport.observations, "qualification": None})
        raise


def fanout_summary(records, joins):
    """Keep every observed attempt; missing receiver or EOF never implies completion."""
    attempts = {}
    receivers = {}
    for record in records["attempts"]:
        value = record["value"]
        call = value["transportCallId"]
        if call in attempts:
            raise ValueError("Native attempt identity is duplicated")
        attempts[call] = value
    for join in joins:
        call = join["transportCallId"]
        if call in receivers:
            raise ValueError("Receiver call identity is duplicated")
        receivers[call] = join
    unresolved = []
    for call, attempt in attempts.items():
        join = receivers.get(call)
        if (join is None or join["requestImage"] != "matched_selected_receiver_byte_image"
                or join["typedPayload"] is None
                or join["typedPayload"]["planIdSha256"] != digest(attempt["planId"].encode())
                or not join["fullReplyConsumed"] or not attempt["replyEof"]
                or join["nativeReplyConsumedBytes"] != attempt["exposedReplyBytes"]
                or attempt["outcome"] != "typed_result_checked"):
            unresolved.append(call)
    return {"state": "observed_selected_attempts" if attempts and not unresolved else "unknown",
            "observedAttemptCount": len(attempts), "unresolvedCallIds": unresolved,
            "wholeFanoutCompleteness": None, "providerState": None}


def fanout(invocation, selected, evidence):
    """Run the existing source-pinned offline assessment; selected reports are forbidden."""
    if invocation is None:
        return {"state": "unknown", "receiverJoins": [], "providerState": None}
    specification = parsed(invocation)
    closed(specification, {"version", "executable", "selection"})
    if type(specification["version"]) is not int or specification["version"] != 1:
        raise ValueError("Offline invocation version differs")
    executable = HOSTED["selected_tool"](specification["executable"])
    wrapper = Path(executable["file"])
    if wrapper.name != "aos-hosted-byte-assessment" or wrapper.parent.name != "bin":
        raise ValueError("Select the installed observation package's exact assessment wrapper")
    library = wrapper.parent.parent / "libexec/aos-observation-tools"
    # Reuse the package's independently measured codec and producer source
    # checks. A private script or a selected JSON report is never an adapter.
    reader = runpy.run_path(str(library / "hosted_assessment.py"))
    if reader["RUNTIME"] != selected["runtime"] or reader["SOURCE_TREE"] != selected["sourceTree"]:
        raise ValueError("Installed observation package uses another actual runtime source")
    descriptors = []
    try:
        fd, raw = HOSTED["assessment_input"](specification["selection"], MAX_JSON)
        descriptors.append(fd)
        chosen = HOSTED["closed_json"](raw)
        if chosen["runtime"] != selected["runtime"]:
            raise ValueError("Offline capture uses another installed runtime")
        policy = parsed(chosen["capturePolicy"])
        if (any(policy[name] != selected[name] for name in ("corpusId", "windowId", "sourceTree"))
                or policy["sourceCommit"] != selected["runtime"]["runtimeCodecRevision"]
                or policy["startsAt"] != selected["startsAt"] or policy["expiresAt"] != selected["expiresAt"]):
            raise ValueError("Receiver corpus or original observation window differs")
        if chosen["indexSnapshots"] is not None:
            if chosen["indexSnapshots"]["signedSourceCommit"] != selected["corpus"]["sourceCommit"]:
                raise ValueError("Authoritative index comparison selects another signed source")
        # Give the child the already checked bytes beneath our held output
        # directory, rather than reopening the mutable operator pathname.
        retained = evidence.save("fanout-selection.json", raw)
        retained_path = str(evidence.path / retained["file"])
        retained_fd = os.open(retained_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        descriptors.append(retained_fd)
        before = {fd: os.fstat(fd) for fd in descriptors}
        result = HOSTED["assessment_process"]([executable["file"], retained_path],
                                               [evidence.fd, *descriptors], timeout=60)
        changed = any(any(getattr(info, field) != getattr(os.fstat(fd), field) for field in FIELDS)
                      for fd, info in before.items())
    finally:
        for fd in descriptors:
            os.close(fd)
    stdout, stderr = result.pop("stdout"), result.pop("stderr")
    evidence.save("fanout-stdout.json", stdout)
    evidence.save("fanout-stderr", stderr)
    evidence.save("fanout-invocation.json", {"specification": specification, "process": result, "inputsChanged": changed})
    if (result["exitCode"] != 2 or changed or any(result.get(name, False) for name in
            ("timedOut", "overflow", "cancelled", "collectionFailed"))
            or result["cleanup"]["state"] != "group_absent"):
        raise ValueError("Actual source-pinned offline observation failed")
    report = HOSTED["closed_json"](stdout)
    if report["runtime"] != selected["runtime"] or report["hostedAcceptance"] != "incomplete":
        raise ValueError("Offline report changed runtime or promoted qualification")
    sidecar = reader["parsed"](chosen["authSidecar"]) if chosen["authSidecar"] else None
    records = reader["execute_records"](sidecar) if sidecar is not None else {"attempts": [], "finalContexts": []}
    for group in ("attempts", "finalContexts"):
        for record in records[group]:
            at = record["value"].get("observedAtUnixMicros", record["value"].get("completedAtUnixMicros"))
            if at is None or not selected["startsAt"] * 10**6 <= int(at) <= selected["expiresAt"] * 10**6:
                raise ValueError("Selected Native attempt lacks the original read-window clock join")
    summary = fanout_summary(records, report["applicationBodyAssessment"]["receiverJoins"])
    return {**summary, "assessment": report, "nativeExecuteRecords": records,
            "captureCompleteness": None, "providerState": None,
            "scope": "actual installed assessment receiver joins; absent attempts, auth and SQL authority remain unknown"}


def assess(reference, evidence):
    """Join later readbacks without extending the original window or issuing reads."""
    chosen = parsed(reference)
    closed(chosen, {"version", "readSelection", "readReport", "afterReadbacks", "fanoutInvocation"})
    if type(chosen["version"]) is not int or chosen["version"] != 1:
        raise ValueError("Read assessment version differs")
    selected, report = parsed(chosen["readSelection"]), parsed(chosen["readReport"], 16 * MAX_JSON)
    if (type(report["version"]) is not int or report["version"] != 1
            or report["state"] != "reads_observed_acceptance_incomplete"
            or report["runtime"] != selected["runtime"] or report["sourceTree"] != selected["sourceTree"]
            or report["harnessSha256"] != digest(Path(__file__).read_bytes())
            or report["selection"]["sha256"] != chosen["readSelection"]["sha256"]
            or any(report[name] != selected[name] for name in ("corpusId", "windowId", "startsAt", "expiresAt"))
            or set(chosen["afterReadbacks"]) != set(MODES)):
        raise ValueError("Retained read invocation lineage differs")
    latest_response = max(int(row["completedAtUnixNs"]) for row in report["observations"])
    after = {mode: readback(parsed(ref), selected, mode, earliest=latest_response,
                           latest=min(time.time_ns(), selected["expiresAt"] * 10**9))
             for mode, ref in chosen["afterReadbacks"].items()}
    result = {"version": 1, "state": "retained_reads_with_incomplete_acceptance", "readReport": chosen["readReport"],
              "afterInstallationReadbacks": after, "fanout": fanout(chosen["fanoutInvocation"], selected, evidence),
              "readReportProducerAuthority": None, "installationReadbackAuthority": None,
              "indexReaderAuthority": None, "outage": None,
              "providerState": None, "nativeBulkBytes": None, "qualification": None}
    evidence.save("assessment.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "assess"))
    parser.add_argument("--selection", required=True, help="Select a private reference JSON file.")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--library-dir", required=True)
    options = parser.parse_args()
    evidence = HOSTED["Evidence"](options.output_dir)
    try:
        ref = HOSTED["closed_json"](HOSTED["private_bytes"](options.selection, 16384))
        result = run(ref, options.library_dir, evidence) if options.command == "run" else assess(ref, evidence)
        print(json.dumps({"state": result["state"], "qualification": None}))
        return 2  # Completed observations do not qualify the hosted deployment.
    except Exception as error:
        evidence.save("failure.json", {"state": "unknown", "errorClass": type(error).__name__, "qualification": None})
        print("Hosted read stopped; private bounded originals retained.")
        return 1
    finally:
        evidence.close()


if __name__ == "__main__":
    raise SystemExit(main())
