"""Inspect actual local issuer observations without manufacturing qualification.

The prospective policy requires genuine operator validation and a separately
reviewed package/process tuple. This collector checks retained event custody and
reports measured facts; it grants no permission or runtime acceptance.
"""

from collections import Counter
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import re
import stat


LOCAL_LEASE_SCALE_POLICY = {
    "version": 1,
    "cohorts": 32,
    "freshWorkerdProcesses": 4,
    "maximumFollowersPerCohort": 32,
    "maximumOwnerRequestSeconds": 30,
    "ownerRetriesInsideOriginalWindow": 0,
    "observedRenewalsPerTtlCase": 2,
    "maximumLifetimeSecondsCases": [8, 120],
    "selectedExecutorUncertaintySeconds": 2,
    "outageThroughActualExpiryCases": 1,
    "warmP95NsExclusive": 100_000_000,
    "warmP99NsExclusive": 250_000_000,
    "coldP95NsExclusive": 500_000_000,
    "coldP99NsExclusive": 1_000_000_000,
    "maximumIssuerAllocatedCpuPercent": 50,
    "scope": "prospective local test inputs; not production limits or reviewed clock evidence",
}

MAX_RECORD_BYTES = 1024
MAX_RECORDS = 262_144
MAX_OUTPUT_BYTES = 256 * 1024 * 1024
RECORD_FIELDS = {"version", "sequence", "atUnixNs", "event", "request", "fields"}
REQUEST_FIELDS = {"nonce", "requestDigest", "receivedBodySha256", "receivedBodyBytes"}
COMMIT_KINDS = {
    "initialization", "read_only", "lease", "control", "clock_session",
    "clock_observation", "recovery_read_only", "clock_resolution",
    "clock_resolution_consume",
}


def _closed_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate observation field")
        result[key] = value
    return result


def _unsigned(value, allow_absent=False):
    if allow_absent and value is None:
        return None
    if type(value) is not int or value < 0 or value > 2**64 - 1:
        raise ValueError("observation count is not a bounded unsigned integer")
    return value


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("observation digest differs")
    return value


def _shape(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError("observation shape differs")


def _private_file(path):
    path = Path(path)
    if not path.is_absolute() or path.parent.resolve() != path.parent:
        raise ValueError("observation path is not exact private custody")
    parent = path.parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
        raise ValueError("observation parent is not owner-private")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    source = os.fdopen(descriptor, "rb")
    metadata = os.fstat(source.fileno())
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > MAX_OUTPUT_BYTES):
        source.close()
        raise ValueError("observation file custody or size differs")
    return source, metadata


def collect_local_issuer_observations(path, selected):
    """Read a complete immutable recorder file and report observed event totals.

    Selected build/source pins require independent verification outside this
    parser. It never authenticates an issuer reply or approves a publication.
    """
    _shape(selected, {"runId", "selectedSourceSha256", "executableSha256",
        "authorityConfigurationSha256", "installationSha256", "processPid", "processStartTicks"})
    if not isinstance(selected["runId"], str) or not re.fullmatch(r"[0-9a-f]{32}", selected["runId"]):
        raise ValueError("selected run differs")
    for name in set(selected) - {"runId", "processPid", "processStartTicks"}:
        _digest(selected[name])
    if _unsigned(selected["processPid"]) == 0 or (not isinstance(selected["processStartTicks"], str)
            or not re.fullmatch(r"[0-9]{1,20}", selected["processStartTicks"])
            or int(selected["processStartTicks"]) > 2**64 - 1):
        raise ValueError("selected actual process lifetime differs")
    source, before = _private_file(path)
    digest = hashlib.sha256()
    byte_count = record_count = 0
    opened = finished = None
    requests = {}
    commit_counts = Counter()
    signature_counts = Counter()
    missing_cpu = 0
    sign_cpu_ns = sign_wall_ns = 0
    sign_cpu_samples = sign_wall_samples = 0

    with source:
        while line := source.readline(MAX_RECORD_BYTES + 1):
            preceding_bytes = byte_count
            byte_count += len(line)
            record_count += 1
            if (len(line) > MAX_RECORD_BYTES or not line.endswith(b"\n")
                    or byte_count > MAX_OUTPUT_BYTES or record_count > MAX_RECORDS or finished is not None):
                raise ValueError("observation stream is incomplete or exceeds its bound")
            digest.update(line)
            row = json.loads(line, object_pairs_hook=_closed_object)
            _shape(row, RECORD_FIELDS)
            if type(row["version"]) is not int or row["version"] != 1 or _unsigned(row["sequence"]) != record_count:
                raise ValueError("observation record sequence differs")
            if row["atUnixNs"] is not None and (not isinstance(row["atUnixNs"], str)
                    or not re.fullmatch(r"[1-9][0-9]{0,38}", row["atUnixNs"])):
                raise ValueError("observation UTC sample differs")
            fields, request = row["fields"], row["request"]
            current = None
            if request is not None:
                _shape(request, REQUEST_FIELDS)
                for name in ("nonce", "requestDigest", "receivedBodySha256"):
                    _digest(request[name])
                if _unsigned(request["receivedBodyBytes"]) > 1024 * 1024 - 512:
                    raise ValueError("received issuer body exceeds its real wire cap")
                if row["event"] == "request_started":
                    if request["nonce"] in requests:
                        raise ValueError("repeated nonce has ambiguous request ownership")
                    requests[request["nonce"]] = {"pins": request, "outcome": None, "queueWaitNs": None}
                current = requests.get(request["nonce"])
                if current is None or current["pins"] != request:
                    raise ValueError("observation request original differs")
            if row["event"] == "opened":
                _shape(fields, set(selected) | {"maximumRecordBytes", "maximumRecords", "maximumOutputBytes", "processCpuNs"})
                if record_count != 1 or request is not None or any(fields[name] != value for name, value in selected.items()):
                    raise ValueError("recorder selected inputs differ")
                if tuple(_unsigned(fields[name]) for name in ("maximumRecordBytes", "maximumRecords", "maximumOutputBytes")) != (MAX_RECORD_BYTES, MAX_RECORDS, MAX_OUTPUT_BYTES):
                    raise ValueError("recorder limits differ")
                _unsigned(fields["processCpuNs"], True)
                opened = fields
            elif opened is None:
                raise ValueError("recorder has no opening identity")
            elif row["event"] == "request_started":
                _shape(fields, set())
                if current is None:
                    raise ValueError("request observation is unjoined")
            elif row["event"] == "gate_acquired":
                _shape(fields, {"queueWaitNs"})
                if current is None or current["queueWaitNs"] is not None:
                    raise ValueError("queue observation ownership differs")
                current["queueWaitNs"] = _unsigned(fields["queueWaitNs"], True)
            elif row["event"] == "signature":
                _shape(fields, {"purpose", "wallNs", "threadCpuNs"})
                if current is None or fields["purpose"] not in {"lease", "reply"}:
                    raise ValueError("signature observation purpose differs")
                signature_counts[fields["purpose"]] += 1
                cpu, wall = _unsigned(fields["threadCpuNs"], True), _unsigned(fields["wallNs"], True)
                missing_cpu += cpu is None
                if cpu is not None:
                    sign_cpu_ns += cpu
                    sign_cpu_samples += 1
                if wall is not None:
                    sign_wall_ns += wall
                    sign_wall_samples += 1
            elif row["event"] == "transaction_commit":
                _shape(fields, {"kind", "wallNs", "outcome"})
                if fields["kind"] not in COMMIT_KINDS or fields["outcome"] not in {"acknowledged", "indeterminate_error"}:
                    raise ValueError("commit observation differs")
                _unsigned(fields["wallNs"], True)
                commit_counts[(fields["kind"], fields["outcome"])] += 1
            elif row["event"] in {"request_completed", "request_abandoned"}:
                expected = {"wallNs", "outcome"} if row["event"] == "request_completed" else {"wallNs", "settlement"}
                _shape(fields, expected)
                if current is None or current["outcome"] is not None:
                    raise ValueError("request completion ownership differs")
                if row["event"] == "request_completed" and fields["outcome"] not in {"success", "refused"}:
                    raise ValueError("request completion differs")
                if row["event"] == "request_abandoned" and fields["settlement"] != "unknown":
                    raise ValueError("abandoned work cannot claim settlement")
                current["outcome"] = fields.get("outcome", "abandoned_unknown")
                current["wallNs"] = _unsigned(fields["wallNs"], True)
            elif row["event"] == "finished":
                _shape(fields, {"precedingRecords", "precedingBytes", "processCpuNs", "processWindowWallNs"})
                if (request is not None or _unsigned(fields["precedingRecords"]) != record_count - 1
                        or _unsigned(fields["precedingBytes"]) != preceding_bytes
                        or any(value["outcome"] is None for value in requests.values())):
                    raise ValueError("recorder terminal acknowledgment is incomplete")
                _unsigned(fields["processCpuNs"], True)
                _unsigned(fields["processWindowWallNs"], True)
                finished = fields
            else:
                raise ValueError("unsupported recorder event")
        after = os.fstat(source.fileno())
    current_file = Path(path).stat(follow_symlinks=False)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    if identity(before) != identity(after) or identity(before) != identity(current_file) or finished is None:
        raise ValueError("observation changed or has no closed terminal record")
    cpu = None
    if opened["processCpuNs"] is not None and finished["processCpuNs"] is not None:
        cpu = finished["processCpuNs"] - opened["processCpuNs"]
        if cpu < 0:
            raise ValueError("process CPU sample moved backwards")
    return {"version": 1, "recordSha256": digest.hexdigest(), "recordBytes": byte_count,
        "recordCount": record_count, "requests": requests,
        "commits": [{"kind": kind, "outcome": outcome, "count": count}
            for (kind, outcome), count in sorted(commit_counts.items())],
        "signatures": dict(signature_counts),
        "signingThreadCpuNsObserved": sign_cpu_ns if sign_cpu_samples else None,
        "signingWallNsObserved": sign_wall_ns if sign_wall_samples else None,
        "signingCpuSamples": sign_cpu_samples, "signingWallSamples": sign_wall_samples,
        "missingSigningCpuSamples": missing_cpu,
        "wholeProcessCpuNs": cpu, "qualification": None,
        "durableRecorderCompletion": None,
        "wholeProcessWindowWallNs": finished["processWindowWallNs"],
        "scope": "private actual recorder events; transport/operator/runtime joins required"}


def measured_latency_summary(samples_ns):
    """Report actual nearest-rank percentiles without filling missing samples."""
    values = sorted(_unsigned(value) for value in samples_ns)
    if not values:
        return {"samples": 0, "p95Ns": None, "p99Ns": None}
    rank = lambda percent: values[(len(values) * percent + 99) // 100 - 1]
    return {"samples": len(values), "p95Ns": rank(95), "p99Ns": rank(99)}


def whole_issuer_cpu_fraction(cpu_ns, elapsed_ns, allocated_millicores):
    """Normalize observed process CPU only against an actual captured allocation."""
    if cpu_ns is None:
        return None
    _unsigned(cpu_ns)
    if _unsigned(elapsed_ns) == 0 or _unsigned(allocated_millicores) == 0:
        raise ValueError("CPU interval or captured allocation is absent")
    value = Fraction(cpu_ns * 1000, elapsed_ns * allocated_millicores)
    return {"numerator": value.numerator, "denominator": value.denominator,
        "scope": "whole dedicated process CPU; not CPU per signature"}
