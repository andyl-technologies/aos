"""Transport exact local scale originals without retry or fabricated metrics.

The workload has four selected workerd listeners and exactly32 configured
cohorts. Each full wave submits one owner plus32 potential followers per cohort
per process. Those are offered requests, not observed issuer RPCs or cache hits.
Issuer signing/commit/CPU evidence comes from the separate actual recorder.
"""

import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat
import time


PATH = "/__hub/lease-scale-acquire"
SIGNATURE_HEADER = "x-aos-lease-scale-signature"
REQUEST_DOMAIN = b"aos-storage-work-v1\0aos-local-lease-scale-request-v1\0"
REPLY_DOMAIN = b"aos-storage-work-v1\0aos-local-lease-scale-reply-v1\0"
MAX_BODY = 4096
MAX_HEADERS = 16 * 1024
MAX_WAVE_CALLS = 4 * 32 * 33
REPLY_FIELDS = {"version", "runId", "isolateLabel", "nonce", "requestSha256",
    "sourceDigest", "configurationDigest", "cohortDigest", "leaseDigest",
    "leaseSequence", "issuedAt", "notAfter", "attestationValidUntil",
    "maximumLifetime", "clockUncertainty", "observedAt"}


def _hex(value, length):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value):
        raise ValueError("selected scale context differs")
    return value


def _json(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()


def _closed(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("duplicate scale reply field")
        value[name] = item
    return value


def plan_scale_wave(run_id, source_digest, workers, cohort_digests, issued_at,
                    label, maximum_lifetime):
    """Prepare the complete declared wave; returned counts are offered only."""
    _hex(run_id, 32)
    _hex(source_digest, 64)
    if len(workers) != 4 or len(cohort_digests) != 32 or len(set(cohort_digests)) != 32:
        raise ValueError("scale wave requires four processes and thirty-two cohorts")
    if type(issued_at) is not int or issued_at <= 0 or maximum_lifetime not in {8, 120}:
        raise ValueError("scale wave clock or selected policy differs")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,47}", label):
        raise ValueError("wave label differs")
    endpoints, labels = set(), set()
    for worker in workers:
        if set(worker) != {"host", "port", "isolateLabel", "configurationDigest", "transport"}:
            raise ValueError("selected Worker endpoint differs")
        if not ipaddress.ip_address(worker["host"]).is_loopback or ":" in worker["host"]:
            raise ValueError("this local workload requires selected IPv4 loopback listeners")
        if type(worker["port"]) is not int or not 1 <= worker["port"] <= 65535:
            raise ValueError("selected Worker port differs")
        endpoint = (worker["host"], worker["port"])
        if endpoint in endpoints or _hex(worker["isolateLabel"], 32) in labels:
            raise ValueError("four fresh process listeners and labels must be distinct")
        endpoints.add(endpoint)
        labels.add(worker["isolateLabel"])
        _hex(worker["configurationDigest"], 64)
        _transport_context(worker["transport"])
    for cohort in cohort_digests:
        _hex(cohort, 64)

    calls = []
    for worker in workers:
        for cohort in cohort_digests:
            for offered_index in range(33):
                original = {"version": 1, "run_id": run_id, "nonce": os.urandom(32).hex(),
                    "source_digest": source_digest, "configuration_digest": worker["configurationDigest"],
                    "cohort_digest": cohort, "issued_at": issued_at, "expires_at": issued_at + 30}
                calls.append({"original": original, "worker": json.loads(_json(worker)),
                    "offeredIndex": offered_index, "wave": label, "maximumLifetime": maximum_lifetime})
    return calls


def _transport_context(transport):
    """Retain selected local TLS trust bytes rather than ambient host trust."""
    if transport == {"kind": "loopback_http"}:
        return None, None
    if (not isinstance(transport, dict) or set(transport) != {"kind", "certificateFile", "certificateSha256", "serverName"}
            or transport["kind"] != "tls" or not isinstance(transport["serverName"], str)
            or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", transport["serverName"])):
        raise ValueError("selected local transport differs")
    _hex(transport["certificateSha256"], 64)
    path = Path(transport["certificateFile"])
    if not path.is_absolute() or path.parent.resolve() != path.parent:
        raise ValueError("selected CA path differs")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > 128 * 1024:
            raise ValueError("selected CA exceeds its bound")
        data = source.read(128 * 1024 + 1)
        after = os.fstat(source.fileno())
    identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns)
    if (identity(before) != identity(after) or identity(before) != identity(path.stat(follow_symlinks=False))
            or hashlib.sha256(data).hexdigest() != transport["certificateSha256"]):
        raise ValueError("selected CA bytes changed")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=data.decode("ascii"))
    return context, transport["serverName"]


async def _read_response(reader):
    header = await reader.readuntil(b"\r\n\r\n")
    if len(header) > MAX_HEADERS:
        raise ValueError("scale response header bound exceeded")
    lines = header[:-4].split(b"\r\n")
    if not re.fullmatch(rb"HTTP/1\.[01] [0-9]{3}(?: [\x20-\x7e]*)?", lines[0]) or len(lines) > 64:
        raise ValueError("scale response framing differs")
    status = int(lines[0].split(b" ")[1])
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if not separator or not re.fullmatch(rb"[A-Za-z0-9-]+", name):
            raise ValueError("scale response header differs")
        name = name.decode().lower()
        if name in headers:
            raise ValueError("duplicate scale response header")
        headers[name] = value.strip().decode("ascii")
    if "content-length" in headers:
        if "transfer-encoding" in headers or not re.fullmatch(r"[0-9]+", headers["content-length"]):
            raise ValueError("scale response length differs")
        size = int(headers["content-length"])
        if size > MAX_BODY:
            raise ValueError("scale response body bound exceeded")
        body = await reader.readexactly(size)
    elif headers.get("transfer-encoding") == "chunked":
        body = bytearray()
        while True:
            line = await reader.readuntil(b"\r\n")
            if len(line) > 32 or not re.fullmatch(rb"[0-9a-fA-F]+\r\n", line):
                raise ValueError("scale chunk framing differs")
            size = int(line[:-2], 16)
            if size == 0:
                if await reader.readexactly(2) != b"\r\n":
                    raise ValueError("scale response trailers are unsupported")
                break
            if size > MAX_BODY - len(body):
                raise ValueError("scale response body bound exceeded")
            body.extend(await reader.readexactly(size))
            if await reader.readexactly(2) != b"\r\n":
                raise ValueError("scale chunk terminator differs")
        body = bytes(body)
    else:
        raise ValueError("scale response requires bounded framing")
    return status, headers, body, len(header)


def _correlate_reply(body, signature, key, call, request_sha):
    if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
        raise ValueError("scale response MAC absent")
    expected = hmac.new(key, REPLY_DOMAIN + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ValueError("scale response MAC differs")
    reply = json.loads(body, object_pairs_hook=_closed)
    original, worker = call["original"], call["worker"]
    if set(reply) != REPLY_FIELDS or type(reply["version"]) is not int or reply["version"] != 1:
        raise ValueError("scale response shape differs")
    pins = {"runId": original["run_id"], "isolateLabel": worker["isolateLabel"],
        "nonce": original["nonce"], "requestSha256": request_sha,
        "sourceDigest": original["source_digest"], "configurationDigest": original["configuration_digest"],
        "cohortDigest": original["cohort_digest"], "maximumLifetime": call["maximumLifetime"], "clockUncertainty": 2}
    if any(reply[name] != value for name, value in pins.items()):
        raise ValueError("scale response belongs to another original")
    _hex(reply["leaseDigest"], 64)
    times = {name: reply[name] for name in ("issuedAt", "notAfter", "attestationValidUntil", "observedAt", "leaseSequence")}
    if any(type(value) is not int or value < 0 or value > 2**64 - 1 for value in times.values()):
        raise ValueError("scale response timing shape differs")
    if (times["leaseSequence"] == 0 or not 0 < times["notAfter"] - times["issuedAt"] <= call["maximumLifetime"]
            or times["notAfter"] > times["attestationValidUntil"]
            or not original["issued_at"] <= times["observedAt"]
            or times["observedAt"] + 2 >= min(times["notAfter"], original["expires_at"])):
        raise ValueError("scale response exceeded its original measured window")
    return reply


async def exchange_scale_original(call, key):
    """Offer one original once and retain actual response or unknown failure."""
    if not isinstance(key, bytes) or not 32 <= len(key) <= 65536:
        raise ValueError("protected local fixture key differs")
    body = _json(call["original"])
    if len(body) > MAX_BODY:
        raise ValueError("scale request body bound exceeded")
    digest = hashlib.sha256(body).hexdigest()
    signature = hmac.new(key, REQUEST_DOMAIN + body, hashlib.sha256).hexdigest()
    worker = call["worker"]
    tls, server_name = _transport_context(worker["transport"])
    header = (f"POST {PATH} HTTP/1.1\r\nHost: {server_name or 'localhost'}\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n{SIGNATURE_HEADER}: {signature}\r\nConnection: close\r\n\r\n").encode()
    started_unix, started = time.time_ns(), time.monotonic_ns()
    writer = None
    result = {"version": 1, "wave": call["wave"], "original": call["original"],
        "isolateLabel": worker["isolateLabel"], "offeredIndex": call["offeredIndex"],
        "requestSha256": digest, "requestBodyBytesOffered": len(body), "requestHeaderBytesOffered": len(header),
        "requestWriteCompleted": False, "replyBodyBytesConsumed": None,
        "startedUnixNs": started_unix, "httpStatus": None, "reply": None, "outcome": "unknown"}
    try:
        async def perform():
            nonlocal writer
            reader, writer = await asyncio.open_connection(worker["host"], worker["port"],
                limit=MAX_HEADERS, ssl=tls, server_hostname=server_name)
            writer.write(header + body)
            await writer.drain()
            result["requestWriteCompleted"] = True
            status, headers, reply_body, header_bytes = await _read_response(reader)
            result.update({"httpStatus": status, "replyBodyBytesConsumed": len(reply_body),
                "replySha256": hashlib.sha256(reply_body).hexdigest(), "replyHeaderBytes": header_bytes})
            if status == 200:
                result["reply"] = _correlate_reply(reply_body, headers.get(SIGNATURE_HEADER), key, call, digest)
                result["outcome"] = "authenticated_probe_metadata"
            else:
                result["outcome"] = "http_refused"
        await asyncio.wait_for(perform(), timeout=35)
    except (ValueError, OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as error:
        result["errorKind"] = type(error).__name__
        # No retry and no claim about whether remote issuance committed.
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except (OSError, asyncio.TimeoutError):
                pass
        result.update({"completedUnixNs": time.time_ns(), "wallNs": time.monotonic_ns() - started,
            "issuerRpcCount": None, "nativeBulkBytes": None, "qualification": None})
    return result


async def run_scale_wave(calls, key):
    """Run a complete offered fanout with no smaller admission limiter."""
    if len(calls) != MAX_WAVE_CALLS or len({row["original"]["nonce"] for row in calls}) != MAX_WAVE_CALLS:
        raise ValueError("scale fanout must retain every unique offered original")
    return await asyncio.gather(*(exchange_scale_original(call, key) for call in calls))


def retain_scale_wave(path, results):
    """Retain actual outcomes under exclusive private bounded file custody."""
    path = Path(path)
    parent = path.parent.stat(follow_symlinks=False)
    if (not path.is_absolute() or path.parent.resolve() != path.parent
            or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) != 0o700 or len(results) != MAX_WAVE_CALLS):
        raise ValueError("wave output custody or complete inventory differs")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    count = 0
    with os.fdopen(descriptor, "wb") as output:
        for row in results:
            data = _json(row) + b"\n"
            if len(data) > 8192 or count + len(data) > 64 * 1024 * 1024:
                raise ValueError("actual wave output exceeds its bounded inventory")
            output.write(data)
            count += len(data)
        output.flush()
        os.fsync(output.fileno())
    return {"path": str(path), "rows": len(results), "byteSize": count,
        "qualification": None, "scope": "actual probe transport; issuer/process/operator joins required"}


def observed_wave(results, workers, cohort_digests):
    """Project actual positive probe metadata without inferring issuer fetches."""
    selected = {(worker["isolateLabel"], cohort) for worker in workers for cohort in cohort_digests}
    if len(results) != MAX_WAVE_CALLS or len({row["original"]["nonce"] for row in results}) != MAX_WAVE_CALLS:
        raise ValueError("actual wave omitted or reused an offered original")
    groups = {identity: [] for identity in selected}
    errors = {}
    for result in results:
        identity = (result["isolateLabel"], result["original"]["cohort_digest"])
        if identity not in groups:
            raise ValueError("actual wave includes an unselected process or cohort")
        if result["outcome"] == "authenticated_probe_metadata":
            groups[identity].append(result["reply"])
        else:
            errors[result["outcome"]] = errors.get(result["outcome"], 0) + 1
    return {"groups": groups, "errors": errors,
        "maximumNotAfter": max((reply["notAfter"] for group in groups.values() for reply in group), default=None),
        "completePositiveCoverage": all(groups.values()),
        "httpRefusalsOnly": all(row["outcome"] == "http_refused" and row["httpStatus"] >= 400 for row in results),
        "issuerRpcCount": None, "renewalCount": None, "qualification": None}


async def wait_actual_utc(target):
    """Wait for the selected real UTC boundary with a bounded monotonic guard."""
    remaining = target - time.time()
    if remaining <= 0:
        return
    if remaining > 3600:
        raise ValueError("actual selected boundary exceeds the fixture window")
    deadline = time.monotonic() + remaining + 2
    while time.time() < target:
        if time.monotonic() >= deadline:
            raise ValueError("actual fixture clock did not reach the selected boundary")
        await asyncio.sleep(min(1, max(0, target - time.time())))


async def run_scale_profile(run_id, source_digest, workers, cohort_digests,
                            maximum_lifetime, key, output_root, stop_issuer,
                            wait_until=wait_actual_utc):
    """Run the declared complete fanout, two renewals and outage through expiry.

    The caller starts four genuinely fresh selected processes and a separate
    genuine issuer store before this function. `stop_issuer` stops only that
    recorded issuer lifetime and returns its actual terminal receipt; it must
    leave the existing TLS proxy running. No process/store reset, publication,
    takeover or same-original retry is performed here. A returned candidate
    remains incomplete until independent dispatch/proxy/issuer evidence joins.
    """
    root = Path(output_root)
    if not root.is_absolute() or root.parent.resolve() != root.parent:
        raise ValueError("selected profile output custody differs")
    parent = root.parent.stat(follow_symlinks=False)
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) != 0o700):
        raise ValueError("selected profile parent is not private")
    # Validate every offered context before creating the exclusive run output.
    plan_scale_wave(run_id, source_digest, workers, cohort_digests,
        int(time.time()), "validation-only", maximum_lifetime)
    root.mkdir(mode=0o700, exist_ok=False)
    retained, renewal_candidates = [], []

    async def wave(label):
        originals = plan_scale_wave(run_id, source_digest, workers, cohort_digests,
            int(time.time()), label, maximum_lifetime)
        results = await run_scale_wave(originals, key)
        receipt = retain_scale_wave(root / (label + ".jsonl"), results)
        facts = observed_wave(results, workers, cohort_digests)
        retained.append({"wave": label, "receipt": receipt, "errors": facts["errors"],
            "offeredRequests": len(originals), "maximumNotAfter": facts["maximumNotAfter"]})
        return facts, max(row["original"]["expires_at"] for row in originals)

    current, _ = await wave("cold")
    if not current["completePositiveCoverage"]:
        terminal = await stop_issuer()
        return {"waves": retained, "issuerTerminalReceipt": terminal,
            "outcome": "incomplete_actual_probe_coverage", "qualification": None}
    reuse, _ = await wave("reuse-candidate")
    if not reuse["completePositiveCoverage"]:
        terminal = await stop_issuer()
        return {"waves": retained, "issuerTerminalReceipt": terminal,
            "outcome": "incomplete_actual_probe_coverage", "qualification": None}
    # An 8s token may miss the unchanged 5s margin. This phase is never called
    # a cache hit or warm issuer observation merely because it returned 200.
    current = reuse
    for index in range(2):
        await wait_until(current["maximumNotAfter"] + 1)
        renewed, _ = await wave(f"renewal-candidate-{index + 1}")
        if not renewed["completePositiveCoverage"]:
            terminal = await stop_issuer()
            return {"waves": retained, "issuerTerminalReceipt": terminal,
                "outcome": "incomplete_actual_probe_coverage", "qualification": None}
        if any(min(reply["issuedAt"] for reply in renewed["groups"][identity])
                <= max(reply["issuedAt"] for reply in previous)
                for identity, previous in current["groups"].items()):
            raise ValueError("actual renewal candidate reused the previous issued time")
        renewal_candidates.append(index + 1)
        current = renewed

    last_expiry = current["maximumNotAfter"]
    terminal = await stop_issuer()
    # A new original starts only beyond the preceding immutable 30s window.
    # This bound derives from the selected maximum lifetime and that unchanged
    # window, allowing a final observation beyond every retained token expiry.
    maximum_outage_waves = (maximum_lifetime + 29) // 30 + 2
    exhausted = False
    for index in range(maximum_outage_waves):
        issued = int(time.time())
        facts, original_expiry = await wave(f"outage-{index:02d}")
        if issued >= last_expiry + 1:
            exhausted = facts["httpRefusalsOnly"]
            break
        await wait_until(max(original_expiry + 1, last_expiry + 1)
            if index + 1 == maximum_outage_waves - 1 else original_expiry + 1)
    return {"waves": retained, "renewalCandidates": renewal_candidates,
        "issuerTerminalReceipt": terminal, "outageObservedBeyondActualExpiry": exhausted,
        "outcome": "candidate_transport_complete" if exhausted else "incomplete_outage",
        "issuerRpcCount": None, "signingCpuNs": None, "commits": None,
        "qualification": None, "scope": "actual probe metadata only; independent closed capture joins required"}


def observed_attestation_cap(facts):
    """Join actual returned expiries to their unchanged attestation bounds."""
    if not facts["completePositiveCoverage"]:
        return None
    replies = [reply for group in facts["groups"].values() for reply in group]
    if any(reply["maximumLifetime"] != 120 or reply["notAfter"] != reply["attestationValidUntil"]
            or not reply["issuedAt"] < reply["notAfter"] < reply["issuedAt"] + 120
            for reply in replies):
        raise ValueError("actual capped profile did not reach the selected attestation ceiling")
    return {"returnedReplies": len(replies), "minimumExpiry": min(reply["notAfter"] for reply in replies),
        "maximumExpiry": max(reply["notAfter"] for reply in replies),
        "qualification": None, "scope": "returned probe metadata; genuine export and signed issuer joins required"}


async def run_scale_cap(run_id, source_digest, workers, cohort_digests, key,
                        output_root, stop_issuer, wait_until=wait_actual_utc):
    """Offer the complete capped120 case, then observe beyond actual expiry."""
    root = Path(output_root)
    parent = root.parent.stat(follow_symlinks=False)
    if (not root.is_absolute() or root.parent.resolve() != root.parent
            or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) != 0o700):
        raise ValueError("capped run output custody differs")
    originals = plan_scale_wave(run_id, source_digest, workers, cohort_digests,
        int(time.time()), "cap-candidate", 120)
    root.mkdir(mode=0o700, exist_ok=False)
    replies = await run_scale_wave(originals, key)
    initial = retain_scale_wave(root / "cap-candidate.jsonl", replies)
    facts = observed_wave(replies, workers, cohort_digests)
    cap = observed_attestation_cap(facts)
    if cap is None:
        terminal = await stop_issuer()
        return {"initial": initial, "issuerTerminalReceipt": terminal,
            "outcome": "incomplete_cap", "qualification": None}
    await wait_until(max(cap["maximumExpiry"] + 1,
        max(row["original"]["expires_at"] for row in originals) + 1))
    expired_originals = plan_scale_wave(run_id, source_digest, workers, cohort_digests,
        int(time.time()), "cap-expired", 120)
    expired_replies = await run_scale_wave(expired_originals, key)
    expired = retain_scale_wave(root / "cap-expired.jsonl", expired_replies)
    expired_facts = observed_wave(expired_replies, workers, cohort_digests)
    # Transport errors do not prove the intended live authenticated refusal.
    refused = all(row["outcome"] == "http_refused" and row["httpStatus"] >= 400 for row in expired_replies)
    terminal = await stop_issuer()
    return {"initial": initial, "capMetadata": cap, "expired": expired,
        "issuerTerminalReceipt": terminal,
        "outcome": "cap_transport_candidate_complete" if refused else "incomplete_cap_refusal",
        "expiredErrors": expired_facts["errors"], "qualification": None}


async def run_selected_scale_cases(selections, prepare_case):
    """Call genuine setup and the complete8/120/capped120 workloads sequentially.

    The callback applies the reviewed normal API/operator setup and starts the
    actual selected fresh process tuple. It returns private runtime parameters;
    those supplied metadata are not independently authenticated evidence. The
    collector must join their actual exports, process lifetimes and transports.
    """
    if len(selections) != 3 or [row["case"] for row in selections] != ["ttl-8", "ttl-120", "cap-120"]:
        raise ValueError("selected workload must preserve both TTL runs and the separate cap")
    expected = [(8, False), (120, False), (120, True)]
    identities = set()
    for selected, (lifetime, capped) in zip(selections, expected):
        if selected["maximumLifetime"] != lifetime or selected["attestationCapped"] is not capped:
            raise ValueError("selected workload policy differs")
        identity = tuple(selected[name] for name in ("authorityId", "guardNamespaceId", "issuerStore", "physicalStore"))
        if any(any(old[index] == value for old in identities) for index, value in enumerate(identity)):
            raise ValueError("selected cases must use distinct authorities, namespaces and stores")
        identities.add(identity)
    outputs = []
    for selected in selections:
        prepared = await prepare_case(selected)
        identity = tuple(prepared[name] for name in ("authorityId", "guardNamespaceId", "issuerStore", "physicalStore"))
        if identity != tuple(selected[name] for name in ("authorityId", "guardNamespaceId", "issuerStore", "physicalStore")):
            raise ValueError("actual setup returned another selected authority, namespace or store")
        arguments = {name: prepared[name] for name in ("run_id", "source_digest", "workers", "cohort_digests", "key", "output_root")}
        if selected["attestationCapped"]:
            outcome = await run_scale_cap(**arguments, stop_issuer=prepared["stop_issuer"])
        else:
            outcome = await run_scale_profile(**arguments,
                maximum_lifetime=selected["maximumLifetime"], stop_issuer=prepared["stop_issuer"])
        outputs.append({"case": selected["case"], "authorityAndStores": identity, "result": outcome})
        if outcome["outcome"] not in {"candidate_transport_complete", "cap_transport_candidate_complete"}:
            break
    return {"cases": outputs, "qualification": None,
        "scope": "called actual transport workflow; independent source/process/operator/issuer joins pending"}
