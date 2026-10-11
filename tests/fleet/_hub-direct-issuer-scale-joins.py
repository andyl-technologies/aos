"""Join actual lease-scale transports and acknowledged issuer work.

Raw private files remain the evidence. These projections identify offered work,
real issuer attempts and actual completed replies separately. They cannot grant
permission, authenticate an issuer signature or replace final process custody.
"""

from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path


SCALE_DISPATCH_FIELDS = {"event", "version", "sourceDigest", "runId", "isolateLabel",
    "configurationDigest", "cohortDigest", "ownerNonce", "requestSha256",
    "requestBytes", "issuedAt", "expiresAt"}
SCALE_CAPTURE_LIMIT = 262144


def scale_dispatch_events(text, selected):
    """Select real pre-Fetch events from complete retained process log windows."""
    if len(text.encode()) > 256 * 1024 * 1024:
        raise ValueError("scale process log exceeds its retained bound")
    selected = {(row["isolateLabel"], row["configurationDigest"]): row for row in selected}
    if len(selected) != 4:
        raise ValueError("scale requires four independently selected process contexts")
    events, nonces = [], set()
    for line in text.splitlines():
        if "aos_lease_scale_measurement_incomplete" in line:
            raise ValueError("actual issuer observation context was incomplete")
        marker = line.find('{"event":"aos_lease_scale_issuer_dispatch"')
        if marker < 0:
            continue
        row = json.loads(line[marker:], object_pairs_hook=_closed_object)
        if set(row) != SCALE_DISPATCH_FIELDS or type(row["version"]) is not int or row["version"] != 1:
            raise ValueError("issuer dispatch observation shape differs")
        context = selected.get((row["isolateLabel"], row["configurationDigest"]))
        if context is None or any(row[name] != context[name] for name in ("runId", "sourceDigest")):
            raise ValueError("issuer dispatch belongs to another selected process")
        for name in ("ownerNonce", "cohortDigest", "requestSha256"):
            _digest(row[name])
        if (row["cohortDigest"] not in context["cohortDigests"]
                or row["ownerNonce"] in nonces or len(events) >= SCALE_CAPTURE_LIMIT):
            raise ValueError("issuer owner original is reused or outside selected cohorts")
        for name in ("requestBytes", "issuedAt", "expiresAt"):
            _unsigned(row[name])
        if not 0 < row["requestBytes"] <= 65536 or not 0 < row["expiresAt"] - row["issuedAt"] <= 30:
            raise ValueError("issuer owner original exceeded its immutable budget")
        nonces.add(row["ownerNonce"])
        events.append(row)
    return events


def scale_native_request_details(path, selected):
    """Retain per-original actual sign and commit events after closed-file checks."""
    summary = collect_local_issuer_observations(path, selected)
    source, before = _private_file(path)
    details = {nonce: {**row, "signatures": [], "commits": []}
        for nonce, row in summary["requests"].items()}
    with source:
        for line in source:
            row = json.loads(line, object_pairs_hook=_closed_object)
            if row["request"] is None:
                continue
            item = details[row["request"]["nonce"]]
            if row["event"] == "signature":
                item["signatures"].append(row["fields"])
            elif row["event"] == "transaction_commit":
                item["commits"].append(row["fields"])
        after = os.fstat(source.fileno())
    current = Path(path).stat(follow_symlinks=False)
    identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns)
    if identity(before) != identity(after) or identity(before) != identity(current):
        raise ValueError("closed Native observation changed during detailed projection")
    return {**summary, "requests": details}


def join_scale_issuer_calls(dispatches, captures, native, verified):
    """Correlate exact owner nonce and bytes across three independent boundaries.

    `verified` contains only outputs of the independently selected source-built
    shared Rust reply codec, with exact request/reply digests. This function does
    not implement cryptography, infer a missing signature or renew live authority.
    Capture refusals and unreceived attempts remain explicit error or unknown.
    """
    if any(len(rows) > SCALE_CAPTURE_LIMIT for rows in (dispatches, captures, verified)):
        raise ValueError("actual issuer call inventory exceeds its selected bound")
    by_nonce = {}
    for row in dispatches:
        if row["ownerNonce"] in by_nonce:
            raise ValueError("an owner issued twice inside the same original")
        by_nonce[row["ownerNonce"]] = row
    bodies, verification = defaultdict(list), defaultdict(list)
    for capture in captures:
        if capture["procedure"] != "/_aos/storage-authority/issuer/v1" or capture["method"] != "POST":
            raise ValueError("issuer corpus contains an unselected control route")
        request = capture["bodies"]["request"]
        if request is None:
            raise ValueError("issuer original was received without retained request bytes")
        bodies[(request["sha256"], request["byteSize"])].append(capture)
    for row in verified:
        verification[(row["requestSha256"], row["replySha256"])].append(row)
    result, used_ids, used_native, used_verified = [], set(), set(), set()
    for nonce, dispatch in by_nonce.items():
        matches = bodies.get((dispatch["requestSha256"], dispatch["requestBytes"]), [])
        if len(matches) > 1:
            raise ValueError("issuer original has ambiguous physical transport ownership")
        received = matches[0] if matches else None
        observed = native["requests"].get(nonce)
        item = {"ownerNonce": nonce, "dispatch": dispatch, "proxyRequestId": None,
            "outcome": "attempt_not_received", "verified": None, "native": observed}
        if observed is not None:
            pins = observed["pins"]
            if (pins["receivedBodySha256"] != dispatch["requestSha256"]
                    or pins["receivedBodyBytes"] != dispatch["requestBytes"]):
                raise ValueError("Native original differs from actual Worker attempt")
            used_native.add(nonce)
        if received is not None:
            used_ids.add(received["requestId"])
            item["proxyRequestId"] = received["requestId"]
            reply = received["bodies"]["response"]
            item["outcome"] = "received_reply_unknown"
            if received["status"] == 200 and reply is not None:
                matches = verification.get((dispatch["requestSha256"], reply["sha256"]), [])
                if len(matches) != 1:
                    raise ValueError("positive physical reply has no exclusive independent codec verification")
                checked = matches[0]
                if (checked["ownerNonce"] != nonce or checked["requestBytes"] != dispatch["requestBytes"]
                        or checked["replyBytes"] != reply["byteSize"]
                        or checked["cohortDigest"] != dispatch["cohortDigest"]):
                    raise ValueError("verified physical reply belongs to another original")
                used_verified.add((checked["requestSha256"], checked["replySha256"]))
                if observed is None or observed["outcome"] != "success":
                    raise ValueError("positive reply has no actual successful Native completion")
                lease_signs = [row for row in observed["signatures"] if row["purpose"] == "lease"]
                reply_signs = [row for row in observed["signatures"] if row["purpose"] == "reply"]
                commits = [row for row in observed["commits"] if row["kind"] == "lease"]
                if (len(lease_signs) != 1 or len(reply_signs) != 1 or len(commits) != 1
                        or commits[0]["outcome"] != "acknowledged"):
                    raise ValueError("positive issuance lacks exact signature and acknowledged lease commit")
                item.update(outcome="verified_acknowledged_issuance", verified=checked)
            elif received["status"] >= 400:
                item["outcome"] = "received_refusal"
        result.append(item)
    if used_ids != {row["requestId"] for row in captures} or used_native != set(native["requests"]):
        raise ValueError("actual received or Native request inventory has no unique pre-Fetch original")
    if used_verified != {(row["requestSha256"], row["replySha256"]) for row in verified}:
        raise ValueError("independent codec output has no exclusive actual transport")
    return {"calls": result, "actualAttempts": len(dispatches), "actualReceived": len(captures),
        "outcomes": dict(Counter(row["outcome"] for row in result)), "qualification": None}


def scale_wave_rpc_facts(rows, wave, joined):
    """Join a full offered wave to actual tokens and distinguish misses from reuse."""
    if len(rows) != 4224 or len({row["original"]["nonce"] for row in rows}) != 4224:
        raise ValueError("actual wave omitted or reused offered originals")
    if any(row["wave"] != wave for row in rows):
        raise ValueError("retained wave contains another original phase")
    lower = min(row["startedUnixNs"] for row in rows)
    upper = max(row["completedUnixNs"] for row in rows)
    issued = [row for row in joined["calls"] if row["verified"] is not None]
    # A nonce cannot be derived from a probe caller's nonce: the coalescer has its
    # own immutable issuer owner. Exact signed-token digest links both records.
    known_tokens = {row["verified"]["leaseDigest"]: row for row in issued}
    if len(known_tokens) != len(issued):
        raise ValueError("one actual issuance token has ambiguous owner identity")
    counts, unresolved, misses, reuse, ambiguous = Counter(), 0, set(), set(), set()
    for row in rows:
        if row["outcome"] != "authenticated_probe_metadata":
            unresolved += 1
            continue
        reply = row["reply"]
        item = known_tokens.get(reply["leaseDigest"])
        if item is None:
            raise ValueError("positive probe token has no independently verified actual issuance")
        selected = item["dispatch"]
        if (selected["isolateLabel"] != row["isolateLabel"]
                or selected["cohortDigest"] != row["original"]["cohort_digest"]
                or item["verified"]["issuedAt"] != reply["issuedAt"]
                or item["verified"]["notAfter"] != reply["notAfter"]
                or item["verified"]["leaseSequence"] != reply["leaseSequence"]):
            raise ValueError("probe token differs from exact source/cohort/issuer original")
        owner = selected["ownerNonce"]
        counts[(row["isolateLabel"], selected["cohortDigest"], owner)] += 1
        if lower // 10**9 < selected["issuedAt"] <= upper // 10**9:
            misses.add(owner)
        elif selected["issuedAt"] == lower // 10**9:
            # Issuer seconds cannot order two calls inside the same second.
            ambiguous.add(owner)
        elif item["verified"]["issuedAt"] < lower // 10**9:
            reuse.add(owner)
        else:
            raise ValueError("token appears after its consuming wave")
    attempts = [item for item in joined["calls"]
        if lower // 10**9 <= item["dispatch"]["issuedAt"] <= upper // 10**9]
    return {"wave": wave, "offeredRequests": len(rows), "unresolvedRequests": unresolved,
        "actualAttemptsInBracket": len(attempts), "newOwnerTokensConsumed": len(misses),
        "retainedOwnerTokensConsumed": len(reuse),
        "boundaryAmbiguousOwnerTokensConsumed": len(ambiguous),
        "coalescedConsumers": [{"isolateLabel": isolate, "cohortDigest": cohort,
            "ownerNonce": owner, "positiveConsumers": number} for (isolate, cohort, owner), number in sorted(counts.items())],
        "qualification": None, "scope": "actual token/owner joins; no inferred cache-hit rate from HTTP200"}


def scale_budget_facts(joined, native, allocated_millicores):
    """Compare measured whole-process and actual cold/warm issuer sample budgets."""
    classes = {"cold": [], "warm": []}
    seen, missing = set(), Counter()
    for row in sorted(joined["calls"], key=lambda row: row["dispatch"]["issuedAt"]):
        if row["outcome"] != "verified_acknowledged_issuance":
            continue
        identity = (row["dispatch"]["isolateLabel"], row["dispatch"]["cohortDigest"])
        kind = "warm" if identity in seen else "cold"
        seen.add(identity)
        sample = row["native"]["wallNs"]
        if sample is not None:
            classes[kind].append(sample)
        else:
            missing[kind] += 1
    latency = {name: measured_latency_summary(samples) for name, samples in classes.items()}
    cpu = whole_issuer_cpu_fraction(native["wholeProcessCpuNs"], native["wholeProcessWindowWallNs"], allocated_millicores)
    latency_ok = all(value["samples"] and value["p95Ns"] < LOCAL_LEASE_SCALE_POLICY[name + "P95NsExclusive"]
        and value["p99Ns"] < LOCAL_LEASE_SCALE_POLICY[name + "P99NsExclusive"] for name, value in latency.items())
    latency_ok = None if missing or any(not value["samples"] for value in latency.values()) else bool(latency_ok)
    cpu_ok = None if cpu is None else cpu["numerator"] * 2 <= cpu["denominator"]
    return {"latency": latency, "missingLatencySamples": dict(missing),
        "wholeIssuerCpu": cpu, "latencyBudgetSatisfied": latency_ok,
        "wholeIssuerCpuBudgetSatisfied": cpu_ok,
        "wholeIssuerCpuScope": "serving-window average including TTL waits and outage; not loaded CPU budget",
        "missingSigningCpuSamples": native["missingSigningCpuSamples"],
        "queueWaitNs": [row["queueWaitNs"] for row in native["requests"].values()],
        "commits": native["commits"], "signatures": native["signatures"],
        "qualification": None, "scope": "local measured policy only; allocation/process/window custody required"}


def _scale_loaded_cpu_wave(interval, rows, records, issuer, workload):
    """Join raw endpoints to the exact offered originals before bounding CPU."""
    if len(rows) != 4224 or len({row["original"]["nonce"] for row in rows}) != 4224:
        raise ValueError("CPU interval has incomplete offered originals")
    offered = [{name: row[name] for name in ("original", "isolateLabel", "offeredIndex", "wave")} for row in rows]
    encode = lambda value: json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
    digest = hashlib.sha256(encode(offered)).hexdigest()
    if digest != interval["waveOriginalsSha256"] or any(row["wave"] != interval["wave"] for row in rows):
        raise ValueError("CPU interval substituted its retained wave")
    for row in rows:
        body = encode(row["original"])
        if row["requestSha256"] != hashlib.sha256(body).hexdigest() or row["requestBodyBytesOffered"] != len(body):
            raise ValueError("CPU wave request bytes differ from their originals")
    identity_fields = {"pid", "ownerUid", "startTicks", "arguments", "executable", "executableSha256"}
    allocation_fields = {"affinityCpus", "cgroupCpuQuotaMillicores", "allocatedMillicores", "cgroupQuotaObservations"}
    actual_workload = interval["workloadProcess"]
    if set(actual_workload) != identity_fields or any(actual_workload[name] != workload[name] for name in actual_workload):
        raise ValueError("CPU wave workload lifetime changed")
    source = interval["start"]["original"]
    if any(row["original"]["source_digest"] != source["sourceDigest"]
            or row["original"]["run_id"] != source["runId"] for row in rows):
        raise ValueError("CPU interval source or run differs from its actual requests")
    for phase in ("start", "end"):
        acknowledgment = interval[phase]
        if sum(record == acknowledgment for record in records) != 1:
            raise ValueError("CPU endpoint has no independent singleton raw acknowledgment")
        original = acknowledgment["original"]
        if (original["phase"] != phase or original["wave"] != interval["wave"]
                or original["waveOriginalsSha256"] != digest
                or original["issuerProcessSha256"] != hashlib.sha256(encode(issuer)).hexdigest()
                or original["issuerPid"] != issuer["pid"] or original["issuerStartTicks"] != issuer["startTicks"]
                or original["workloadPid"] != workload["pid"] or original["workloadStartTicks"] != workload["startTicks"]
                or any(original[name] != source[name] for name in ("runId", "sourceDigest"))
                or original["runId"] != issuer["runId"] or original["runId"] != workload["runId"]):
            raise ValueError("CPU endpoint substituted original process, source or configuration")
    if (interval["end"]["original"]["sequence"] != source["sequence"] + 1
            or source["sequence"] % 2 or source["nonce"] == interval["end"]["original"]["nonce"]):
        raise ValueError("CPU endpoint ordering or nonce differs")
    a, b = interval["start"]["sample"], interval["end"]["sample"]
    if a.get("outcome") != "observed" or b.get("outcome") != "observed":
        raise ValueError("CPU endpoint unavailable, including issuer outage")
    for sample in (a, b):
        if (set(sample["process"]) != identity_fields or set(sample["allocation"]) != allocation_fields
                or any(sample["process"][name] != issuer[name] for name in sample["process"])
                or sample["selectedFiles"] != issuer["selectedFiles"]
                or any(sample["allocation"][name] != issuer[name] for name in sample["allocation"])):
            raise ValueError("CPU endpoint allocation, inputs or process changed")
        for field in ("userTicks", "systemTicks", "ticksPerSecond", "monotonicBeforeNs", "monotonicAfterNs", "utcBeforeNs", "utcAfterNs"):
            if type(sample[field]) is not int or not 0 <= sample[field] < 2**64:
                raise ValueError("CPU endpoint counter or clock is invalid")
        if sample["monotonicBeforeNs"] > sample["monotonicAfterNs"] or sample["utcBeforeNs"] > sample["utcAfterNs"]:
            raise ValueError("CPU endpoint clock bracket reversed")
    for field in ("startedUnixNs", "completedUnixNs", "monotonicStartNs", "monotonicEndNs", "monotonicResolutionNs"):
        if type(interval[field]) is not int or not 0 < interval[field] < 2**64:
            raise ValueError("offered wave clock is invalid")
    if (source["requestedUnixNs"] > interval["startedUnixNs"]
            or interval["end"]["original"]["requestedUnixNs"] < interval["completedUnixNs"]
            or interval["startedUnixNs"] > interval["completedUnixNs"]
            or any(not interval["startedUnixNs"] <= row["startedUnixNs"] <= row["completedUnixNs"] <= interval["completedUnixNs"] for row in rows)
            or a["monotonicAfterNs"] > b["monotonicBeforeNs"]):
        raise ValueError("actual samples do not bracket the complete offered wave")
    hz = a["ticksPerSecond"]
    if hz <= 0 or hz != b["ticksPerSecond"] or any(b[name] < a[name] for name in ("userTicks", "systemTicks")):
        raise ValueError("CPU counters regressed or clock frequency changed")
    ticks = b["userTicks"] + b["systemTicks"] - a["userTicks"] - a["systemTicks"]
    # Two separately rounded process counters permit two ticks of uncertainty.
    upper_cpu = ((ticks + 2) * 1_000_000_000 + hz - 1) // hz
    lower_wall = interval["monotonicEndNs"] - interval["monotonicStartNs"] - 2 * interval["monotonicResolutionNs"]
    allocation = issuer["allocatedMillicores"]
    if lower_wall <= 0 or type(allocation) is not int or allocation <= 0:
        raise ValueError("offered duration or allocation has no positive lower bound")
    numerator, denominator = upper_cpu * 1000, lower_wall * allocation
    return {"wave": interval["wave"], "outcome": "observed", "actualDeltaTicks": ticks,
        "ticksPerSecond": hz, "cpuUpperBoundNs": upper_cpu, "offeredDurationLowerBoundNs": lower_wall,
        "allocatedMillicores": allocation, "normalizedUpperBound": {"numerator": numerator, "denominator": denominator},
        "loadedCpuBudgetSatisfied": numerator * 2 <= denominator,
        "waveOriginalsSha256": digest, "qualification": None}


def scale_loaded_cpu_facts(intervals, waves, records, issuer, workload):
    """Retain missing wave CPU as unknown; never substitute serving-window CPU."""
    if len(intervals) > 16 or len(records) > 32 or len(waves) > 16:
        raise ValueError("CPU evidence exceeds its fixed bounded workload")
    names = [name for name, _ in waves]
    if len(set(names)) != len(names) or len({row["wave"] for row in intervals}) != len(intervals):
        raise ValueError("CPU wave identity was reused")
    if any(row["wave"] not in names for row in intervals):
        raise ValueError("CPU evidence belongs to an unoffered wave")
    results = []
    for name, rows in waves:
        interval = next((row for row in intervals if row["wave"] == name), None)
        try:
            if interval is None:
                raise ValueError("CPU wave endpoints absent")
            result = _scale_loaded_cpu_wave(interval, rows, records, issuer, workload)
        except (KeyError, TypeError, ValueError) as error:
            result = {"wave": name, "outcome": "unknown", "reason": str(error),
                "loadedCpuBudgetSatisfied": None, "qualification": None}
        results.append(result)
    complete = bool(results) and all(row["loadedCpuBudgetSatisfied"] is not None for row in results)
    return {"waves": results, "loadedCpuBudgetSatisfied": all(row["loadedCpuBudgetSatisfied"] for row in results) if complete else None,
        "qualification": None, "scope": "actual offered-wave process CPU upper bound; no per-signature CPU or peak/headroom claim"}


SCALE_POSITIVE_PHASES = ("cold", "reuse-candidate", "renewal-candidate-1", "renewal-candidate-2")


def _scale_policy_originals(waves, contexts, cohorts):
    """Check the complete fixed fanout against independently selected contexts."""
    selected = {row["isolateLabel"]: row for row in contexts}
    if len(contexts) != 4 or len(selected) != 4 or len(cohorts) != 32 or len(set(cohorts)) != 32:
        raise ValueError("policy inventory has no exact four-process/thirty-two-cohort selection")
    expected = {(label, cohort, index) for label in selected for cohort in cohorts for index in range(33)}
    nonces, previous_end = set(), 0
    for name, rows in waves:
        groups = set()
        if len(rows) != 4224:
            raise ValueError("policy wave omitted offered outcomes")
        for row in rows:
            original = row["original"]
            context = selected[row["isolateLabel"]]
            if type(row["offeredIndex"]) is not int or any(type(original[key]) is not int or original[key] < 0
                    for key in ("version", "issued_at", "expires_at")):
                raise ValueError("policy original integer shape differs")
            _digest(original["nonce"])
            identity = (row["isolateLabel"], original["cohort_digest"], row["offeredIndex"])
            if identity not in expected or identity in groups or original["nonce"] in nonces:
                raise ValueError("policy original is reused or outside the fixed fanout")
            body = json.dumps(original, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
            if (row["wave"] != name or original["version"] != 1
                    or original["run_id"] != context["runId"] or original["source_digest"] != context["sourceDigest"]
                    or original["configuration_digest"] != context["configurationDigest"]
                    or row["requestSha256"] != hashlib.sha256(body).hexdigest()
                    or row["requestBodyBytesOffered"] != len(body)
                    or original["expires_at"] - original["issued_at"] != 30
                    or not previous_end <= row["startedUnixNs"] <= row["completedUnixNs"]):
                raise ValueError("policy source, bytes, original window or phase ordering differs")
            groups.add(identity)
            nonces.add(original["nonce"])
        if groups != expected:
            raise ValueError("policy wave lost selected cohort/follower coverage")
        previous_end = max(row["completedUnixNs"] for row in rows)


def _scale_policy_cpu(name, rows, loaded_cpu):
    """Assess the existing independently joined upper bound for one required wave."""
    matches = [row for row in loaded_cpu["waves"] if row["wave"] == name]
    if len(matches) != 1 or matches[0]["outcome"] != "observed":
        return None
    fact = matches[0]
    offered = [{field: row[field] for field in ("original", "isolateLabel", "offeredIndex", "wave")} for row in rows]
    digest = hashlib.sha256(json.dumps(offered, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()).hexdigest()
    bound = fact["normalizedUpperBound"]
    if fact["waveOriginalsSha256"] != digest or any(type(bound[key]) is not int or bound[key] <= 0 for key in ("numerator", "denominator")):
        raise ValueError("required CPU wave does not join its actual offered originals")
    passed = bound["numerator"] * 2 <= bound["denominator"]
    if fact["loadedCpuBudgetSatisfied"] is not passed:
        raise ValueError("CPU summary differs from its actual conservative bound")
    return passed


def scale_case_policy_assessment(case, waves, contexts, cohorts, joined, native,
                                 loaded_cpu, transport, issuer, terminal,
                                 attestation_until, evidence):
    """Assess the authored local schedule without rewriting raw aggregate facts.

    Inputs are existing retained collectors and their actual selected originals,
    never an authentication or dispatch entry point. Outage CPU remains unknown;
    it is not substituted for required positive or live cap CPU. Missing evidence
    cannot satisfy local completion, and this result confers no live authority.
    """
    requirements = []

    def requirement(name, value, reference):
        requirements.append({"name": name, "status": "unknown" if value is None else "satisfied" if value else "failed",
            "evidence": reference})

    try:
        if case not in {"ttl-8", "ttl-120", "cap-120"} or not 0 < len(waves) <= 16:
            raise ValueError("policy case or bounded phase inventory differs")
        names = [name for name, _ in waves]
        lifetime = 8 if case == "ttl-8" else 120
        if case == "cap-120":
            positive = ("cap-candidate",)
            scheduled = names == ["cap-candidate", "cap-expired"]
        else:
            positive = SCALE_POSITIVE_PHASES
            outage_count = len(names) - len(positive)
            scheduled = (1 <= outage_count <= (lifetime + 29) // 30 + 2
                and names == list(positive) + [f"outage-{index:02d}" for index in range(outage_count)])
        requirement("fixed phase schedule", scheduled, evidence["waves"])
        if not scheduled:
            raise ValueError("actual phase order differs from authored positive/negative schedule")
        _scale_policy_originals(waves, contexts, cohorts)
        requirement("complete original fanout and source joins", True, evidence["waves"])
        if (terminal != transport["issuerTerminalReceipt"] or terminal["pid"] != issuer["pid"]
                or terminal["startTicks"] != issuer["startTicks"] or terminal["exitCode"] != 0
                or terminal["resourceRoot"] != issuer["processRoot"]):
            raise ValueError("issuer terminal does not join its exact selected lifetime")
        stopped_at = terminal["completedUnixNs"]
        by_name = dict(waves)
        known = {row["verified"]["leaseDigest"]: row for row in joined["calls"] if row["verified"] is not None}
        if len(known) != sum(row["verified"] is not None for row in joined["calls"]):
            raise ValueError("signed issuance has ambiguous token ownership")
        previous = None
        for name in positive:
            rows = by_name[name]
            complete = all(row["outcome"] == "authenticated_probe_metadata" and row["httpStatus"] == 200 for row in rows)
            requirement(name + " positive outcomes", complete, evidence["waves"] + "#" + name)
            if not complete:
                raise ValueError("required positive phase contains refused or unresolved calls")
            # Reuse the existing exact Core-token/owner/process/cohort correlation.
            scale_wave_rpc_facts(rows, name, joined)
            groups = defaultdict(list)
            for row in rows:
                reply = row["reply"]
                original = row["original"]
                pins = {"version": 1, "runId": original["run_id"], "nonce": original["nonce"],
                    "requestSha256": row["requestSha256"], "sourceDigest": original["source_digest"],
                    "configurationDigest": original["configuration_digest"], "cohortDigest": original["cohort_digest"],
                    "isolateLabel": row["isolateLabel"]}
                if any(reply[key] != value for key, value in pins.items()):
                    raise ValueError("actual probe reply belongs to another offered original")
                if (reply["maximumLifetime"] != lifetime or reply["clockUncertainty"] != 2
                        or reply["attestationValidUntil"] != attestation_until
                        or reply["notAfter"] > attestation_until
                        or row["completedUnixNs"] // 10**9 + 2 >= min(reply["notAfter"], row["original"]["expires_at"])):
                    raise ValueError("positive token exceeds selected cap or actual consumption cutoff")
                groups[(row["isolateLabel"], row["original"]["cohort_digest"])].append(reply)
            if name.startswith("renewal-"):
                requirement(name + " actual replacement", all(min(row["issuedAt"] for row in replies)
                    > max(row["issuedAt"] for row in previous[identity]) for identity, replies in groups.items()), evidence["waves"] + "#" + name)
            previous = groups
            requirement(name + " loaded CPU <=50%", _scale_policy_cpu(name, rows, loaded_cpu), evidence["measurement"] + "#loadedCpu/" + name)
            requirement(name + " issuer still live", max(row["completedUnixNs"] for row in rows) < stopped_at, evidence["measurement"] + "#issuerTerminal")

        # Budget classes follow all actual acknowledged positive issuer work,
        # including an issued token not consumed by a probe. Negative transport
        # observations remain raw; none can supply a latency or CPU zero.
        calls = [row for row in joined["calls"] if row["verified"] is not None]
        required_native = [row["native"] for row in calls]
        missing_sign = sum(signature.get("threadCpuNs") is None or signature.get("wallNs") is None
            for row in required_native for signature in row["signatures"])
        selected_native = {**native, "requests": {row["ownerNonce"]: row["native"] for row in calls},
            "missingSigningCpuSamples": missing_sign}
        budgets = scale_budget_facts({"calls": calls}, selected_native, issuer["allocatedMillicores"])
        for kind in (("cold",) if case == "cap-120" else ("cold", "warm")):
            latency = budgets["latency"][kind]
            passed = None if not latency["samples"] or budgets["missingLatencySamples"].get(kind) else (
                latency["p95Ns"] < LOCAL_LEASE_SCALE_POLICY[kind + "P95NsExclusive"]
                and latency["p99Ns"] < LOCAL_LEASE_SCALE_POLICY[kind + "P99NsExclusive"])
            requirement(kind + " actual issuer latency", passed, evidence["measurement"] + "#dispatchAndIssuerCalls")
        requirement("positive signing CPU/wall and queue samples", None if missing_sign or any(row["queueWaitNs"] is None for row in required_native) else True,
            evidence["measurement"] + "#dispatchAndIssuerCalls")
        requirement("positive acknowledged issuance commits", all(row["outcome"] == "verified_acknowledged_issuance"
            and len([commit for commit in row["native"]["commits"] if commit["kind"] == "lease" and commit["outcome"] == "acknowledged"]) == 1 for row in calls),
            evidence["measurement"] + "#dispatchAndIssuerCalls")

        if case == "cap-120":
            initial, final = by_name["cap-candidate"], by_name["cap-expired"]
            requirement("selected attestation cap", all(row["reply"]["notAfter"] == attestation_until
                and row["reply"]["issuedAt"] < attestation_until < row["reply"]["issuedAt"] + 120 for row in initial), evidence["publication"])
            requirement("cap-expired loaded CPU <=50%", _scale_policy_cpu("cap-expired", final, loaded_cpu), evidence["measurement"] + "#loadedCpu/cap-expired")
            requirement("cap-expired issuer still live", max(row["completedUnixNs"] for row in final) < stopped_at, evidence["measurement"] + "#issuerTerminal")
            boundary = attestation_until
        else:
            final = waves[-1][1]
            boundary = max(row["reply"]["notAfter"] for row in by_name["renewal-candidate-2"])
            outage_rows = [row for name, rows in waves if name.startswith("outage-") for row in rows]
            requirement("issuer stopped before outage originals", all(stopped_at <= row["startedUnixNs"]
                and row["original"]["issued_at"] >= stopped_at // 10**9 for row in outage_rows), evidence["measurement"] + "#issuerTerminal")
            # Before expiry, retained positive tokens are permitted, but their
            # real owner joins remain required. Unknown transport stays raw.
            for name, rows in waves[len(positive):]:
                scale_wave_rpc_facts(rows, name, joined)
        requirement("final originals beyond actual expiry", all(row["original"]["issued_at"] >= boundary + 1 for row in final), evidence["waves"] + "#" + names[-1])
        requirement("final complete HTTP refusals", all(row["outcome"] == "http_refused" and type(row["httpStatus"]) is int
            and 400 <= row["httpStatus"] <= 599 for row in final), evidence["waves"] + "#" + names[-1])
    except (KeyError, IndexError, TypeError, ValueError) as error:
        requirement("complete policy evidence", None, str(error))
    states = {row["status"] for row in requirements}
    status = "failed" if "failed" in states else "unknown" if "unknown" in states else "satisfied"
    return {"case": case, "status": status, "requirements": requirements,
        "qualification": None, "scope": "scheduled local measurement assessment only; raw outage/aggregate unknowns retained"}
