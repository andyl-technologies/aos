"""Paired fresh-connection curl timing observations for the hybrid fleet.

Only selected cumulative curl fields, numeric Server-Timing spans and canonical
request IDs are retained. No response header dump, cookie or assertion is read.
Missing response spans remain missing: aggregate Worker logs cannot supply an
invented per-request association.
"""

import json
import math
import re
import statistics


# The first four fields preserve the prior fleet writeout order and gate inputs.
PAGE_PERF_WRITEOUT = (
    "%{time_starttransfer} %{http_code} %{time_connect} %{time_appconnect} "
    "%{time_namelookup} %{time_pretransfer} %{time_total} %{num_connects}"
    "|%header{server-timing}|%header{x-aos-request-id}|%header{x-request-id}\\n"
)

CURL_TIMING_FIELDS = (
    "time_starttransfer", "http_code", "time_connect", "time_appconnect",
    "time_namelookup", "time_pretransfer", "time_total", "num_connects",
)


def parse_page_observations(text, expected_count):
    """Validate and preserve timings, deriving phases within each request."""
    lines = text.splitlines()
    if len(lines) != expected_count:
        raise ValueError("unexpected page timing sample count")

    observations = []
    for sequence, line in enumerate(lines):
        if len(line) > 8192:
            raise ValueError("page timing observation exceeds bounds")
        sections = line.split("|")
        if len(sections) != 4:
            raise ValueError("invalid page timing observation")
        raw = sections[0].split()
        if len(raw) != len(CURL_TIMING_FIELDS):
            raise ValueError("invalid page cumulative timing fields")
        cumulative = dict(zip(CURL_TIMING_FIELDS, raw))
        if cumulative["http_code"] != "200" or cumulative["num_connects"] != "1":
            raise ValueError("fresh page probe requires one successful connection")

        names = (
            "time_namelookup", "time_connect", "time_appconnect",
            "time_pretransfer", "time_starttransfer", "time_total",
        )
        try:
            values = [float(cumulative[name]) for name in names]
        except ValueError:
            raise ValueError("invalid cumulative timing number") from None
        if not all(math.isfinite(value) and value >= 0 for value in values):
            raise ValueError("nonfinite or negative page timing")
        if any(left > right for left, right in zip(values, values[1:])):
            raise ValueError("page cumulative timings regressed")
        phase_names = (
            "dns", "tcp_after_dns", "tls_after_tcp", "pretransfer_after_tls",
            "ttfb_after_pretransfer", "response_after_ttfb",
        )
        phases = dict(zip(phase_names, [values[0]] + [
            right - left for left, right in zip(values, values[1:])
        ]))
        spans = parse_response_spans(sections[1])
        request_id = None
        for value in sections[2:]:
            if not value:
                continue
            if re.fullmatch(
                r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"
                r"|[0-9a-fA-F]{32}|fleet-[a-z0-9-]{1,100}", value,
            ):
                if request_id is not None and request_id != value:
                    raise ValueError("conflicting response request IDs")
                request_id = value

        observations.append({
            "sequence": sequence,
            "curl_cumulative_raw": cumulative,
            "phase_seconds": phases,
            "response_spans_ms": spans,
            "response_request_id": request_id,
            "span_association": "same_response" if spans else "unavailable",
        })
    return observations


def parse_response_spans(header):
    """Retain numeric span fields without SQL descriptions or arbitrary text."""
    if len(header) > 4096:
        raise ValueError("response timing header exceeds bounds")
    # Descriptions may contain commas and text resembling metrics. Split only
    # outside quoted descriptions, then retain numeric fields from each metric.
    segments = []
    start = 0
    quoted = escaped = False
    for offset, character in enumerate(header):
        if escaped:
            escaped = False
        elif quoted and character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif character == "," and not quoted:
            segments.append(header[start:offset])
            start = offset + 1
    if quoted or escaped:
        raise ValueError("unterminated response timing description")
    segments.append(header[start:])
    if len(segments) > 64:
        raise ValueError("response timing metric count exceeds bounds")

    spans = {}
    for segment in segments:
        match = re.match(
            r"\s*([A-Za-z][A-Za-z0-9_-]{0,63})\s*;\s*dur=([0-9]+(?:\.[0-9]+)?)(?=\s*(?:;|$))",
            segment,
        )
        if match is None:
            continue
        name, raw = match.groups()
        value = float(raw)
        if not math.isfinite(value) or value > 300_000 or name in spans:
            raise ValueError("invalid numeric response timing span")
        spans[name] = {"raw_ms": raw, "milliseconds": value}
    return spans


def report_page_observations(label, observations):
    """Report raw timings and quantiles of paired deltas, never p95 subtraction."""
    print(f"hybrid {label} fresh-connection observations:", json.dumps(
        observations, sort_keys=True, separators=(",", ":"),
    ))
    summaries = {}
    for name in observations[0]["phase_seconds"]:
        values = sorted(sample["phase_seconds"][name] for sample in observations)
        summaries[name] = {
            "p50": statistics.median(values),
            "p95": values[math.ceil(len(values) * 0.95) - 1],
            "p99": values[math.ceil(len(values) * 0.99) - 1],
            "max": values[-1],
        }
    print(f"hybrid {label} paired phase seconds:", summaries)
    print(f"hybrid {label} response span associations:", {
        "same_response": sum(bool(sample["response_spans_ms"]) for sample in observations),
        "unavailable": sum(not sample["response_spans_ms"] for sample in observations),
        "request_id_present": sum(sample["response_request_id"] is not None for sample in observations),
        "aggregate_worker_logs_are_not_per_request_associations": True,
    })


def report_process_window(label, before, after):
    """Retain counter boundaries and qualify deltas only for identical processes."""
    result = {"before": before, "after": after, "process_deltas": {}}
    for role in ("node", "workerd"):
        first, last = before["processes"][role], after["processes"][role]
        identity = ("pid", "start_ticks", "exe")
        if any(first[key] != last[key] for key in identity):
            result["process_deltas"][role] = {"status": "process_identity_changed"}
            continue
        counters = {}
        for group in ("cpu_ticks", "schedstat", "io"):
            if first[group] is None or last[group] is None:
                if group == "cpu_ticks":
                    raise ValueError("mandatory CPU counters are unavailable")
                counters[group] = None
                continue
            counters[group] = {}
            for key, value in first[group].items():
                final = last[group].get(key)
                if final is None or final < value:
                    raise ValueError("process counter regressed")
                counters[group][key] = final - value
        result["process_deltas"][role] = {"status": "same_process", **counters}
    print(f"hybrid {label} process counter window:", json.dumps(result, sort_keys=True))
    return result


def page_cumulative_values(observations, name):
    """Return one sorted raw cumulative field for the unchanged fresh gate."""
    return sorted(float(sample["curl_cumulative_raw"][name]) for sample in observations)
