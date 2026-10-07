"""Collect Cloud Run evidence and assess it in the same owning process.

The installed collector keeps its live transport observations in memory. This
entry point uses that map directly; importing retained receipts into another
process cannot authenticate them. Provider completeness, runtime image custody
and byte accounting remain separate assessment requirements.
"""

import json
import math
import os
from pathlib import Path
import runpy
import sys
import time


DIRECTORY = Path(__file__).resolve(strict=True).parent
PACKAGE_READER = runpy.run_path(str(DIRECTORY / "package_context.py"))
PACKAGE = PACKAGE_READER["context"](__file__)
MAX_SELECTION = 1024 * 1024
MAX_PAGES = 1024
MAX_WINDOW_SECONDS = 2700


def installed_assessment():
    """Load the adjacent assessment and retain its actual reader namespace."""
    path = DIRECTORY / "hosted_assessment.py"
    raw = PACKAGE_READER["installed_bytes"](path, MAX_SELECTION)
    namespace = {"__file__": str(path), "__name__": "installed_live_assessment"}
    exec(compile(raw, str(path), "exec"), namespace)
    return namespace


def original_deadline(selected):
    """Translate a selected boot deadline without renewing its remaining time."""
    expected = {"bootId", "bootTimeNanos", "unixNanos"}
    if not isinstance(selected, dict) or set(selected) != expected:
        raise ValueError("Qualification original deadline differs")
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if selected["bootId"] != boot_id:
        raise ValueError("Qualification belongs to another host boot")

    counts = {}
    for name in ("bootTimeNanos", "unixNanos"):
        value = selected[name]
        if (not isinstance(value, str) or not value.isascii()
                or not value.isdecimal() or str(int(value)) != value
                or len(value) > 20):
            raise ValueError("Qualification deadline count differs")
        counts[name] = int(value)

    remaining_boot = (counts["bootTimeNanos"]
                      - time.clock_gettime_ns(time.CLOCK_BOOTTIME)) / 1_000_000_000
    remaining_wall = (counts["unixNanos"] - time.time_ns()) / 1_000_000_000
    remaining = min(remaining_boot, remaining_wall)
    if not math.isfinite(remaining) or not 2 < remaining <= MAX_WINDOW_SECONDS:
        raise ValueError("Qualification original window elapsed or exceeds its bound")

    return {"monotonic": time.monotonic() + remaining,
            "unix": counts["unixNanos"] / 1_000_000_000,
            "bootId": boot_id, "bootTimeNanos": selected["bootTimeNanos"]}


def collect_cloud_run(supervisor, collector, custody, selected, authorization_fd, output):
    """Collect exact resource and paginated log images for one selected window."""
    expected = {"runtime", "project", "location", "serviceName", "revisionName",
                "imageDigest", "policy", "instances", "firstUnixMicros", "lastUnixMicros"}
    if not isinstance(selected, dict) or set(selected) != expected:
        raise ValueError("Qualification Cloud Run selection differs")
    if selected["runtime"] != PACKAGE["runtime"]:
        raise ValueError("Qualification selected runtime differs")

    scope = {name: selected[name] for name in (
        "runtime", "serviceName", "revisionName", "imageDigest",
        "firstUnixMicros", "lastUnixMicros")}
    result = {"version": 1, "kind": "cloud_run", **selected, "pages": []}

    def retain(operation, request, name, maximum):
        request_raw = json.dumps(request, separators=(",", ":")).encode()
        images = supervisor.collect(operation, request_raw, scope,
                                    authorization_fd, maximum)
        directory = output / name
        directory.mkdir(mode=0o700)
        return collector["retain_images"](directory, *images), images[1]

    for name in ("service", "revision"):
        exchange, _ = retain("cloud_run_" + name,
                             {"name": selected[name + "Name"]}, name, MAX_SELECTION)
        result[name] = exchange

    query = {"resourceNames": ["projects/" + selected["project"]],
             "filter": custody["log_filter"](result),
             "orderBy": "timestamp asc", "pageSize": 1000}
    tokens = set()
    for index in range(MAX_PAGES):
        exchange, raw = retain("logging_entries_list", query,
                               "page-" + str(index), collector["MAX_RESPONSE"])
        result["pages"].append(exchange)
        response = collector["closed_json"](raw)
        if not isinstance(response, dict):
            raise ValueError("Qualification log response differs")
        token = response.get("nextPageToken")
        if token is None:
            return result
        if (not isinstance(token, str) or not 0 < len(token) <= 8192
                or token in tokens):
            raise ValueError("Qualification pagination token is invalid or repeated")
        tokens.add(token)
        query = {**query, "pageToken": token}

    raise ValueError("Qualification pagination remains incomplete at the page bound")


def assess_live(specification, authorization_fd):
    """Own collection and partial assessment without asserting final acceptance."""
    adapter = installed_assessment()
    readers = adapter["READERS"]
    expected = {"version", "runtime", "originalCutoff", "cloudRun",
                "assessmentSelection", "outputDirectory"}
    readers["fields"](specification, expected)
    if (type(specification["version"]) is not int or specification["version"] != 1
            or specification["runtime"] != PACKAGE["runtime"]):
        raise ValueError("Qualification source-bound runtime differs")

    deadline = original_deadline(specification["originalCutoff"])
    selection = readers["closed_json"](readers["read_ref"](
        specification["assessmentSelection"], MAX_SELECTION))
    if selection.get("runtime") != PACKAGE["runtime"] or selection.get("authSidecar") is None:
        raise ValueError("Qualification assessment lacks the selected runtime or sidecar")
    sidecar = readers["closed_json"](readers["read_ref"](
        selection["authSidecar"], MAX_SELECTION))
    if sidecar.get("nativeProcess") is not None:
        raise ValueError("Qualification invents a local Native process")
    inventory = selection.get("nativeInventory")
    if inventory is not None and inventory.get("sidecar") != selection["authSidecar"]:
        raise ValueError("Qualification inventory selects a different original sidecar")

    output = Path(specification["outputDirectory"])
    if not output.is_absolute() or output.parent != output.parent.resolve(strict=True):
        raise ValueError("Qualification output parent is not canonical")
    output.mkdir(mode=0o700)
    tools = PACKAGE["hostedCollectorTools"]
    collector = readers["hosted_collector"]()
    supervisor = readers["start_hosted_supervision"](
        tools["python"], tools["collector"], tools["trust"], deadline)
    custody = readers["hosted_custody"]()

    try:
        selected_log = collect_cloud_run(supervisor, collector, custody,
                                        specification["cloudRun"], authorization_fd, output)
        log_path = output / "cloud-run-selection.json"
        raw = json.dumps(selected_log, separators=(",", ":")).encode()
        with log_path.open("xb") as stream:
            os.chmod(log_path, 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        reference = {"file": str(log_path), "sha256": collector["sha"](raw),
                     "byteSize": str(len(raw))}
        # This namespace owns the live observation map. A source-bound copy of
        # the sidecar selects our observed images without replacing its other
        # policy, capture or immutable runtime inputs.
        sidecar = {**sidecar, "nativeLog": {"format": "cloud_run", "selection": reference}}
        sidecar_path = output / "observed-sidecar.json"
        sidecar_raw = json.dumps(sidecar, separators=(",", ":")).encode()
        with sidecar_path.open("xb") as stream:
            os.chmod(sidecar_path, 0o600)
            stream.write(sidecar_raw)
            stream.flush()
            os.fsync(stream.fileno())
        selected = {**selection, "authSidecar": {
            "file": str(sidecar_path), "sha256": collector["sha"](sidecar_raw),
            "byteSize": str(len(sidecar_raw))}}
        if inventory is not None:
            selected["nativeInventory"] = {
                **inventory, "sidecar": selected["authSidecar"]}
        collector["remaining"](deadline)
        result = adapter["assess"](selected)
        collector["remaining"](deadline)
        return result
    finally:
        failures = json.dumps(supervisor.failures(), separators=(",", ":")).encode()
        with (output / "collection-failures.json").open("xb") as stream:
            os.chmod(stream.name, 0o600)
            stream.write(failures)
            stream.flush()
            os.fsync(stream.fileno())


def main():
    """Consume one private plan and an inherited authorization descriptor."""
    if len(sys.argv) != 3 or not sys.argv[2].isascii() or not sys.argv[2].isdecimal():
        raise ValueError("Expected a private qualification plan and authorization descriptor")
    adapter = installed_assessment()
    raw = adapter["READERS"]["private_bytes"](sys.argv[1], MAX_SELECTION)
    specification = adapter["READERS"]["closed_json"](raw)
    result = assess_live(specification, int(sys.argv[2]))
    print(json.dumps(result, separators=(",", ":")))
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        # Provider exceptions may include credential-bearing transport details.
        print("Live hosted qualification refused: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
