"""Runs incremental Direct checks and small real workerd integration scenarios.

The development bundle uses the current checkout and a persistent Cargo target.
It is never a fleet qualification artifact. Runtime checks use fresh disposable
SQLite state and a controlled provider instead of the publication stress corpus.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import statistics
import subprocess
import tempfile
import time


class CheckFailure(Exception):
    """Identifies a failed phase whose private output has been retained."""


def interrupt(signum, frame):
    """Lets ordinary termination unwind the active phase's child cleanup."""
    raise KeyboardInterrupt


def provider_timings(root):
    """Reports fixed timing labels from the disposable controlled runtime."""
    allowed = {"provider_response_headers", "provider_response_body", "stage_provider",
               "provider_foreground_capacity", "provider_bulk_capacity", "provider_metadata_capacity"}
    samples = {name: [] for name in allowed}
    logs = list((root / "connected").glob("workerd-*.log"))
    queue_log = root / "queue/runtime.private.log"
    if queue_log.exists():
        logs.append(queue_log)
    for log in logs:
        for phase, elapsed in re.findall(
                r"direct_(?:stage|transport)_timing phase=(\w+) elapsed_millis=(\d+) success=true", log.read_text(errors="replace")):
            if phase in samples:
                samples[phase].append(int(elapsed))
    result = {}
    for phase, values in sorted(samples.items()):
        if values:
            values.sort()
            result[phase] = {"count": len(values), "medianMillis": statistics.median(values),
                             "p95Millis": values[int(.95 * (len(values) - 1))], "maximumMillis": values[-1]}
    (root / "provider-timings.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"controlledProviderTimings": result}), flush=True)


def run_phase(label, arguments, root, results, *, environment=None, timeout=180):
    """Bounds a process group and reports only elapsed time and test counts."""
    log = root / (label + ".log")
    started = time.monotonic()
    timed_out = False
    with log.open("xb") as output:
        process = subprocess.Popen(
            arguments, stdout=output, stderr=output,
            env=environment, start_new_session=True,
        )
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            # Rust tests can launch Node and workerd. Terminate every remaining
            # descendant even when the test parent exits before its children.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()

    body = log.read_text(errors="replace")
    no_space = "no space left on device" in body.lower()
    result = {
        "phase": label, "seconds": round(time.monotonic() - started, 2),
        "passed": process.returncode == 0 and not timed_out and not no_space,
        "timedOut": timed_out, "noSpace": no_space,
        "tests": [dict(zip(("passed", "failed", "ignored"), map(int, match)))
                  for match in re.findall(
                      r"test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored", body)],
    }
    results.append(result)
    (root / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(result), flush=True)
    if not result["passed"]:
        raise CheckFailure(label)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scope", nargs="?", choices=("all", "unit", "runtime", "paired", "queue", "stress"), default="all")
    parser.add_argument("--timeout", type=int, default=180,
                        help="deadline in seconds for each test phase (default: 180)")
    parser.add_argument("--keep", action="store_true", help="retain private logs on success too")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 600:
        parser.error("--timeout must be between 1 and 600 seconds")

    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupt)
    checkout = Path(os.environ["AOS_DEV_ROOT"]).resolve()
    os.chdir(checkout)
    target = Path(os.environ.get("CARGO_TARGET_DIR", str(checkout / "crates/target"))).resolve()
    if any(target == path or path in target.parents for path in (Path("/run"), Path("/dev/shm"))):
        parser.error("the Cargo target must use disk-backed storage")
    os.environ["CARGO_TARGET_DIR"] = str(target)
    os.environ.setdefault("TOKIO_WORKER_THREADS", "2")
    root = Path(tempfile.mkdtemp(prefix="aos-hub-direct-", dir="/tmp"))
    results = []
    success = False
    started = time.monotonic()
    # Cargo starts in the repository root, so load the workspace's target flags
    # explicitly; --manifest-path alone does not discover crates/.cargo/config.
    cargo = ["cargo", "--config", "crates/.cargo/config.toml", "test", "--manifest-path",
             "crates/Cargo.toml", "--locked", "--offline", "--lib"]
    print("Direct development checks: incremental builds, fresh local state; no fleet qualification.", flush=True)
    try:
        if args.scope in ("all", "unit"):
            run_phase("worker-unit", cargo + ["-p", "aos-hub-worker"], root, results, timeout=args.timeout)
            run_phase("native-direct-unit", cargo + ["-p", "aos-hub-native", "direct_upload::"],
                      root, results, timeout=args.timeout)
            if any(sum(row["passed"] for row in phase["tests"]) == 0 for phase in results):
                raise CheckFailure("a unit test filter selected no tests")

        if args.scope in ("all", "runtime", "paired", "queue", "stress"):
            environment = dict(os.environ)
            # This cheap profile preserves the code and feature set but avoids
            # whole-program release LTO on every edit. Cold dependencies compile
            # once; subsequent runs reuse Cargo's incremental artifacts.
            environment.update(CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_DEV_OPT_LEVEL="1")
            source = environment["AOS_COPY_WORKER_SOURCE_PATH"]
            environment["AOS_HUB_WORKER_SOURCE_DIGEST"] = hashlib.sha256(source.encode()).hexdigest()
            run_phase("worker-build", ["cargo", "--config", "crates/.cargo/config.toml",
                      "build", "--manifest-path", "crates/Cargo.toml",
                      "--locked", "--offline", "-p", "aos-hub-worker", "--target", "wasm32-unknown-unknown",
                      "--features", "aos-hub-worker/do-e2e"], root, results,
                      environment=environment, timeout=600)
            dist = root / "dist"
            run_phase("worker-bundle", ["node", "tools/dev/hub-direct-bundle.mjs",
                      str(target / "wasm32-unknown-unknown/debug/aos_hub_worker.wasm"), str(dist)],
                      root, results, timeout=args.timeout)

            runtime_environment = dict(os.environ)
            runtime_environment.update(
                AOS_DIRECT_GUARD_E2E_DIST=str(dist), AOS_DIRECT_GUARD_E2E_WORKERD=shutil.which("workerd"),
                AOS_COPY_DIST=str(dist), AOS_COPY_NODE=shutil.which("node"),
                AOS_COPY_WORKERD=shutil.which("workerd"), AOS_COPY_CONNECTED_ROOT=str(root / "connected"),
                AOS_COPY_PROVIDER_SOURCE_DIGEST=environment["AOS_HUB_WORKER_SOURCE_DIGEST"],
                AOS_COPY_TRACE_PROVIDER="1",
                AOS_DIRECT_QUEUE_ROOT=str(root / "queue"),
            )
            if args.scope == "stress":
                runtime_environment.update(
                    AOS_DIRECT_QUEUE_OBJECTS="32", AOS_DIRECT_QUEUE_PROVIDER_MILLIS="50",
                    AOS_DIRECT_QUEUE_BULK_OBJECTS="8",
                    AOS_DIRECT_QUEUE_FOREGROUND_ROUNDS="4", AOS_DIRECT_QUEUE_FOREGROUND_OBJECTS="64",
                )
            if args.scope not in ("queue", "stress"):
                run_phase("guard-restarts", ["node", "pkgs/tools/aos-hub-direct-guard-e2e.mjs", str(root / "guards")],
                          root, results, environment=runtime_environment, timeout=args.timeout)
            connected = ("actual_cross_binding_copy_and_cold_terminal_replay" if args.scope == "paired"
                         else "actual_native_copy_guard_issuer_and_cold_terminal_replay")
            connected_cargo = cargo
            if args.scope in ("queue", "stress"):
                connected = "actual_signed_uploads_drain_verification_queues"
                connected_cargo = [argument for argument in cargo if argument != "--lib"]
                connected_cargo += ["--bin", "aos-hub-authority-bootstrap"]
                run_phase("queue-test-build", connected_cargo + ["-p", "aos-hub-native", "--no-run"],
                          root, results, environment=runtime_environment, timeout=600)
            run_phase("native-worker-provider", connected_cargo + ["-p", "aos-hub-native",
                      connected, "--", "--ignored", "--test-threads=1"],
                      root, results, environment=runtime_environment, timeout=args.timeout)
            # An ignored/misspelled filter must never silently produce a pass.
            if sum(row["passed"] for row in results[-1]["tests"]) != 1:
                raise CheckFailure("connected integration test did not run exactly once")
            provider_timings(root)
            queue_summary = root / "queue/queue-summary.json"
            if queue_summary.exists():
                summary = json.loads(queue_summary.read_text())
                rows = summary.pop("rows")
                for name in ("waitMillis", "activeMillis"):
                    values = sorted(row[name] for row in rows)
                    summary[name] = {"median": statistics.median(values), "maximum": values[-1]}
                summary["maximumProviderRequests"] = max(row["peakProviderRequests"] for row in rows)
                # The fixture summary contains only counts, elapsed times and
                # development scope; signed requests stay in private logs.
                print(json.dumps({"controlledQueue": summary}), flush=True)

        success = True
        print(f"Direct development checks passed in {time.monotonic() - started:.1f}s.", flush=True)
    except CheckFailure as failure:
        print(f"Direct check failed: {failure}. Private logs: {root}", flush=True)
        return 1
    except BaseException:
        print(f"Direct checks interrupted; private logs: {root}", flush=True)
        raise
    finally:
        if success and not args.keep:
            shutil.rmtree(root)
        elif success:
            print(f"Private logs: {root}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
