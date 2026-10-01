"""Exercise actual dependency outages after the measured publication window.

Each scenario retains its own HTTP and runtime window. Injected failures remain
separate from accepted-workload byte and latency conclusions. Missing non-200
private body captures stay unknown; no failure is omitted to manufacture zero.
"""

import json
import re
import shlex
import time


def probe_direct_failure_route(client, tools, label, path, authenticated):
    """Retain a bounded actual reply without printing cookies or private bodies."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,47}", label):
        raise ValueError("failure probe label is invalid")
    if path not in {"/-/instance", "/_assets/style.css"}:
        raise ValueError("failure probe route is not selected")
    observed = json.loads(direct_guest_python(client, tools["python"], """
        import hashlib, os, subprocess, time
        from pathlib import Path

        root = Path('/var/lib/hybrid-client/failure-observations')
        root.mkdir(mode=0o700, exist_ok=True)
        body = root / (selected['label'] + '.body')
        descriptor = os.open(body, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        arguments = selected['curl'] + ['-sS', '--max-time', '40', '--max-filesize', '262144',
            '-o', str(body), '-w', '%{http_code}', '-H', 'cf-connecting-ip: 192.0.2.10']
        if selected['authenticated']:
            arguments += ['-b', '/var/lib/hybrid-client/browser-session/cookies']
        arguments += ['https://aos.andyl.org' + selected['path']]
        started = time.time_ns()
        try:
            result = subprocess.run(arguments, stdin=subprocess.DEVNULL,
                capture_output=True, check=False, timeout=45)
            stdout, stderr = result.stdout, result.stderr
            exit_code, timed_out = result.returncode, False
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b'', error.stderr or b''
            exit_code, timed_out = None, True
        captured = body.read_bytes()
        if len(captured) > 262144:
            raise ValueError('failure reply exceeded its retained probe bound')
        status = int(stdout) if len(stdout) == 3 and stdout.isdigit() else None
        print(json.dumps({'version': 1, 'label': selected['label'], 'path': selected['path'],
            'authenticated': selected['authenticated'], 'status': status,
            'exitCode': exit_code, 'timedOut': timed_out,
            'startedUnixNs': str(started), 'finishedUnixNs': str(time.time_ns()),
            'bodySha256': hashlib.sha256(captured).hexdigest(), 'bodyBytes': len(captured),
            'stderrSha256': hashlib.sha256(stderr).hexdigest(), 'stderrBytes': len(stderr),
            'bodyFile': str(body), 'scope': 'actual reply or consumed prefix; no missing response becomes zero'}))
    """, {"curl": shlex.split(tools["curl"]), "label": label, "path": path,
            "authenticated": authenticated}, timeout=60))
    retain_direct_flow("failure-" + label + ".json", observed)
    return observed


def assert_direct_private_failure(observed):
    """Require an actual unavailable-origin response for the live private session."""
    if (observed["exitCode"] != 0 or observed["timedOut"]
            or observed["status"] is None or not 500 <= observed["status"] <= 599):
        raise AssertionError(observed)


def assert_direct_recovered_page(client, tools, label):
    """Require the same actual browser session to recover after the dependency."""
    attempts = []
    for index in range(6):
        observed = probe_direct_failure_route(
            client, tools, label + "-" + str(index), "/-/instance", True,
        )
        attempts.append(observed)
        if observed["exitCode"] == 0 and observed["status"] == 200:
            return {"attempts": attempts, "recovered": observed}
        if index < 5:
            time.sleep(2)
    raise AssertionError({"recoveryAttempts": attempts})


def run_direct_dependency_outages(client, native, worker, database_machine, tools, process):
    """Inject bounded Native, PostgreSQL and executor failures without state reset."""
    # Renew browser authorization before testing dependencies. Expired cookies
    # would exercise a different refusal from an origin/database outage.
    direct_root_browser_token(client, tools["curl"], tools["python"], private_guest_command,
                              reuse_session=True)
    before = assert_direct_recovered_page(client, tools, "pre-outage-page")
    asset = probe_direct_failure_route(client, tools, "pre-outage-asset", "/_assets/style.css", False)
    assert asset["exitCode"] == 0 and asset["status"] == 200 and asset["bodyBytes"] > 0, asset
    native_position = direct_log_position(native, tools["python"],
        "/var/lib/hybrid-native-observations/requests.jsonl")
    worker_position = direct_log_position(worker, tools["python"], process["logFile"])
    results = {"version": 1, "before": before, "asset": asset,
        "scenarios": {}, "acceptedPublicationWindow": "separate completed A/B window",
        "nativeBulkBytes": None,
        "scope": "actual injected failure windows; non-200 body classification remains explicit"}
    resumed_position = None
    try:
        try:
            native.succeed("systemctl stop aos-hub.service", timeout=60)
            denied = probe_direct_failure_route(client, tools, "native-outage-private", "/-/instance", True)
            cached = probe_direct_failure_route(client, tools, "native-outage-asset", "/_assets/style.css", False)
            results["scenarios"]["native"] = {"private": denied, "publicStaticAsset": cached}
            assert_direct_private_failure(denied)
            assert cached["status"] == 200 and cached["exitCode"] == 0, cached
            assert (cached["bodyBytes"], cached["bodySha256"]) == (asset["bodyBytes"], asset["bodySha256"]), cached
        finally:
            native.succeed("systemctl start aos-hub.service", timeout=60)
            native.wait_for_unit("aos-hub.service", timeout=90)
        results["scenarios"]["native"]["recovery"] = assert_direct_recovered_page(client, tools, "native-recovered")

        pg_ctl = shlex.join([tools["chroot"], "--userspec=802:802", "/",
            tools["postgres"] + "/pg_ctl", "-D", "/var/lib/hybrid-postgres"])
        try:
            database_machine.succeed(pg_ctl + " -m immediate -w stop", timeout=60)
            denied = probe_direct_failure_route(client, tools, "postgres-outage-private", "/-/instance", True)
            cached = probe_direct_failure_route(client, tools, "postgres-outage-asset", "/_assets/style.css", False)
            results["scenarios"]["postgres"] = {"private": denied, "publicStaticAsset": cached}
            assert_direct_private_failure(denied)
            assert cached["status"] == 200 and cached["exitCode"] == 0, cached
            assert (cached["bodyBytes"], cached["bodySha256"]) == (asset["bodyBytes"], asset["bodySha256"]), cached
        finally:
            status, _ = database_machine.execute(pg_ctl + " status", timeout=30)
            if status != 0:
                database_machine.succeed(pg_ctl + " -l /var/lib/hybrid-postgres/server.log -w start "
                    "-o '-c config_file=/var/lib/hybrid-postgres/fleet.conf'", timeout=120)
        results["scenarios"]["postgres"]["recovery"] = assert_direct_recovered_page(client, tools, "postgres-recovered")

        results["scenarios"]["executor"] = {"disposal": stop_direct_worker(worker, tools["python"], process)}
        try:
            denied = probe_direct_failure_route(client, tools, "executor-outage-private", "/-/instance", True)
            results["scenarios"]["executor"]["private"] = denied
            assert denied["exitCode"] != 0 and denied["status"] in {None, 0}, denied
            native.succeed("systemctl is-active --quiet aos-hub.service", timeout=30)
        finally:
            resumed = start_direct_worker(worker, tools, process["configurationFile"], "post-outage")
            results["scenarios"]["executor"]["restart"] = resumed
            resumed_position = direct_log_position(worker, tools["python"], resumed["logFile"])
            # Include startup as well as subsequent recovery requests in this
            # new process's retained window; the prior runner has its own log.
            resumed_position["byteSize"] = 0
            assert resumed["configurationSha256"] == process["configurationSha256"], resumed
            wait_worker_transport(worker, tools["curl"], tools["python"], True,
                                  observation_label="worker-post-outage")
        results["scenarios"]["executor"]["recovery"] = assert_direct_recovered_page(client, tools, "executor-recovered")
    finally:
        _, results["nativeLogWindow"] = retain_direct_log_window(native, tools["python"],
            native_position, "failure-native.jsonl")
        _, results["priorWorkerLogWindow"] = retain_direct_log_window(worker, tools["python"],
            worker_position, "failure-worker-prior.log")
        if resumed_position is not None:
            _, results["resumedWorkerLogWindow"] = retain_direct_log_window(
                worker, tools["python"], resumed_position, "failure-worker-resumed.log",
            )
        retain_direct_flow("actual-dependency-failure-windows.json", results)
    return results
