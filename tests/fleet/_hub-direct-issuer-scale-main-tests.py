"""Exercise called scale custody and joins with explicit controlled source fixtures.

These tests execute local file/process transport and pure collectors. Supplied
unit events are not issuer signatures, workerd observations or scale acceptance.
"""

import asyncio
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable


def load(name):
    path = ROOT / ("_hub-direct-issuer-scale-" + name + ".py")
    namespace = {"__name__": "scale_source_test_" + name, "__file__": str(path)}
    exec(compile(path.read_bytes(), str(path), "exec"), namespace)
    return namespace


COLLECTOR = {"__name__": "scale_source_test_collector"}
collector_path = ROOT / "_hub-direct-issuer-scale.py"
exec(compile(collector_path.read_bytes(), str(collector_path), "exec"), COLLECTOR)
JOINS, PROCESS, RUNTIME, MAIN = (load(name) for name in ("joins", "process", "runtime", "main"))
JOINS.update({name: COLLECTOR[name] for name in ("_closed_object", "_digest", "_unsigned", "_private_file",
    "collect_local_issuer_observations", "measured_latency_summary", "whole_issuer_cpu_fraction", "LOCAL_LEASE_SCALE_POLICY")})


def call_fixture():
    dispatch = {"event": "aos_lease_scale_issuer_dispatch", "version": 1,
        "sourceDigest": "1" * 64, "runId": "2" * 32, "isolateLabel": "3" * 32,
        "configurationDigest": "4" * 64, "cohortDigest": "5" * 64,
        "ownerNonce": "6" * 64, "requestSha256": "7" * 64, "requestBytes": 200,
        "issuedAt": 100, "expiresAt": 130}
    capture = {"requestId": "actual-fixture-transport-1", "procedure": "/_aos/storage-authority/issuer/v1",
        "method": "POST", "status": 200, "bodies": {
            "request": {"sha256": "7" * 64, "byteSize": 200},
            "response": {"sha256": "8" * 64, "byteSize": 300}}}
    verified = {"ownerNonce": "6" * 64, "requestSha256": "7" * 64, "requestBytes": 200,
        "replySha256": "8" * 64, "replyBytes": 300, "cohortDigest": "5" * 64,
        "leaseDigest": "9" * 64, "issuedAt": 100, "notAfter": 108, "leaseSequence": 1}
    native = {"requests": {"6" * 64: {"pins": {"receivedBodySha256": "7" * 64, "receivedBodyBytes": 200},
        "outcome": "success", "wallNs": 10, "queueWaitNs": 1,
        "signatures": [{"purpose": "lease"}, {"purpose": "reply"}],
        "commits": [{"kind": "lease", "outcome": "acknowledged"}]}},
        "wholeProcessCpuNs": 1, "wholeProcessWindowWallNs": 100,
        "missingSigningCpuSamples": 0, "commits": {}, "signatures": {}}
    return dispatch, capture, native, verified


class ScaleSourceTests(unittest.TestCase):
    def test_hidden_cgroup_mount_refuses_even_with_visible_root_quota(self):
        with tempfile.TemporaryDirectory() as directory:
            # A visible max file cannot reveal quotas above a namespace root.
            maximum = Path(directory) / 'cpu.max'
            maximum.write_text('max 100000\n')
            self.assertTrue(maximum.is_file())
            hidden = '1 0 0:1 /hidden /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n'
            with self.assertRaises(ValueError):
                PROCESS["scale_validate_cpu_mountinfo"](hidden)
            exposed = hidden.replace('/hidden ', '/ ')
            PROCESS["scale_validate_cpu_mountinfo"](exposed)

    def test_exact_join_preserves_actual_attempt_without_received_reply(self):
        dispatch, capture, native, checked = call_fixture()
        value = JOINS["join_scale_issuer_calls"]([dispatch], [capture], native, [checked])
        self.assertEqual(value["actualAttempts"], 1)
        self.assertEqual(value["calls"][0]["outcome"], "verified_acknowledged_issuance")
        unreceived = JOINS["join_scale_issuer_calls"]([dispatch], [], {"requests": {}}, [])
        self.assertEqual(unreceived["calls"][0]["outcome"], "attempt_not_received")
        self.assertIsNone(unreceived["qualification"])

    def test_substituted_cohort_and_duplicate_transport_refuse(self):
        dispatch, capture, native, checked = call_fixture()
        checked["cohortDigest"] = "a" * 64
        with self.assertRaises(ValueError):
            JOINS["join_scale_issuer_calls"]([dispatch], [capture], native, [checked])
        checked["cohortDigest"] = dispatch["cohortDigest"]
        with self.assertRaises(ValueError):
            JOINS["join_scale_issuer_calls"]([dispatch], [capture, copy.deepcopy(capture)], native, [checked])

    def test_positive_missing_acknowledged_commit_refuses(self):
        dispatch, capture, native, checked = call_fixture()
        native["requests"][dispatch["ownerNonce"]]["commits"][0]["outcome"] = "unknown"
        with self.assertRaises(ValueError):
            JOINS["join_scale_issuer_calls"]([dispatch], [capture], native, [checked])

    def test_missing_latency_cannot_satisfy_budget(self):
        dispatch, capture, native, checked = call_fixture()
        native["requests"][dispatch["ownerNonce"]]["wallNs"] = None
        joined = JOINS["join_scale_issuer_calls"]([dispatch], [capture], native, [checked])
        result = JOINS["scale_budget_facts"](joined, native, 1000)
        self.assertEqual(result["missingLatencySamples"], {"cold": 1})
        self.assertIsNone(result["latencyBudgetSatisfied"])

    def test_wave_first_second_is_ambiguous_not_a_warm_hit(self):
        dispatch, capture, native, checked = call_fixture()
        joined = JOINS["join_scale_issuer_calls"]([dispatch], [capture], native, [checked])
        rows = [{"original": {"nonce": f"{index:064x}", "cohort_digest": dispatch["cohortDigest"]},
            "wave": "cold", "startedUnixNs": 100_500_000_000, "completedUnixNs": 101_000_000_000,
            "outcome": "authenticated_probe_metadata", "reply": checked,
            "isolateLabel": dispatch["isolateLabel"]} for index in range(4224)]
        result = JOINS["scale_wave_rpc_facts"](rows, "cold", joined)
        self.assertEqual(result["boundaryAmbiguousOwnerTokensConsumed"], 1)
        self.assertEqual(result["retainedOwnerTokensConsumed"], 0)

    def owner_wait(self, root, omit=False, overlap=False):
        contexts, owners, cohorts = [], [], [f"{index:064x}" for index in range(32)]
        for isolate in range(4):
            label = f"{isolate:032x}"
            contexts.append({"isolateLabel": label, "configurationDigest": "4" * 64})
            rows = []
            for cohort_index, cohort in enumerate(cohorts):
                if omit and isolate == 3 and cohort_index == 31:
                    continue
                dispatch = call_fixture()[0]
                dispatch.update(isolateLabel=label, cohortDigest=cohort,
                    ownerNonce=f"{isolate * 32 + cohort_index:064x}")
                rows.append(dispatch)
            if overlap:
                old = copy.deepcopy(rows[0])
                old.update(ownerNonce="f" * 64, issuedAt=109, expiresAt=139)
                rows.append(old)
            log = root / f"worker-{isolate}.log"
            PROCESS["scale_write_private"](log, b"".join(json.dumps(row, separators=(",", ":")).encode() + b"\n" for row in rows))
            owners.append({"pid": isolate + 1, "startTicks": "1", "logFile": str(log)})
        selected = {"root": str(root), "run_id": "2" * 32, "source_digest": "1" * 64,
            "workers": contexts, "workerProcesses": owners, "cohort_digests": cohorts,
            "sources": {name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                for name, path in (("joins", ROOT / "_hub-direct-issuer-scale-joins.py"), ("collector", collector_path))}}
        # Unit process pins deliberately substitute for four actual workerds.
        process = {**PROCESS, "scale_process_identity": lambda pid: {"pid": pid, "startTicks": "1"}}
        waited = []
        async def wait(target):
            waited.append(target)
        asyncio.run(RUNTIME["wait_scale_owner_windows"](selected, process, {"wait_actual_utc": wait}, 109))
        return waited

    def test_actual_owner_window_dominates_short_token_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(self.owner_wait(root), [131])
            receipt = json.loads(next(root.glob("wait-*.json")).read_bytes())
            self.assertEqual(len(receipt["ownerOriginals"]), 128)
            self.assertEqual(receipt["requestedActualTokenBoundary"], 109)
            self.assertEqual(len(receipt["logSnapshots"]), 4)

    def test_missing_owner_and_overlap_cannot_guess_wait(self):
        for parameters in ({"omit": True}, {"overlap": True}):
            with self.subTest(parameters=parameters), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    self.owner_wait(Path(directory), **parameters)
                self.assertEqual(list(Path(directory).glob("wait-*.json")), [])

    def test_large_closed_capture_keeps_each_agent_frame_bounded(self):
        sizes = []
        def guest(machine, python, program, selected):
            wrapped = "import json,base64\nselected=json.loads(base64.b64decode(" + repr(base64.b64encode(json.dumps(selected).encode()).decode()) + "))\n" + __import__("textwrap").dedent(program)
            reply = subprocess.check_output([PYTHON, "-B", "-c", wrapped])
            sizes.append(len(reply))
            return reply
        MAIN["direct_guest_python"] = guest
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "closed.log"
            body = b"a" * (9 * 1024 * 1024 + 7)
            path.write_bytes(body)
            path.chmod(0o600)
            self.assertEqual(MAIN["_scale_capture_file"](None, PYTHON, str(path), 16 * 1024 * 1024), body)
            self.assertLess(max(sizes), 6 * 1024 * 1024)
            path.chmod(0o644)
            with self.assertRaises(subprocess.CalledProcessError):
                MAIN["_scale_capture_file"](None, PYTHON, str(path), 16 * 1024 * 1024)

    def test_process_stop_refuses_substituted_lifetime_before_signal(self):
        actual = PROCESS["scale_process_identity"](os.getpid())
        wrong = {**actual, "startTicks": str(int(actual["startTicks"]) + 1)}
        with self.assertRaises(ValueError):
            PROCESS["scale_stop_process"](wrong, "/tmp/unused-scale-stop", True)

    def test_actual_supervisor_retains_real_child_terminal_and_no_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child_source = root / "child.py"
            child_source.write_text("import time\ntime.sleep(0.2)\n")
            child_source.chmod(0o600)
            inputs = {PYTHON: hashlib.sha256(Path(PYTHON).read_bytes()).hexdigest(),
                str(child_source): hashlib.sha256(child_source.read_bytes()).hexdigest()}
            spec = {"version": 1, "root": str(root / "process"), "arguments": [PYTHON, str(child_source)],
                "environment": {}, "files": inputs, "runId": "1" * 32, "role": "workload"}
            PROCESS["scale_supervise"](spec)
            receipt = json.loads((root / "process/process.json").read_bytes())
            terminal = json.loads((root / "process/terminal.json").read_bytes())
            self.assertEqual(terminal["pid"], receipt["pid"])
            self.assertEqual(terminal["startTicks"], receipt["startTicks"])
            self.assertEqual(terminal["exitCode"], 0)
            self.assertGreater(receipt["allocatedMillicores"], 0)
            with self.assertRaises(FileExistsError):
                PROCESS["scale_supervise"](spec)


class LoadedCpuTests(unittest.TestCase):
    """Exercise conservative CPU joins with explicitly supplied unit endpoints."""

    def fixture(self):
        identity = {"pid": 100, "startTicks": "10", "ownerUid": 1,
            "arguments": ["/nix/store/unit-authority", "serve"], "executable": "/nix/store/unit-authority",
            "executableSha256": "a" * 64}
        allocation = {"affinityCpus": [0], "cgroupCpuQuotaMillicores": None, "allocatedMillicores": 1000,
            "cgroupQuotaObservations": [{"directory": "/sys/fs/cgroup", "quota": None, "period": None}]}
        issuer = {**identity, **allocation, "runId": "1" * 32, "role": "issuer", "selectedFiles": {"/unit/input": "b" * 64}}
        workload = {**identity, "pid": 200, "startTicks": "20", "runId": "1" * 32}
        rows = []
        for index in range(4224):
            original = {"version": 1, "nonce": f"{index:064x}", "run_id": "1" * 32,
                "source_digest": "2" * 64, "configuration_digest": "3" * 64,
                "cohort_digest": f"{index // 132:064x}", "issued_at": 10, "expires_at": 40}
            body = RUNTIME["_scale_runtime_json"](original)
            rows.append({"original": original, "wave": "cold", "isolateLabel": f"{index % 4:032x}",
                "offeredIndex": index % 33, "requestSha256": hashlib.sha256(body).hexdigest(),
                "requestBodyBytesOffered": len(body), "startedUnixNs": 200, "completedUnixNs": 300})
        offered = [{name: row[name] for name in ("original", "isolateLabel", "offeredIndex", "wave")} for row in rows]
        digest = hashlib.sha256(RUNTIME["_scale_runtime_json"](offered)).hexdigest()
        pins = {"version": 1, "runId": "1" * 32, "sourceDigest": "2" * 64,
            "issuerPid": 100, "issuerStartTicks": "10", "workloadPid": 200, "workloadStartTicks": "20",
            "issuerProcessSha256": hashlib.sha256(RUNTIME["_scale_runtime_json"](issuer)).hexdigest()}
        records = []
        for sequence, phase in enumerate(("start", "end")):
            request = {**pins, "sequence": sequence, "phase": phase, "wave": "cold", "waveOriginalsSha256": digest,
                "nonce": f"{sequence:032x}", "requestedUnixNs": 100 if sequence == 0 else 400}
            sample = {"outcome": "observed", "process": identity, "selectedFiles": issuer["selectedFiles"],
                "allocation": allocation, "userTicks": 10 + sequence * 20, "systemTicks": 10,
                "ticksPerSecond": 100, "monotonicBeforeNs": 100 + sequence * 100,
                "monotonicAfterNs": 101 + sequence * 100, "utcBeforeNs": 100 + sequence * 100,
                "utcAfterNs": 101 + sequence * 100}
            records.append({"original": request, "sample": sample})
        interval = {"wave": "cold", "waveOriginalsSha256": digest, "start": records[0], "end": records[1],
            "workloadProcess": {name: workload[name] for name in identity}, "startedUnixNs": 150, "completedUnixNs": 350,
            "monotonicStartNs": 1_000_000_000, "monotonicEndNs": 2_000_000_000, "monotonicResolutionNs": 1}
        return interval, rows, records, issuer, workload, pins

    def project(self, value):
        interval, rows, records, issuer, workload, _ = value
        return JOINS["scale_loaded_cpu_facts"]([interval], [("cold", rows)], records, issuer, workload)

    def test_loaded_cpu_uses_ticks_upper_and_actual_wave_lower_bounds(self):
        value = self.fixture()
        result = self.project(value)
        self.assertTrue(result["loadedCpuBudgetSatisfied"])
        row = result["waves"][0]
        self.assertEqual(row["cpuUpperBoundNs"], 220_000_000)
        self.assertEqual(row["offeredDurationLowerBoundNs"], 999_999_998)
        self.assertIsNone(row["qualification"])
        # Ten seconds of handshakes cannot enlarge a 0.1 second offered wave.
        value[0]["monotonicEndNs"] = 1_100_000_000
        value[2][1]["sample"]["monotonicBeforeNs"] = 10_000_000_000
        value[2][1]["sample"]["monotonicAfterNs"] = 10_000_000_001
        self.assertFalse(self.project(value)["loadedCpuBudgetSatisfied"])

    def test_counter_allocation_process_and_missing_endpoints_are_unknown(self):
        for change in ("counter", "allocation", "process", "missing", "frequency", "duration"):
            value = self.fixture()
            end = value[2][1]["sample"]
            if change == "counter":
                end["userTicks"] = 9
            elif change == "allocation":
                end["allocation"] = {**end["allocation"], "allocatedMillicores": 500}
            elif change == "process":
                end["process"] = {**end["process"], "startTicks": "11"}
            elif change == "missing":
                value[2][1]["sample"] = {"outcome": "unknown", "reason": "outage"}
            elif change == "frequency":
                end["ticksPerSecond"] = 200
            else:
                value[0]["monotonicEndNs"] = value[0]["monotonicStartNs"] + 2
            with self.subTest(change=change):
                self.assertIsNone(self.project(value)["loadedCpuBudgetSatisfied"])

    def test_original_body_raw_endpoint_and_workload_substitution_are_unknown(self):
        for change in ("body", "raw", "workload", "original", "time"):
            value = self.fixture()
            if change == "body":
                value[1][0]["requestSha256"] = "f" * 64
            elif change == "raw":
                value[2].append(copy.deepcopy(value[2][0]))
            elif change == "workload":
                value[0]["workloadProcess"] = {**value[0]["workloadProcess"], "pid": 201}
            elif change == "original":
                value[2][1]["original"]["issuerProcessSha256"] = "e" * 64
            else:
                value[1][0]["completedUnixNs"] = 351
            with self.subTest(change=change):
                self.assertIsNone(self.project(value)["loadedCpuBudgetSatisfied"])

    def test_handshake_order_and_nonce_are_closed_before_sampling(self):
        interval, rows, records, issuer, workload, pins = self.fixture()
        MAIN["_scale_validate_cpu_request"](records[0]["original"], pins, [])
        MAIN["_scale_validate_cpu_request"](records[1]["original"], pins, records[:1])
        for field, new in (("sequence", 2), ("nonce", records[0]["original"]["nonce"]),
                ("waveOriginalsSha256", "f" * 64), ("issuerPid", 101)):
            altered = {**records[1]["original"], field: new}
            with self.subTest(field=field), self.assertRaises(ValueError):
                MAIN["_scale_validate_cpu_request"](altered, pins, records[:1])

    def test_atomic_private_handshake_never_replaces_a_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cpu-request-00.json"
            value = {"nonce": "1" * 32}
            PROCESS["scale_publish_private"](path, value)
            self.assertEqual(json.loads(PROCESS["scale_private_bytes"](path, 65536)), value)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                PROCESS["scale_publish_private"](path, {"nonce": "2" * 32})
            self.assertEqual(json.loads(path.read_bytes()), value)
            self.assertEqual(list(Path(directory).glob('.cpu-*')), [])

    def test_runtime_wraps_exact_wave_once_and_retains_independent_handshakes(self):
        _, rows, _, issuer, _, _ = self.fixture()
        calls = [{"original": row["original"], "worker": {"isolateLabel": row["isolateLabel"]},
            "offeredIndex": row["offeredIndex"], "wave": row["wave"]} for row in rows]
        invoked, requests = [], []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            PROCESS["scale_write_private"](root / 'key', b'k' * 32)
            selected = {"root": str(root), "run_id": "1" * 32, "source_digest": "2" * 64,
                "issuer": {"pid": 100, "startTicks": "10"}, "issuerProcessSha256": "3" * 64,
                "workers": [], "cohort_digests": [], "keyFile": str(root / 'key'), "capped": True}

            def publish(path, value):
                PROCESS["scale_publish_private"](path, value)
                requests.append(value)
                # Explicit unit endpoint, not actual issuer/CPU evidence.
                acknowledgment = {"original": value, "sample": {"outcome": "unknown", "reason": "unit_stub"}}
                PROCESS["scale_publish_private"](root / f"cpu-ack-{value['sequence']:02}.json", acknowledgment)

            process = {**PROCESS, "scale_publish_private": publish}
            async def actual_wave(actual, key):
                self.assertIs(actual, calls)
                self.assertEqual(key, b'k' * 32)
                invoked.append(actual)
                await asyncio.sleep(0)
                return rows

            workload = {"run_scale_wave": actual_wave}
            async def profile(**arguments):
                await workload["run_scale_wave"](calls, arguments['key'])
                return {"waves": [{"wave": "cold"}]}

            workload["run_scale_cap"] = profile
            asyncio.run(RUNTIME["execute_scale_runtime"](selected, process, workload))
            result = json.loads((root / 'result.json').read_bytes())
            self.assertEqual(len(invoked), 1)
            self.assertEqual([row['phase'] for row in requests], ['start', 'end'])
            self.assertEqual(result['loadedCpuWaves'][0]['start']['original'], requests[0])
            self.assertEqual(result['loadedCpuWaves'][0]['end']['original'], requests[1])
            self.assertLessEqual(requests[0]['requestedUnixNs'], result['loadedCpuWaves'][0]['startedUnixNs'])
            self.assertGreaterEqual(requests[1]['requestedUnixNs'], result['loadedCpuWaves'][0]['completedUnixNs'])

    def test_actual_readonly_process_sample_rechecks_selected_inputs(self):
        # This is an actual local Python process, not a genuine Native issuer.
        identity = PROCESS["scale_process_identity"](os.getpid())
        allocation = PROCESS["scale_cpu_allocation"](os.getpid())
        selected = {**identity, **allocation, "role": "issuer", "selectedFiles": {
            PYTHON: hashlib.sha256(Path(PYTHON).read_bytes()).hexdigest()}}
        before = PROCESS["scale_sample_process_cpu"](selected)
        for _ in range(10000):
            hashlib.sha256(b'actual local test CPU').digest()
        after = PROCESS["scale_sample_process_cpu"](selected)
        self.assertEqual(before["outcome"], "observed")
        self.assertEqual(after["outcome"], "observed")
        self.assertGreaterEqual(after["userTicks"], before["userTicks"])
        selected["selectedFiles"][PYTHON] = "f" * 64
        self.assertEqual(PROCESS["scale_sample_process_cpu"](selected)["outcome"], "unknown")


class FinalPolicyTests(unittest.TestCase):
    """Exercise real consumer code with explicitly supplied source-test evidence."""

    def fixture(self, case="ttl-8"):
        lifetime = 8 if case == "ttl-8" else 120
        contexts = [{"isolateLabel": f"{index:032x}", "configurationDigest": "4" * 64,
            "sourceDigest": "1" * 64, "runId": "2" * 32} for index in range(4)]
        cohorts = [f"{index:064x}" for index in range(32)]
        if case == "cap-120":
            schedule = [("cap-candidate", 200), ("cap-expired", 251)]
            stopped, cap = 253, 250
        else:
            schedule = [("cold", 100), ("reuse-candidate", 101),
                ("renewal-candidate-1", 132), ("renewal-candidate-2", 164),
                ("outage-00", 166), ("outage-01", 297)]
            stopped, cap = 166, 1000
        issuer = {"pid": 7, "startTicks": "8", "processRoot": "/actual-unit-root", "allocatedMillicores": 1000}
        terminal = {"pid": 7, "startTicks": "8", "resourceRoot": issuer["processRoot"],
            "exitCode": 0, "completedUnixNs": stopped * 10**9}
        calls, owners, waves, cpu, requests = [], {}, [], [], {}
        for phase_index, (name, at) in enumerate(schedule):
            rows = []
            positive = name in JOINS["SCALE_POSITIVE_PHASES"] or name == "cap-candidate"
            for context_index, context in enumerate(contexts):
                for cohort_index, cohort in enumerate(cohorts):
                    group = context_index * 32 + cohort_index
                    owner_phase = 0 if name == "reuse-candidate" else phase_index
                    identity = (owner_phase, group)
                    if positive and identity not in owners:
                        owner = f"{1000000 + owner_phase * 128 + group:064x}"
                        issued = schedule[owner_phase][1]
                        lease = f"{2000000 + owner_phase * 128 + group:064x}"
                        observed = {"queueWaitNs": 1, "wallNs": 10, "outcome": "success",
                            "signatures": [{"purpose": purpose, "threadCpuNs": 1, "wallNs": 2} for purpose in ("lease", "reply")],
                            "commits": [{"kind": "lease", "outcome": "acknowledged"}]}
                        checked = {"leaseDigest": lease, "issuedAt": issued,
                            "notAfter": cap if case == "cap-120" else issued + lifetime, "leaseSequence": owner_phase + 1}
                        item = {"ownerNonce": owner, "outcome": "verified_acknowledged_issuance", "native": observed,
                            "dispatch": {"ownerNonce": owner, "isolateLabel": context["isolateLabel"],
                                "cohortDigest": cohort, "issuedAt": issued}, "verified": checked}
                        owners[identity] = item
                        calls.append(item)
                        requests[owner] = observed
                    for offered in range(33):
                        original = {"version": 1, "run_id": context["runId"],
                            "nonce": f"{phase_index * 4224 + group * 33 + offered:064x}",
                            "source_digest": context["sourceDigest"], "configuration_digest": context["configurationDigest"],
                            "cohort_digest": cohort, "issued_at": at, "expires_at": at + 30}
                        body = json.dumps(original, separators=(",", ":")).encode()
                        digest = hashlib.sha256(body).hexdigest()
                        reply = None
                        if positive:
                            reply = {**owners[identity]["verified"], "version": 1,
                                "runId": context["runId"], "nonce": original["nonce"], "requestSha256": digest,
                                "sourceDigest": context["sourceDigest"], "configurationDigest": context["configurationDigest"],
                                "cohortDigest": cohort, "isolateLabel": context["isolateLabel"],
                                "maximumLifetime": lifetime, "clockUncertainty": 2, "attestationValidUntil": cap}
                        rows.append({"original": original, "wave": name, "offeredIndex": offered,
                            "isolateLabel": context["isolateLabel"], "requestSha256": digest,
                            "requestBodyBytesOffered": len(body), "startedUnixNs": at * 10**9,
                            "completedUnixNs": at * 10**9 + 1000000,
                            "httpStatus": 200 if positive else 409,
                            "outcome": "authenticated_probe_metadata" if positive else "http_refused", "reply": reply})
            offered_rows = [{field: row[field] for field in ("original", "isolateLabel", "offeredIndex", "wave")} for row in rows]
            digest = hashlib.sha256(json.dumps(offered_rows, separators=(",", ":")).encode()).hexdigest()
            cpu.append({"wave": name, "outcome": "observed" if positive or case == "cap-120" else "unknown",
                "normalizedUpperBound": {"numerator": 1, "denominator": 10},
                "loadedCpuBudgetSatisfied": True if positive or case == "cap-120" else None, "waveOriginalsSha256": digest})
            waves.append((name, rows))
        native = {"requests": requests, "wholeProcessCpuNs": 1, "wholeProcessWindowWallNs": 100,
            "missingSigningCpuSamples": 0, "signatures": {}, "commits": {}}
        return [case, waves, contexts, cohorts, {"calls": calls}, native,
            {"waves": cpu, "loadedCpuBudgetSatisfied": None}, {"issuerTerminalReceipt": terminal},
            issuer, terminal, cap, {name: "sha256:" + "a" * 64 for name in ("measurement", "waves", "publication")}]

    def assess(self, inputs):
        return JOINS["scale_case_policy_assessment"](*inputs)

    def test_fixed_schedules_accept_required_facts_without_changing_outage_unknown(self):
        for case in ("ttl-8", "ttl-120", "cap-120"):
            with self.subTest(case=case):
                inputs = self.fixture(case)
                before = copy.deepcopy(inputs[6])
                result = self.assess(inputs)
                self.assertEqual(result["status"], "satisfied", result)
                self.assertIsNone(result["qualification"])
                self.assertEqual(inputs[6], before)

    def test_positive_cpu_missing_and_failed_budget_cannot_use_serving_average(self):
        inputs = self.fixture()
        inputs[6]["waves"][0]["outcome"] = "unknown"
        self.assertEqual(self.assess(inputs)["status"], "unknown")
        inputs[6]["waves"][0].update(outcome="observed", normalizedUpperBound={"numerator": 6, "denominator": 10}, loadedCpuBudgetSatisfied=False)
        self.assertEqual(self.assess(inputs)["status"], "failed")

    def test_actual_latency_failure_missing_warm_and_signing_queue_samples(self):
        inputs = self.fixture()
        inputs[4]["calls"][0]["native"]["wallNs"] = 2_000_000_000
        # All cold samples must fail, rather than hiding one in a percentile.
        for row in inputs[4]["calls"][:128]:
            row["native"]["wallNs"] = 2_000_000_000
        self.assertEqual(self.assess(inputs)["status"], "failed")
        for row in inputs[4]["calls"]:
            row["native"]["wallNs"] = None
        self.assertEqual(self.assess(inputs)["status"], "unknown")
        inputs = self.fixture()
        inputs[4]["calls"][0]["native"]["signatures"][0]["threadCpuNs"] = None
        self.assertEqual(self.assess(inputs)["status"], "unknown")
        inputs = self.fixture()
        inputs[4]["calls"][0]["native"]["queueWaitNs"] = None
        self.assertEqual(self.assess(inputs)["status"], "unknown")

    def test_unconsumed_actual_positive_work_still_enters_latency_budget(self):
        inputs = self.fixture()
        for index in range(128):
            item = copy.deepcopy(inputs[4]["calls"][-128 + index])
            item["ownerNonce"] = f"{3000000 + index:064x}"
            item["dispatch"]["ownerNonce"] = item["ownerNonce"]
            item["dispatch"]["issuedAt"] += 1
            item["verified"]["leaseDigest"] = f"{4000000 + index:064x}"
            item["native"]["wallNs"] = 2_000_000_000
            inputs[4]["calls"].append(item)
            inputs[5]["requests"][item["ownerNonce"]] = item["native"]
        self.assertEqual(self.assess(inputs)["status"], "failed")

    def test_missing_actual_warm_and_acknowledged_commit_stay_unresolved(self):
        inputs = self.fixture()
        for item in inputs[4]["calls"][128:]:
            item["native"]["wallNs"] = None
        self.assertEqual(self.assess(inputs)["status"], "unknown")
        inputs = self.fixture()
        inputs[4]["calls"][0]["native"]["commits"][0]["outcome"] = "unknown"
        self.assertEqual(self.assess(inputs)["status"], "failed")

    def test_cap_expired_requires_live_cpu_refusal_and_independent_bound(self):
        inputs = self.fixture("cap-120")
        inputs[6]["waves"][1]["outcome"] = "unknown"
        self.assertEqual(self.assess(inputs)["status"], "unknown")
        inputs = self.fixture("cap-120")
        inputs[1][1][1][0].update(outcome="unknown", httpStatus=None)
        self.assertEqual(self.assess(inputs)["status"], "failed")
        inputs = self.fixture("cap-120")
        inputs[10] += 1
        self.assertNotEqual(self.assess(inputs)["status"], "satisfied")
        inputs = self.fixture("cap-120")
        inputs[9]["completedUnixNs"] = 250 * 10**9
        self.assertEqual(self.assess(inputs)["status"], "failed")

    def test_source_body_duplicate_geometry_and_wrong_token_refuse(self):
        for field, value in (("requestSha256", "f" * 64), ("offeredIndex", 1), ("isolateLabel", "f" * 32)):
            inputs = self.fixture()
            inputs[1][0][1][0][field] = value
            self.assertEqual(self.assess(inputs)["status"], "unknown")
        inputs = self.fixture()
        inputs[1][0][1][0]["reply"]["nonce"] = "f" * 64
        self.assertEqual(self.assess(inputs)["status"], "unknown")
        inputs = self.fixture()
        inputs[4]["calls"].pop()
        self.assertEqual(self.assess(inputs)["status"], "unknown")

    def test_missing_phases_and_final_http200_do_not_pass(self):
        inputs = self.fixture()
        inputs[1].pop(1)
        self.assertEqual(self.assess(inputs)["status"], "failed")
        inputs = self.fixture()
        inputs[1][-1][1][0].update(outcome="unknown", httpStatus=200)
        self.assertEqual(self.assess(inputs)["status"], "failed")
        inputs = self.fixture()
        inputs[9]["completedUnixNs"] = 170 * 10**9
        self.assertEqual(self.assess(inputs)["status"], "failed")

    def test_caller_retains_failure_unknown_and_requires_all_three_satisfied(self):
        captured = []
        namespace = dict(MAIN)
        namespace["retain_direct_flow"] = lambda name, value: captured.append((name, copy.deepcopy(value)))
        exec(compile(ROOT.joinpath('_hub-direct-issuer-scale-main.py').read_bytes(), 'main', 'exec'), namespace)
        for state in ("failed", "unknown"):
            report = {"cases": [{"case": case, "policyAssessment": {"case": case, "status": state}}
                for case in ("ttl-8", "ttl-120", "cap-120")], "qualification": None}
            before = copy.deepcopy(report)
            with self.assertRaisesRegex(RuntimeError, state):
                namespace["_scale_finish_window"](report)
            self.assertEqual(report, before)
            self.assertEqual(captured[-1][1]["status"], state)
        report = {"cases": [{"case": case, "policyAssessment": {"case": case, "status": "satisfied"}}
            for case in ("ttl-8", "ttl-120", "cap-120")], "qualification": None}
        self.assertEqual(namespace["_scale_finish_window"](report)["localPolicyAssessment"]["status"], "satisfied")
        report["cases"].pop()
        with self.assertRaisesRegex(RuntimeError, "unknown"):
            namespace["_scale_finish_window"](report)



if __name__ == "__main__":
    unittest.main()
