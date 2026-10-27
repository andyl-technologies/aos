"""Exercises genuine cold encoded recovery before and after acknowledged Resume."""

import os
import re
import time
import tomllib

from encoded_eviction_vm import Original
from source_cleanup_vm import files, quota


CASES = ["encoded-recovery", "encoded-cold", "encoded-corrupt", "encoded-duplicate",
         "encoded-missing-dictionary", "encoded-unknown", "encoded-sealed", "encoded-old-range",
         "encoded-metadata", "encoded-metadata-only", "encoded-data-pack"]


def seed(vm, uuid):
    """Creates untrusted candidates before either native role starts."""
    for case in CASES:
        result = vm.run(vm.admin_command(vm.SEED_CAPS,
                        [vm.IMAGE / "bin/host_cache_fixture", "seed-encoded"]),
                        env=vm.actor_environment(case, uuid), text=True, capture_output=True)
        vm.require(result.stdout.splitlines() == [
            "SEEDED cold encoded candidates; no recovery or serving authority"],
            "missing cold encoding seed witness: " + case)
    # Ordinary cold policy is candidate data, never a native pin receipt. The
    # physical owner must reconcile this exact identity against verified bytes.
    raw = sorted((vm.root("encoded-cold") / "chunks").glob("*/*.0"))[0]
    path = vm.root("encoded-cold") / "state/cache/records.toml"
    path.write_text('version = 1\nresidences = []\n'
                    '[[pins]]\nowner = "cold-encoded"\nhash = "' + raw.stem + '"\n'
                    'expires = 9223372036854775807\n'
                    '[[leases]]\nowner = "cold-encoded"\nexpires = 9223372036854775807\n'
                    '[[reservations]]\nid = "' + 'a' * 32 + '"\nowner = "' + vm.owner("encoded-cold")
                    + '"\nbytes = 262144\n')
    vm.metadata(path, 840, 844, 0o640)
    with path.open("rb") as file:
        os.fsync(file.fileno())
    # This contradictory cold range was never durably removed. A valid sealed
    # body and standalone encoding cannot authorize recovery to erase that row.
    sealed = next(path for path in (vm.root("encoded-old-range") / "sealed").glob("*/*")
                  if path.is_file())
    path = vm.root("encoded-old-range") / "state/cache/records.toml"
    path.write_text('version = 1\npins = []\nleases = []\nreservations = []\n'
                    '[[residences]]\nchunk = "' + sealed.name + '"\nobject = "' + sealed.name
                    + '"\noffset = 0\nlength = ' + str(sealed.stat().st_size) + '\n')
    vm.metadata(path, 840, 844, 0o640)
    with path.open("rb") as file:
        os.fsync(file.fileno())


def run(vm, uuid):
    """Checks real consumer reads, unchanged source inodes and retained cold promises."""
    for case in CASES:
        recovers = case in {"encoded-recovery", "encoded-cold", "encoded-sealed", "encoded-metadata", "encoded-metadata-only", "encoded-data-pack"}
        sources = list((vm.root(case) / "chunks").glob("*/*")) + list((vm.root(case) / "objects/pack").glob("*/*"))
        before = {path: (path.stat().st_dev, path.stat().st_ino, path.read_bytes())
                  for path in sources if path.is_file()}
        policy = vm.root(case) / "state/cache/records.toml"
        old = tomllib.loads(policy.read_text()) if policy.exists() else None
        def check_recovery(output):
            if case == "encoded-data-pack":
                vm.require(output.splitlines().count(
                    "PASS actual verified pack extraction preserves original envelopes, descriptors and cursor without admission or Resume") == 1,
                    "missing genuine native pack extraction witness")
                vm.require(output.splitlines().count(
                    "PASS cold data pack serves original raw and nested dictionary envelopes through actual consumer pins without standalone extraction") == 1,
                    "missing original data-pack consumer witness")
            witness = ("original pair registered after Resume" if case == "encoded-metadata-only"
                       else "original inodes served under durable consumer pins")
            vm.require((witness in output) if recovers
                       else ("unresolved cold encoding refused; no Resume" in output),
                       "cold encoding recovery witness missing: " + case)
            vm.require(all(path.exists() and (path.stat().st_dev, path.stat().st_ino, path.read_bytes()) == original
                           for path, original in before.items()),
                       "cold encoding recovery changed original source: " + case)
            new = tomllib.loads(policy.read_text())
            vm.require(old is None or all(row in new[group] for group in ["pins", "leases", "reservations", "residences"]
                                          for row in old.get(group, [])),
                       "cold encoding recovery discarded old policy: " + case)

        if case == "encoded-data-pack":
            retire_data_pack(vm, uuid, check_recovery)
        else:
            check_recovery(vm.actor(case, "recover-encoded" if recovers else "refuse-encoded", uuid))
    print("PASS actual cold encoded recovery, original consumer custody and refusal controls", flush=True)


def retire_data_pack(vm, uuid, check_recovery):
    """Checks actual paired retirement and charge through final observer closure."""
    case = "encoded-data-pack"
    root = vm.root(case)
    policy = root / "state/cache/records.toml"
    process = vm.controlled_actor(case, "recover-encoded", uuid)
    lines = vm.Lines(process)
    originals = []

    def control(value):
        process.stdin.write((value + "\n").encode())
        process.stdin.flush()

    def measurement(kind):
        matches = re.findall(
            rf"^ENCODED_EVICTION_MEASUREMENT kind={kind} charged=(\d+) future=(\d+)$",
            lines.bytes.decode(), re.M)
        vm.require(len(matches) == 1, "missing original data-pack quota observation")
        charged, future = map(int, matches[0])
        state = tomllib.loads(policy.read_text())
        vm.require(quota(vm, case) == charged
                   and sum(row["bytes"] for row in state["reservations"]) == future,
                   "data-pack measurement differs from actual kernel charge or durable funding")
        return charged, future, state["reservations"]

    try:
        lines.until("READY original data pack and independent standalone consumers retain actual grace", timeout=30)
        check_recovery(lines.bytes.decode())
        paths = sorted((root / "objects/pack").glob("*/*"))
        vm.require(len(paths) == 2 and {path.suffix for path in paths} == {".idx", ".pack"},
                   "data-pack observer lacks the exact original pair")
        for path in paths:
            originals.append(Original(vm, case, path, 840))
        matches = re.findall(r"^PACKED_PAIR_GRACE expires=(\d+) allocated=(\d+)$",
                             lines.bytes.decode(), re.M)
        vm.require(len(matches) == 1, "missing original data-pack grace")
        deadline, allocated = map(int, matches[0])
        vm.require(allocated == sum(member.allocated for member in originals),
                   "data-pack unit allocation differs from both original inodes")
        wait = deadline - time.time() + 3
        vm.require(0 < wait <= 35, "data pack lost its actual bounded consumer grace")
        time.sleep(wait)
        control("retire-data-pack")
        lines.until("READY original whole data pack retires as one unit with both descriptions retained", timeout=30)
        vm.require(all(not original.path.exists() for original in originals)
                   and sorted(files(root / "pending-delete").values()) == sorted(original.key for original in originals),
                   "whole-data-pack retirement did not preserve exactly both original members")
        for original in originals:
            original.check(1)
        time.sleep(1)
        for original in originals:
            original.check(1)
        time.sleep(31)
        stop = time.monotonic() + 5
        while files(root / "pending-delete"):
            vm.require(process.poll() is None and time.monotonic() < stop,
                       "original data-pack paired removal did not complete")
            time.sleep(0.05)
        for original in originals:
            original.check(0)

        control("close-data-pack-actor")
        lines.until("READY actor data pack descriptions closed while independent observers retain charge", timeout=30)
        held, future, reservations = measurement("data-pack-held")
        for original in originals:
            original.close()
        control("data-pack-observers-closed")
        lines.until("READY independent standalone consumers survive actual whole data pack charge release", timeout=30)
        closed, remaining, final_reservations = measurement("data-pack-closed")
        vm.require(closed <= held - allocated and future == remaining
                   and reservations == final_reservations,
                   "whole-data-pack charge was not released only after original descriptions closed")
        control("finish-data-pack")
        output, _ = process.communicate(timeout=30)
        print(output.decode(), end="", flush=True)
        complete = (lines.bytes + output).decode()
        vm.require(process.returncode == 0 and complete.splitlines().count(
            "PASS actual whole data pack retires as one native pair and preserves independent consumer custody") == 1,
            "original data-pack actor did not finish its real lifecycle")
        print("PASS independent data-pack observer verifies original paired retirement, last-description quota release and unchanged funding", flush=True)
    finally:
        for original in originals:
            original.close()
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
