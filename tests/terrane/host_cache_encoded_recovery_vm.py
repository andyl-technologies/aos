"""Exercises genuine cold encoded recovery before and after acknowledged Resume."""

import os
import re
import struct
import time
import tomllib

from encoded_eviction_vm import Original
from source_cleanup_vm import files, quota


CASES = ["encoded-recovery", "encoded-cold", "encoded-corrupt", "encoded-duplicate",
         "encoded-missing-dictionary", "encoded-unknown", "encoded-sealed", "encoded-old-range",
         "encoded-metadata", "encoded-metadata-only", "encoded-data-pack",
         "encoded-packed-manifest", "encoded-packed-manifest-bad-whole"]


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
        recovers = case in {"encoded-recovery", "encoded-cold", "encoded-sealed", "encoded-metadata", "encoded-metadata-only", "encoded-data-pack",
                            "encoded-packed-manifest", "encoded-packed-manifest-bad-whole"}
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
            if case == "encoded-packed-manifest-bad-whole":
                witness = "PASS actual packed manifest rejects a wrong whole-file hash while retaining original pairs and durable copy funding; no Ready"
            elif case == "encoded-packed-manifest":
                witness = "PASS actual packed manifest verifies repeated dictionary-backed chunks and whole-file hashes, publishes immutable ranges and releases private pair reads under durable container grace without standalone extraction; no Ready"
            elif case == "encoded-metadata-only":
                witness = "original pair registered after Resume"
            else:
                witness = "original inodes served under durable consumer pins"
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
            if case.startswith("encoded-packed-manifest"):
                check_packed_manifest(vm, case, before, new)

        if case == "encoded-data-pack":
            retire_data_pack(vm, uuid, check_recovery)
        else:
            check_recovery(vm.actor(case, "recover-encoded" if recovers else "refuse-encoded", uuid))
    print("PASS actual cold encoded recovery, original consumer custody and refusal controls", flush=True)


def check_packed_manifest(vm, case, originals, state):
    """Compares the actual sealed ranges with original pack records and raw bodies."""
    packs = {}
    vm.require(len(originals) == 4, "packed manifest seed lost its two original pairs")
    for path, (_, _, packed) in originals.items():
        if path.suffix != ".pack":
            continue
        offset = struct.unpack_from("<Q", packed, len(packed) - 16)[0]
        count = struct.unpack_from("<Q", packed, offset + 4)[0]
        vm.require(packed[:6] == b"TRPK\x01\x00" and packed[-4:] == b"TRPE"
                   and 24 <= offset < len(packed) - 16
                   and packed[offset:offset + 4] == b"TRIX" and 0 < count <= 3
                   and len(packed) - 16 == offset + 12 + 56 * count
                   and originals[path.with_suffix(".idx")][2] == packed[:24] + packed[offset:-16],
                   "packed manifest observer lost original version-one format bindings")
        records = []
        for index in range(count):
            record = packed[offset + 12 + 56 * index:offset + 12 + 56 * (index + 1)]
            start, encoded, length, codec, kind = struct.unpack_from("<QIIBB", record, 32)
            vm.require(24 <= start < start + encoded <= offset and record[50:] == bytes(6),
                       "packed manifest observer found an invalid original record")
            records.append({"hash": record[:32].hex(), "length": length, "codec": codec,
                            "kind": kind, "body": packed[start:start + encoded]})
        meta = bool(struct.unpack_from("<H", packed, 6)[0] & 2)
        vm.require(meta not in packs, "packed manifest duplicated its original pack class")
        packs[meta] = records
    vm.require(set(packs) == {False, True} and len(packs[True]) == 1
               and len(packs[False]) == 3 and all(row["kind"] == 0 for row in packs[False]),
               "packed manifest observer lacks original metadata or dictionary closure")
    root = vm.root(case)
    bodies = list((root / "sealed").glob("*/*"))
    vm.require(not list((root / "chunks").glob("*/*"))
               and not list((root / "pending-delete").iterdir()),
               "packed manifest invented standalone extraction or retirement")
    if case.endswith("-bad-whole"):
        vm.require(not bodies and not state["residences"] and state["reservations"]
                   and any(row["owner"].startswith("publication:") for row in state["pins"]),
                   "wrong whole-file packed control lost real funded refusal")
        return

    raw = sorted((row for row in packs[False] if row["codec"] == 0),
                 key=lambda row: row["length"])
    encoded = [row for row in packs[False] if row["codec"] == 2]
    vm.require(len(raw) == 2 and len(encoded) == 1
               and all(row["body"][0] == 0 and len(row["body"]) == row["length"] + 1 for row in raw)
               and encoded[0]["body"][:33] == b"\x02" + bytes.fromhex(raw[1]["hash"]),
               "packed manifest observer lost the actual original dictionary envelope")
    tail, dictionary = raw[0]["body"][1:], raw[1]["body"][1:]
    # Identify the bounded fixture seed from the original raw dictionary, never
    # from the published output or an actor-reported plaintext hash.
    prefixes = []
    for seed in range(1, 513):
        generator = seed
        sample = bytearray()
        for _ in range(17):
            generator ^= (generator << 13) & ((1 << 64) - 1)
            generator ^= generator >> 7
            generator ^= (generator << 17) & ((1 << 64) - 1)
            sample.append(generator & 255)
        if sample[1:] == dictionary[:16]:
            prefixes.append(sample[:1])
    vm.require(len(prefixes) == 1, "original packed dictionary lacks a unique fixture prefix")
    first = bytes(prefixes[0]) + dictionary
    expected = first + first + tail
    vm.require(len(bodies) == 1 and bodies[0].name == packs[True][0]["hash"]
               and encoded[0]["length"] == len(first) and bodies[0].read_bytes() == expected
               and vm.kernel_seal(bodies[0]) is not None,
               "packed manifest differs from original records, bytes or actual kernel seal")
    observer = Original(vm, case, bodies[0], 841)
    try:
        observer.check(1)
    finally:
        observer.close()
    vm.require(sorted(state["residences"], key=lambda row: row["chunk"]) == sorted([
        {"chunk": encoded[0]["hash"], "object": bodies[0].name, "offset": 0, "length": len(first)},
        {"chunk": raw[0]["hash"], "object": bodies[0].name, "offset": 2 * len(first), "length": len(tail)},
    ], key=lambda row: row["chunk"]), "packed manifest ranges lost original repeated-chunk positions")
    print("PASS independent observer matches sealed packed-manifest bytes, ranges and kernel seal to original dictionary and metadata records", flush=True)


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
