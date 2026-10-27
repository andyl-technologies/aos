"""Checks actual API returns against coherently observed stock-kernel bases."""

import argparse
import copy

READS = [f"{batch}-{clock}" for batch in range(2)
         for clock in ("realtime", "monotonic", "gettimeofday", "tsc")]
FIELDS = ("version", "sequence", "mode", "cycle_last", "max_cycles", "mask",
          "multiplier", "shift", "realtime_seconds", "realtime_shifted_ns",
          "monotonic_seconds", "monotonic_shifted_ns", "tsc_before", "tsc_after",
          "retries", "sequence_after")
U64_MAX = 2**64 - 1
S64_MAX = 2**63 - 1
NS_PER_SECOND = 1_000_000_000


def kernel_base(read):
    """Decodes the private fixture vector without selecting an offset or rate."""
    words = read.get("vvar")
    if (not isinstance(words, list) or len(words) != len(FIELDS)
            or any(type(value) is not int or not 0 <= value <= U64_MAX for value in words)):
        raise ValueError("missing or malformed published kernel runtime anchor")
    base = dict(zip(FIELDS, words))
    if (base["version"] != 1 or base["mode"] != 1 or base["sequence"] > 2**32 - 1
            or base["sequence"] & 1 or base["sequence_after"] != base["sequence"]
            or base["retries"] >= 16 or base["mask"] != U64_MAX
            or not 0 < base["multiplier"] <= 2**32 - 1 or base["shift"] > 32
            or not 0 < base["max_cycles"] <= U64_MAX
            or not 0 <= base["cycle_last"] <= base["tsc_before"] <= base["tsc_after"] <= S64_MAX
            or base["tsc_after"] - base["cycle_last"] > base["max_cycles"]):
        raise ValueError("unsupported VVAR generation, mode or x86 conversion branch")
    for clock in ("realtime", "monotonic"):
        if (base[f"{clock}_seconds"] > S64_MAX
                or base[f"{clock}_shifted_ns"] >= NS_PER_SECOND << base["shift"]):
            raise ValueError("published kernel clock base is not normalized")
    return base


def published_ns(base, clock, cycles):
    """Uses the audited x86 vDSO branch with its observed integer parameters."""
    delta = cycles - base["cycle_last"]
    shifted = delta * base["multiplier"] + base[f"{clock}_shifted_ns"]
    # Overflow/negative motion need different kernel branches. Do not turn an
    # unsupported observation into a replacement conversion implementation.
    if shifted > U64_MAX:
        raise ValueError("unsupported x86 vDSO multiplication overflow")
    return base[f"{clock}_seconds"] * NS_PER_SECOND + (shifted >> base["shift"])


def validate(evidence):
    """Binds the observed kernel conversion to each original API/TSC bracket."""
    if not isinstance(evidence, list) or len(evidence) != 2:
        raise ValueError("expected two original fresh clock-read runs")
    for run in evidence:
        if [read["instance"] for read in run["reads"]] != READS:
            raise ValueError("missing or reordered original read returns")
        for read in run["reads"]:
            base = kernel_base(read)
            before, after = read["before_ps"], read["after_ps"]
            if (type(before) is not int or type(after) is not int
                    or not 0 <= before < after <= U64_MAX):
                raise ValueError("invalid original canonical read bracket")
            for counter in (base["tsc_before"], base["tsc_after"]):
                lower_ps = counter * 250
                if lower_ps > U64_MAX - 249 or lower_ps > after or lower_ps + 249 < before:
                    raise ValueError("observer TSC read does not bind its original canonical bracket")

            clock = read["instance"].split("-", 1)[1]
            seconds, fraction, value = read["seconds"], read["fraction"], read["value"]
            if any(type(item) is not int for item in (seconds, fraction, value)):
                raise ValueError("original API return is not integral")
            if clock == "tsc":
                if (seconds != 0 or fraction != 0 or read["unit"] != "cycles"
                        or not base["tsc_before"] <= value <= base["tsc_after"]):
                    raise ValueError("original TSC return differs from its observed kernel interval")
                continue

            quantum_ns = 1000 if clock == "gettimeofday" else 1
            expected_unit = "microseconds" if quantum_ns == 1000 else "nanoseconds"
            if (not 0 <= seconds <= S64_MAX or not 0 <= fraction < NS_PER_SECOND // quantum_ns
                    or value != 0 or read["unit"] != expected_unit):
                raise ValueError("original Linux API bucket is not normalized")
            kernel_clock = "realtime" if clock == "gettimeofday" else clock
            lower_ns = published_ns(base, kernel_clock, base["tsc_before"])
            upper_ns = published_ns(base, kernel_clock, base["tsc_after"])
            returned_ns = seconds * NS_PER_SECOND + fraction * quantum_ns
            if returned_ns > upper_ns or returned_ns + quantum_ns <= lower_ns:
                raise ValueError(f"published kernel conversion refused instance={read['instance']} "
                                 f"returned_ns={returned_ns} bucket_ns={quantum_ns} "
                                 f"kernel_ns=[{lower_ns},{upper_ns}] "
                                 f"multiplier={base['multiplier']} shift={base['shift']}")


def self_test():
    # Distinct wall/monotonic bases are intentional, not a QEMU unit defect.
    evidence = []
    for pid in (100, 200):
        reads = []
        for batch in range(2):
            returns = [(1000 + batch, 25, 0, "nanoseconds"),
                       (7 + batch, 60, 0, "nanoseconds"),
                       (1000 + batch, 0, 0, "microseconds"),
                       (0, 0, 1350 + batch * 4_000_000_000, "cycles")]
            for index, (seconds, fraction, value, unit) in enumerate(returns):
                counter = 1040 + index * 100 + batch * 4_000_000_000
                words = [1, 2, 1, 1000, 8_000_000_000, U64_MAX, 4, 4,
                         1000, 160, 7, 320, counter, counter + 40, 0, 2]
                reads.append({"instance": READS[batch * 4 + index], "vvar": words,
                              "before_ps": (counter - 10) * 250, "after_ps": (counter + 50) * 250,
                              "seconds": seconds, "fraction": fraction, "value": value, "unit": unit})
        evidence.append({"pid": pid, "reads": reads})
    validate(evidence)

    # A different observed conversion remains valid when the actual API agrees;
    # this is published-kernel consistency, not a nominal-frequency assertion.
    different_rate = copy.deepcopy(evidence)
    for run in different_rate:
        for index, read in enumerate(run["reads"]):
            read["vvar"][6] = 8
            batch, clock = divmod(index, 4)
            if clock == 0:
                read.update(seconds=1000 + batch * 2, fraction=40)
            elif clock == 1:
                read.update(seconds=7 + batch * 2, fraction=100)
            elif clock == 2:
                read.update(seconds=1000 + batch * 2)
    validate(different_rate)

    def word(index, value):
        return lambda read: read["vvar"].__setitem__(index, value)

    changes = [
        ("missing anchor", lambda read: read.pop("vvar")),
        ("layout", word(0, 2)), ("odd generation", word(1, 3)),
        ("changed generation", word(15, 4)), ("clock mode", word(2, 0)),
        ("conversion scale", word(6, 4000)), ("base epoch", word(8, 1001)),
        ("per-clock base", word(9, 160_000)), ("retry exhaustion", word(14, 16)),
        ("negative motion", word(3, 1041)), ("overflow branch", word(4, 1)),
        ("non-normalized base", word(9, NS_PER_SECOND << 4)),
        ("non-integral anchor", word(6, True)),
        ("canonical bracket", lambda read: read.update(before_ps=1, after_ps=2)),
        ("API bucket", lambda read: read.update(fraction=10000)),
        ("half-open API bucket", lambda read: read.update(fraction=19)),
        ("API unit", lambda read: read.update(unit="microseconds")),
    ]
    for name, change in changes:
        altered = copy.deepcopy(evidence)
        change(altered[0]["reads"][0])
        try:
            validate(altered)
        except ValueError:
            continue
        raise AssertionError(f"accepted invalid published kernel {name}")
    print(f"PASS published-kernel runtime parser positive=2 refusal={len(changes)} (schema fixtures only)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true", required=True)
    parser.parse_args()
    self_test()
