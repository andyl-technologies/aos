"""Reject compiled source lifetime regressions through the actual held callback."""

from pathlib import Path
import subprocess
import sys


MUTATIONS = {
    "clock-native-boundary": (
        "accel/kvm/kvm-all.c",
        "    if (!kvm_crucible_response_service_allow_clock_ioctl(s, type, arg)) {",
        "    if (false) {",
    ),
    "clock-mutation-without-BQL": (
        "accel/kvm/crucible-clock.c",
        "    return bql_locked() &&\n        !qatomic_load_acquire(&state->crucible_response_service_active);",
        "    return !qatomic_load_acquire(&state->crucible_response_service_active);",
    ),
    "clock-reopen-during-handler": (
        "accel/kvm/crucible-clock.c",
        "    if (clock->operation == KVM_CRUCIBLE_CLOCK_QUERY) {",
        "    if (clock->operation == KVM_CRUCIBLE_CLOCK_QUERY ||\n        clock->operation == KVM_CRUCIBLE_CLOCK_BEGIN) {",
    ),
    "other-CPU-RUN-credit": (
        "accel/kvm/crucible-clock.c",
        "        (!state->crucible_response_service_configured ||\n         !qatomic_load_acquire(&state->crucible_response_service_active)) &&",
        "        true &&",
    ),
    "fault-during-handler-forgotten": (
        "accel/kvm/crucible-clock.c",
        "    if (state->crucible_userspace_faulted ||\n        !service->issued || service->completed || !service->executing ||",
        "    if (!service->issued || service->completed || !service->executing ||",
    ),
}


def main():
    if len(sys.argv) != 8:
        raise SystemExit("usage: lifetime_mutations.py SOURCE AOS_CC OUTPUT KERNEL MODEL BASELINE LIFETIME_MODEL")
    source, compiler, output, kernel, model, baseline, lifetime = (
        Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4]),
        Path(sys.argv[5]), Path(sys.argv[6]), Path(sys.argv[7]),
    )
    output.mkdir(parents=True, exist_ok=True)
    for name, (relative, before, after) in MUTATIONS.items():
        original = (source / relative).read_text()
        if original.count(before) != 1:
            raise ValueError("ambiguous actual lifetime predicate: " + name)
        case = output / name
        candidate = case / "source"
        candidate.mkdir(parents=True, exist_ok=True)
        for child in source.iterdir():
            if child.name not in ("accel", "build"):
                (candidate / child.name).symlink_to(child.resolve())
        (candidate / "accel/kvm").mkdir(parents=True, exist_ok=True)
        for child in (source / "accel/kvm").iterdir():
            if "accel/kvm/" + child.name != relative:
                (candidate / "accel/kvm" / child.name).symlink_to(child.resolve())
        (candidate / relative).write_text(original.replace(before, after))

        # The companion original response cases must still compile and pass;
        # these mutants are caught by the independent lifetime regression.
        result = subprocess.run([
            sys.executable, str(model), str(candidate), compiler,
            str(case / "response"), str(kernel), str(baseline),
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=45)
        (case / "response.log").write_text(result.stdout)
        if result.returncode != 0:
            raise AssertionError("mutation failed before lifetime execution: " + name)
        result = subprocess.run([
            sys.executable, str(lifetime), str(candidate), compiler,
            str(case / "lifetime"), str(case / "response/response.c"),
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=45)
        (case / "lifetime.log").write_text(result.stdout)
        if (result.returncode == 0 or not (case / "lifetime/lifetime").is_file()
                or "Signals.SIGABRT" not in result.stdout):
            raise AssertionError("compiled lifetime mutant not asserted: " + name)
        print("Compiled response lifetime regression rejected:", name)
    print("All five lifetime mutants rejected by actual assertion after successful compilation; no native qualification")


if __name__ == "__main__":
    main()
