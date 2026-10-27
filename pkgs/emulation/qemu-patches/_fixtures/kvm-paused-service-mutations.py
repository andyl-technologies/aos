"""Reject compiled defects in the original CPU service and producer boundaries."""

from pathlib import Path
import subprocess
import sys


MUTATIONS = {
    "queue-producer-conflict": (
        """    if (cpu->crucible_paused_service.active) {
        paused_service_conflict_locked(cpu, "ordinary-work-producer");
    }""",
        "",
    ),
    "direct-producer-conflict": (
        "slot->active || slot->ordinary_depth == UINT32_MAX",
        "slot->ordinary_depth == UINT32_MAX",
    ),
    "inflight-admission": (
        "slot->active || slot->ordinary_depth ||",
        "slot->active ||",
    ),
    "original-response-identity": (
        "exit_sequence == slot->exit_sequence ? 0 : -ESTALE",
        "0",
    ),
    "failed-callback-custody": (
        "if (slot->result >= 0 && slot->active) {",
        "if (true) {",
    ),
    "native-roster-identity": (
        "!slot->enrolled || slot->native_id != native_id || !operation_id ||",
        "!slot->enrolled || !operation_id ||",
    ),
    "callback-BQL-context": (
        """    bql_unlock();
    result = slot->callback(cpu, operation_id, exit_sequence);
    bql_lock();""",
        "    result = slot->callback(cpu, operation_id, exit_sequence);",
    ),
    "original-reclamation": (
        """    if (cpu->crucible_paused_service.active ||
        cpu->crucible_paused_service.ordinary_depth) {""",
        "    if (false) {",
    ),
    "callback-idle-visibility": (
        """    return !qatomic_load_acquire(&cpu->crucible_paused_service.active) &&
        !qatomic_load_acquire(&cpu->crucible_paused_service.pending) &&""",
        "    return !qatomic_load_acquire(&cpu->crucible_paused_service.pending) &&",
    ),
    "custody-wait-erased": (
        """    while (qatomic_load_acquire(&cpu->crucible_paused_service.active) &&
           !qatomic_load_acquire(&cpu->crucible_paused_service.pending)) {
        qemu_cond_wait(cpu->halt_cond, &bql);
    }""",
        "",
    ),
}


def main():
    if len(sys.argv) != 5:
        raise SystemExit("usage: slot-mutations.py SOURCE AOS_CC OUTPUT_DIR MODEL_SCRIPT")
    source, compiler, output, model = (
        Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4])
    )
    output.mkdir(parents=True, exist_ok=True)
    for name, (before, after) in MUTATIONS.items():
        relative = "system/cpus.c" if name in [
            "callback-idle-visibility", "custody-wait-erased"
        ] else "cpu-common.c"
        original = (source / relative).read_text()
        if original.count(before) != 1:
            raise ValueError(f"ambiguous actual source mutation: {name}")
        case = output / name
        candidate = case / "source"
        candidate.mkdir(parents=True, exist_ok=True)
        if relative == "cpu-common.c":
            (candidate / "cpu-common.c").write_text(original.replace(before, after))
            (candidate / "system").symlink_to((source / "system").resolve())
        else:
            (candidate / "cpu-common.c").symlink_to((source / "cpu-common.c").resolve())
            (candidate / "system").mkdir()
            (candidate / relative).write_text(original.replace(before, after))
        (candidate / "include").symlink_to((source / "include").resolve())
        result = subprocess.run(
            [sys.executable, str(model), str(candidate), compiler, str(case / "proof")],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=40,
        )
        (case / "result.log").write_text(result.stdout)
        # A missing source declaration or compiler failure is never evidence of
        # a detected custody defect. Each generated executable must have run.
        if result.returncode == 0 or not (case / "proof/slot").is_file():
            raise AssertionError(f"compiled mutation was not rejected: {name}")
        print(f"Compiled original source mutation rejected: {name}")
    print(f"All {len(MUTATIONS)} source custody mutants rejected; no native qualification")


if __name__ == "__main__":
    main()
