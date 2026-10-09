"""Reject compiled mutations of actual KVM exit-custody bookkeeping.

The companion fixture extracts each candidate's original production functions.
A compiler failure never counts as a rejected mutation. This single-threaded
model proves bookkeeping assertions, not KVM execution or physical containment.
"""

from pathlib import Path
import shutil
import subprocess
import sys


MUTATIONS = (
    ("interrupted-completion",
     "entry->phase = CRUCIBLE_KVM_USERSPACE_UNKNOWN;",
     "entry->phase = CRUCIBLE_KVM_USERSPACE_READY;"),
    ("callback-claims-complete",
     "entry->phase = CRUCIBLE_KVM_USERSPACE_PENDING;",
     "entry->phase = CRUCIBLE_KVM_USERSPACE_READY;"),
    ("consumed-before-reentry",
     "if (result < 0) {\n        /* A clock-ceiling",
     "entry->consumed_sequence = entry->exit_sequence;\n"
     "    if (result < 0) {\n        /* A clock-ceiling"),
    ("stolen-reservation",
     "available - state->crucible_userspace_reserved_revisions >= 3",
     "available >= 3"),
    ("opaque-history-lost",
     "entry->opaque_effects = true;",
     "entry->opaque_effects = false;"),
    ("uncertain-history-lost",
     "entry->uncertain_effects = true;",
     "entry->uncertain_effects = false;"),
    ("reused-original-slot",
     "if (entry->assigned) {",
     "if (false && entry->assigned) {"),
    ("duplicate-kernel-vcpu",
     "original->assigned && original->kernel_vcpu_id == native_id",
     "false && original->assigned && original->kernel_vcpu_id == native_id"),
    ("pending-register-replacement",
     "entry->phase == CRUCIBLE_KVM_USERSPACE_READY &&\n"
     "        entry->consumed_sequence == entry->exit_sequence",
     "true"),
)


def main():
    """Compile each broken production body and require its native assertion."""
    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: kvm-userspace-exit-mutations.py QEMU_SOURCE AOS_CC OUTPUT_DIR"
        )
    source, compiler, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    fixture = Path(__file__).with_name("kvm-userspace-exit-model.py")
    body = (source / "accel/kvm/crucible-clock.c").read_text()

    for name, original, replacement in MUTATIONS:
        if body.count(original) != 1:
            raise ValueError(f"{name}: expected exactly one production predicate")

        candidate = output / name
        for relative in (
            "include/system/crucible-kvm-clock.h",
            "include/system/kvm_int.h",
            "linux-headers/linux/kvm.h",
            "accel/kvm/kvm-all.c",
        ):
            target = candidate / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / relative, target)

        target = candidate / "accel/kvm/crucible-clock.c"
        target.write_text(body.replace(original, replacement))
        executable = candidate / "proof/kvm-userspace-exit-model"
        # A stale binary must not turn a later compiler error into evidence.
        executable.unlink(missing_ok=True)
        result = subprocess.run([
            sys.executable, str(fixture), str(candidate), compiler,
            str(candidate / "proof"),
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        (candidate / "proof.log").write_text(result.stdout)

        if not executable.is_file():
            raise RuntimeError(f"{name}: compiler failure is not a mutation rejection")
        if result.returncode == 0:
            raise RuntimeError(f"{name}: broken exit custody was accepted")
        print(f"{name}: actual production code compiled; broken custody rejected")

    print("Nine compiled negative mutations rejected; native qualification not executed.")


if __name__ == "__main__":
    main()
