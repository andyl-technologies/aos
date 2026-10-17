"""Reject compiled mutations of original completion custody and native gates.

Both positive companions must already pass. The candidates reuse their original
production ABI, policy and ioctl bodies; a compiler error never counts as a
rejected mutation, and no model result is a native KVM qualification.
"""

from pathlib import Path
import shutil
import subprocess
import sys


MUTATIONS = (
    ("lost-original-retry", "virt/kvm/crucible-completion.c",
     "if (result == 1) {", "if (false && result == 1) {", "ioctl"),
    ("lost-original-result-id", "include/linux/kvm_crucible_completion.h",
     "state->last_result = *request;",
     "state->last_result = *request;\n\tstate->last_result.operation_id = 0;", "ioctl"),
    ("consumed-unknown-response", "include/linux/kvm_crucible_completion.h",
     "if (callback_result < 0) {",
     "state->consumed_sequence = state->sequence;\n\tif (callback_result < 0) {", "policy"),
    ("running-original-owner", "arch/x86/kvm/x86.c",
     "return !kvm->arch.crucible_clock.run_owners &&",
     "return true &&", "ioctl"),
    ("active-window-completion", "virt/kvm/crucible-completion.c",
     "!kvm->crucible_controlled || kvm->crucible_active || kvm->crucible_effect_owners ||",
     "!kvm->crucible_controlled || false || kvm->crucible_effect_owners ||", "ioctl"),
    ("unreserved-revision", "include/linux/kvm_crucible_completion.h",
     "state->revision >= U64_MAX - 1 ||", "false ||", "policy"),
)


def main():
    if len(sys.argv) != 6:
        raise SystemExit(
            "usage: completion-mutations.py SOURCE AOS_CC OUTPUT_DIR POLICY_TEST IOCTL_TEST"
        )
    source, compiler, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    fixtures = {"policy": Path(sys.argv[4]), "ioctl": Path(sys.argv[5])}
    files = (
        "include/uapi/linux/kvm.h", "include/linux/kvm_crucible_completion.h",
        "virt/kvm/crucible-completion.c", "arch/x86/kvm/x86.c",
        "arch/arm64/kvm/mmio.c",
    )

    for name, relative, original, replacement, mode in MUTATIONS:
        candidate = output / name
        for selected in files:
            target = candidate / selected
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / selected, target)

        target = candidate / relative
        body = target.read_text()
        if body.count(original) != 1:
            raise ValueError(f"{name}: expected exactly one original native predicate")
        target.write_text(body.replace(original, replacement))
        executable = candidate / "proof" / (
            "completion-state-test" if mode == "policy" else "completion-ioctl-test"
        )
        executable.unlink(missing_ok=True)
        result = subprocess.run([
            sys.executable, str(fixtures[mode]), str(candidate), compiler,
            str(candidate / "proof"),
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        (candidate / "proof.log").write_text(result.stdout)

        if not executable.is_file():
            raise RuntimeError(f"{name}: compiler failure is not a rejected mutation")
        if result.returncode == 0:
            raise RuntimeError(f"{name}: incorrect completion custody was accepted")
        print(f"{name}: original mutated production code compiled; broken custody rejected")

    print("Six compiled native policy/ioctl mutations rejected; no hardware qualification.")


if __name__ == "__main__":
    main()
