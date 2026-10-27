"""Compile the original completion ABI/policy, without native qualification."""

from pathlib import Path
import re
import subprocess
import sys


CASES = r"""
_Static_assert(sizeof(struct kvm_crucible_completion) == 96, "private ABI");
_Static_assert(offsetof(struct kvm_crucible_completion, reserved) == 64, "reserved offset");

static struct kvm_crucible_completion step(uint64_t operation, uint64_t sequence)
{
    return (struct kvm_crucible_completion) {
        .version = 1, .operation = KVM_CRUCIBLE_COMPLETION_STEP,
        .operation_id = operation, .expected_sequence = sequence,
    };
}

int main(void)
{
    struct kvm_crucible_response_state state = {0}, before;
    struct kvm_crucible_completion request, query = {
        .version = 1, .operation = KVM_CRUCIBLE_COMPLETION_QUERY,
    };
    unsigned index;

    assert(kvm_crucible_response_admit(&state, &query) == 0);
    query.version = 2;
    assert(kvm_crucible_response_admit(&state, &query) == -EINVAL);
    query.version = 1;
    for (index = 0; index < 4; index++) {
        query.reserved[index] = 1;
        assert(kvm_crucible_response_admit(&state, &query) == -EINVAL);
        query.reserved[index] = 0;
    }
    query.phase = KVM_CRUCIBLE_COMPLETION_DONE;
    assert(kvm_crucible_response_admit(&state, &query) == -EINVAL);
    query.phase = 0;

    request = step(1, 0);
    assert(kvm_crucible_response_admit(&state, &request) == -EIO);
    assert(kvm_crucible_response_birth(&state));
    assert(state.sequence == 1 && state.revision == 1);
    before = state;
    assert(!kvm_crucible_response_birth(&state));
    assert(memcmp(&state, &before, sizeof(state)) == 0);

    request = step(1, 1);
    assert(kvm_crucible_response_admit(&state, &request) == 0);
    kvm_crucible_response_finish(&state, &request, 1, false, 37);
    assert(state.phase == KVM_CRUCIBLE_COMPLETION_DONE);
    assert(state.consumed_sequence == 1 && state.sequence == 1);
    assert(state.last_result.native_vcpu_id == 37);
    before = state;
    /* Native delivery failure cannot remove this original completed result. */
    assert(kvm_crucible_response_admit(&state, &request) == 1);
    assert(memcmp(&state, &before, sizeof(state)) == 0);
    request.expected_sequence = 2;
    assert(kvm_crucible_response_admit(&state, &request) == -ESTALE);

    assert(kvm_crucible_response_birth(&state));
    request = step(2, 2);
    assert(kvm_crucible_response_admit(&state, &request) == 0);
    kvm_crucible_response_finish(&state, &request, 0, true, 37);
    assert(state.phase == KVM_CRUCIBLE_COMPLETION_MORE);
    assert(state.consumed_sequence == 2 && state.sequence == 3);
    before = state;
    assert(kvm_crucible_response_admit(&state, &request) == 1);
    assert(memcmp(&state, &before, sizeof(state)) == 0);
    request = step(3, 3);
    assert(kvm_crucible_response_admit(&state, &request) == 0);
    kvm_crucible_response_finish(&state, &request, -EINTR, false, 37);
    assert(state.phase == KVM_CRUCIBLE_COMPLETION_UNKNOWN);
    assert(state.consumed_sequence == 2 && state.sequence == 3);
    assert(state.flags == KVM_CRUCIBLE_COMPLETION_UNCERTAIN);
    assert(kvm_crucible_response_admit(&state, &request) == 1);
    request = step(4, 3);
    assert(kvm_crucible_response_admit(&state, &request) == -EIO);
    assert(!kvm_crucible_response_birth(&state));

    state = (struct kvm_crucible_response_state) {0};
    assert(kvm_crucible_response_birth(&state));
    state.revision = U64_MAX - 1;
    request = step(1, 1);
    before = state;
    assert(kvm_crucible_response_admit(&state, &request) == -EOVERFLOW);
    assert(memcmp(&state, &before, sizeof(state)) == 0);
    state.revision = U64_MAX - 2;
    assert(kvm_crucible_response_admit(&state, &request) == 0);
    kvm_crucible_response_finish(&state, &request, 0, true, 37);
    assert(state.revision == U64_MAX && state.sequence == 2);
    request = step(2, 2);
    assert(kvm_crucible_response_admit(&state, &request) == -EOVERFLOW);

    state = (struct kvm_crucible_response_state) { .sequence = U64_MAX };
    before = state;
    assert(!kvm_crucible_response_birth(&state));
    assert(memcmp(&state, &before, sizeof(state)) == 0);
    state = (struct kvm_crucible_response_state) {0};
    assert(kvm_crucible_response_birth(&state));
    request = step(2, 1);
    assert(kvm_crucible_response_admit(&state, &request) == -ESTALE);
    request = step(1, 2);
    assert(kvm_crucible_response_admit(&state, &request) == -ESTALE);
    puts("actual completion policy: ABI, closed requests, original retry, MMIO continuation, unknown custody and finite counters PASS; no native qualification");
    return 0;
}
"""


def function(source, declaration):
    """Extract a complete original native source body for placement checks."""
    start = source.index(declaration)
    return source[start:source.index("\n}\n", start) + 3]


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: completion-state-test.py SOURCE AOS_CC OUTPUT_DIR")
    source, compiler, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    uapi = (source / "include/uapi/linux/kvm.h").read_text()
    packet = uapi[uapi.index("#define KVM_CAP_CRUCIBLE_COMPLETION_V1"):uapi.index("#define KVM_CAP_CRUCIBLE_CLOCK_V1")]
    policy = (source / "include/linux/kvm_crucible_completion.h").read_text()
    policy = re.sub(r"^#include.*$", "", policy, flags=re.M)
    context = """#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint64_t __u64;
typedef uint32_t __u32;
typedef int32_t __s32;
#define U64_MAX UINT64_MAX
"""
    output.mkdir(parents=True, exist_ok=True)
    candidate = output / "completion-state-test.c"
    executable = output / "completion-state-test"
    candidate.write_text(context + packet + policy + CASES)
    subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", str(candidate), "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True)

    module = (source / "virt/kvm/crucible-completion.c").read_text()
    ioctl = function(module, "int kvm_crucible_response_ioctl(")
    assert ioctl.count("kvm_arch_crucible_response_complete(vcpu, &more)") == 1
    assert ioctl.index("kvm_crucible_response_admit") < ioctl.index("kvm_arch_crucible_response_complete")
    assert ioctl.index("kvm_arch_crucible_response_stopped") < ioctl.index("kvm_arch_crucible_response_complete")
    assert ioctl.index("kvm_crucible_response_finish") < ioctl.index("copy_to_user")
    for path in ("arch/x86/kvm/x86.c", "arch/arm64/kvm/mmio.c"):
        native = (source / path).read_text()
        complete = function(native, "int kvm_arch_crucible_response_complete(")
        for forbidden in ("vcpu_run(", "vcpu_enter_guest(", "kvm_arm_vcpu_enter_exit("):
            assert forbidden not in complete
    print("original native completion placement: single callback, retained before delivery, no guest-entry path PASS")


if __name__ == "__main__":
    main()
