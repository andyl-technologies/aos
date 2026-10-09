"""Compile actual KVM userspace custody transitions without native qualification.

The entry definitions, transition functions, reservation wrappers and exit numbers
come from the supplied QEMU source. A single-threaded lock substitute verifies
mechanical bookkeeping only; actual KVM_RUN and device handlers are never faked
as hardware qualification. The compiler must be an explicit AOS-built executable.
"""

from pathlib import Path
import re
import subprocess
import sys


def function(source, name):
    """Extract an original complete function without copying its implementation."""
    declaration = r"^(?:static )?(?:bool|int|void|CrucibleKvmUserspaceExit \*)\s*"
    match = re.search(declaration + name + r"\(", source, re.M)
    if match is None:
        raise ValueError(f"missing production function {name}")
    end = source.index("\n}\n", match.start()) + 3
    return source[match.start():end] + "\n"


PREFIX = r"""// SPDX-License-Identifier: GPL-2.0-only
/* Extracted original custody bookkeeping, never a live KVM qualification. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

@EXIT_NUMBERS@
@ENTRY_DEFINITION@

typedef int QemuMutex;
typedef struct KVMState {
    @STATE_FIELDS@
} KVMState;

struct kvm_run { uint32_t exit_reason; };
typedef struct CPUState {
    int cpu_index;
    struct kvm_run *kvm_run;
    uint64_t native_id;
} CPUState;

static uint64_t kvm_arch_vcpu_id(CPUState *cpu)
{
    return cpu->native_id;
}

static bool autostart, allocation_fails;
static unsigned allocation_calls;

static void *checked_allocation(size_t count, size_t size)
{
    allocation_calls++;
    return allocation_fails ? NULL : calloc(count, size);
}

#define g_try_new0(type, count) checked_allocation(count, sizeof(type))
#define g_free(pointer) free(pointer)
#define error_report(...) ((void)0)

static void qemu_mutex_init(QemuMutex *mutex)
{
    *mutex = 0;
}

static void qemu_mutex_destroy(QemuMutex *mutex)
{
    assert(*mutex == 0);
}

static void qemu_mutex_lock(QemuMutex *mutex)
{
    assert(*mutex == 0);
    *mutex = 1;
}

static void qemu_mutex_unlock(QemuMutex *mutex)
{
    assert(*mutex == 1);
    *mutex = 0;
}

@FUNCTIONS@
"""


CASES = r"""
static void dispatch(KVMState *state, CPUState *cpu, uint32_t reason)
{
    assert(kvm_crucible_userspace_before_run(state, cpu));
    cpu->kvm_run->exit_reason = reason;
    assert(kvm_crucible_userspace_after_run(state, cpu, 0));
    assert(state->crucible_userspace_exits[cpu->cpu_index].phase ==
           CRUCIBLE_KVM_USERSPACE_HANDLING);
    assert(kvm_crucible_userspace_after_dispatch(state, cpu));
}

static void returns(KVMState *state, CPUState *cpu, int result, uint32_t reason)
{
    assert(kvm_crucible_userspace_before_run(state, cpu));
    cpu->kvm_run->exit_reason = reason;
    assert(kvm_crucible_userspace_after_run(state, cpu, result));
}

static void bind_roster(KVMState *state, CPUState *cpus)
{
    assert(kvm_crucible_userspace_bind_vcpu(state, &cpus[0]));
    assert(kvm_crucible_userspace_bind_vcpu(state, &cpus[1]));
}

int main(void)
{
    CrucibleKvmUserspaceExit entries[2] = { 0 };
    struct kvm_run runs[2] = { 0 };
    CPUState cpus[2] = { { 0, &runs[0], 100 }, { 1, &runs[1], 200 } };
    KVMState state = {
        .crucible_userspace_configured = true,
        .crucible_userspace_capacity = 2,
        .crucible_userspace_exits = entries,
    };
    CrucibleKvmUserspaceExit retained;
    KVMState preparation = { 0 };

    /* Initialization refuses unbounded or non-stopped profiles before allocation. */
    assert(kvm_crucible_userspace_configure(&preparation, 0) == 0);
    assert(allocation_calls == 0);
    preparation.crucible_userspace_experiment = true;
    assert(kvm_crucible_userspace_configure(&preparation, 1) == -EINVAL);
    preparation.crucible_clock_configured = true;
    autostart = true;
    assert(kvm_crucible_userspace_configure(&preparation, 1) == -EINVAL);
    autostart = false;
    assert(kvm_crucible_userspace_configure(&preparation, 0) == -EINVAL);
    assert(kvm_crucible_userspace_configure(&preparation, 4097) == -EINVAL);
    assert(allocation_calls == 0);
    allocation_fails = true;
    assert(kvm_crucible_userspace_configure(&preparation, 2) == -ENOMEM);
    assert(!preparation.crucible_userspace_configured);

    allocation_fails = false;
    assert(kvm_crucible_userspace_configure(&preparation, 2) == 0);
    assert(preparation.crucible_userspace_configured);
    assert(kvm_crucible_userspace_configure(&preparation, 2) == -EINVAL);
    assert(allocation_calls == 2);
    kvm_crucible_userspace_destroy(&preparation);
    kvm_crucible_userspace_destroy(&preparation);
    assert(!preparation.crucible_userspace_configured);

    bind_roster(&state, cpus);
    assert(kvm_crucible_userspace_allow_state_put(&state, &cpus[0]));

    /* A returned actual IO callback still leaves its original kernel response. */
    dispatch(&state, &cpus[0], KVM_EXIT_IO);
    assert(entries[0].exit_sequence == 1 && entries[0].consumed_sequence == 0);
    assert(entries[0].phase == CRUCIBLE_KVM_USERSPACE_PENDING);
    assert(!kvm_crucible_userspace_allow_state_put(&state, &cpus[0]));
    assert(state.crucible_userspace_reserved_revisions == 0);

    /* Reusing a CPU slot or native ID cannot consume an older response. */
    {
        CrucibleKvmUserspaceExit copies[2] = { entries[0], entries[1] };
        KVMState replacement = state;

        replacement.crucible_userspace_exits = copies;
        retained = copies[0];
        cpus[0].native_id = 999;
        assert(!kvm_crucible_userspace_bind_vcpu(&replacement, &cpus[0]));
        assert(memcmp(&retained, &copies[0], sizeof(retained)) == 0);
        cpus[0].native_id = 100;
        copies[1] = (CrucibleKvmUserspaceExit) { 0 };
        replacement.crucible_userspace_faulted = false;
        cpus[1].native_id = 100;
        assert(!kvm_crucible_userspace_bind_vcpu(&replacement, &cpus[1]));
        assert(memcmp(&retained, &copies[0], sizeof(retained)) == 0);
        cpus[1].native_id = 200;
    }

    /* EINTR/EAGAIN/error do not invent completion, even with immediate_exit. */
    returns(&state, &cpus[0], -EINTR, KVM_EXIT_IO);
    assert(entries[0].phase == CRUCIBLE_KVM_USERSPACE_UNKNOWN);
    assert(entries[0].uncertain_effects);
    assert(!kvm_crucible_userspace_allow_state_put(&state, &cpus[0]));
    assert(entries[0].exit_sequence == 1 && entries[0].consumed_sequence == 0);
    returns(&state, &cpus[0], -EAGAIN, KVM_EXIT_IO);
    returns(&state, &cpus[0], -EFAULT, KVM_EXIT_IO);
    assert(entries[0].phase == CRUCIBLE_KVM_USERSPACE_UNKNOWN);
    assert(entries[0].exit_sequence == 1 && entries[0].consumed_sequence == 0);

    /* Positive re-entry consumes one response but can create another MMIO piece. */
    dispatch(&state, &cpus[0], KVM_EXIT_MMIO);
    assert(entries[0].exit_sequence == 2 && entries[0].consumed_sequence == 1);
    returns(&state, &cpus[0], 0, KVM_EXIT_HLT);
    assert(entries[0].phase == CRUCIBLE_KVM_USERSPACE_READY);
    assert(entries[0].consumed_sequence == 2);
    assert(entries[0].uncertain_effects);
    assert(kvm_crucible_userspace_allow_state_put(&state, &cpus[0]));

    /* Original vCPU identities and response sequences are independent. */
    dispatch(&state, &cpus[1], KVM_EXIT_IO);
    assert(entries[0].exit_sequence == 2 && entries[1].exit_sequence == 1);
    assert(entries[0].phase == CRUCIBLE_KVM_USERSPACE_READY);
    assert(entries[1].phase == CRUCIBLE_KVM_USERSPACE_PENDING);

    /* Unsupported handlers retain their opaque-effects history after completion. */
    returns(&state, &cpus[0], 0, KVM_EXIT_HYPERCALL);
    assert(entries[0].phase == CRUCIBLE_KVM_USERSPACE_UNSUPPORTED);
    assert(entries[0].opaque_effects);
    returns(&state, &cpus[0], 0, KVM_EXIT_HLT);
    assert(entries[0].phase == CRUCIBLE_KVM_USERSPACE_READY);
    assert(entries[0].consumed_sequence == 3 && entries[0].opaque_effects);

    /* Illegal calls leave original entry bytes untouched, and refuse more runs. */
    retained = entries[1];
    assert(!userspace_dispatch_return(&entries[1]));
    assert(memcmp(&retained, &entries[1], sizeof(retained)) == 0);
    assert(kvm_crucible_userspace_before_run(&state, &cpus[1]));
    retained = entries[1];
    assert(!userspace_run_start(&entries[1]));
    assert(memcmp(&retained, &entries[1], sizeof(retained)) == 0);
    assert(kvm_crucible_userspace_after_run(&state, &cpus[1], -EINTR));

    /* Interrupting an initial run is still unknown, with no invented exit ID. */
    entries[1] = (CrucibleKvmUserspaceExit) { 0 };
    assert(kvm_crucible_userspace_bind_vcpu(&state, &cpus[1]));
    returns(&state, &cpus[1], -EINTR, KVM_EXIT_IO);
    assert(entries[1].phase == CRUCIBLE_KVM_USERSPACE_UNKNOWN);
    assert(entries[1].exit_sequence == 0 && entries[1].consumed_sequence == 0);

    /* Counter exhaustion is refused BEFORE the next native KVM_RUN. */
    entries[1].exit_sequence = UINT64_MAX;
    retained = entries[1];
    assert(!kvm_crucible_userspace_before_run(&state, &cpus[1]));
    assert(state.crucible_userspace_faulted);
    assert(memcmp(&retained, &entries[1], sizeof(retained)) == 0);

    /* Two live original runs reserve independent finite completion credits. */
    memset(entries, 0, sizeof(entries));
    state.crucible_userspace_faulted = false;
    bind_roster(&state, cpus);
    state.crucible_userspace_revision = UINT64_MAX - 6;
    state.crucible_userspace_reserved_revisions = 0;
    assert(kvm_crucible_userspace_before_run(&state, &cpus[0]));
    assert(kvm_crucible_userspace_before_run(&state, &cpus[1]));
    runs[0].exit_reason = KVM_EXIT_IO;
    runs[1].exit_reason = KVM_EXIT_MMIO;
    assert(kvm_crucible_userspace_after_run(&state, &cpus[1], 0));
    assert(kvm_crucible_userspace_after_run(&state, &cpus[0], 0));
    assert(kvm_crucible_userspace_after_dispatch(&state, &cpus[0]));
    assert(kvm_crucible_userspace_after_dispatch(&state, &cpus[1]));
    assert(state.crucible_userspace_revision == UINT64_MAX);
    assert(state.crucible_userspace_reserved_revisions == 0);
    retained = entries[0];
    assert(!kvm_crucible_userspace_before_run(&state, &cpus[0]));
    assert(memcmp(&retained, &entries[0], sizeof(retained)) == 0);

    /* Global exhaustion cannot steal a run's already reserved return receipt. */
    memset(entries, 0, sizeof(entries));
    state.crucible_userspace_faulted = false;
    bind_roster(&state, cpus);
    state.crucible_userspace_revision = UINT64_MAX - 3;
    assert(kvm_crucible_userspace_before_run(&state, &cpus[0]));
    assert(!kvm_crucible_userspace_before_run(&state, &cpus[1]));
    runs[0].exit_reason = KVM_EXIT_IO;
    assert(kvm_crucible_userspace_after_run(&state, &cpus[0], 0));
    assert(kvm_crucible_userspace_after_dispatch(&state, &cpus[0]));
    assert(entries[0].phase == CRUCIBLE_KVM_USERSPACE_PENDING);
    assert(entries[0].exit_sequence == 1 && entries[0].consumed_sequence == 0);
    assert(state.crucible_userspace_revision == UINT64_MAX);

    /* Remaining credits cannot admit another run before native effects. */
    memset(entries, 0, sizeof(entries));
    state.crucible_userspace_faulted = false;
    bind_roster(&state, cpus);
    state.crucible_userspace_revision = UINT64_MAX - 4;
    assert(kvm_crucible_userspace_before_run(&state, &cpus[0]));
    assert(!kvm_crucible_userspace_before_run(&state, &cpus[1]));
    runs[0].exit_reason = KVM_EXIT_MMIO;
    assert(kvm_crucible_userspace_after_run(&state, &cpus[0], 0));
    assert(kvm_crucible_userspace_after_dispatch(&state, &cpus[0]));
    assert(state.crucible_userspace_revision == UINT64_MAX - 1);

    /* A disabled ledger changes no legacy handler/run state. */
    state.crucible_userspace_configured = false;
    retained = entries[0];
    assert(kvm_crucible_userspace_before_run(&state, &cpus[0]));
    assert(kvm_crucible_userspace_after_run(&state, &cpus[0], 0));
    assert(kvm_crucible_userspace_after_dispatch(&state, &cpus[0]));
    assert(memcmp(&retained, &entries[0], sizeof(retained)) == 0);
    puts("actual extracted KVM userspace ledger: 15 configuration/lineage/state/lifecycle/reservation cases PASS; native qualification not executed");
    return 0;
}
"""


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: kvm-userspace-exit-model.py QEMU_SOURCE AOS_CC OUTPUT_DIR")
    source, compiler, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    output.mkdir(parents=True, exist_ok=True)
    body = (source / "accel/kvm/crucible-clock.c").read_text()
    header = (source / "include/system/crucible-kvm-clock.h").read_text()
    state = (source / "include/system/kvm_int.h").read_text()
    kernel = (source / "linux-headers/linux/kvm.h").read_text()
    exit_pattern = (
        r"^#define KVM_EXIT_(?:IO|MMIO|OSI|PAPR_HCALL|XEN|EPR|HYPERCALL|TDX|"
        r"X86_RDMSR|X86_WRMSR|HLT)\s+\d+\s*$"
    )
    numbers = re.findall(exit_pattern, kernel, re.M)
    assert len(numbers) == 11
    definition = header[
        header.index("#define QEMU_CRUCIBLE_USERSPACE_EXIT_MAX_VCPUS"):
        header.index("int kvm_crucible_userspace_configure")
    ]
    fields = state[
        state.index("    bool crucible_clock_experiment;"):
        state.index("    int coalesced_mmio;")
    ]
    names = [
        "userspace_exit_requires_completion",
        "userspace_run_start",
        "userspace_run_return",
        "userspace_dispatch_return",
        "kvm_crucible_userspace_configure",
        "kvm_crucible_userspace_destroy",
        "kvm_crucible_userspace_bind_vcpu",
        "userspace_entry_locked",
        "kvm_crucible_userspace_allow_state_put",
        "kvm_crucible_userspace_before_run",
        "kvm_crucible_userspace_after_run",
        "kvm_crucible_userspace_after_dispatch",
    ]
    caller = (source / "accel/kvm/kvm-all.c").read_text()
    initialization = caller[
        caller.index("int kvm_init_vcpu("):caller.index("void kvm_close(")
    ]
    assert (
        initialization.index("kvm_crucible_userspace_bind_vcpu")
        < initialization.index("kvm_arch_pre_create_vcpu")
    )
    state_put = caller[
        caller.index("static bool kvm_cpu_synchronize_put("):
        caller.index("static void do_kvm_cpu_synchronize_post_reset(")
    ]
    assert (
        state_put.index("kvm_crucible_userspace_allow_state_put")
        < state_put.index("kvm_arch_put_registers")
    )
    if 'CrucibleKvmCompletionJournal' in definition:
        definition = definition.replace('int kvm_crucible_completion_configure(KVMState *state);', '')
        # This fixture preserves legacy clock-only bookkeeping. The separate
        # completion proof compiles the actual enabled geometry/caller paths.
        disabled_completion_geometry = """static bool completion_geometry(KVMState *state, CPUState *cpu,
                                CrucibleKvmUserspaceExit *entry, bool retain)
{
    (void)cpu; (void)entry; (void)retain;
    assert(!state->crucible_completion_configured);
    return false;
}

@FUNCTIONS@"""
        prefix = PREFIX.replace("@FUNCTIONS@", disabled_completion_geometry)
    else:
        prefix = PREFIX
    code = (
        prefix.replace("@EXIT_NUMBERS@", "\n".join(numbers))
        .replace("@ENTRY_DEFINITION@", definition)
        .replace("@STATE_FIELDS@", fields)
        .replace("@FUNCTIONS@", "\n".join(function(body, name) for name in names))
        + CASES
    )
    path, executable = output / "kvm-userspace-exit-model.c", output / "kvm-userspace-exit-model"
    path.write_text(code)
    subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", str(path), "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    main()
