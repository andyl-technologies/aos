"""Exercise response lifetime against extracted ioctl/RUN source with pthreads.

The callback and handler are actual source from the companion response model.
The host syscall and device transaction are deliberately counted substitutions;
this is source/component evidence, never native KVM or device qualification.
"""

from pathlib import Path
import subprocess
import re
import sys

import model


PLUMBING = r'''
#include <pthread.h>
#include <stdarg.h>

static pthread_mutex_t handler_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t handler_condition = PTHREAD_COND_INITIALIZER;
static bool hold_handler, handler_waiting, handler_release;
static unsigned clock_native_effects, clock_trace_effects, ioctl_owners;
static CrucibleKvmUserspaceExit entries[2];

static void lifetime_handler_pause(void)
{
    assert(pthread_mutex_lock(&handler_lock) == 0);
    if (hold_handler) {
        handler_waiting = true;
        assert(pthread_cond_broadcast(&handler_condition) == 0);
        while (!handler_release) {
            assert(pthread_cond_wait(&handler_condition, &handler_lock) == 0);
        }
    }
    assert(pthread_mutex_unlock(&handler_lock) == 0);
}

static void trace_kvm_vm_ioctl(unsigned long type, const void *argument)
{
    assert(type == KVM_ENABLE_CAP && argument);
    clock_trace_effects++;
}

static void accel_ioctl_begin(void)
{
    ioctl_owners++;
}

static void accel_ioctl_end(void)
{
    assert(ioctl_owners);
    ioctl_owners--;
}

static int counted_clock_ioctl(int fd, unsigned long type, const void *argument)
{
    const struct kvm_enable_cap *capability = argument;
    struct kvm_crucible_clock *clock;

    assert(fd == 42 && type == KVM_ENABLE_CAP);
    assert(capability->cap == KVM_CAP_CRUCIBLE_CLOCK_V1 ||
           capability->cap == KVM_CAP_CRUCIBLE_CLOCK_V3);
    clock = (struct kvm_crucible_clock *)(uintptr_t)capability->args[0];
    clock_native_effects++;
    clock->coverage = capability->cap == KVM_CAP_CRUCIBLE_CLOCK_V3 ? 159 : 7;
    clock->current_ns = 17;
    clock->active = clock_active;
    clock->run_owners = native_clock_owners;
    clock->close_acknowledged = clock_ack;
    return 0;
}
'''


TESTS = r'''
static void *held_callback(void *unused)
{
    execute_callback();
    return NULL;
}

static void expect_clock(uint32_t operation, bool allowed)
{
    unsigned before_effects = clock_native_effects;
    unsigned before_trace = clock_trace_effects;
    struct kvm_crucible_clock clock = { .version = 3, .operation = operation };
    int result = lifetime_clock_control(&native, &clock);

    assert(result == (allowed ? 0 : -EBUSY));
    assert(clock_native_effects == before_effects + (allowed ? 1 : 0));
    assert(clock_trace_effects == before_trace + (allowed ? 1 : 0));
    assert(ioctl_owners == 0);
}

static void expect_mutations(bool allowed)
{
    expect_clock(KVM_CRUCIBLE_CLOCK_CONFIGURE, allowed);
    expect_clock(KVM_CRUCIBLE_CLOCK_BEGIN, allowed);
    expect_clock(KVM_CRUCIBLE_CLOCK_FREEZE, allowed);
    expect_clock(KVM_CRUCIBLE_CLOCK_STEP, allowed);
}

static void begin_held(pthread_t *thread, bool failure)
{
    reset_service(false);
    entries[0] = original_entry;
    entries[1] = (CrucibleKvmUserspaceExit){
        .assigned = true, .seen = true, .kernel_vcpu_id = 43,
        .phase = CRUCIBLE_KVM_USERSPACE_READY,
    };
    native.crucible_userspace_exits = entries;
    native.crucible_userspace_capacity = 2;
    native.vmfd = 42;
    native.crucible_clock_kernel_edition = 3;
    fail_transaction = failure;
    hold_handler = true;
    handler_waiting = handler_release = false;
    g_free(service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT, 1, 2, false));
    assert(qatomic_load_acquire(&native.crucible_response_service_active));

    assert(pthread_create(thread, NULL, held_callback, NULL) == 0);
    assert(pthread_mutex_lock(&handler_lock) == 0);
    while (!handler_waiting) {
        assert(pthread_cond_wait(&handler_condition, &handler_lock) == 0);
    }
    assert(pthread_mutex_unlock(&handler_lock) == 0);
    assert(original_service.executing && !original_service.completed);
}

static void finish_held(pthread_t thread)
{
    assert(pthread_mutex_lock(&handler_lock) == 0);
    handler_release = true;
    assert(pthread_cond_broadcast(&handler_condition) == 0);
    assert(pthread_mutex_unlock(&handler_lock) == 0);
    assert(pthread_join(thread, NULL) == 0);
    assert(original_service.completed && !original_service.executing);
}

int main(void)
{
    pthread_t thread;

    /* A successful original callback owns the domain through collection,
     * not just through physical return from its synchronous device handler. */
    begin_held(&thread, false);
    expect_mutations(false);
    expect_clock(KVM_CRUCIBLE_CLOCK_QUERY, true);
    model_bql = false;
    expect_mutations(false);
    expect_clock(KVM_CRUCIBLE_CLOCK_QUERY, true);
    model_bql = true;
    finish_held(thread);
    assert(model_slot.result == 0);
    expect_mutations(false);
    g_free(service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_POLL, 1, 2, false));
    expect_mutations(true);

    /* Without BQL, even an inactive mutation cannot race future admission.
     * Read-only reconciliation and the original disabled path remain usable. */
    model_bql = false;
    expect_mutations(false);
    expect_clock(KVM_CRUCIBLE_CLOCK_QUERY, true);
    native.crucible_response_service_configured = false;
    expect_mutations(true);
    model_bql = true;

    /* A failed original callback cannot release its domain through Poll. */
    begin_held(&thread, true);
    expect_mutations(false);
    finish_held(thread);
    assert(model_slot.result == -EIO);
    g_free(service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_POLL, 1, 2, false));
    expect_mutations(false);
    expect_clock(KVM_CRUCIBLE_CLOCK_QUERY, true);

    /* Admission of another original READY vCPU fails before any reserved RUN
     * receipt or transition; the prior callback and its history remain owned. */
    begin_held(&thread, false);
    CPUState other = { .cpu_index = 1, .native_id = 43, .created = true,
                       .stopped = true };
    uint64_t revision = native.crucible_userspace_revision;
    uint64_t reserved = native.crucible_userspace_reserved_revisions;
    assert(!kvm_crucible_userspace_before_run(&native, &other));
    assert(native.crucible_userspace_faulted);
    assert(entries[1].phase == CRUCIBLE_KVM_USERSPACE_READY);
    assert(entries[1].reserved_revisions == 0);
    assert(native.crucible_userspace_revision == revision);
    assert(native.crucible_userspace_reserved_revisions == reserved);
    finish_held(thread);
    assert(model_slot.result < 0 && entries[0].uncertain_effects);
    expect_mutations(false);

    puts("Actual source response lifetime PASS: held pthread handler, syscall/trace-free clock refusal, BQL admission serialization, Query/recovery, original RUN credit refusal and sticky failure custody; no native qualification");
    return 0;
}
'''


def main():
    if len(sys.argv) != 5:
        raise SystemExit("usage: lifetime_model.py SOURCE AOS_CC OUTPUT GENERATED_RESPONSE")
    source, compiler, output, generated = (
        Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4]),
    )
    output.mkdir(parents=True, exist_ok=True)
    body = generated.read_text()
    body = body.replace("int main(void)", "int response_original_model_tests(void)")
    body = body.replace("typedef struct KVMState {", "typedef struct KVMState { int vmfd;")
    body = body.replace("static bool model_bql = true, model_more_io;",
                        "static _Thread_local bool model_bql = true;\nstatic bool model_more_io;")
    body = body.replace("static bool model_cpu_thread;", "static _Thread_local bool model_cpu_thread;")
    body = body.replace("static uint32_t address_space_rw(",
                        "static void lifetime_handler_pause(void);\nstatic uint32_t address_space_rw(")
    marker = "    observed_attributes = attributes;"
    assert body.count(marker) == 1
    body = body.replace(marker, "    lifetime_handler_pause();\n" + marker)

    clock = (source / "accel/kvm/crucible-clock.c").read_text()
    caller = (source / "accel/kvm/kvm-all.c").read_text()
    header = (source / "include/system/crucible-kvm-clock.h").read_text()
    constants = "\n".join(re.findall(
        r"^#define (?:KVM_CRUCIBLE_CLOCK_|QEMU_CRUCIBLE_CLOCK_)[A-Z0-9_]+ [0-9]+$",
        header, re.M,
    )) + "\n"
    ioctl = model.function(caller, "kvm_vm_ioctl", "int")
    # Give the actual variadic boundary a fixture namespace; the only native
    # effect substitution is the explicit counted Linux syscall below.
    ioctl = ioctl.replace("int kvm_vm_ioctl(", "int lifetime_vm_ioctl(", 1)
    # The original response profile leaves the atomic-window component off;
    # its actual syscall predicate is retained instead of bypassed by a stub.
    window = (source / "accel/kvm/crucible-window.c").read_text()
    functions = "\n\n".join([
        model.function(window, "kvm_crucible_window_allow_clock_ioctl", "bool"),
        "#define ioctl counted_clock_ioctl\n" + ioctl + "\n#undef ioctl",
        model.function(clock, "clock_capability", "uint32_t"),
        model.function(clock, "clock_components", "uint32_t"),
        model.function(clock, "clock_control", "int")
            .replace("clock_control(", "lifetime_clock_control(", 1)
            .replace("kvm_vm_ioctl(", "lifetime_vm_ioctl("),
        model.function(clock, "userspace_run_start", "bool"),
        model.function(clock, "kvm_crucible_userspace_before_run", "bool"),
    ])
    target = output / "lifetime.c"
    target.write_text(body + "\n" + constants + PLUMBING + functions + TESTS)
    executable = output / "lifetime"
    subprocess.run([
        compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-pthread", "-I" + str(source / "linux-headers"),
        "-I" + str(generated.parent / "completion-disabled/include"),
        str(target), "-o", str(executable),
    ], check=True)
    subprocess.run([str(executable)], check=True, timeout=20)


if __name__ == "__main__":
    main()
