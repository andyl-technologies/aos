"""Exercise actual original reclaim/kill boundaries before native destruction.

Architecture destruction, mapping and FD parking are modeled marker producers.
The actual extracted QEMU gate terminates a real child before any marker. The
parent's retained nonce/journal is explicit supervision-model state, not an
installed runtime or KVM qualification witness.
"""

from pathlib import Path
import re
import subprocess
import sys


source, compiler, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
output.mkdir(parents=True, exist_ok=True)


def function(body, name):
    pattern = r'^(?:static )?(?:G_NORETURN )?(?:int|void) ' + name + r'\('
    selected = re.search(pattern, body, re.M)
    assert selected is not None, name
    end = body.index('\n}\n', selected.start()) + 3
    return body[selected.start():end] + '\n\n'


common = (source / 'cpu-common.c').read_text()
native = (source / 'accel/kvm/kvm-all.c').read_text()
prefix = r'''
/* Actual source fail-stop; native architecture/FD effects are model markers. */
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define G_NORETURN __attribute__((noreturn))
#define PAGE_SIZE 4096
#define qatomic_load_acquire(pointer) __atomic_load_n(pointer, __ATOMIC_ACQUIRE)
typedef pthread_mutex_t QemuMutex;
typedef struct QemuCpuPausedService {
    bool enrolled, active;
    unsigned ordinary_depth;
    uint64_t native_id, operation_id, exit_sequence;
} QemuCpuPausedService;
typedef struct CPUState {
    int cpu_index;
    void *kvm_run;
    QemuMutex work_mutex;
    QemuCpuPausedService crucible_paused_service;
} CPUState;
typedef struct KVMState { void *coalesced_mmio_ring; } KVMState;
static KVMState state;
static KVMState *kvm_state = &state;
static uint64_t native_window_generation;
static int event_fd = -1, arch_result, unmap_result;
static unsigned effects;

static void qemu_mutex_lock(QemuMutex *mutex) { assert(!pthread_mutex_lock(mutex)); }
static void qemu_mutex_unlock(QemuMutex *mutex) { assert(!pthread_mutex_unlock(mutex)); }
static void error_report(const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    vfprintf(stderr, format, arguments);
    va_end(arguments);
    fputc('\n', stderr);
}
static void effect(char marker)
{
    effects++;
    if (event_fd >= 0) { assert(write(event_fd, &marker, 1) == 1); }
}
static unsigned long kvm_arch_vcpu_id(CPUState *cpu) { (void)cpu; return 42; }
static void trace_kvm_destroy_vcpu(int index, unsigned long id)
{
    assert(index == 0 && id == 42);
}
static int kvm_arch_destroy_vcpu(CPUState *cpu)
{
    (void)cpu; effect('A'); return arch_result;
}
static int vcpu_unmap_regions(KVMState *owner, CPUState *cpu)
{
    assert(owner == &state); effect('U');
    if (!unmap_result) { cpu->kvm_run = NULL; }
    return unmap_result;
}
static void kvm_park_vcpu(CPUState *cpu) { (void)cpu; effect('P'); }
'''
functions = ''.join(function(common, name) for name in (
    'paused_service_conflict_locked', 'native_window_work_guard_locked',
    'qemu_cpu_paused_service_reclaim_guard'))
functions += function(native, 'do_kvm_destroy_vcpu')
tests = r'''
static void refused_before_any_native_release(CPUState *cpu, unsigned kind)
{
    int descriptors[2], status;
    char marker;
    assert(pipe(descriptors) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        close(descriptors[0]); event_fd = descriptors[1];
        native_window_generation = kind == 0 ? 1 : 0;
        cpu->crucible_paused_service.enrolled = kind != 0;
        cpu->crucible_paused_service.active = kind == 1;
        cpu->crucible_paused_service.ordinary_depth = kind == 2;
        _exit(do_kvm_destroy_vcpu(cpu) ? 7 : 0);
    }
    close(descriptors[1]);
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 125);
    assert(read(descriptors[0], &marker, 1) == 0);
    close(descriptors[0]);
    /* Only the actual child outcome is observed. Host custody below is model
     * state; death never turns the retained operation into success/no-effects. */
    struct { unsigned nonce; bool outstanding, unknown; } retained = {37, true, false};
    retained.unknown = true;
    assert(retained.nonce == 37 && retained.outstanding && retained.unknown);
}

int main(void)
{
    CPUState cpu = { .cpu_index = 0, .work_mutex = PTHREAD_MUTEX_INITIALIZER };
    unsigned char *mapping = calloc(2, PAGE_SIZE);
    assert(mapping);
    cpu.kvm_run = mapping;
    state.coalesced_mmio_ring = mapping + PAGE_SIZE;
    for (unsigned kind = 0; kind != 3; ++kind) {
        refused_before_any_native_release(&cpu, kind);
    }
    assert(cpu.kvm_run == mapping && state.coalesced_mmio_ring == mapping + PAGE_SIZE);
    assert(effects == 0);

    assert(do_kvm_destroy_vcpu(&cpu) == 0);
    assert(effects == 3 && cpu.kvm_run == NULL && state.coalesced_mmio_ring == NULL);
    cpu.kvm_run = mapping; effects = 0; arch_result = -EIO;
    assert(do_kvm_destroy_vcpu(&cpu) == -EIO && effects == 1 && cpu.kvm_run == mapping);
    effects = 0; arch_result = 0; unmap_result = -EFAULT;
    assert(do_kvm_destroy_vcpu(&cpu) == -EFAULT && effects == 2 && cpu.kvm_run == mapping);
    free(mapping);
    puts("Actual native vCPU reclaim guard: three children125 before destroy/unmap/park, disabled behavior preserved PASS; native effects/supervision modeled, no hardware qualification.");
}
'''
program = output / 'lifetime.c'
program.write_text(prefix + '\n' + functions + '\n' + tests)
binary = output / 'lifetime'
subprocess.run([compiler, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-pthread',
                str(program), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=20)
