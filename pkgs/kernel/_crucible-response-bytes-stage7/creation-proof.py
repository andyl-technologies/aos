"""Exercise the actual immutable cap function against a held creation mutex.

The source function and ABI are real. VM state and syscall plumbing are modeled;
actual pthread mutexes and a finite operational wait test the creation race.
No KVM device, ioctl, guest or full-node qualification is involved.
"""
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode = True
from return_proof import function

PREFIX = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint8_t __u8;
typedef int64_t __s64;
typedef int32_t __s32;
#define CONFIG_X86 1
#define CONFIG_ARM64 0
#define IS_ENABLED(option) (option)
#define WRITE_ONCE(value, replacement) ((value) = (replacement))
struct kvm {
    pthread_mutex_t lock, crucible_configuration_lock;
    bool crucible_controlled, crucible_response_enabled, crucible_active;
    bool crucible_run_return_enabled;
    unsigned created_vcpus, crucible_effect_owners;
};
static struct kvm vm = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .crucible_configuration_lock = PTHREAD_MUTEX_INITIALIZER,
    .crucible_controlled = true,
    .crucible_response_enabled = true,
};
static pthread_mutex_t probe_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t probe_condition = PTHREAD_COND_INITIALIZER;
static bool original_creation_lock_attempted;
static int configured_result;

static void mutex_lock(pthread_mutex_t *lock)
{
    if (lock == &vm.lock) {
        assert(pthread_mutex_lock(&probe_lock) == 0);
        original_creation_lock_attempted = true;
        assert(pthread_cond_signal(&probe_condition) == 0);
        assert(pthread_mutex_unlock(&probe_lock) == 0);
    }
    assert(pthread_mutex_lock(lock) == 0);
}

static void mutex_unlock(pthread_mutex_t *lock)
{
    assert(pthread_mutex_unlock(lock) == 0);
}
'''

CASES = r'''
static void *configure(void *argument)
{
    const struct kvm_enable_cap *cap = argument;
    configured_result = kvm_crucible_run_return_configure(&vm, cap);
    return NULL;
}

int main(void)
{
    struct kvm_enable_cap cap = { .cap = KVM_CAP_CRUCIBLE_RUN_RETURN_V1 };
    pthread_t controller;
    struct timespec deadline;

    assert(pthread_mutex_lock(&vm.lock) == 0);
    assert(pthread_create(&controller, NULL, configure, &cap) == 0);
    assert(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_sec += 2;
    assert(pthread_mutex_lock(&probe_lock) == 0);
    while (!original_creation_lock_attempted) {
        int result = pthread_cond_timedwait(&probe_condition, &probe_lock, &deadline);
        assert(result == 0);
    }
    assert(pthread_mutex_unlock(&probe_lock) == 0);
    /* The genuine original cap blocks behind native creation ownership. */
    assert(!vm.crucible_run_return_enabled);
    vm.created_vcpus = 1;
    assert(pthread_mutex_unlock(&vm.lock) == 0);
    assert(pthread_join(controller, NULL) == 0);
    assert(configured_result == -EBUSY && !vm.crucible_run_return_enabled);

    vm.created_vcpus = 0;
    assert(kvm_crucible_run_return_configure(&vm, &cap) == 0);
    assert(vm.crucible_run_return_enabled);
    assert(kvm_crucible_run_return_configure(&vm, &cap) == -EBUSY);
    puts("Actual new-cap body with real held pthread creation mutex: opt-in cannot race pre-vCPU publication PASS; modeled VM only, no hardware qualification.");
    return 0;
}
'''


def main():
    source, compiler, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    uapi = (source / 'include/uapi/linux/kvm.h').read_text()
    packet = uapi[uapi.index('#define KVM_CAP_CRUCIBLE_RUN_RETURN_V1'):uapi.index('#define KVM_CAP_CRUCIBLE_COMPLETION_V1')]
    enable = uapi[uapi.index('struct kvm_enable_cap {'):]
    enable = enable[:enable.index('\n};') + 4]
    original = function((source / 'virt/kvm/crucible-completion.c').read_text(), 'int kvm_crucible_run_return_configure(')
    output.mkdir(parents=True, exist_ok=True)
    native, binary = output / 'creation-proof.c', output / 'creation-proof'
    native.write_text(PREFIX + packet + enable + original + CASES)
    subprocess.run([compiler, '-std=c11', '-pthread', '-Wall', '-Wextra', '-Werror', str(native), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    main()
