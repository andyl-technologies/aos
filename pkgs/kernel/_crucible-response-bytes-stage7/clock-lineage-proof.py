"""Compile actual x86/ARM clock transitions with finite owner-custody inputs.

Only primitive clock and register plumbing are modeled. Neither native IRQs nor
hardware stop behavior is qualified by these source transition tests.
"""
from pathlib import Path
import re
import subprocess
import sys
sys.dont_write_bytecode = True
from return_proof import function

PREFIX = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint64_t __u64;
typedef uint32_t __u32;
#define U64_MAX UINT64_MAX
#define KTIME_MAX INT64_MAX
#define KVM_X86_DEFAULT_VM 0
#define KVM_ARCH_FLAG_VM_COUNTER_OFFSET 0
#define smp_store_release(pointer, value) (*(pointer) = (value))
#define set_bit(index, pointer) (*(pointer) |= (1UL << (index)))
struct kvm_crucible_clock_domain {
    bool enabled, active, close_acknowledged;
    u32 version, numerator, denominator, run_owners, timer_owners;
    u64 window_generation, frozen_ns, host_origin_ns, host_ceiling_ns, start_ns, end_ns;
};
struct kvm {
    u32 created_vcpus, crucible_effect_owners, crucible_uncollected_returns;
    bool crucible_controlled, crucible_active, crucible_run_return_enabled;
    u64 crucible_host_ceiling_ns;
    struct {
        u32 vm_type;
        bool enable_pmu;
        unsigned long flags;
        struct { u64 voffset, poffset; } timer_data;
        struct kvm_crucible_clock_domain crucible_clock;
    } arch;
};
static bool kvm_crucible_arm_supported(void) { return true; }
static u64 ktime_get_ns(void) { return 1000; }
static u64 clock_now_locked(struct kvm_crucible_clock_domain *clock)
{ return clock->frozen_ns; }
'''

CASES = r'''
int main(void)
{
    int (*transitions[])(struct kvm *, struct kvm_crucible_clock *) = {x86_transition, arm_transition};

    for (unsigned index = 0; index < 2; index++) {
        struct kvm vm = {
            .crucible_run_return_enabled = true, .crucible_uncollected_returns = 2,
            .arch.crucible_clock = {
                .enabled = true, .version = 2, .numerator = 1, .denominator = 1,
                .window_generation = 5, .frozen_ns = 100, .close_acknowledged = true,
            },
        };
        struct kvm_crucible_clock request = { .version = 2, .operation = KVM_CRUCIBLE_CLOCK_BEGIN,
            .window_generation = 6, .start_ns = 100, .end_ns = 110 };
        struct kvm original = vm;

        assert(transitions[index](&vm, &request) == -EBUSY);
        assert(memcmp(&vm, &original, sizeof(vm)) == 0);
        request.operation = KVM_CRUCIBLE_CLOCK_STEP;
        request.window_generation = 5;
        request.start_ns = 105;
        assert(transitions[index](&vm, &request) == -EBUSY);
        assert(memcmp(&vm, &original, sizeof(vm)) == 0);
        request.operation = KVM_CRUCIBLE_CLOCK_QUERY;
        assert(transitions[index](&vm, &request) == 0);
        assert(memcmp(&vm, &original, sizeof(vm)) == 0);
        request.operation = KVM_CRUCIBLE_CLOCK_FREEZE;
        assert(transitions[index](&vm, &request) == 0);
        assert(vm.crucible_uncollected_returns == 2 && vm.arch.crucible_clock.window_generation == 5);

        vm.crucible_uncollected_returns = 1;
        request.operation = KVM_CRUCIBLE_CLOCK_BEGIN;
        request.window_generation = 6;
        request.start_ns = 100;
        assert(transitions[index](&vm, &request) == -EBUSY);
        vm.crucible_uncollected_returns = 0;
        assert(transitions[index](&vm, &request) == 0);
        assert(vm.arch.crucible_clock.window_generation == 6 && vm.arch.crucible_clock.active);
        assert(vm.arch.crucible_clock.start_ns == 100 && vm.arch.crucible_clock.end_ns == 110);
        assert(vm.crucible_host_ceiling_ns == 1010);

        vm = original;
        vm.crucible_run_return_enabled = false;
        assert(transitions[index](&vm, &request) == 0);
        assert(vm.arch.crucible_clock.window_generation == 6);
    }
    puts("Actual x86/ARM transition bodies: uncollected original receipts seal Begin/Step; Query/Freeze and disabled legacy behavior retained PASS; hardware stop not qualified.");
    return 0;
}
'''


def main():
    source, compiler, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    uapi = (source / 'include/uapi/linux/kvm.h').read_text()
    packet = uapi[uapi.index('#define KVM_CAP_CRUCIBLE_CLOCK_V1'):uapi.index('#define KVM_CAP_USER_MEMORY 3')]
    arithmetic = re.sub(r'^#include.*$', '', (source / 'include/linux/kvm_crucible_clock_math.h').read_text(), flags=re.M)
    x86 = function((source / 'arch/x86/kvm/crucible-clock.c').read_text(), 'static int clock_control_locked(').replace('clock_control_locked', 'x86_transition')
    arm = function((source / 'arch/arm64/kvm/crucible-clock.c').read_text(), 'static int clock_transition_locked(').replace('clock_transition_locked', 'arm_transition')
    output.mkdir(parents=True, exist_ok=True)
    native, binary = output / 'clock-proof.c', output / 'clock-proof'
    native.write_text(PREFIX + packet + arithmetic + x86 + arm + CASES)
    subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', str(native), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    main()
