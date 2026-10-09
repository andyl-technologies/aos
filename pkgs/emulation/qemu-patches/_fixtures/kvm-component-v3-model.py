"""Compile actual component marshalling with model-only kernel response faults.

The source functions and fixed-width syscall structure come from the supplied
QEMU tree. This tests ABI/error handling; it cannot qualify a real KVM node.
Pass the AOS-built compiler explicitly. No upstream or host compiler is selected.
"""

from pathlib import Path
import subprocess
import sys


def source_function(source, name):
    """Select one complete production function without duplicating its body."""
    marker = "static "
    position = source.index(name + "(")
    start = source.rfind(marker, 0, position)
    brace = source.index("{", position)
    depth = 1
    end = brace + 1
    while depth:
        character = source[end]
        depth += (character == "{") - (character == "}")
        end += 1
    return source[start:end] + "\n\n"


PREFIX = r"""// SPDX-License-Identifier: GPL-2.0-only
/* Extracted source component marshalling model; no real KVM qualification. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <linux/kvm.h>

/* Header-only later declarations need an opaque CPU type, not a CPU model. */
typedef struct CPUState CPUState;

typedef struct KVMState {
    uint32_t crucible_clock_kernel_edition;
} KVMState;

static uint32_t expected_cap, expected_version, response_coverage;
static unsigned defect, calls;
static int result;
static int kvm_vm_ioctl(KVMState *state, unsigned long operation,
                        struct kvm_enable_cap *cap);

@NATIVE_HEADER@
_Static_assert(sizeof(struct kvm_crucible_clock) == 96, "component ABI size");
_Static_assert(offsetof(struct kvm_crucible_clock, current_ns) == 48, "coordinate ABI offset");
_Static_assert(offsetof(struct kvm_crucible_clock, reserved) == 76, "reserved ABI offset");

static int kvm_vm_ioctl(KVMState *state, unsigned long operation,
                        struct kvm_enable_cap *cap)
{
    struct kvm_crucible_clock *clock = (void *)(uintptr_t)cap->args[0];
    assert(operation == KVM_ENABLE_CAP && cap->cap == expected_cap);
    assert(clock->version == expected_version);
    assert(state->crucible_clock_kernel_edition == expected_version);
    assert(cap->args[1] == 0 && cap->args[2] == 0 && cap->args[3] == 0);
    calls++;
    if (result) {
        return result;
    }

    clock->coverage = response_coverage;
    if (defect == 1) {
        clock->version++;
    }
    if (defect == 2) {
        clock->current_ns = UINT64_MAX;
    }
    if (defect == 3) {
        clock->active = 2;
    }
    if (defect == 4) {
        clock->close_acknowledged = 2;
    }
    return 0;
}

"""

SUFFIX = r"""int main(void)
{
    for (unsigned edition = 1; edition <= 3; edition += 2) {
        KVMState state = { .crucible_clock_kernel_edition = edition };
        expected_cap = edition == 1 ? 0xa025 : 0xa027;
        expected_version = edition;
        response_coverage = edition == 1 ? 7 : 159;
        struct kvm_crucible_clock clock = { .version = edition };
        unsigned before_calls = calls;

        assert(clock_control(&state, &clock) == 0);
        assert(calls == before_calls + 1);
        for (defect = 1; defect <= 4; defect++) {
            clock = (struct kvm_crucible_clock){ .version = edition };
            assert(clock_control(&state, &clock) == -EPROTO);
        }
        defect = 0;
        result = -EIO;
        assert(clock_control(&state, &clock) == -EIO);
        result = 0;

        clock = (struct kvm_crucible_clock){ .version = edition };
        response_coverage ^= 128;
        assert(clock_control(&state, &clock) == -EPROTO);
    }
    puts("PASS model-only: original/v3 capability, exact coverage, layout and "
         "response refusals; no native KVM qualification");
    return 0;
}
"""


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: kvm-component-v3-model.py QEMU_SOURCE AOS_CC OUTPUT_DIR")
    source_root = Path(sys.argv[1])
    compiler = Path(sys.argv[2])
    output = Path(sys.argv[3])
    output.mkdir(parents=True, exist_ok=True)

    header = (source_root / "include/system/crucible-kvm-clock.h").read_text()
    header = header.replace('#include "system/kvm.h"', "")
    header = header.replace('int kvm_crucible_clock_configure(KVMState *state);', "")
    header = header.replace('bool kvm_crucible_clock_read_ns(int64_t *nanoseconds);', "")
    source = (source_root / "accel/kvm/crucible-clock.c").read_text()
    functions = "".join(source_function(source, name) for name in
                        ("clock_capability", "clock_components", "clock_control"))
    translation_unit = output / "component-model.c"
    translation_unit.write_text(PREFIX.replace("@NATIVE_HEADER@", header) + functions + SUFFIX)
    executable = output / "component-model"
    subprocess.run([str(compiler), "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-Wmissing-prototypes", "-Wstrict-prototypes",
                    str(translation_unit), "-o", str(executable)],
                   check=True, timeout=60)
    subprocess.run([str(executable)], check=True, timeout=10)


if __name__ == "__main__":
    main()
