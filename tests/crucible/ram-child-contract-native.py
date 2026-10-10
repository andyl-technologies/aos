"""Checks actual child kernel limits before production pager reconstruction.

The fixture compiles the production contract and coordinator child branch,
then uses real fork, setrlimit, getrlimit and cancellation descriptors. It
qualifies ordering and limit isolation, without claiming a live pager flight.
"""

import argparse
from pathlib import Path
import subprocess
import tempfile


def function(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 1
    cursor = opening + 1
    while depth:
        depth += (source[cursor] == "{") - (source[cursor] == "}")
        cursor += 1
    return source[start:cursor]


parser = argparse.ArgumentParser()
parser.add_argument("--source", required=True, type=Path)
parser.add_argument("--cc", required=True)
arguments = parser.parse_args()
monitor = (arguments.source / "monitor/qmp-cmds.c").read_text()
coordinator = (arguments.source / "system/crucible-hot-fork-coordinator.c").read_text()
contract = function(monitor, "static int crucible_hot_fork_apply_child_process_contract(")
# Extract from the actual transaction branch rather than the earlier fork helper.
start = coordinator.index("    if (child_pid == 0)", coordinator.index("operation.ram_source_generation"))
child = function(coordinator[start:], "    if (child_pid == 0)")
program = r"""
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
/* This isolated branch uses only constant-size atomic operands. */
#define qemu_build_assert(test) _Static_assert((test), "invalid atomic operand size")
#include "qemu/atomic.h"
#define QEMU_CRUCIBLE_HOT_FORK_CHILD_CONTRACT_EXIT 65
#define QEMU_PLUGIN_CRUCIBLE_RAM_REBIND_CHILD 4

typedef struct CrucibleHotForkOperation {
    bool prepared;
    int child_process_cgroup_fd;
    int child_process_cgroup_procs_fd;
    int child_process_cancellation_fd;
    uint64_t maximum_file_bytes;
    uint64_t maximum_locked_bytes;
} CrucibleHotForkOperation;
""" + contract + r"""
static unsigned int stage;
static int qemu_plugin_crucible_ram_lifecycle(uint32_t operation, uint64_t generation)
{
    struct rlimit lock_limit, file_limit;
    assert(stage == 1 && operation == 4 && generation == 7);
    assert(getrlimit(RLIMIT_MEMLOCK, &lock_limit) == 0);
    assert(lock_limit.rlim_cur == 0 && lock_limit.rlim_max == 0);
    assert(getrlimit(RLIMIT_FSIZE, &file_limit) == 0);
    assert(file_limit.rlim_cur == 8192 && file_limit.rlim_max == 8192);
    stage++;
    return 0;
}
static void qemu_crucible_block_seal_child_reset(void) { assert(stage++ == 2); }
static void event_notifier_cleanup(int *wake) { (void)wake; assert(stage++ == 0); }
static int reconstruct(void *opaque) {
    CrucibleHotForkOperation *contract = opaque;
    assert(stage++ == 3);
    assert(contract->child_process_cancellation_fd == -1);
    return 0;
}
static void actual_child_branch(CrucibleHotForkOperation *contract)
{
    struct {
        int (*child_contract)(void *);
        int (*child)(void *);
        void *opaque;
        uint64_t ram_source_generation;
    } operation = {
        .child_contract = crucible_hot_fork_apply_child_process_contract,
        .child = reconstruct, .opaque = contract, .ram_source_generation = 7,
    };
    struct {
        int wake;
        bool initialized, busy, executing, completed, child_runtime_pending;
    } state = { .initialized = true };
    __typeof__(state) *coordinator = &state;
    int child_pid = 0;
    int result;
""" + child + r"""
}
int main(void)
{
    struct rlimit parent_lock, parent_file, observed;
    int cancellation[2];
    assert(getrlimit(RLIMIT_MEMLOCK, &parent_lock) == 0);
    assert(getrlimit(RLIMIT_FSIZE, &parent_file) == 0);
    assert(parent_file.rlim_max == RLIM_INFINITY || parent_file.rlim_max >= 8192);
    assert(pipe(cancellation) == 0);
    for (int cancel = 0; cancel < 2; cancel++) {
        if (cancel) { assert(write(cancellation[1], "x", 1) == 1); }
        pid_t child = fork();
        assert(child >= 0);
        if (child == 0) {
            CrucibleHotForkOperation contract = {
                .prepared = true,
                .child_process_cgroup_fd = dup(cancellation[0]),
                .child_process_cgroup_procs_fd = dup(cancellation[0]),
                .child_process_cancellation_fd = dup(cancellation[0]),
                .maximum_file_bytes = 8192, .maximum_locked_bytes = 0,
            };
            actual_child_branch(&contract);
            assert(stage == 4);
            _exit(0);
        }
        int status;
        assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status));
        assert(WEXITSTATUS(status) == (cancel ? 65 : 0));
        assert(getrlimit(RLIMIT_MEMLOCK, &observed) == 0);
        assert(observed.rlim_cur == parent_lock.rlim_cur);
        assert(observed.rlim_max == parent_lock.rlim_max);
        assert(getrlimit(RLIMIT_FSIZE, &observed) == 0);
        assert(observed.rlim_cur == parent_file.rlim_cur);
        assert(observed.rlim_max == parent_file.rlim_max);
    }
    close(cancellation[0]); close(cancellation[1]);
    return 0;
}
"""
with tempfile.TemporaryDirectory(prefix="crucible-child-contract-") as directory:
    source = Path(directory) / "contract.c"
    binary = Path(directory) / "contract"
    source.write_text(program)
    subprocess.run([
        arguments.cc, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
        "-I", str(arguments.source / "include"), str(source), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True)
print("child_contract_before_pager_rebind=true")
print("child_kernel_limits_verified=true")
print("child_contract_cancel_before_reconstruction=true")
print("parent_kernel_limits_preserved=true")
