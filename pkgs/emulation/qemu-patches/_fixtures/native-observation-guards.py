# SPDX-License-Identifier: GPL-2.0-or-later
"""Check original native observation guards, without granting profile authority.

Function-local predicates cannot be supplied by an unrelated consumer. The
compiled model/mutation suite separately exercises the actual registry bodies.
"""

from pathlib import Path
import re
import sys


def function(source, name):
    """Select the unique native declaration through its column-zero close."""
    declaration = re.compile(
        r"^(?:static )?(?:int|bool|void) " + re.escape(name) + r"\([^;]*?\)\n\{",
        re.M,
    )
    matches = list(declaration.finditer(source))
    if len(matches) != 1:
        raise SystemExit(f"FAIL unique native declaration: {name}")
    start = matches[0].start()
    closing = re.search(r"^}[ \t]*\n", source[matches[0].end():], re.M)
    if closing is None:
        raise SystemExit(f"FAIL native function close: {name}")
    return source[start:matches[0].end() + closing.end()]


def require(label, source, expression):
    if len(re.findall(expression, source, re.S)) != 1:
        raise SystemExit(f"FAIL {label}")


def main():
    root = Path(sys.argv[1])
    registry = (root / "util/crucible-timer-selection.c").read_text()
    timers = (root / "util/qemu-timer.c").read_text()
    rr = (root / "accel/tcg/tcg-accel-ops-rr.c").read_text()
    native = (root / "accel/tcg/tcg-accel-ops-sim-shmem.c").read_text()
    api = (root / "plugins/api-system.c").read_text()
    header = (root / "include/plugins/qemu-plugin.h").read_text()
    meson = (root / "util/meson.build").read_text()
    capture = function(rr, "qemu_plugin_crucible_node_capture_timer_selection")
    cause = function(rr, "rr_crucible_node_selection_cause")
    publish = function(timers, "qemu_timer_node_selection_publish")
    pending = function(timers, "crucible_hot_fork_timer_set_pending")
    dequeue = function(timers, "crucible_hot_fork_timer_callback_begin")
    enroll = function(native, "qemu_plugin_register_crucible_node_administration")
    query = function(native, "qemu_plugin_crucible_node_query_administration")
    socket = function(native, "node_administration_socket_matches")
    manifest = function(api, "qemu_plugin_crucible_register_resource_manifest")

    checks = [
        ("finite bound64", header, r"TIMER_SELECTION_MAX 64\b"),
        ("retained bound16", header, r"TIMER_SELECTION_RETAINED_MAX 16\b"),
        ("system build owns finite registry", meson, r"'crucible-timer-selection.c'"),
        ("capture requires genuine parked source", capture,
         r"result = qemu_plugin_crucible_node_query_cpu_park\(scope, &park\);"),
        ("capture requires Applied original", capture,
         r"rr_initialization_receipt.status !=\s*QEMU_PLUGIN_CRUCIBLE_NODE_INITIALIZATION_APPLIED"),
        ("no active writer or HOME", capture,
         r"rr_initialization_home_pending \|\|\s*rr_node_writer_dispatch \|\|"),
        ("same original HOLD", capture,
         r"if \(rr_node_writer_gate != expected_generation\) \{\s*return -ESTALE;"),
        ("roots and ordering remain unknown", capture,
         r"origin.flags = QEMU_PLUGIN_CRUCIBLE_NODE_TIMER_SELECTION_UNKNOWN_ROOTS \|\s*QEMU_PLUGIN_CRUCIBLE_NODE_TIMER_SELECTION_UNKNOWN_ORDER;"),
        ("authentic accepted command digest", capture,
         r"if \(rr_node_command_valid\) \{.*?origin.source_original_sequence = rr_node_command.sequence;.*?rr_node_command.grant_hash"),
        ("cause refuses outside RR seam", cause,
         r"if \(!bql_locked\(\) \|\| !first_cpu \|\| !qemu_cpu_is_self\(first_cpu\) \|\|.*?!rr_node_writer_dispatch.*?!rr_node_phase_sealed.*?!rr_node_command_valid.*?rr_node_command_stopped\)"),
        ("native timer generation publication", publish,
         r"crucible_hot_fork_timer_lock\(\);\s*if \(crucible_hot_fork_timer_generation != expected_mutation_generation\) \{\s*result = -EAGAIN;.*?qemu_timer_node_selection_install\(candidate, timers, selection\);.*?crucible_hot_fork_timer_unlock\(\);"),
        ("rearm preserves old identity", pending,
         r"uint64_t original_arm = timer->crucible_node_arm_generation;.*?original_arm, QEMU_PLUGIN_CRUCIBLE_NODE_TIMER_DISPOSITION_REARMED.*?timer->crucible_node_arm_generation = crucible_hot_fork_timer_generation;"),
        ("cancellation records original arm", pending,
         r"qemu_timer_node_selection_note\(timer->crucible_hot_fork_id,\s*timer->crucible_node_arm_generation,\s*QEMU_PLUGIN_CRUCIBLE_NODE_TIMER_DISPOSITION_CANCELLED"),
        ("dequeue records removal", dequeue,
         r"QEMU_PLUGIN_CRUCIBLE_NODE_TIMER_DISPOSITION_DEQUEUED,\s*crucible_hot_fork_timer_generation,\s*timer->crucible_hot_fork_id, timer->crucible_node_arm_generation"),
        ("canonical checksum domain", registry,
         r'static const char tag\[\] = "crucible.qemu-native-timer-selection.v1";'),
        ("actual connected UNIX datagram", socket,
         r"S_ISSOCK\(identity.st_mode\).*?identity.st_dev == policy->socket_device.*?identity.st_ino == policy->socket_inode.*?type == SOCK_DGRAM.*?local.ss_family == AF_UNIX.*?getpeername.*?peer.ss_family == AF_UNIX"),
        ("original complete policy before enrollment", enroll,
         r"memcmp\(policy, &node_administration_policy, sizeof\(\*policy\)\).*?!crucible_node_administration_pin_matches_phase\(\)"),
        ("actual original thread TLS", enroll,
         r"node_administration_registration !=\s*node_administration_facts.registration_id \|\|\s*node_administration_facts.thread_id != thread_id"),
        ("unexecuted first enrollment", enroll, r"else if \(qemu_plugin_icount_raw\(\) != 0\)"),
        ("other roots remain unknown", enroll,
         r"QEMU_PLUGIN_CRUCIBLE_NODE_ADMINISTRATION_SOCKET_OBSERVED \|\s*QEMU_PLUGIN_CRUCIBLE_NODE_ADMINISTRATION_THREAD_OBSERVED \|\s*QEMU_PLUGIN_CRUCIBLE_NODE_ADMINISTRATION_UNKNOWN_ROOTS"),
        ("fork refusal precedes inherited mutex", query,
         r"if \(node_administration_launch_process != getpid\(\)\) \{\s*return -ESTALE;\s*\}\s*status = pthread_mutex_lock"),
        ("V7 requires actual enrolled original fd", manifest,
         r"crucible_node_administration_manifest_matches\(.*?administration->administration_commitment,.*?administration->phase.initialization.native.node_control_fd\)"),
        ("old manifest cannot conceal reader", manifest,
         r"else if \(crucible_node_administration_launch_pinned\(\)\) \{.*?return -EINVAL;"),
        ("control worker remains present", header,
         r"#define QEMU_PLUGIN_CRUCIBLE_WORKER_NODE_CONTROL \(UINT64_C\(1\) << 3\)"),
    ]
    for label, source, expression in checks:
        require(label, source, expression)

    # Removing or duplicating each scoped predicate must fail. A consumer in
    # another function cannot replace the original native declaration's guard.
    for label, source, expression in checks:
        match = re.search(expression, source, re.S)
        for changed in (source[:match.start()] + source[match.end():],
                        source + "\n" + match.group()):
            try:
                require(label, changed, expression)
            except SystemExit:
                continue
            raise SystemExit(f"FAIL guard mutation survived: {label}")
    print(f"PASS {len(checks)} native finite/administrative source predicates and removed/duplicate negatives; no authority")


if __name__ == "__main__":
    main()
