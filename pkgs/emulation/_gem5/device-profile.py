# SPDX-License-Identifier: MIT
"""Writes the source-owned closed device mechanism manifest after real gates.

The caller is a fixed hermetic package phase. This writer is not a runtime
qualification API, accepts no public admission flag, and cannot mint a live
prepared owner or make a portable native capture authoritative.
"""

import hashlib
import json
import os
from pathlib import Path
import stat
import sys


MAX_ARTIFACT_BYTES = 2 * 1024**3
MAX_ROLES = 64
MAX_EVIDENCE = 1024 * 1024


def measure(path, maximum=MAX_ARTIFACT_BYTES):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 <= before.st_size <= maximum:
            raise ValueError('profile artifact is not one bounded immutable source leaf')
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            part = os.read(descriptor, min(remaining, 1024**2))
            if not part:
                raise ValueError('profile artifact was truncated')
            remaining -= len(part)
            digest.update(part)
        after = os.fstat(descriptor)
        if os.read(descriptor, 1) or (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ):
            raise ValueError('profile artifact changed during source binding')
        return {'path': str(path), 'sha256': digest.hexdigest(), 'length': str(before.st_size)}
    finally:
        os.close(descriptor)


def configuration_tree(root):
    """Measures the source-owned immutable directory using the native row codec."""
    root = Path(root)
    if root.resolve() != root or not str(root).startswith("/nix/store/"):
        raise ValueError("Device board configuration lacks immutable source custody")
    rows = []
    total = 0
    pending = [(root, 0)]
    directories = 0
    while pending:
        directory, depth = pending.pop()
        directories += 1
        metadata = directory.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o222
                or depth > 32 or directories + len(rows) > 4096):
            raise ValueError("Device configuration tree exceeds immutable finite custody")
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    pending.append((path, depth + 1))
                    if len(pending) > 4096:
                        raise ValueError("Device configuration directory credit exhausted")
                    continue
                if directories + len(rows) >= 4096:
                    raise ValueError("Device configuration file credit exhausted")
                if path.lstat().st_mode & 0o222:
                    raise ValueError('device configuration leaf is not immutable')
                observed = measure(path, maximum=64 * 1024**2 - total)
                total += int(observed["length"])
                if total > 64 * 1024**2:
                    raise ValueError("Device configuration byte credit exhausted")
                rows.append({"path": str(path.relative_to(root)), "bytes": observed["length"],
                             "sha256": observed["sha256"]})
    rows.sort(key=lambda row: row["path"])
    body = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return {"files": str(len(rows)), "bytes": str(total),
            "sha256": hashlib.sha256(body).hexdigest()}


def validate_evidence(evidence):
    if (evidence.get('schema') != 'crucible.gem5.arm-linux-inflight-device-mechanism.v1'
            or evidence.get('original_namespace_gone') is not True
            or evidence.get('closed_terminal_monitor') is not True
            or evidence.get('external_serial_admitted') is not False
            or evidence.get('typed_diagnostics_complete') is not False
            or evidence.get('common_preparation_qualified') is not False
            or evidence.get('full_device_parity_qualified') is not False
            or evidence.get('cpu_timing_qualified') is not False
            or evidence.get('capture_phase') != 'first-kernel-virtio-block-request-v1'
            or evidence.get('guest_application_ready_qualified') is not False):
        raise ValueError('actual native device evidence is absent or overclaims its scope')
    branches = evidence.get('branches')
    if not isinstance(branches, list) or len(branches) != 2 or {branch.get('name') for branch in branches} != {'child-a', 'child-b'}:
        raise ValueError('device evidence does not identify two independent native children')
    counts = []
    for branch in branches:
        for field in ('fresh_byte_closure', 'held_original_request_and_future_reply',
                      'native_completion_unchanged', 'group_reclaimed'):
            if branch.get(field) is not True:
                raise ValueError('native fresh branch is missing an actual required gate')
        count = branch.get('original_terminal_births_and_bytes')
        if type(count) is not int or not 0 < count <= 32768:
            raise ValueError('original closed terminal FIFO proof exceeds finite source scope')
        counts.append(count)
    if counts[0] != counts[1]:
        raise ValueError('native children disagree on original UART custody')


def write(specification, evidence, output):
    if set(specification) != {'artifacts', 'configuration_tree'}:
        raise ValueError('profile source specification has unknown fields')
    paths = specification['artifacts']
    if not isinstance(paths, dict) or not 1 <= len(paths) <= MAX_ROLES:
        raise ValueError('profile artifact census exceeds finite source roles')
    required = {'native_executable', 'controller', 'entrypoint', 'model', 'board_model',
                'publication_model', 'asset_checker', 'auditor', 'auditor_core',
                'image_guard', 'dmtcp_launch', 'dmtcp_restart', 'mtcp_restart', 'python',
                'kernel', 'initramfs', 'firmware', 'source_manifest', 'source_recipe',
                'witness', 'image_witness', 'archive_custody', 'diagnostic_projection', 'mechanism_evidence', 'profile_writer',
                'native_diagnostic_manifest', 'native_diagnostic_patch', 'native_fifo_patch', 'license_inventory'}
    if set(paths) != required:
        raise ValueError('profile source roles differ from the complete installed mechanism closure')
    validate_evidence(evidence)
    artifacts = {role: measure(Path(path)) for role, path in sorted(paths.items())}
    configs = configuration_tree(Path(specification['configuration_tree']))
    result = {
        'schema': 'crucible.gem5.arm-linux-device-foundation-profile.v1',
        'model_id': 'arm-linux-vexpress-atomic-net-block-functional-v1',
        'native_dialect': 'crucible.gem5.arm-linux-devices-native/1',
        'selection_schema': 'crucible.gem5.arm-linux-net-block-model.v1',
        'capture_phase': 'first-kernel-virtio-block-request-v1',
        'guest_application_ready_qualified': False,
        'artifacts': artifacts, 'configuration_tree': configs,
        'configuration_root': specification['configuration_tree'],
        'model': {'isa': 'aarch64', 'board': 'VExpress_GEM5_V2',
                  'cpu': 'ArmAtomicSimpleCPU', 'instruction_width': '16',
                  'clock_hz': '100000000', 'memory_bytes': '268435456',
                  'native_device_execution_parent': '17', 'native_terminal_parent': '0',
                  'mmio': [{'kind': 'network', 'address': '471007232', 'queue_size': '256'},
                           {'kind': 'block', 'address': '471072768', 'queue_size': '256'}]},
        'clock': {'native_tick_ps': '1', 'maximum_callbacks': '16000000',
                  'maximum_tick': '1000000000000', 'common_full_position_admitted': False},
        'diagnostics': {'scope': 'native-event-metadata-device-control-fields-and-closed-terminal-fifo-v2',
                        'complete': False, 'maximum_object_bytes': '4194304',
                        'maximum_total_bytes': '268435456', 'maximum_files': '1024',
                        'maximum_terminal_rows': '32768',
                        'omitted': ['cpu', 'ram', 'cache', 'unselected-device-fields',
                                    'complete-polymorphic-payloads']},
        'mechanism': evidence,
        'admission': {'common_ready': False, 'native_archive': False,
                      'external_serial': False, 'cpu_timing': False, 'full_device_parity': False},
    }
    output.write_text(json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n')


if __name__ == '__main__':
    specification, evidence, output = map(Path, sys.argv[1:])
    if specification.stat().st_size > MAX_EVIDENCE or evidence.stat().st_size > MAX_EVIDENCE:
        raise ValueError('profile metadata exceeds pre-read finite credit')
    write(json.loads(specification.read_bytes()), json.loads(evidence.read_bytes()), output)
