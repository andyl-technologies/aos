"""Require each compiled original-source mutation to fail the custody model."""

from pathlib import Path
import shutil
import subprocess
import sys

if len(sys.argv) != 6:
    raise SystemExit('usage: kvm-completion-mutations.py QEMU_SOURCE AOS_CC OUTPUT_DIR KERNEL_PATCH MODEL_SCRIPT')

source = Path(sys.argv[1]).resolve()
cc = sys.argv[2]
root = Path(sys.argv[3])

root.mkdir(parents=True, exist_ok=True)

patch = sys.argv[4]
model = sys.argv[5]
body = (source / 'accel/kvm/crucible-clock.c').read_text()

changes = {
    'erase-state-put-taint-gate': (
        '(!entry->uncertain_effects && !entry->opaque_effects));',
        'true);',
    ),
    'reexecute-known-result': (
        '        if (journal->known) {',
        '        if (false && journal->known) {',
    ),
    'change-original-retry-id': (
        '    request = journal->original_request;',
        '    request = journal->original_request;\n    request.operation_id++;',
    ),
    'lose-response-byte-custody': (
        '!memcmp(original->response, bytes, value.length)',
        'true',
    ),
    'running-native-owner': (
        'clock.active || clock.run_owners || !clock.close_acknowledged',
        'clock.active || !clock.close_acknowledged',
    ),
    'active-native-window': (
        'clock.active || clock.run_owners || !clock.close_acknowledged',
        'clock.run_owners || !clock.close_acknowledged',
    ),
    'clear-uncertain-attempt': (
        '            entry->response.prepared = false;',
        '            entry->response.prepared = false;\n            entry->uncertain_effects = false;',
    ),
    'invent-more-dispatch': (
        '                entry->phase = CRUCIBLE_KVM_USERSPACE_HANDLING;',
        '                entry->phase = CRUCIBLE_KVM_USERSPACE_READY;',
    ),
    'consume-failed-callback': (
        '        if (request.callback_result < 0) {',
        '        if (request.callback_result < 0) {\n            entry->consumed_sequence = journal->original_exit_sequence;',
    ),
    'omit-revision-reservation': (
        'available - state->crucible_userspace_reserved_revisions < 3',
        'available - state->crucible_userspace_reserved_revisions < 2',
    ),
}

for name, (old, new) in changes.items():
    assert body.count(old) == 1, (name, body.count(old))
    target = root / name
    if target.exists():
        shutil.rmtree(target)
    candidate = target / 'source'
    candidate.mkdir(parents=True)
    for directory in ('scripts', 'qapi', 'linux-headers', 'include'):
        (candidate / directory).symlink_to(source / directory)
    path = candidate / 'accel/kvm/crucible-clock.c'
    path.parent.mkdir(parents=True)
    path.write_text(body.replace(old, new))
    result = subprocess.run([sys.executable, model, str(candidate), cc, str(target / 'proof'), patch], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=90)
    (target / 'log').write_text(result.stdout)
    # A compiler failure cannot count as a negative native policy witness.
    assert (target / 'proof/completion').exists(), ('mutation did not compile', name, result.stdout[-3000:])
    assert result.returncode != 0, ('broken custody survived', name)
    print(name + ': actual modified production function compiled; broken custody detected', flush=True)

print(f'{len(changes)} compiled original-source mutations rejected; no native KVM qualification.')
