"""Require actual compiled source assertions to reject initial-response defects."""
from pathlib import Path
import shutil
import subprocess
import sys

root = Path(__file__).parent
source, compiler, output, kernel = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4])
output.mkdir(parents=True, exist_ok=True)
changes = [
    ('unissued-return', 'window', '!record->issued ||', 'false ||'),
    ('unknown-original-receipt', 'window', '!record->receipt_known ||', 'false ||'),
    ('unborn-return', 'window', 'record->no_birth_known ||', 'false ||'),
    ('negative-original-run', 'window', 'record->native_result < 0', 'false'),
    ('native-cpu-identity', 'window', 'receipt->native_vcpu_id != userspace->kernel_vcpu_id ||', 'false ||'),
    ('original-begin-generation', 'window', 'receipt->generation_begin != generation ||', 'false ||'),
    ('original-end-generation', 'window', 'receipt->generation_end != generation ||', 'false ||'),
    ('initial-not-more', 'window', 'receipt->response_phase != KVM_CRUCIBLE_COMPLETION_PENDING ||', 'false ||'),
    ('sticky-native-response-uncertainty', 'window', 'receipt->response_flags ||', 'false ||'),
    ('original-response-sequence', 'window', 'receipt->response_sequence != userspace->exit_sequence ||', 'false ||'),
    ('private-mmio-pending', 'window', 'receipt->pending_mask != pending', 'receipt->pending_mask != pending && false'),
    ('known-closed-window', 'initial', 'qatomic_load_acquire(&state->crucible_window_phase) !=\n                CRUCIBLE_KVM_WINDOW_CLOSED ||', 'false ||'),
    ('original-closed-kernel-generation', 'initial', 'clock.window_generation != generation ||', 'false ||'),
    ('original-post-run-attributes', 'initial', '!service->attributes_known ||', 'false ||'),
    ('pinned-initial-geometry', 'initial', '!completion_geometry(state, original_cpu, entry, false)', 'false'),
    ('callback-original-birth', 'callback', 'kvm_crucible_window_initial_response_owner_locked(\n             state, service->original_record, service->original_generation,\n             service->original_invocation) != cpu', 'false'),
    ('premature-profile-qualification', 'initial', 'info->profile_qualified = false;', 'info->profile_qualified = true;'),
    ('cached-result-bypasses-current-fragment', 'initial',
     'journal->issued && journal->result_known', 'false'),
    ('original-result-custody-not-retained', 'initial',
     'journal->result_known = true;', 'journal->result_known = false;'),
    ('cached-original-service-identity', 'initial',
     '        goto reply;',
     '        journal->service_id = response_service_locked(state, original_cpu)->service_id;\n        goto reply;'),
    ('historical-original-generation', 'history',
     'record->generation != generation ||', 'false ||'),
    ('historical-original-native-cpu', 'history',
     'receipt->native_vcpu_id !=\n            state->crucible_userspace_exits[record->vcpu_index].kernel_vcpu_id ||', 'false ||'),

]
for name, scope, before, after in changes:
    candidate = output / name / 'source'
    # Each mutant retains only independently needed native source and QAPI
    # inputs, avoiding firmware/build-tree copies for every source defect.
    for directory in ('qapi', 'scripts/qapi', 'linux-headers'):
        shutil.copytree(source / directory, candidate / directory, symlinks=True)
    for relative in (
        'scripts/qapi-gen.py', 'accel/kvm/crucible-clock.c',
        'accel/kvm/crucible-window.c', 'accel/kvm/kvm-all.c',
        'include/system/crucible-kvm-clock.h', 'include/system/crucible-kvm-window.h',
        'include/system/kvm_int.h', 'include/exec/memattrs.h',
    ):
        target = candidate / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, target)
    if scope in ('window', 'history'):
        file = candidate / 'accel/kvm/crucible-window.c'
        start = ('CrucibleKvmOriginalReturn *kvm_crucible_window_initial_record_locked(' if scope == 'history' else
                 'CPUState *kvm_crucible_window_initial_response_owner_locked(')
    else:
        file = candidate / 'accel/kvm/crucible-clock.c'
        start = ('static int response_service_callback(' if scope == 'callback' else
                 'CrucibleKvmInitialResponseInfo *qmp_x_crucible_kvm_initial_response(')
    body = file.read_text()
    begin = body.index(start)
    end = body.index('\n}\n', begin) + 3
    function = body[begin:end]
    assert function.count(before) == 1, (name, function.count(before))
    changed = body[:begin] + function.replace(before, after, 1) + body[end:]
    if name == 'historical-original-generation':
        # All three independent comparisons authenticate this same original
        # generation. Removing only one would leave the safety fact intact.
        mutated = function.replace(before, after, 1)
        for predicate in ('receipt->generation_begin != generation ||',
                          'receipt->generation_end != generation ||'):
            assert mutated.count(predicate) == 1
            mutated = mutated.replace(predicate, 'false ||', 1)
        changed = body[:begin] + mutated + body[end:]
    if scope == 'window':
        # Fresh admission and historical recovery independently authenticate
        # some original facts. Mutate every copy of that one source predicate
        # so redundant checks cannot hide a now-ineffective negative test.
        history_start = body.index('CrucibleKvmOriginalReturn *kvm_crucible_window_initial_record_locked(')
        history_end = body.index('\n}\n', history_start) + 3
        history = body[history_start:history_end]
        expected = 1 if name in {
            'unissued-return', 'unknown-original-receipt', 'unborn-return',
            'negative-original-run', 'original-begin-generation',
            'original-end-generation',
        } else 0
        assert history.count(before) == expected, name
        if expected:
            changed = changed.replace(history, history.replace(before, after, 1), 1)
    file.write_text(changed)
    proof = output / name / 'proof'
    result = subprocess.run([sys.executable, str(root / 'model.py'), str(candidate), compiler, str(proof), str(kernel)], capture_output=True, timeout=30)
    (output / name / 'stdout').write_bytes(result.stdout)
    (output / name / 'stderr').write_bytes(result.stderr)
    assert (proof / 'initial-response').is_file(), (name, result.stderr[-1000:])
    assert result.returncode != 0 and b'Assertion' in result.stderr, name
    assert b'died with <Signals.SIGABRT: 6>' in result.stderr, name
    print(name + ': compiler-success original assertion rejects defect', flush=True)
print('Twenty-two meaningful initial-response source defects rejected; no hardware/profile qualification.')
