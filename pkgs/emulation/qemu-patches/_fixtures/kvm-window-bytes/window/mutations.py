"""Require compiler-success assertion failures for exact actual native predicates."""
from pathlib import Path
import subprocess
import shutil
import sys

sys.dont_write_bytecode = True
root = Path(__file__).parent
source, kernel, compiler, output = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4])
output.mkdir(parents=True, exist_ok=True)
changes = [
    ('hidden-pending', 'accel/kvm/crucible-window.c', '!receipt->pending_mask && !receipt->response_flags', 'true && !receipt->response_flags'),
    ('uncertain-history', 'accel/kvm/crucible-window.c', '!receipt->pending_mask && !receipt->response_flags', '!receipt->pending_mask && true'),
    ('generation', 'accel/kvm/crucible-window.c', 'receipt->generation_end == generation &&', 'true &&'),
    ('ceiling', 'accel/kvm/crucible-window.c', 'receipt->current_end_ns <= end_ns &&', 'true &&'),
    ('native-owner', 'accel/kvm/crucible-window.c', 'receipt->native_vcpu_id == native_id &&', 'true &&'),
    ('returned-receipt', 'accel/kvm/crucible-window.c', '(receipt->flags & KVM_CRUCIBLE_RUN_RETURN_RETURNED) &&', 'true &&'),
    ('old-response-consumption', 'accel/kvm/crucible-window.c', 'receipt->response_sequence == receipt->response_consumed &&', 'true &&'),
    ('negative-result', 'accel/kvm/crucible-window.c', '(result == -EINTR || result == -EAGAIN) &&', 'true &&'),
    ('ack-once', 'accel/kvm/crucible-window.c', '!record->ack_known) {', 'true) {'),
    ('original-ack-identity', 'accel/kvm/crucible-window.c', '!run_receipt_same(&record->receipt, &entry->last_receipt)', 'false'),
    ('previous-ack-identity', 'accel/kvm/crucible-window.c', 'run_receipt_same(&receipt, &entry->last_receipt)', 'true'),
    ('closed-entry', 'accel/kvm/crucible-window.c', 'entry && qatomic_load_acquire(&state->crucible_window_phase) ==\n        CRUCIBLE_KVM_WINDOW_RUNNING &&', 'entry && true &&'),
    ('closed-pre-run', 'accel/kvm/crucible-clock.c', '(!state->crucible_window_configured ||\n         qatomic_load_acquire(&state->crucible_window_phase) ==\n         CRUCIBLE_KVM_WINDOW_RUNNING) &&', 'true &&'),
    ('whole-roster-credit', 'accel/kvm/crucible-window.c', 'state->crucible_window_roster_count >\n            QEMU_CRUCIBLE_WINDOW_MAX_RETURNS -\n            state->crucible_window_return_count', 'false'),
    ('roster-replacement', 'accel/kvm/crucible-window.c', '!state->crucible_window_roster_sealed;', 'true;'),
    ('kernel-clock-generation', 'accel/kvm/crucible-window.c', 'if (clock.window_generation != state->crucible_window_generation) {', 'if (false) {'),
    ('original-return-physical-cut', 'accel/kvm/crucible-window.c', '!qemu_cpu_native_window_stopped(cpu) || entry->current_reserved ||', '!cpu->stopped || entry->current_reserved ||'),
    ('ABI-native-capability', 'include/system/crucible-kvm-window.h', '#define KVM_CAP_CRUCIBLE_RUN_RETURN_V1 0xa029', '#define KVM_CAP_CRUCIBLE_RUN_RETURN_V1 0xa02a'),
    ('ABI-native-ioctl', 'include/system/crucible-kvm-window.h', '_IOWR(KVMIO, 0xd7, struct kvm_crucible_run_return)', '_IOWR(KVMIO, 0xd8, struct kvm_crucible_run_return)'),
    ('ABI-native-owner', 'include/system/crucible-kvm-window.h', '    uint32_t native_vcpu_id;\n    uint32_t pending_mask;', '    uint32_t pending_mask;\n    uint32_t native_vcpu_id;'),
]
paths = [
    'accel/kvm/crucible-clock.c', 'accel/kvm/crucible-window.c',
    'include/system/crucible-kvm-clock.h', 'include/system/crucible-kvm-window.h',
    'include/system/kvm_int.h', 'include/exec/memattrs.h',
    'build/qapi/qapi-types-run-state.h',
]
for name, relative, before, after in changes:
    copied = output / name / 'source'
    for path in paths:
        target = copied / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / path, target)
    path = copied / relative
    body = path.read_text()
    assert body.count(before) == 1, (name, body.count(before))
    path.write_text(body.replace(before, after))
    result = subprocess.run([sys.executable, str(root/'model.py'), str(copied), str(kernel), compiler, str(output/name/'proof')], capture_output=True)
    (output/name/'stdout').write_bytes(result.stdout)
    (output/name/'stderr').write_bytes(result.stderr)
    assert result.returncode != 0, name
    # The retained stderr must identify the native executable's SIGABRT and
    # assertion. Compile errors, adapter failures and segmentation faults fail.
    assert b'died with <Signals.SIGABRT: 6>' in result.stderr, name
    assert b'Assertion' in result.stderr, name
    assert (output/name/'proof/window-model').is_file(), name
    print(name + ': actual compiled native assertion detected mutation')
print(str(len(changes)) + ' actual compiled mutation assertions PASS; source/model scope, no KVM execution.')
