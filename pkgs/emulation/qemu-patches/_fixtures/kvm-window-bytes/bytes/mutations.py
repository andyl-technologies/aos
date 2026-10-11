"""Require compiler-success/real assertion failures for actual native guards."""
from pathlib import Path
import importlib.util
import json
import shutil
import signal
import subprocess
import sys


CONTROLS = [
    ('original-native-id', 'response_bytes_journal',
     'entry->kernel_vcpu_id != kvm_arch_vcpu_id(cpu)', 'false'),
    ('canonical-reserved', 'response_bytes_packet_valid',
     'if (packet->reserved[index])', 'if (false && packet->reserved[index])'),
    ('canonical-zero-tail', 'response_bytes_packet_valid',
     'if (packet->data[index])', 'if (false && packet->data[index])'),
    ('canonical-mmio-width', 'response_bytes_packet_valid',
     'packet->length > 8', 'packet->length > 4096'),
    ('canonical-read-data', 'response_bytes_packet_valid',
     'return packet->data_length == (packet->direction ? total : 0);',
     'return packet->data_length == (packet->direction ? total : 0) || true;'),
    ('query-native-id', 'response_bytes_query_valid',
     'packet->native_vcpu_id == native_id', '(packet->native_vcpu_id == native_id || true)'),
    ('original-write-bytes', 'kvm_crucible_response_bytes_geometry',
     '(packet->direction && memcmp(original->response, packet->data, total))', 'false'),
    ('handler-executing', 'kvm_crucible_response_bytes_dispatch_geometry',
     '!service->executing', 'false'),
    ('handler-active', 'kvm_crucible_response_bytes_dispatch_geometry',
     '!qatomic_load_acquire(&state->crucible_response_service_active)', 'false'),
    ('handler-original-fragment', 'kvm_crucible_response_bytes_dispatch_geometry',
     'service->exit_sequence != entry->exit_sequence', 'false'),
    ('handler-metadata', 'kvm_crucible_response_bytes_geometry',
     'original->address != packet->address', 'false'),
    ('clock-generation', 'response_bytes_clock_closed',
     'clock.window_generation != generation', '(clock.window_generation != generation && false)'),
    ('clock-inactive', 'response_bytes_clock_closed',
     'clock.active || clock.run_owners || clock.close_acknowledged != 1 ||',
     'clock.run_owners ||'),
    ('step-native-id', 'response_bytes_step_valid',
     'result->native_vcpu_id != native_id', '(result->native_vcpu_id != native_id && false)'),
    ('cached-original-result', 'qmp_x_crucible_kvm_response_bytes',
     'if (journal->result_known)', 'if (false && journal->result_known)'),
    ('cached-original-sequence', 'qmp_x_crucible_kvm_response_bytes',
     'journal->original_request.expected_sequence != expected_sequence', 'false'),
    ('original-stopped-owner', 'qmp_x_crucible_kvm_response_bytes',
     '!qemu_cpu_native_window_stopped(cpu)',
     '(!qemu_cpu_native_window_stopped(cpu) && false)'),
    ('finite-original-credits', 'qmp_x_crucible_kvm_response_bytes',
     'available - state->crucible_userspace_reserved_revisions < 3', 'false'),
    ('sticky-unknown-recovery', 'qmp_x_crucible_kvm_response_bytes',
     'entry->uncertain_effects |= packet->callback_result < 0 ||',
     'entry->uncertain_effects = packet->callback_result < 0 ||'),
    ('sticky-native-opacity', 'qmp_x_crucible_kvm_response_bytes',
     'entry->opaque_effects |=\n            (packet->flags & KVM_CRUCIBLE_COMPLETION_OPAQUE);',
     'entry->opaque_effects |= false;'),
    ('configuration-autostart', 'kvm_crucible_response_bytes_configure',
     'if (autostart ||', 'if (false ||'),
    ('configuration-kernel-cap', 'kvm_crucible_response_bytes_configure',
     'kvm_vm_check_extension(state, KVM_CAP_CRUCIBLE_RESPONSE_BYTES_V1) != 1',
     '(kvm_vm_check_extension(state, KVM_CAP_CRUCIBLE_RESPONSE_BYTES_V1) != 1 && false)'),
    ('configuration-finite-roster', 'kvm_crucible_response_bytes_configure',
     'state->crucible_userspace_capacity > QEMU_CRUCIBLE_RESPONSE_BYTES_MAX_VCPUS', 'false'),
]


def main():
    source, kernel, compiler, output = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4])
    root = Path(__file__).parent
    spec = importlib.util.spec_from_file_location('bridge_proof', root / 'model.py')
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)
    output.mkdir(parents=True, exist_ok=True)
    original = (source / 'accel/kvm/crucible-response-bytes.c').read_text()
    rows = []
    for name, native_function, old, new in CONTROLS:
        owned = output / name
        candidate = owned / 'source'
        if (source / 'scripts/qapi-gen.py').is_file():
            # A model needs only its actual native inputs and schema generator;
            # copying all built binaries/firmware per control wastes custody.
            for relative in ('accel/kvm/crucible-clock.c',
                             'accel/kvm/crucible-window.c',
                             'accel/kvm/crucible-response-bytes.c',
                             'accel/kvm/kvm-all.c',
                             'include/system/crucible-kvm-clock.h',
                             'include/system/crucible-kvm-window.h',
                             'include/system/crucible-kvm-response-bytes.h',
                             'include/system/kvm_int.h', 'scripts/qapi-gen.py'):
                copied = candidate / relative
                copied.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source / relative, copied)
            for relative in ('qapi', 'scripts/qapi'):
                shutil.copytree(source / relative, candidate / relative,
                                dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__'))
        else:
            shutil.copytree(source, candidate, dirs_exist_ok=True)
        function = model.function(original, native_function)
        if function.count(old) != 1:
            raise ValueError(name + ': expected one actual native function predicate')
        changed = original.replace(function, function.replace(old, new))
        (candidate / 'accel/kvm/crucible-response-bytes.c').write_text(changed)
        proof = owned / 'proof'
        with (owned / 'build-and-assertion.log').open('w') as log:
            result = subprocess.run([sys.executable, str(root / 'model.py'), str(candidate), str(kernel), compiler, str(proof)], stdout=log, stderr=subprocess.STDOUT, timeout=30)
        binary = proof / 'bridge'
        if result.returncode == 0 or not binary.is_file():
            raise ValueError(name + ': compile failure or missing semantic negative')
        with (owned / 'actual-assertion.log').open('w') as log:
            actual = subprocess.run([str(binary)], stdout=log, stderr=subprocess.STDOUT, timeout=30)
        diagnostic = (owned / 'actual-assertion.log').read_text()
        if actual.returncode != -signal.SIGABRT or 'Assertion' not in diagnostic:
            raise ValueError(name + ': must fail a compiled genuine assertion')
        rows.append({'name': name, 'function': native_function, 'compiler_success': True,
                     'child_return': actual.returncode, 'assertion': diagnostic.strip()})
        print(name + ': compiler-success actual source assertion detected', flush=True)
    (output / 'manifest.json').write_text(json.dumps(rows, indent=2) + '\n')
    print(str(len(rows)) + ' actual native guard controls PASS; no hardware qualification')


if __name__ == '__main__':
    main()
