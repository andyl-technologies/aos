"""Require compiler-success assertion failures for altered original custody."""
from pathlib import Path
import shutil
import signal
import subprocess
import sys


CHANGES = [
    ('implicit-private-pending-consumption', 'virt/kvm/crucible-completion.c',
        'state->outstanding || kvm_arch_crucible_run_pending(vcpu)', 'state->outstanding'),
    ('positive-hidden-callback-cleaned', 'virt/kvm/crucible-completion.c',
        'result >= 0 && receipt->pending_mask &&', 'false &&'),
    ('overwrite-unacknowledged', 'virt/kvm/crucible-completion.c',
        'if (state->outstanding || kvm_arch_crucible_run_pending(vcpu))\n\t\treturn -EBUSY;', 'if (false)\n\t\treturn -EBUSY;'),
    ('lost-native-result', 'virt/kvm/crucible-completion.c',
        'receipt->run_result = result;', 'receipt->run_result = 0;'),
    ('lost-original-generation', 'arch/x86/kvm/crucible-clock.c',
        'receipt->generation_begin = clock->window_generation;', 'receipt->generation_begin = 0;'),
    ('hidden-callback-ignored', 'arch/x86/kvm/x86.c',
        'pending |= KVM_CRUCIBLE_RUN_PENDING_CALLBACK;', 'pending |= 0;'),
    ('hidden-arm-reset-ignored', 'arch/arm64/kvm/mmio.c',
        'kvm_test_request(KVM_REQ_VCPU_RESET, vcpu))\n\t\tpending |= KVM_CRUCIBLE_RUN_PENDING_OPAQUE;', 'kvm_test_request(KVM_REQ_VCPU_RESET, vcpu))\n\t\tpending |= 0;'),
    ('negative-pending-cleaned', 'virt/kvm/crucible-completion.c',
        'if (result < 0 && receipt->pending_mask) {', 'if (false) {'),
    ('foreign-receipt-accepted', 'virt/kvm/crucible-completion.c',
        'if (request.expected_invocation != state->original.invocation)', 'if (false)'),
    ('ack-lost-custody', 'virt/kvm/crucible-completion.c',
        'state->outstanding = false;', 'state->outstanding = true;'),
    ('receipt-counter-wrap', 'virt/kvm/crucible-completion.c',
        'if (state->original.invocation == U64_MAX)', 'if (false)'),
    ('world-counter-wrap', 'virt/kvm/crucible-completion.c',
        'kvm->crucible_uncollected_returns == U32_MAX', 'false'),
]


def main():
    source, compiler, output, fixture = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4])
    output.mkdir(parents=True, exist_ok=True)
    changes = [(name, relative, before, after, fixture, 'return-proof')
               for name, relative, before, after in CHANGES]
    for isa in ('x86', 'arm64'):
        relative = f'arch/{isa}/kvm/crucible-clock.c'
        changes.append((f'{isa}-clock-lineage-reopened', relative,
            'kvm->crucible_run_return_enabled && kvm->crucible_uncollected_returns',
            'false && kvm->crucible_uncollected_returns',
            Path(sys.argv[5]), 'clock-proof'))
        changes.append((f'{isa}-clock-step-before-ack', relative,
            'request->operation == KVM_CRUCIBLE_CLOCK_STEP))',
            'request->operation == KVM_CRUCIBLE_CLOCK_BEGIN))',
            Path(sys.argv[5]), 'clock-proof'))
    changes.append(('cap-races-original-vcpu-creation', 'virt/kvm/crucible-completion.c',
        ('mutex_lock(&kvm->lock);', 'mutex_unlock(&kvm->lock);'),
        ('/* Mutant omits native creation lock. */', '/* Mutant omits paired unlock. */'),
        Path(sys.argv[6]), 'creation-proof'))
    for name, relative, before, after, selected_fixture, executable_name in changes:
        target = output / name
        target.mkdir(exist_ok=True)
        # These exact native files are the complete fixture dependency roster.
        # A full Linux source tree must not be multiplied per mutant.
        for relative_source in (
            'include/uapi/linux/kvm.h',
            'include/linux/kvm_crucible_completion.h',
            'include/linux/kvm_crucible_clock_math.h',
            'virt/kvm/crucible-completion.c',
            'virt/kvm/kvm_main.c',
            'arch/x86/kvm/x86.c',
            'arch/arm64/kvm/mmio.c',
            'arch/x86/kvm/crucible-clock.c',
            'arch/arm64/kvm/crucible-clock.c',
        ):
            destination = target / relative_source
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / relative_source, destination)
        edited = target / relative
        body = edited.read_text()
        replacements = zip(before, after) if isinstance(before, tuple) else ((before, after),)
        for original_predicate, mutated_predicate in replacements:
            if body.count(original_predicate) != 1:
                raise ValueError(f'{name}: expected one exact production predicate')
            body = body.replace(original_predicate, mutated_predicate)
        edited.write_text(body)
        proof = target / 'proof'
        completed = subprocess.run([sys.executable, str(selected_fixture), str(target), compiler, str(proof)], capture_output=True, text=True)
        (target / 'proof.log').write_text(completed.stdout + completed.stderr)
        binary = proof / executable_name
        if completed.returncode == 0 or not binary.exists():
            raise AssertionError(f'{name}: source mutation did not yield compiler-success failure')
        repeated = subprocess.run([str(binary)], capture_output=True, text=True)
        (target / 'assertion.log').write_text(repeated.stdout + repeated.stderr)
        if repeated.returncode != -signal.SIGABRT or 'Assertion' not in repeated.stderr:
            raise AssertionError(f'{name}: mutation failed outside an actual source assertion')
        print(f'{name}: actual production mutation compiled; original custody assertion rejected it')
    print('Seventeen compiled source mutations rejected; no native hardware qualification.')


if __name__ == '__main__':
    main()
