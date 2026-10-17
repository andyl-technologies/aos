"""Require actual byte-custody source regressions to compile and hit C assertions."""
from pathlib import Path
import hashlib
import shutil
import signal
import subprocess
import sys


MUTANTS = [
    ('mmio-shared-input', 'arch/x86/kvm/x86.c',
     'const void *input = kvm_crucible_response_bytes_input(vcpu, run->mmio.data, len);',
     'const void *input = run->mmio.data;'),
    ('pio-shared-input', 'arch/x86/kvm/x86.c',
     'const void *input = kvm_crucible_response_bytes_input(vcpu,\n\t\tvcpu->arch.pio_data, size * count);',
     'const void *input = vcpu->arch.pio_data;'),
    ('arm-shared-input', 'arch/arm64/kvm/mmio.c',
     'input = kvm_crucible_response_bytes_input(vcpu, run->mmio.data, len);',
     'input = run->mmio.data;'),
    ('write-mapped-substitution', 'virt/kvm/crucible-response-bytes.c',
     'memcpy(fragment->output, data, total);',
     '(void)data, memcpy(fragment->output, reason == KVM_EXIT_MMIO ? vcpu->run->mmio.data : vcpu->arch.pio_data, total);'),
    ('request-byte-substitution-retry', 'virt/kvm/crucible-response-bytes.c',
     'if (memcmp(request, &bytes->last_request, sizeof(*request)))', 'if (false)'),
    ('lost-copy-result-erased', 'virt/kvm/crucible-response-bytes.c',
     'bytes->result_known = true;', 'bytes->result_known = false;'),
    ('private-freeze-omitted', 'virt/kvm/crucible-response-bytes.c',
     'bytes->last_request = *request;', '(void)request;'),
    ('input-geometry-discrepancy', 'virt/kvm/crucible-response-bytes.c',
     'if (length != bytes->last_request.data_length)', 'if ((void)length, false)'),
    ('original-address', 'virt/kvm/crucible-response-bytes.c',
     'fragment->valid && request->address == fragment->address &&', 'fragment->valid &&'),
    ('original-revision', 'virt/kvm/crucible-response-bytes.c',
     'request->expected_revision != state->revision ||', 'false ||'),
    ('original-generation', 'virt/kvm/crucible-response-bytes.c',
     'request->expected_generation != vcpu->crucible_run_return.original.generation_end ||', 'false ||'),
    ('current-generation', 'virt/kvm/crucible-response-bytes.c',
     'clock.generation_end != request->expected_generation', 'false'),
    ('canonical-zero-tail', 'virt/kvm/crucible-response-bytes.c',
     'if (request->data[index])', 'if (false)'),
    ('reserved-field', 'virt/kvm/crucible-response-bytes.c',
     'if (request->reserved[index])', 'if (false)'),
    ('effect-owner', 'virt/kvm/crucible-response-bytes.c',
     '!kvm->crucible_controlled || kvm->crucible_active || kvm->crucible_effect_owners ||',
     '!kvm->crucible_controlled || kvm->crucible_active ||'),
    ('native-stopped', 'virt/kvm/crucible-response-bytes.c',
     '!kvm_arch_crucible_response_stopped(kvm) ||', '(kvm_arch_crucible_response_stopped(kvm), false) ||'),
    ('closed-clock', 'virt/kvm/crucible-response-bytes.c',
     '!kvm->crucible_controlled || kvm->crucible_active || kvm->crucible_effect_owners ||',
     '!kvm->crucible_controlled || kvm->crucible_effect_owners ||'),
    ('pre-vcpu-immutable', 'virt/kvm/crucible-response-bytes.c',
     'kvm->created_vcpus || kvm->crucible_effect_owners ||', 'kvm->crucible_effect_owners ||'),
    ('run-return-prerequisite', 'virt/kvm/crucible-response-bytes.c',
     '!kvm->crucible_run_return_enabled || kvm->crucible_active ||', 'kvm->crucible_active ||'),
    ('sequence-credit', 'include/linux/kvm_crucible_completion.h',
     'request->expected_sequence != state->sequence)', 'false)'),
    ('finite-revision-credit', 'include/linux/kvm_crucible_completion.h',
     'state->revision >= U64_MAX - 1 ||', 'false ||'),
]


def main():
    source, compiler, output, proof = sys.argv[1:]
    source, output, proof = Path(source), Path(output), Path(proof)
    output.mkdir(parents=True, exist_ok=True)
    for name, relative, original, replacement in MUTANTS:
        candidate = output / name
        tree = candidate / 'source'
        for selected in (
            'include/uapi/linux/kvm.h', 'include/linux/kvm_crucible_completion.h',
            'virt/kvm/crucible-response-bytes.c', 'arch/x86/kvm/x86.c',
            'arch/x86/kvm/x86.h', 'arch/arm64/kvm/mmio.c',
        ):
            destination = tree / selected
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / selected, destination)
        target = tree / relative
        body = target.read_text()
        if body.count(original) != 1:
            raise ValueError(f'{name}: requires one exact native selector')
        target.write_text(body.replace(original, replacement))
        result = subprocess.run([sys.executable, str(proof), str(tree), compiler, str(candidate / 'proof')],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=45)
        (candidate / 'output.log').write_text(result.stdout)
        binary = candidate / 'proof/proof'
        if not binary.exists():
            raise RuntimeError(f'{name}: compiler/adapter failure cannot count as a negative')
        actual = subprocess.run([str(binary)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=30)
        if actual.returncode != -signal.SIGABRT or 'Assertion' not in actual.stdout:
            raise RuntimeError(f'{name}: did not detect a compiled native assertion ({actual.returncode})')
        (candidate / 'assertion.log').write_text(actual.stdout)
        print(f'{name}: compiled source assertion PASS; mutated sha256 {hashlib.sha256(target.read_bytes()).hexdigest()}')
    print(f'{len(MUTANTS)} meaningful compiled byte-custody mutants: PASS')


if __name__ == '__main__':
    main()
