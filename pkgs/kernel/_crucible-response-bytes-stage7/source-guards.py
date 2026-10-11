"""Check actual native allocation, opt-in and response-consumer placement."""
from pathlib import Path
import re
import sys

from importlib.util import module_from_spec, spec_from_file_location

helper = Path(__file__).with_name('bytes-proof.py')
spec = spec_from_file_location('bytes_proof', helper)
proof = module_from_spec(spec)
spec.loader.exec_module(proof)


def main():
    source = Path(sys.argv[1])
    main_body = (source / 'virt/kvm/kvm_main.c').read_text()
    create = proof.function(main_body, 'kvm_vm_ioctl_create_vcpu')
    assert create.index('kvm_crucible_response_bytes_vcpu_init(vcpu)') < create.index('kvm_arch_vcpu_create(vcpu)')
    assert 'goto vcpu_free_response_bytes;' in create
    assert create.index('vcpu_free_response_bytes:') < create.index('vcpu_free_run_page:')
    destroy = proof.function(main_body, 'kvm_vcpu_destroy')
    assert destroy.index('kvm_arch_vcpu_destroy(vcpu)') < destroy.index('kvm_crucible_response_bytes_vcpu_destroy(vcpu)')
    assert destroy.index('kvm_crucible_response_bytes_vcpu_destroy(vcpu)') < destroy.index('kmem_cache_free(')
    dispatcher = proof.function(main_body, 'kvm_vcpu_ioctl')
    assert 'ioctl != KVM_CRUCIBLE_RESPONSE_BYTES' in dispatcher
    assert 'case KVM_CRUCIBLE_RESPONSE_BYTES:' in dispatcher
    old = (source / 'virt/kvm/crucible-completion.c').read_text()
    old_ioctl = proof.function(old, 'kvm_crucible_response_ioctl')
    assert old_ioctl.index('request.operation == KVM_CRUCIBLE_COMPLETION_STEP') < old_ioctl.index('kvm_arch_crucible_response_complete(')
    assert 'crucible_response_bytes_enabled' in old_ioctl
    assert 'return -EOPNOTSUPP;' in old_ioctl
    new = (source / 'virt/kvm/crucible-response-bytes.c').read_text()
    step = proof.function(new, 'kvm_crucible_response_bytes_ioctl')
    assert 'kvm_arch_vcpu_ioctl_run' not in step and 'vcpu_run(' not in step
    assert step.index('bytes->last_request = *request;') < step.index('kvm_arch_crucible_response_complete(')
    assert step.index('bytes->last_result = *request;') < step.index('copy_to_user(')
    assert step.index('bytes->result_known = true;') < step.index('copy_to_user(')
    assert not re.search(r'\b(?:kzalloc|kmalloc|kvzalloc|vmalloc)\(', step)
    configure = proof.function(new, 'kvm_crucible_response_bytes_configure')
    assert configure.index('mutex_lock(&kvm->lock)') < configure.index('mutex_lock(&kvm->crucible_configuration_lock)')
    assert configure.index('kvm->created_vcpus') < configure.index('WRITE_ONCE(')
    x86 = (source / 'arch/x86/kvm/x86.c').read_text()
    pio = proof.function(x86, 'emulator_pio_in_out')
    assert pio.index('kvm_crucible_response_bytes_produce(') < pio.index('memcpy(vcpu->arch.pio_data,')
    assert pio.index('kvm_crucible_response_bytes_produce(') < pio.index('vcpu->run->exit_reason =')
    header = (source / 'arch/x86/kvm/x86.h').read_text()
    mmio = proof.function(header, '__kvm_prepare_emulated_mmio_exit')
    assert mmio.index('kvm_crucible_response_bytes_produce(') < mmio.index('run->mmio.len =')
    arm = (source / 'arch/arm64/kvm/mmio.c').read_text()
    produce = proof.function(arm, 'io_mem_abort')
    assert produce.index('kvm_crucible_response_bytes_produce(') < produce.index('memcpy(run->mmio.data, data_buf, len);', produce.index('kvm_crucible_response_bytes_produce('))
    for body in (proof.function(x86, 'kvm_arch_crucible_response_complete'),
                 proof.function(arm, 'kvm_arch_crucible_response_complete')):
        assert 'kvm_crucible_response_bytes_consume_begin(vcpu)' in body
    print('Actual native constructor/free, opt-in ordering, original producer/callback and no-entry placement: PASS')


if __name__ == '__main__':
    main()
