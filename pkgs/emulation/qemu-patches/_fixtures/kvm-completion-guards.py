"""Require original native admission ordering without qualifying execution."""
from pathlib import Path
import sys
source = Path(sys.argv[1])
clock = (source / 'accel/kvm/crucible-clock.c').read_text()
caller = (source / 'accel/kvm/kvm-all.c').read_text()
header = (source / 'include/system/crucible-kvm-clock.h').read_text()
qapi = (source / 'qapi/run-state.json').read_text()

def function(text, declaration):
    assert text.count(declaration) == 1, declaration
    start = text.index(declaration)
    end = text.index('\n}\n', start) + 3
    return text[start:end]
configure = function(clock, 'int kvm_crucible_completion_configure(')
assert configure.index('!state->crucible_completion_experiment') < configure.index('kvm_vm_check_extension')
assert configure.index('!state->crucible_clock_configured') < configure.index('kvm_vm_ioctl')
assert configure.index('!state->crucible_userspace_configured') < configure.index('kvm_vm_ioctl')
assert configure.index('kvm_vm_check_extension') < configure.index('kvm_vm_ioctl') < configure.index('state->crucible_completion_configured = true')
setter = function(caller, 'static void kvm_set_crucible_completion(')
assert setter.index('state->fd != -1') < setter.index('state->crucible_completion_experiment = enabled')
initialize = function(caller, 'static int kvm_init(')
assert initialize.index('kvm_crucible_clock_configure') < initialize.index('kvm_crucible_userspace_configure') < initialize.index('kvm_crucible_completion_configure')
create = function(caller, 'int kvm_init_vcpu(')
assert create.index('kvm_crucible_userspace_bind_vcpu') < create.index('kvm_arch_pre_create_vcpu')
command = function(clock, 'CrucibleKvmCompletionInfo *qmp_x_crucible_kvm_completion(')
assert 'KVM_RUN' not in command and 'run_on_cpu(' not in command
assert command.count('kvm_vcpu_ioctl(original_cpu, KVM_CRUCIBLE_COMPLETION, &request)') == 3
assert command.index('original_cpu->created') < command.index('kvm_vcpu_ioctl')
assert command.index('g_try_new0') < command.index('kvm_vcpu_ioctl')
assert command.index('if (journal->known)') < command.index('clock_control')
assert command.index('journal->original_exit_sequence != expected_exit_sequence') < command.index('if (journal->known)')
assert command.index('clock.active || clock.run_owners || !clock.close_acknowledged') < command.index('journal->issued = true')
assert command.index('completion_geometry(state, original_cpu, entry, false)') < command.index('journal->issued = true')
assert command.index('available - state->crucible_userspace_reserved_revisions < 3') < command.index('journal->issued = true')
assert command.index('journal->issued = true') < command.index('request = journal->original_request;')
assert command.index('state->crucible_userspace_reserved_revisions += 2') < command.index('result = kvm_vcpu_ioctl', command.index('request = journal->original_request;'))
assert 'entry->uncertain_effects = false' not in command
assert 'entry->opaque_effects = false' not in command
assert 'entry->phase = CRUCIBLE_KVM_USERSPACE_HANDLING' in command
assert 'exclusive paused-vCPU response work is not enrolled' in command
fill = function(clock, 'static void completion_fill_info(')
for name in ('device_closure', 'input_custody', 'output_custody', 'profile_qualified'):
    assert 'info->' + name + ' = false;' in fill
geometry = function(clock, 'static bool completion_geometry(KVMState *state, CPUState *cpu,\n                                CrucibleKvmUserspaceExit *entry, bool retain)\n{')
assert '!memcmp(original->response, bytes, value.length)' in geometry
assert 'value.length > state->crucible_completion_mmap_size - value.data_offset' in geometry
assert 'uint8_t response[4096];' in header
print('Completion source guards PASS: immutable actual cap/clock/roster, exact paused original request, pre-effect bounded journal/reply, no run/ordinary queue drain, retained geometry/More/unknown, no profile promotion.')
