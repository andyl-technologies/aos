"""Check source-owned response callback placement without claiming native closure."""

from pathlib import Path
import sys


def function(body, declaration):
    assert body.count(declaration) == 1, declaration
    start = body.index(declaration)
    return body[start:body.index("\n}\n", start) + 3]


source = Path(sys.argv[1])
clock = (source / "accel/kvm/crucible-clock.c").read_text()
caller = (source / "accel/kvm/kvm-all.c").read_text()
qapi = (source / "qapi/run-state.json").read_text()
configure = function(clock, "int kvm_crucible_response_service_configure(")
assert configure.index("!state->crucible_response_service_experiment") < configure.index("g_try_new0")
assert configure.index("!state->crucible_completion_configured") < configure.index("g_try_new0")
assert configure.index("autostart") < configure.index("g_try_new0")

setter = function(caller, "static void kvm_set_crucible_response_service(")
assert setter.index("state->fd != -1") < setter.index("state->crucible_response_service_experiment = enabled")
create = function(caller, "int kvm_init_vcpu(")
assert create.index("kvm_crucible_userspace_bind_vcpu") < create.index("kvm_crucible_response_service_bind_vcpu") < create.index("kvm_arch_pre_create_vcpu")
initialize = function(caller, "static int kvm_init(")
assert initialize.index("kvm_crucible_completion_configure") < initialize.index("kvm_crucible_response_service_configure")
run = function(caller, "int kvm_cpu_exec(")
assert run.index("kvm_vcpu_ioctl(cpu, KVM_RUN, 0)") < run.index("kvm_arch_post_run(cpu, run)") < run.index("kvm_crucible_response_service_retain_attrs")

callback = function(clock, "static int response_service_callback(")
assert "qemu_cpu_is_self(cpu) && !bql_locked()" in callback
assert callback.index("completion_geometry(state, cpu, entry, false)") < callback.index("kvm_crucible_dispatch_original_response")
assert callback.index("service->executing = true;") < callback.index("kvm_crucible_dispatch_original_response")
assert callback.count("kvm_crucible_dispatch_original_response") == 1
assert "if (result >= 0 && !kvm_crucible_userspace_after_dispatch" in callback
assert callback.index("kvm_crucible_dispatch_original_response") < callback.index("service->completed = true;")
assert "entry->uncertain_effects = true;" in callback
assert "entry->uncertain_effects = false;" not in callback

handler = function(caller, "int kvm_crucible_dispatch_original_response(")
# Retain the original mapped-exit branch assertions separately from the
# canonical private-byte branch, whose actual dispatcher has its own proof.
legacy_handler = handler[handler.index("switch (run->exit_reason)"):]
assert legacy_handler.count("kvm_handle_io(") == 1
assert legacy_handler.count("address_space_rw(") == 1
assert "MemTxAttrs attributes" in handler
assert "== MEMTX_OK ? 0 : -EIO" in handler
command = function(clock, "CrucibleKvmResponseServiceInfo *qmp_x_crucible_kvm_response_service(")
assert command.index("g_try_new0") < command.index("qemu_cpu_paused_service_submit")
assert command.index("entry->completion.result.phase != KVM_CRUCIBLE_COMPLETION_MORE") < command.index("qemu_cpu_paused_service_submit")
assert command.index("clock.active || clock.run_owners || !clock.close_acknowledged") < command.index("qemu_cpu_paused_service_submit")
assert command.index("if (!service->collected)") < command.index("qatomic_store_release(&state->crucible_response_service_active, false);")
for flag in ("device_closure", "input_custody", "output_custody", "profile_qualified"):
    assert "info->" + flag + " = false;" in command
for body in (callback, handler, command):
    for forbidden in ("KVM_RUN", "kvm_arch_post_run(", "process_queued_cpu_work(", "run_on_cpu(", "KVM_CRUCIBLE_COMPLETION,"):
        assert forbidden not in body, forbidden
assert qapi.count("'command': 'x-crucible-kvm-response-service'") == 1
print("Original response source guards PASS: immutable enrollment, exact More/attrs/geometry/clock, one original handler, no kernel reentry/drain, bounded original reply, no profile promotion")

clock_gate = function(clock, "bool kvm_crucible_response_service_allow_clock_ioctl(")
assert "clock->operation == KVM_CRUCIBLE_CLOCK_QUERY" in clock_gate
assert "return bql_locked() &&" in clock_gate
assert "!qatomic_load_acquire(&state->crucible_response_service_active)" in clock_gate
ioctl = function(caller, "int kvm_vm_ioctl(")
assert ioctl.index("kvm_crucible_response_service_allow_clock_ioctl") < ioctl.index("trace_kvm_vm_ioctl") < ioctl.index("ret = ioctl(")
run_gate = function(clock, "bool kvm_crucible_userspace_before_run(")
assert run_gate.index("qemu_mutex_lock") < run_gate.index("qatomic_load_acquire(&state->crucible_response_service_active)") < run_gate.index("userspace_run_start")
print("Original response lifetime guards PASS: BQL-serialized clock mutation, query-only reconciliation, RUN gate under original journal lock")
