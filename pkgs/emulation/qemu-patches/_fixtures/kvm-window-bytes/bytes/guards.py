"""Validate actual canonical-byte integration and legacy compatibility seams."""
from pathlib import Path
import importlib.util
import hashlib
import json
import re
import sys


def main():
    source, baseline = Path(sys.argv[1]), Path(sys.argv[2])
    spec = importlib.util.spec_from_file_location('byte_bridge', Path(__file__).with_name('model.py'))
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)
    native = (source / 'accel/kvm/crucible-response-bytes.c').read_text()
    clock = (source / 'accel/kvm/crucible-clock.c').read_text()
    # The small co-retained compatibility record pins exact original bodies
    # and wire lines without carrying two large duplicate native source files.
    compatibility = json.loads(baseline.read_text())
    assert compatibility['schema'] == 'crucible-kvm-byte-compatibility/v1'
    for name in ('execute_clock_component', 'qmp_x_crucible_kvm_clock', 'qmp_x_crucible_kvm_clock_v3'):
        actual = model.function(clock, name).encode()
        expected = compatibility['clock_functions'][name]
        assert len(actual) == expected['bytes'], name
        assert hashlib.sha256(actual).hexdigest() == expected['sha256'], name
    qapi = (source / 'qapi/run-state.json').read_text()
    qapi = qapi[:qapi.index('# @CrucibleKvmResponseBytesOperation:')]
    def wire_lines(text):
        return [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')]
    actual_wire = json.dumps(wire_lines(qapi), separators=(',', ':')).encode()
    expected_wire = compatibility['prior_wire']
    assert len(actual_wire) == expected_wire['bytes'], 'old wire declarations'
    assert hashlib.sha256(actual_wire).hexdigest() == expected_wire['sha256'], 'old wire declarations'
    caller = (source / 'accel/kvm/kvm-all.c').read_text()
    init = model.function(caller, 'kvm_init')
    assert init.index('kvm_crucible_window_configure(s)') < init.index('kvm_crucible_response_bytes_configure(s)')
    setter = model.function(caller, 'kvm_set_crucible_response_bytes')
    assert setter.index('state->vmfd >= 0') < setter.index('state->crucible_response_bytes_experiment =')
    configure = model.function(native, 'kvm_crucible_response_bytes_configure')
    assert configure.index('state->crucible_response_bytes_experiment') < configure.index('g_try_new0(')
    assert configure.index('g_try_new0(') < configure.index('kvm_vm_ioctl(')
    dispatch = model.function(caller, 'kvm_crucible_dispatch_original_response')
    assert dispatch.index('state->crucible_response_bytes_configured'.replace('state->', 'kvm_state->')) < dispatch.index('switch (run->exit_reason)')
    byte_branch = dispatch[:dispatch.index('switch (run->exit_reason)')]
    assert not re.search(r'run->(?:io|mmio|exit_reason)', byte_branch)
    assert 'original->response' in byte_branch
    original_geometry = model.function(clock, 'completion_geometry')
    assert original_geometry.index('kvm_crucible_response_bytes_geometry(') < original_geometry.index('value.reason = run->exit_reason')
    window = (source / 'accel/kvm/crucible-window.c').read_text()
    returned = model.function(window, 'kvm_crucible_window_after_run')
    assert returned.index('kvm_crucible_response_bytes_capture_return(') < returned.index('kvm_crucible_userspace_after_run(')
    command = model.function(native, 'qmp_x_crucible_kvm_response_bytes')
    assert command.index('g_try_malloc0(') < command.index('kvm_vcpu_ioctl(')
    assert command.index('journal->request_issued = true;') < command.rindex('kvm_vcpu_ioctl(')
    assert command.index('journal->result = *packet;') < command.index('response_bytes_fill_info(')
    assert command.index('if (journal->result_known)') < command.index('response_bytes_clock_closed(')
    assert 'kvm_arch_vcpu_ioctl_run' not in native
    assert not re.search(r'\b(?:run_on_cpu|async_run_on_cpu|kvm_cpu_exec|qemu_process_cpu_events)\s*\(', native)
    assert not re.search(r'run->(?:io|mmio|exit_reason)', native)
    for claim in ('kernel_source_qualified', 'device_closure', 'input_custody', 'output_custody', 'profile_qualified'):
        assert 'info->' + claim + ' = false;' in native
    lifetime = model.function(caller, 'do_kvm_destroy_vcpu')
    assert lifetime.index('qemu_cpu_paused_service_reclaim_guard(cpu)') < lifetime.index('kvm_arch_destroy_vcpu(')
    for relative in ('accel/kvm/crucible-response-bytes.c', 'include/system/crucible-kvm-response-bytes.h'):
        assert 'SPDX-License-Identifier: GPL-2.0-only' in (source / relative).read_text().splitlines()[0]
    print('Actual byte ownership/cached retry/constructor/lifetime seams and old v1/v3/wire declarations: PASS')


if __name__ == '__main__':
    main()
