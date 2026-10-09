"""Exercise real completion-only refusal, without KVM qualification."""
import importlib.util
import os
import subprocess
import sys
from pathlib import Path
if len(sys.argv) != 4:
    raise SystemExit('usage: kvm-completion-refusal.py QEMU_X86_64 QEMU_AARCH64 ORIGINAL_PEER_HELPER')
helper = Path(sys.argv[3])
spec = importlib.util.spec_from_file_location('native_refusal', helper)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
for executable in sys.argv[1:3]:
    peer = module.QmpPeer(executable)
    try:
        assert 'QMP' in peer.read()
        assert 'return' in peer.request('qmp_capabilities')
        commands = peer.request('query-commands')['return']
        assert sum((row['name'] == 'x-crucible-kvm-completion' for row in commands)) == 1
        for operation in ('query', 'complete', 'dispatch'):
            response = peer.request('x-crucible-kvm-completion', {'operation': operation, 'vcpu-index': 0, 'operation-id': 0 if operation == 'query' else 1, 'expected-exit-sequence': 0 if operation == 'query' else 1})
            assert response['error']['class'] == 'GenericError'
            assert 'paused native CPUs' in response['error']['desc'] or 'unavailable' in response['error']['desc']
        assert 'return' in peer.request('quit')
        peer.process.wait(timeout=10)
        assert peer.process.returncode == 0
    finally:
        peer.close()
    print('Actual completion namespace refusal PASS:', Path(executable).name)
if not os.path.exists('/dev/kvm'):
    result = subprocess.run([sys.argv[1], '-machine', 'none', '-accel', 'kvm,x-crucible-clock-experiment=on,x-crucible-clock-kernel-edition=3,x-crucible-userspace-exit-ledger=on,x-crucible-completion-only=on', '-S', '-nodefaults', '-display', 'none'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    assert result.returncode != 0 and b'Could not access KVM kernel module' in result.stderr
    assert b'Property' not in result.stderr
    print('Actual component launch EnvironmentUnavailable: /dev/kvm absent. Native qualification not executed.')
