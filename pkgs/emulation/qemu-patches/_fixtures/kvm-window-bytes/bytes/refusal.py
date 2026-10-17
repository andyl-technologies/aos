"""Exercise actual two-ISA TCG refusal and observe native-device availability."""
from pathlib import Path
import importlib.util
import sys


def main():
    x86, arm, component = sys.argv[1:]
    spec = importlib.util.spec_from_file_location('component_refusal', component)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    for binary in (x86, arm):
        peer = helper.QmpPeer(binary)
        try:
            assert 'QMP' in peer.read()
            assert 'return' in peer.request('qmp_capabilities')
            assert peer.request('query-kvm')['return']['enabled'] is False
            original = peer.request('query-status')['return']
            assert original['running'] is False
            for operation in ('query', 'complete'):
                response = peer.request('x-crucible-kvm-response-bytes', {
                    'operation': operation, 'record-index': 0, 'generation': 1,
                    'expected-invocation': 1,
                    'operation-id': 1 if operation == 'complete' else 0,
                    'expected-sequence': 1 if operation == 'complete' else 0,
                })
                assert response.get('error', {}).get('class') == 'GenericError', response
                assert 'response byte' in response['error']['desc'].lower(), response
                assert peer.request('query-status')['return'] == original
            assert 'return' in peer.request('quit')
            peer.process.wait(timeout=10)
            assert peer.process.returncode == 0
        finally:
            peer.close()
        print('Actual ' + Path(binary).name + ' canonical-byte namespace TCG refusal: PASS')
    helper.observe_unavailable_native_device(x86)
    print('Canonical-byte native hardware/whole-node qualification: not executed')


if __name__ == '__main__':
    main()
