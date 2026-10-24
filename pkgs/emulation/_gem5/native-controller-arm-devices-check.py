# SPDX-License-Identifier: MIT
"""Exercises a closed Linux boot monitor and an actual in-flight block image.

Every original UART FIFO birth is retained. This mechanism has no external
serial route and no common preparation/timing/device admission. It never drains
native state, edits a process image, or recreates a deleted source namespace.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys


native, sources, output, configs, kernel, initrd, firmware, dmtcp, guard = sys.argv[1:]
source_directory = Path(sources).resolve()
root = Path(output).resolve()
root.mkdir(mode=0o700)
spec = importlib.util.spec_from_file_location('device_image_custody', source_directory / 'device-image-check.py')
image = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image)
spec = importlib.util.spec_from_file_location('device_archive_custody', source_directory / 'device-archive-custody.py')
archive_custody = importlib.util.module_from_spec(spec)
spec.loader.exec_module(archive_custody)
source = root / 'source'
source.mkdir(mode=0o700)
resource = source / 'resources'
resource.mkdir(mode=0o700)
temporary = source / 'temporary'
temporary.mkdir(mode=0o700)
images = source / 'images'
images.mkdir(mode=0o700)
for name in ('native-controller-device.py', 'native-controller-models.py',
             'native-controller-arm-model.py', 'native-controller-arm-devices.py',
             'native-controller-arm-devices-model.py', 'native-model-assets.py', 'causal-device-projection.py'):
    descriptor, metadata = image.checked_file(source_directory / name)
    os.close(descriptor)
    image.copy_file(source_directory / name, resource / name, metadata, 0o600)
for origin, name in ((kernel, 'kernel.elf'), (initrd, 'initrd.img'), (firmware, 'boot_v2.arm64')):
    descriptor, metadata = image.checked_file(Path(origin))
    os.close(descriptor)
    image.copy_file(Path(origin), resource / name, metadata, 0o600)
image.copy_tree(Path(configs), resource / 'configs')
spec = importlib.util.spec_from_file_location('fixed_device_asset_custody', resource / 'native-model-assets.py')
assets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assets)
selection = {'schema': 'crucible.gem5.arm-linux-net-block-model.v1',
             'assets': {}, 'configs': assets.configuration_tree(resource / 'configs')}
for role, name in (('kernel', 'kernel.elf'), ('initramfs', 'initrd.img'), ('firmware', 'boot_v2.arm64')):
    selection['assets'][role] = {'file': name, **assets.digest_file(resource / name, assets.MAX_ASSET_BYTES)}


def endpoint(name):
    path = root / name
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(1)
    listener.settimeout(180)
    return path, listener


def send(stream, value):
    body = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    assert 0 < len(body) <= 4 * 1024 * 1024
    stream.sendall(struct.pack('!I', len(body)) + body)


def receive(stream):
    def exact(count):
        body = bytearray()
        while len(body) < count:
            part = stream.recv(count - len(body))
            if not part:
                raise EOFError('actual native device owner disconnected')
            body.extend(part)
        return body

    count = struct.unpack('!I', exact(4))[0]
    assert 0 < count <= 4 * 1024 * 1024
    return json.loads(exact(count))


def exchange(stream, request):
    send(stream, request)
    return receive(stream)


def accept(listener, process):
    stream, _ = listener.accept()
    stream.settimeout(180)
    peer, uid, _ = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    assert peer == process.pid and uid == os.getuid()
    return stream


def diagnostic(resource, boundary):
    receipt = boundary['inventory']['full_blob']
    path = resource / receipt['path']
    descriptor, metadata = image.checked_file(path)
    assert metadata.st_size == int(receipt['bytes']) <= 4 * 1024 * 1024
    with os.fdopen(descriptor, 'rb') as reader:
        raw = reader.read(4 * 1024 * 1024 + 1)
    assert hashlib.sha256(raw).hexdigest() == receipt['sha256']
    body = json.loads(raw)
    assert body['schema'] == 'crucible.gem5.causal-device-state.v1'
    assert body['diagnostic_scope'] == 'native-event-metadata-device-control-fields-and-closed-terminal-fifo-v2'
    assert body['complete'] is False
    assert body['native_tick'] == boundary['tick']
    return body


def run(stream, operation, budget=262144):
    request = {'kind': 'run', 'operation': operation, 'exclusive_tick': '1000000000000',
               'maximum_events': str(budget), 'exact_range': None}
    receipt = exchange(stream, request)
    assert receipt['kind'] == 'completed', receipt
    assert receipt['original'] == request and int(receipt['processed_events']) <= budget
    assert exchange(stream, request) == receipt
    return request, receipt


def acknowledge(stream, request):
    original = {'kind': 'acknowledge', 'operation': request['operation']}
    expected = {'kind': 'acknowledged', 'operation': request['operation']}
    assert exchange(stream, original) == expected
    assert exchange(stream, original) == expected


route, listener = endpoint('source.sock')
parent, bootstrap = socket.socketpair()
environment = os.environ.copy()
environment['CRUCIBLE_CAPTURE_RESOURCE_ROOT'] = str(resource)
command = [str(Path(dmtcp) / 'bin/dmtcp_launch'), '--new-coordinator', '--no-gzip',
           '--ckpt-signal', '40', '--with-plugin', guard, '--ckptdir', str(images),
           native, '--listener-mode=off', f'--outdir={resource / "output"}',
           str(resource / 'native-controller-arm-devices.py')]
log = os.fdopen(os.open(resource / 'native.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
child = subprocess.Popen(command, stdin=bootstrap, stdout=log, stderr=log,
                         env=environment, cwd=temporary, start_new_session=True)
bootstrap.close()
branches = []
try:
    image.own_process(child)
    send(parent, {'schema': 'crucible.gem5.arm-linux-devices-native/1', 'owner': 'closed-device-node',
                  'incarnation': 'source', 'generation': '1', 'controller_uid': str(os.getuid()),
                  'guest_isa': 'aarch64', 'executable': '', 'resource_root': str(resource),
                  'control_socket': str(route), 'model': selection})
    parent.close()
    control = accept(listener, child)
    ready = receive(control)
    assert ready['schema'] == 'crucible.gem5.arm-linux-devices-native/1'
    scope = ready['model_scope']
    assert scope['closed_terminal_monitor'] and not scope['external_serial_route']
    assert not scope['complete_process_closure_qualified']
    assert not scope['cpu_timing_qualified'] and not scope['device_parity_qualified']
    assert exchange(control, {'kind': 'observe'})['boundary'] == ready['boundary']
    first_request = first = None
    for index in range(64):
        request, receipt = run(control, f'closed-boot-prefix/{index}')
        print(json.dumps({'schema': 'crucible.gem5.device-monitor-progress.v1',
                          'prefix': index, 'tick': receipt['after']['tick'],
                          'ordinal': receipt['after']['ordinal'],
                          'diagnostic_bytes': receipt['after']['inventory']['full_blob']['bytes'],
                          'publications': len(receipt['publications'])}), flush=True)
        if receipt['publications']:
            assert len(receipt['publications']) == 1
            first = receipt['publications'][0]
            assert first['facet'] == 'block_request' and first['opcode'] == '0'
            assert first['native_id'] == '1' and not first['payload']
            assert first['causal_parent'] == '17'
            assert int(first['event_ordinal']) <= int(receipt['after']['ordinal'])
            assert int(first['tick']) <= int(receipt['after']['tick'])
            first_request = request
            break
        acknowledge(control, request)
    assert first_request is not None, 'real Linux produced no block request within native credits'
    original_receipt = receipt
    captured_diagnostic = diagnostic(resource, receipt['after'])
    terminal_rows = captured_diagnostic['original_closed_terminal_fifo']['rows']
    serial = bytes(row[5] for row in terminal_rows)
    assert b'Linux version ' in serial
    assert b'GEM5_LINUX_PROBE_FAILED' not in serial
    assert len(terminal_rows) <= 32768
    reply = {'kind': 'device_control', 'operation': 'original-future-block-read',
             'action': 'block_reply', 'native_id': first['native_id'],
             'tick': str(int(receipt['after']['tick']) + 10000),
             'causal_parent': '23', 'status': '0', 'payload': [0] * int(first['count'])}
    staged = exchange(control, reply)
    assert staged['kind'] == 'device_controlled' and staged['accepted']
    assert staged['before'] == receipt['after']
    assert staged['before']['ordinal'] == staged['after']['ordinal']
    assert staged['before']['tick'] == staged['after']['tick']
    assert exchange(control, reply) == staged
    assert exchange(control, first_request) == original_receipt
    cut = staged['after']
    assert exchange(control, {'kind': 'observe'})['boundary'] == cut
    capture = {'kind': 'capture', 'capture': 'held-real-linux-block-and-future-read'}
    send(control, capture)
    assert receive(control) == {'kind': 'capture_ready', 'capture': capture['capture'], 'boundary': cut}
    control.close()
    control = accept(listener, child)
    captured_ready = receive(control)
    assert captured_ready['continuation'] == 'captured' and captured_ready['boundary'] == cut
    primary = list(images.glob('*.dmtcp'))
    assert len(primary) == 1
    primary = primary[0]
    image.audit(exchange, control, child, root, resource, primary, cut, scope,
                native, guard, source_directory, 'source')
    saved = primary.with_name(primary.stem + '_files')
    metadata = archive_custody.preflight_archive(image, primary, saved, resource)
    archive = root / 'archive'
    archive.mkdir(mode=0o700)
    image.copy_file(primary, archive / primary.name, metadata, 0o400)
    image.copy_tree(saved, archive / saved.name, mode=0o400)
    image.copy_tree(resource, archive / 'resources')

    def suffix(stream, current_resource):
        assert exchange(stream, first_request) == original_receipt
        assert exchange(stream, reply) == staged
        acknowledge(stream, first_request)
        request, result = run(stream, 'first-sealed-block-completion', 4096)
        assert result['reason'] == 'output' and len(result['publications']) == 1
        publication = result['publications'][0]
        assert publication['facet'] == 'block_completion'
        assert publication['native_id'] == first['native_id']
        assert publication['tick'] == reply['tick']
        assert publication['causal_parent'] == '23' and publication['execution_parent'] == '17'
        assert publication['status'] == '0' and int(publication['count']) == len(reply['payload']) + 1
        assert int(publication['event_ordinal']) > int(first['event_ordinal'])
        after = diagnostic(current_resource, result['after'])
        before_rows = captured_diagnostic['original_closed_terminal_fifo']['rows']
        assert after['original_closed_terminal_fifo']['rows'][:len(before_rows)] == before_rows
        assert exchange(stream, request) == result
        acknowledge(stream, request)
        return result

    expected = suffix(control, resource)
    assert exchange(control, {'kind': 'shutdown'}) == {'kind': 'shutdown'}
    control.close()
    assert image.wait_exited(child, timeout=30) == 0
    assert image.reclaim(child)
    shutil.rmtree(source)
    assert not source.exists() and not primary.exists() and not saved.exists()

    for name in ('child-a', 'child-b'):
        branch = root / name
        image.copy_tree(archive / 'resources', branch)
        scratch = root / f'temporary-{name}'
        scratch.mkdir(mode=0o700)
        fresh_images = root / f'images-{name}'
        fresh_images.mkdir(mode=0o700)
        imported = root / f'saved-{name}'
        image.copy_tree(archive / saved.name, imported, mode=0o400)
        roster_body = archive_custody.saved_manifest(image, saved, imported)
        roster = root / f'saved-{name}.manifest'
        with os.fdopen(os.open(roster, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400), 'wb') as writer:
            writer.write(roster_body)
            writer.flush()
            os.fsync(writer.fileno())
        route, branch_listener = endpoint(f'{name}.sock')
        env = os.environ.copy()
        env.update({'CRUCIBLE_GEM5_CONTROL_SOCKET': str(route),
                    'CRUCIBLE_RESTORE_RESOURCE_ROOT': str(branch),
                    'DMTCP_PATH_MAPPING': archive_custody.future_path_mapping(resource, branch),
                    'CRUCIBLE_GEM5_OPERATIONAL_ROOT': str(scratch),
                    'CRUCIBLE_RESTORE_SAVED_FILES_SOURCE_ROOT': str(saved),
                    'CRUCIBLE_RESTORE_SAVED_FILES_TARGET_ROOT': str(imported),
                    'CRUCIBLE_RESTORE_SAVED_FILES_MANIFEST': str(roster)})
        branch_log = os.fdopen(os.open(root / f'{name}.stderr', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
        restored = subprocess.Popen([str(Path(dmtcp) / 'bin/dmtcp_restart'), '--new-coordinator',
                                     '--ckptdir', str(fresh_images), str(archive / primary.name)],
                                    env=env, cwd=scratch, stdout=branch_log, stderr=branch_log,
                                    start_new_session=True)
        try:
            image.own_process(restored)
            peer = accept(branch_listener, restored)
            send(peer, {'kind': 'restore_bind', 'owner': 'closed-device-node',
                        'source_incarnation': 'source', 'source_generation': '1',
                        'incarnation': name, 'generation': '2', 'capture': capture['capture']})
            branch_ready = receive(peer)
            assert branch_ready['continuation'] == 'restored' and branch_ready['boundary'] == cut
            assert diagnostic(branch, cut)['original_closed_terminal_fifo']['rows'] == terminal_rows
            branches.append((restored, peer, branch, fresh_images, branch_listener, branch_log))
        except BaseException:
            image.reclaim(restored)
            branch_log.close()
            branch_listener.close()
            raise
    results = []
    for restored, peer, branch, fresh_images, branch_listener, branch_log in branches:
        fresh_capture = {'kind': 'capture', 'capture': f'fresh-real-linux-block/{branch.name}'}
        send(peer, fresh_capture)
        assert receive(peer)['boundary'] == cut
        peer.close()
        peer = accept(branch_listener, restored)
        assert receive(peer)['boundary'] == cut
        current_image = list(fresh_images.glob('*.dmtcp'))
        assert len(current_image) == 1
        image.audit(exchange, peer, restored, root, branch, current_image[0], cut, scope,
                    native, guard, source_directory, branch.name)
        actual = suffix(peer, branch)
        assert actual == expected
        assert exchange(peer, {'kind': 'shutdown'}) == {'kind': 'shutdown'}
        peer.close()
        assert image.wait_exited(restored, timeout=30) == 0
        assert image.reclaim(restored)
        results.append({'name': branch.name, 'fresh_byte_closure': True,
                        'original_terminal_births_and_bytes': len(terminal_rows),
                        'held_original_request_and_future_reply': True,
                        'native_completion_unchanged': True, 'group_reclaimed': True})
    result = {'schema': 'crucible.gem5.arm-linux-inflight-device-mechanism.v1',
              'original_namespace_gone': True, 'original_request': first,
              'capture_phase': 'first-kernel-virtio-block-request-v1',
              'guest_application_ready_qualified': False,
              'sealed_future_reply_tick': reply['tick'], 'branches': results,
              'closed_terminal_monitor': True, 'external_serial_admitted': False,
              'typed_diagnostics_complete': False, 'common_preparation_qualified': False,
              'full_device_parity_qualified': False, 'cpu_timing_qualified': False}
    (root / 'result.json').write_text(json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n')
    print(json.dumps(result, sort_keys=True, separators=(',', ':')), flush=True)
except BaseException:
    # Native stderr is a bounded private diagnostic, not a guest publication.
    # Emit the failure tail before guarded reclamation removes process custody.
    failures = [resource / 'native.log'] + [root / f'{name}.stderr' for name in ('child-a', 'child-b')]
    for path in failures:
        if path.is_file():
            with path.open('rb') as reader:
                reader.seek(max(0, path.stat().st_size - 4096))
                print(f'Native failure diagnostic {path.name}:', reader.read().decode(errors='replace'),
                      file=sys.stderr, flush=True)
    raise
finally:
    for restored, peer, branch, fresh_images, branch_listener, branch_log in branches:
        image.reclaim(restored)
        branch_listener.close()
        branch_log.close()
    image.reclaim(child)
    listener.close()
    log.close()
