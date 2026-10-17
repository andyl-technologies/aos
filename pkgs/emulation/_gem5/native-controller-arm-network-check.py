# SPDX-License-Identifier: MIT
"""Preserves actual Ethernet frames, owned future RX and zero-disk state.

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
spec = importlib.util.spec_from_file_location('device_image_custody', source_directory / 'closed-network-image-check.py')
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
             'native-controller-arm-devices-model.py', 'native-model-assets.py', 'causal-device-projection.py',
             'native-controller-arm-network.py', 'native-controller-arm-block-model.py', 'closed-memory-block.py',
             'native-controller-arm-network-model.py', 'native-controller-arm-network-board.py',
             'closed-network-loopback.py'):
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
selection = {'schema': 'crucible.gem5.arm-linux-closed-network-model.v1',
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
    assert body['diagnostic_scope'] == 'native-event-device-terminal-and-closed-network-block-metadata-v1'
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
           str(resource / 'native-controller-arm-network.py')]
log = os.fdopen(os.open(resource / 'native.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
child = subprocess.Popen(command, stdin=bootstrap, stdout=log, stderr=log,
                         env=environment, cwd=temporary, start_new_session=True)
bootstrap.close()
branches = []
try:
    image.own_process(child)
    send(parent, {'schema': 'crucible.gem5.arm-linux-closed-network-native/1', 'owner': 'closed-device-node',
                  'incarnation': 'source', 'generation': '1', 'controller_uid': str(os.getuid()),
                  'guest_isa': 'aarch64', 'executable': '', 'resource_root': str(resource),
                  'control_socket': str(route), 'model': selection})
    parent.close()
    control = accept(listener, child)
    ready = receive(control)
    assert ready['schema'] == 'crucible.gem5.arm-linux-closed-network-native/1'
    scope = ready['model_scope']
    assert scope['closed_terminal_monitor'] and not scope['external_serial_route']
    assert not scope['complete_process_closure_qualified']
    assert not scope['cpu_timing_qualified'] and not scope['device_parity_qualified']
    assert exchange(control, {'kind': 'observe'})['boundary'] == ready['boundary']
    expected_frame = bytes([255] * 6 + [2, 0, 0, 0, 0, 1, 0x88, 0xb5])
    expected_frame += b'CRUCIBLE_GEM5_NATIVE_FRAME'[:25] + bytes(25)
    assert len(expected_frame) == 64
    first_request = first = None
    prefix_receipts = []
    for index in range(128):
        request, receipt = run(control, f'closed-application-prefix/{index}')
        prefix_receipts.append(receipt)
        current_diagnostic = diagnostic(resource, receipt['after'])
        serial = bytes(row[5] for row in current_diagnostic['original_closed_terminal_fifo']['rows'])
        assert b'GEM5_LINUX_PROBE_FAILED' not in serial
        assert int(receipt['after']['ordinal']) <= 16000000
        print(json.dumps({'schema': 'crucible.gem5.closed-network-progress.v1',
                          'prefix': index, 'tick': receipt['after']['tick'],
                          'ordinal': receipt['after']['ordinal'],
                          'diagnostic_bytes': receipt['after']['inventory']['full_blob']['bytes'],
                          'publication_facets': [row['facet'] for row in receipt['publications']],
                          'application_init_ready': b'GEM5_LINUX_INIT_READY' in serial}), flush=True)
        frames = [publication for publication in receipt['publications']
                  if publication['facet'] == 'network_tx'
                  and bytes(publication['payload']) == expected_frame]
        if frames:
            assert len(frames) == 1
            first = frames[0]
            print(json.dumps({'schema': 'crucible.gem5.closed-network-original-tx.v1',
                              'native_id': first['native_id'], 'native_bytes': len(first['payload']),
                              'payload_sha256': hashlib.sha256(bytes(first['payload'])).hexdigest(),
                              'tick': first['tick'], 'ordinal': first['event_ordinal']}, sort_keys=True), flush=True)
            assert first['causal_parent'] == '17'
            assert b'GEM5_LINUX_INIT_READY' in serial
            assert first['tick'] == receipt['after']['tick']
            assert first['event_ordinal'] == receipt['after']['ordinal']
            assert current_diagnostic['native_publication_boundary']['enabled']
            command = next(row for row in current_diagnostic['closed_network_backend']['rows']
                           if row[0] == int(first['native_id']))
            assert command[4] == 64 and command[13] == hashlib.sha256(expected_frame).hexdigest()
            assert command[5] > int(receipt['after']['tick']) and command[7:12] == [0, 0, 0, 0, 0]
            assert [int(first['native_id']), True, str(command[5])] in current_diagnostic['closed_network_backend']['pending_event_rows']
            assert current_diagnostic['closed_block_backend']['backing_sha256'] == hashlib.sha256(bytes(1048576)).hexdigest()
            first_request = request
            break
        acknowledge(control, request)
    assert first_request is not None, 'actual application produced no held source-owned Ethernet frame within native credits'
    original_receipt = receipt
    captured_diagnostic = current_diagnostic
    terminal_rows = captured_diagnostic['original_closed_terminal_fifo']['rows']
    assert len(terminal_rows) <= 32768
    cut = receipt['after']
    assert exchange(control, {'kind': 'observe'})['boundary'] == cut
    assert exchange(control, first_request) == original_receipt
    capture = {'kind': 'capture', 'capture': 'held-application-tx-and-owned-future-rx-reaction'}
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
        assert diagnostic(current_resource, cut) == captured_diagnostic
        acknowledge(stream, first_request)
        history = []
        for index in range(128):
            request, result = run(stream, f'original-network-lifecycle-suffix/{index}')
            observed = diagnostic(current_resource, result['after'])
            rows = observed['original_closed_terminal_fifo']['rows']
            assert rows[:len(terminal_rows)] == terminal_rows
            serial = bytes(row[5] for row in rows)
            assert b'GEM5_LINUX_PROBE_FAILED' not in serial
            for publication in result['publications']:
                assert publication['facet'] in ('block_request', 'block_completion', 'network_tx', 'network_rx')
                if publication['facet'] == 'block_completion':
                    assert publication['status'] == '0' and 'descriptor_head' in publication
                    assert publication['causal_parent'] == '23' and publication['execution_parent'] == '17'
                if publication['facet'] == 'network_rx':
                    assert publication['causal_parent'] == '23' and publication['execution_parent'] == '17'
                    assert publication['count'] == str(len(publication['payload']))
            history.append(result)
            acknowledge(stream, request)
            if b'GEM5_LINUX_PROBE_COMPLETE' in serial:
                assert b'GEM5_NETWORK_TX_READY bytes=64' in serial
                assert b'GEM5_NETWORK_RX_VERIFIED bytes=64' in serial
                target = next(row for row in observed['closed_network_backend']['rows']
                              if row[0] == int(first['native_id']))
                assert target[7] and target[10] and target[13] == hashlib.sha256(expected_frame).hexdigest()
                assert any(publication['facet'] == 'network_rx'
                           and publication['native_id'] == first['native_id']
                           and bytes(publication['payload']) == expected_frame
                           for original in history for publication in original['publications'])
                assert observed['closed_block_backend']['backing_sha256'] == hashlib.sha256(bytes(1048576)).hexdigest()
                after_ack = exchange(stream, {'kind': 'observe'})['boundary']
                final = diagnostic(current_resource, after_ack)
                target = next(row for row in final['closed_network_backend']['rows']
                              if row[0] == int(first['native_id']))
                assert target[-2:] == [1, 1]
                return {'original_receipts': history, 'final_diagnostic': final,
                        'final_boundary': after_ack, 'terminal_rows': rows}
        raise AssertionError('actual application did not finish incoming-only Ethernet readback within finite suffix credit')

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
        fresh_capture = {'kind': 'capture', 'capture': f'fresh-real-linux-network/{branch.name}'}
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
                        'held_original_tx_and_owned_future_rx_reaction': True,
                        'native_completion_unchanged': True, 'group_reclaimed': True})
    result = {'schema': 'crucible.gem5.arm-linux-closed-network-lifecycle-mechanism.v1',
              'original_namespace_gone': True, 'original_request': first,
              'capture_phase': 'application-ethernet-tx-before-owned-rx-reaction-v1',
              'actual_application_init_ready_observed': True,
              'actual_network_incoming_readback_verified': True,
              'guest_application_ready_qualified': False,
              'sealed_future_reaction_tick': str(command[5]), 'branches': results,
              'final_disk_sha256': expected['final_diagnostic']['closed_block_backend']['backing_sha256'],
              'final_network_command_count': expected['final_diagnostic']['closed_network_backend']['command_count'],
              'final_disk_command_count': expected['final_diagnostic']['closed_block_backend']['command_count'],
              'final_native_tick': expected['final_boundary']['tick'],
              'final_native_ordinal': expected['final_boundary']['ordinal'],
              'original_terminal_births_and_bytes': len(expected['terminal_rows']),
              'source_prefix_count': len(prefix_receipts),
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
