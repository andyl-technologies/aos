"""Guest operations for the confined real Managed terminal-cleanup window.

These operations consume real pair files and actual process lifetimes. They
neither seed SQL nor create R2 objects. A missing/failed join stops the window.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import time


TEST = "storage_work::oci_cleanup::controlled::actual_managed_terminal_cleanup_pair"


def load(path, name):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def retained(path, body):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    return {"path": str(path), "sha256": hashlib.sha256(body).hexdigest(), "byteSize": len(body)}


def bounded(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit,
                "actual selected input is not a bounded regular file")
        body = source.read(limit + 1)
        after = os.fstat(source.fileno())
    identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns)
    require(len(body) <= limit and identity(before) == identity(after)
            == identity(Path(path).lstat()), "actual selected input changed")
    return body


def private(path, limit):
    metadata = Path(path).lstat()
    require(metadata.st_uid == os.getuid() and stat.S_IMODE(metadata.st_mode) == 0o600
            and metadata.st_nlink == 1, "cleanup private custody differs")
    return bounded(path, limit)


def process_identity(process):
    proc = Path('/proc') / str(process['pid'])
    before = (proc/'stat').read_text().rpartition(') ')[2].split()
    require(before[0] != 'Z' and before[19] == process['startTicks']
            and proc.stat().st_uid == process['ownerUid'], "owned process lifetime differs")
    for name, field in (('environ', 'environmentSha256'), ('cmdline', 'commandLineSha256')):
        body = (proc/name).read_bytes()
        require(len(body) <= 65536 and hashlib.sha256(body).hexdigest() == process[field],
                "owned process original differs")
    with (proc/'exe').open('rb') as stream:
        require(hashlib.file_digest(stream, 'sha256').hexdigest() == process['executableSha256'],
                "owned process executable differs")
    after = (proc/'stat').read_text().rpartition(') ')[2].split()
    require(after[19] == before[19] and after[0] != 'Z', "owned process changed during inspection")
    return proc


def readiness(selected):
    """Match the actual post-bind private record to the original launch pin."""
    process_identity(selected['lossProcess'])
    deadline = time.monotonic() + 30
    while not Path(selected['readyFile']).exists():
        process_identity(selected['lossProcess'])
        require(time.monotonic() < deadline, 'cleanup listener post-bind readiness absent')
        time.sleep(0.05)
    value = json.loads(private(selected['readyFile'], 16384))
    fields = {'version', 'scope', 'pid', 'startTicks', 'ownerUid',
              'configurationSha256', 'listenerSourceSha256', 'listenAddress', 'route'}
    require(set(value) == fields and value['version'] == 1
            and value['scope'] == 'managed_terminal_cleanup_loss_listener'
            and value['pid'] == selected['lossProcess']['pid']
            and value['startTicks'] == selected['lossProcess']['startTicks']
            and value['ownerUid'] == selected['lossProcess']['ownerUid']
            and value['configurationSha256'] == selected['configurationSha256']
            and value['listenerSourceSha256'] == selected['listenerSourceSha256']
            and value['listenAddress'] == '127.0.0.1:4660'
            and value['route'] == '/_internal/storage/managed-oci-cleanup/v1',
            'actual cleanup listener has not bound its selected configuration')
    process_identity(selected['lossProcess'])
    return value


def runner_command(selected, request, label):
    """Use the actual owner-private runner peer, once, with retained bytes."""
    namespace = load(selected['namespaceObserver'], 'cleanup_namespace')
    root = Path(selected['workerRoot'])/'cleanup-controls'/label
    root.parent.mkdir(mode=0o700, exist_ok=True)
    root.mkdir(mode=0o700, exist_ok=False)
    process_identity(selected['workerProcess'])
    original = encoded(request) + b'\n'
    retained(root/'original.json', original)
    socket_path = Path(selected['workerRoot'])/'control.sock'
    metadata = socket_path.lstat()
    require(stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == os.getuid()
            and stat.S_IMODE(metadata.st_mode) == 0o600, "actual runner socket custody differs")
    response = bytearray()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(20)
            peer.connect(str(socket_path))
            pid, uid, _ = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(pid == selected['workerProcess']['pid'] and uid == selected['workerProcess']['ownerUid'],
                    "actual runner peer differs")
            process_identity(selected['workerProcess'])
            peer.sendall(original)
            peer.shutdown(socket.SHUT_WR)
            while block := peer.recv(4096):
                response.extend(block)
                require(len(response) <= 32768, "actual cleanup control reply exceeds bound")
        process_identity(selected['workerProcess'])
        value = namespace.closed_json(bytes(response))
        require(value.get('version') == 1, 'actual cleanup runner control refused')
        if request['kind'] == 'oci-sdk-namespace-readback':
            require(value.get('observationScope') == 'oci_sdk_emulator_namespace_readback'
                    and value.get('runnerPid') == pid, 'actual namespace reply differs')
        elif request['kind'] == 'managed-oci-cleanup-fixture-install':
            require(value.get('status') == 'stored' and value.get('runnerPid') == pid,
                    'actual fixture installation reply differs')
        else:
            raise ValueError('unsupported cleanup runner control')
        return value
    finally:
        retained(root/'reply.private.json', bytes(response))


def helper(selected):
    """Select exactly one ignored test from the reviewed current-source ELF."""
    proof_bytes = bounded(selected['helperProvenance'], 65536)
    proof = json.loads(proof_bytes)
    require(set(proof) == {'version', 'commonSourceStorePath', 'workerFilteredSourceStorePath',
                          'testExecutableSha256', 'testExecutableBytes'} and proof['version'] == 1
            and proof['commonSourceStorePath'] == selected['commonSourceStorePath']
            and proof['workerFilteredSourceStorePath'] == selected['workerSourcePath'],
            "cleanup test ELF is not the independently selected common-source build")
    executable = Path(selected['nativeHelper'])
    with executable.open('rb') as stream:
        sha = hashlib.file_digest(stream, 'sha256').hexdigest()
    require(isinstance(proof['testExecutableBytes'], str)
            and re.fullmatch(r'[1-9][0-9]{0,8}', proof['testExecutableBytes'])
            and int(proof['testExecutableBytes']) <= 512 * 1024 * 1024
            and sha == proof['testExecutableSha256']
            and executable.stat().st_size == int(proof['testExecutableBytes']),
            "selected cleanup test ELF differs")
    root = Path(selected['nativeRoot'])/'cleanup-helper'/selected['label']
    root.parent.mkdir(mode=0o700, exist_ok=True)
    root.mkdir(mode=0o700, exist_ok=False)
    parameters = {**selected['input'], 'outputFile': str(root/'result.private.json')}
    retained(root/'input.private.json', encoded(parameters))
    environment = dict(os.environ, AOS_MANAGED_CLEANUP_CONTROLLED_INPUT=str(root/'input.private.json'))
    process = subprocess.run([str(executable), TEST, '--exact', '--ignored', '--nocapture'],
        env=environment, stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=90)
    retained(root/'stdout', process.stdout)
    retained(root/'stderr', process.stderr)
    require(process.returncode == 0 and b'1 passed;' in process.stdout
            and b'0 failed;' in process.stdout, "actual selected cleanup helper failed")
    body = private(root/'result.private.json', 65536)
    value = json.loads(body)
    return {'value': value, 'input': parameters, 'receipt': {
        'path': str(root/'result.private.json'), 'sha256': hashlib.sha256(body).hexdigest(),
        'byteSize': len(body), 'testExecutableSha256': sha,
        'provenanceSha256': hashlib.sha256(proof_bytes).hexdigest(), 'exitCode': process.returncode}}


def arm(selected):
    process_identity(selected['lossProcess'])
    body = bounded(selected['lossConfiguration'], 65536)
    require(hashlib.sha256(body).hexdigest() == selected['lossConfigurationSha256'],
            'cleanup initial listener configuration changed')
    config = json.loads(body)
    value = selected['arm']
    require(value['expiresAt'] > int(time.time()) and value['helperInput']['phase'] == 'observe'
            and value['helperInput']['expectedOriginalSha256'] == value['originalSha256'],
            'cleanup one-shot arm lacks current observed SQL original')
    return retained(config['armFile'], encoded(value))


def lost_receipt(selected):
    root = Path(selected['nativeRoot'])/'cleanup-loss'
    consumed = json.loads(private(root/'arm-consumed.json', 65536))
    exchange_root = Path(consumed['exchange'])
    require(exchange_root.parent == root and consumed['originalSha256'] == selected['originalSha256'],
            'cleanup arm consumed a different original')
    deadline = time.monotonic() + 5
    while not (exchange_root/'exchange.json').exists():
        require(time.monotonic() < deadline, 'actual completed-response loss receipt absent')
        time.sleep(0.05)
    body = private(exchange_root/'exchange.json', 65536)
    value = json.loads(body)
    require(value['outcome'] == 'authenticated_completed_response_deliberately_lost'
            and value['authentication']['proof']['originalSha256'] == selected['originalSha256'],
            'generic transport error is not authenticated completed-response loss')
    return {'value': value, 'receipt': {'path':str(exchange_root/'exchange.json'),
        'sha256':hashlib.sha256(body).hexdigest(), 'byteSize':len(body)}}


def forwarded_receipt(selected):
    """Authenticate the one fresh replay's actual retained request and reply."""
    listener = load(selected['listenerModule'], 'cleanup_loss_authentication')
    config = json.loads(private(selected['listenerConfiguration'],65536))
    root=Path(config['root'])
    matches=[]
    for path in sorted(root.glob('exchange-*/exchange.json')):
        value=json.loads(private(path,65536))
        if value['outcome']!='ordinary_forwarded_response' or value.get('status')!=200:
            continue
        request=private(value['request']['path'],16384)
        parsed=json.loads(request)
        if hashlib.sha256(encoded(parsed['original'])).hexdigest()==selected['originalSha256']:
            matches.append((path.parent,value,request))
    require(len(matches)==1,'cold replay has no unique actual forwarded signed reply')
    exchange,value,request=matches[0]
    authentication_root=exchange/'replay-authentication'
    authentication_root.mkdir(mode=0o700,exist_ok=False)
    arm={'helperInput':selected['helperInput'],'originalSha256':selected['originalSha256'],
         'protectedProfileDigest':selected['protectedProfileDigest']}
    proof=listener.authenticate_completion(config,arm,authentication_root,request,
        private(value['requestSignature']['path'],1024).decode(),
        private(value['reply']['path'],16384),private(value['replySignature']['path'],1024).decode())
    return {'exchange':value,'authentication':proof}


def cold_restart(selected):
    """Kill only both recorded lifetimes, then restart the exact argv/env/stores."""
    require(Path(selected['workerProcess']['logFile']) == Path(selected['workerRoot'])/'worker.log',
            'cold continuation requires the actual original log path')
    observed = runner_command(selected, {'version':1,'kind':'oci-sdk-namespace-readback'}, 'before-cold')
    namespace = observed['namespace'] if 'namespace' in observed else observed
    process = selected['workerProcess']
    proc = process_identity(process)
    argv = (proc/'cmdline').read_bytes().split(b'\0')[:-1]
    environment_bytes = (proc/'environ').read_bytes()
    environment = dict(item.split(b'=',1) for item in environment_bytes.split(b'\0') if item)
    config = bounded(selected['configuration'], 1024*1024)
    require(hashlib.sha256(config).hexdigest() == selected['configurationSha256'], 'initial Worker configuration changed')
    child_pid = namespace['workerdPid']
    child = Path('/proc')/str(child_pid)
    child_stat = (child/'stat').read_text().rpartition(') ')[2].split()
    require(child_stat[19] == str(namespace['workerdStartTicks']) and child.stat().st_uid == process['ownerUid']
            and (child/'exe').resolve() == Path(selected['workerd']).resolve(), 'actual workerd lifetime differs')
    # Readback must identify this Node's own direct child. No name-wide signals.
    require(int(child_stat[1]) == process['pid'], 'selected workerd is not the actual runner child')
    descriptors = [os.pidfd_open(child_pid), os.pidfd_open(process['pid'])]
    try:
        process_identity(process)
        current_child = (child/'stat').read_text().rpartition(') ')[2].split()
        require(current_child[19] == child_stat[19] and current_child[0] != 'Z'
                and int(current_child[1]) == process['pid'], 'workerd changed before cold signal')
        for descriptor in reversed(descriptors):
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
        poller = select.poll()
        for descriptor in descriptors:
            poller.register(descriptor, select.POLLIN)
        completed = set()
        deadline = time.monotonic()+20
        while len(completed) != 2:
            require(time.monotonic()<deadline, 'owned cold stop unresolved')
            completed.update(fd for fd,event in poller.poll(100) if event & select.POLLIN)
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    require(hashlib.sha256(bounded(selected['configuration'],1024*1024)).hexdigest()==selected['configurationSha256'],
            'configuration changed across cold stop')
    root = Path(selected['workerRoot'])
    log_path = Path(process['logFile'])
    require(log_path == root/'worker.log', 'cold continuation must retain the actual original log path')
    descriptor = os.open(log_path, os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
    log_metadata = os.fstat(descriptor)
    require(stat.S_ISREG(log_metadata.st_mode) and log_metadata.st_uid == process['ownerUid']
            and stat.S_IMODE(log_metadata.st_mode) == 0o600 and log_metadata.st_nlink == 1,
            'original Worker log lost private custody')
    continuation = {'path':str(log_path), 'device':str(log_metadata.st_dev),
                    'inode':str(log_metadata.st_ino), 'oldByteSize':str(log_metadata.st_size)}
    with os.fdopen(descriptor,'ab') as log:
        replacement = subprocess.Popen(argv,env=environment,stdin=subprocess.DEVNULL,
            stdout=log,stderr=log,start_new_session=True)
    deadline=time.monotonic()+60
    while True:
        require(replacement.poll() is None, 'cold replacement exited; retain state')
        current=Path('/proc')/str(replacement.pid)
        actual_argv=(current/'cmdline').read_bytes()
        actual_env=(current/'environ').read_bytes()
        if (actual_argv==b'\0'.join(argv)+b'\0' and actual_env==environment_bytes
                and (current/'exe').resolve()==(Path(os.fsdecode(argv[0]))).resolve()):
            record={**process,'pid':replacement.pid,'startTicks':(current/'stat').read_text().rpartition(') ')[2].split()[19],
                'logFile':str(log_path)}
            socket_path = root/'control.sock'
            try:
                metadata = socket_path.lstat()
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                    peer.settimeout(1)
                    peer.connect(str(socket_path))
                    peer_pid, peer_uid, _ = struct.unpack('3i', peer.getsockopt(
                        socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                ready = (stat.S_ISSOCK(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600
                         and peer_pid == replacement.pid and peer_uid == record['ownerUid'])
            except OSError:
                ready = False
            if ready:
                after=runner_command({**selected,'workerProcess':record},
                    {'version':1,'kind':'oci-sdk-namespace-readback'},'after-cold')
                new_namespace=after['namespace'] if 'namespace' in after else after
                for field in ('namespaceId','namespaceObjectId','namespaceUniqueKey','buildDerivedSourceDigest',
                              'buildDerivedScriptVersion','configurationSha256','wasmSha256','shimSha256'):
                    require(namespace[field]==new_namespace[field], 'cold replacement changed source/stores/pins')
                retained(root/'cleanup-cold-result.json',encoded({'old':process,'new':record,'before':observed,'after':after,'logContinuation':continuation}))
                return {'old':process,'new':record,'before':observed,'after':after,'logContinuation':continuation}
        require(time.monotonic()<deadline, 'actual cold replacement readback did not complete')
        time.sleep(0.2)


def sdk(selected):
    collector=load(selected['collector'],'cleanup_collector')
    process_identity(selected['workerProcess'])
    log=Path(selected['workerProcess']['logFile'])
    with log.open('rb') as source:
        source.seek(selected['offset'])
        raw=source.read(8*1024*1024+1)
    require(len(raw)<=8*1024*1024,'actual cleanup log window exceeds bound')
    records=[]
    marker='managed_gc_sdk_observer '
    for line in raw.decode().splitlines():
        if marker in line:
            value=json.loads(line.split(marker,1)[1])
            if value['scope']=='managed_terminal_cleanup':
                records.append(value)
    result=collector.collect(records,selected['runId'],selected['backingIdentity'],selected['expected'])
    process_identity(selected['workerProcess'])
    return {'result':result,'rawLogSha256':hashlib.sha256(raw).hexdigest(),'rawLogBytes':len(raw)}


def execute(operation, selected):
    """Dispatch one closed fixture operation without implicit retries."""
    operations={'readiness':readiness,'helper':helper,'arm':arm,'lost_receipt':lost_receipt,'forwarded_receipt':forwarded_receipt,'cold_restart':cold_restart,
                'runner_command':lambda row:runner_command(row,row['request'],row['label']), 'sdk':sdk}
    require(operation in operations, 'cleanup operation is not supported')
    return operations[operation](selected)
