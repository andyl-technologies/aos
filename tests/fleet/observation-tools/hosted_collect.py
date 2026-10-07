"""Supervise bounded read-only provider observations through pinned TLS tools.

Only a successful invocation held by this supervisor can populate its verifier.
Reopening a receipt from disk does not authenticate that receipt. The caller
retains the supervisor's source/process/window custody independently; these
observations are source-checked transport, not signed provider log records.

The optional official SQL reader is a separately selected source-built tool.
This module never discovers credentials or starts a proxy; only that pinned
SELECT-only reader can open the explicitly selected managed database.
"""

import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote


MAX_REQUEST = 64 * 1024
MAX_RESPONSE = 16 * 1024 * 1024
MAX_HEADER = 16 * 1024
MAX_TOKEN = 8192
MAX_CALLS = 4096
MAX_CORPUS = 256 * 1024 * 1024
INODE_FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def closed_json(raw):
    def pairs(items):
        result = {}
        for name, value in items:
            if name in result:
                raise ValueError('Collector duplicate field')
            result[name] = value
        return result

    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda *_: (_ for _ in ()).throw(ValueError('Collector number differs')))


def closed(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError('Collector closed schema differs')


def destination(operation, request, scope):
    """Map source-declared purposes to exact authenticated read-only routes."""
    if operation in ('cloud_run_service', 'cloud_run_revision', 'cloud_sql_instance'):
        closed(request, {'name'})
        key = {'cloud_run_service': 'serviceName', 'cloud_run_revision': 'revisionName',
               'cloud_sql_instance': 'instanceName'}[operation]
        name = request['name']
        pattern = (r'projects/[a-z][a-z0-9-]{0,62}/instances/[a-z][a-z0-9-]{0,62}'
                   if operation == 'cloud_sql_instance' else
                   r'projects/[a-z][a-z0-9-]{0,62}/locations/[a-z][a-z0-9-]{0,62}/services/'
                   r'[a-z][a-z0-9-]{0,62}' +
                   (r'/revisions/[a-z][a-z0-9-]{0,62}' if operation.endswith('revision') else ''))
        if not isinstance(name, str) or re.fullmatch(pattern, name) is None or name != scope.get(key):
            raise ValueError('Collector selected resource differs')
        if operation == 'cloud_sql_instance':
            project, instance = name.split('/')[1::2]
            return 'sqladmin.googleapis.com', '/sql/v1beta4/projects/' + project + '/instances/' + instance, 'GET', b''
        return 'run.googleapis.com', '/v2/' + quote(name, safe='/'), 'GET', b''

    if operation == 'logging_entries_list':
        closed(request, {'resourceNames', 'filter', 'orderBy', 'pageSize'} |
               ({'pageToken'} if 'pageToken' in request else set()))
        service = scope.get('serviceName', '')
        project = service.split('/')[1] if service.startswith('projects/') else None
        if project is None or request['resourceNames'] != ['projects/' + project]:
            raise ValueError('Collector log project differs')
        if (not isinstance(request['filter'], str) or len(request['filter'].encode()) > 8192
                or request['orderBy'] != 'timestamp asc' or type(request['pageSize']) is not int
                or not 1 <= request['pageSize'] <= 1000
                or ('pageToken' in request and (not isinstance(request['pageToken'], str)
                    or not 0 < len(request['pageToken']) <= 8192))):
            raise ValueError('Collector log request differs')
        # The receiver also compares this filter against the exact selected
        # policy window. This transport mapping does not classify log messages.
        return 'logging.googleapis.com', '/v2/entries:list', 'POST', None

    raise ValueError('Collector operation is not an admitted provider read')


def remaining(deadline):
    value = min(deadline['monotonic'] - time.monotonic(), deadline['unix'] - time.time())
    if value <= 0:
        raise ValueError('Collector original observation cutoff elapsed')
    return value


def pin_process(pid):
    """Observe a locally owned child lifetime without retaining its argv."""
    root = Path('/proc') / str(pid)
    status = (root / 'status').read_text()
    owners = next(row for row in status.splitlines() if row.startswith('Uid:')).split()[1:]
    if any(int(value) != os.getuid() for value in owners):
        raise ValueError('Collector child owner differs')
    fields = (root / 'stat').read_text().rsplit(')', 1)[1].split()
    with (root / 'exe').open('rb') as stream:
        executable = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'pid': pid, 'ownerUid': os.getuid(), 'startTicks': fields[19],
            'executableSha256': executable}


def immutable(reference):
    """Hold canonical immutable Nix input custody through bounded hashing."""
    closed(reference, {'file', 'sha256', 'byteSize'})
    path = Path(reference['file'])
    if (not path.is_absolute() or path != path.resolve(strict=True)
            or not re.fullmatch(r'/nix/store/[0-9a-z]{32}-[^/]+/.+', str(path))):
        raise ValueError('Collector input is not canonical installed code')
    descriptors = []
    try:
        directory = os.open('/nix/store', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(directory)
        owner = os.fstat(directory).st_uid
        brackets = []
        for component in path.parts[3:-1]:
            directory = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            descriptors.append(directory)
            before = os.fstat(directory)
            if before.st_uid != owner or before.st_mode & 0o222:
                raise ValueError('Collector immutable ancestor differs')
            brackets.append((directory, before))
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner
                    or before.st_mode & 0o222 or before.st_size > 128 * 1024 * 1024
                    or str(before.st_size) != reference['byteSize']):
                raise ValueError('Collector immutable file differs')
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            after = os.fstat(stream.fileno())
        if (digest != reference['sha256'] or any(getattr(before, name) != getattr(after, name)
                for name in INODE_FIELDS) or any(any(getattr(old, name) != getattr(os.fstat(fd), name)
                for name in INODE_FIELDS) for fd, old in brackets)):
            raise ValueError('Collector installed image changed')
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    return path


def retain_images(root, request, response, receipt):
    """Publish create-only private byte images without asserting their custody."""
    root = Path(root)
    if not root.is_absolute() or root != root.resolve(strict=True):
        raise ValueError('Collector output directory is not canonical')
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if before.st_uid != os.getuid() or before.st_mode & 0o077:
            raise ValueError('Collector output directory custody differs')
        references = {}
        for name, raw, maximum in (('request', request, MAX_REQUEST),
                                    ('response', response, MAX_RESPONSE),
                                    ('collectorReceipt', receipt, MAX_HEADER)):
            if len(raw) > maximum:
                raise ValueError('Collector retained image exceeds bound')
            temporary = '.' + name + '.' + os.urandom(16).hex()
            image = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600, dir_fd=descriptor)
            try:
                with os.fdopen(image, 'wb') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.link(temporary, name + '.bin', src_dir_fd=descriptor,
                        dst_dir_fd=descriptor, follow_symlinks=False)
            finally:
                os.unlink(temporary, dir_fd=descriptor)
            references[name] = {'file': str(root / (name + '.bin')),
                                'sha256': sha(raw), 'byteSize': str(len(raw))}
        os.fsync(descriptor)
        return references
    finally:
        os.close(descriptor)


def https_read(host, path, method, body, token, trust, deadline, maximum):
    """Consume one checked HTTPS reply within the original bounded window."""
    context = ssl.create_default_context(cafile=str(trust))
    connection = http.client.HTTPSConnection(host, timeout=min(30, remaining(deadline)), context=context)
    try:
        connection.connect()
        certificate = connection.sock.getpeercert(binary_form=True)
        tls_version = connection.sock.version()
        connection.sock.settimeout(min(30, remaining(deadline)))
        connection.request(method, path, body=body, headers={
            'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json',
            'Accept': 'application/json'})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError('Collector provider read was refused or redirected')
        content_length = response.getheader('Content-Length')
        if content_length is not None and (not re.fullmatch(r'0|[1-9][0-9]*', content_length)
                                           or int(content_length) > maximum):
            raise ValueError('Collector reply length exceeds bound')
        chunks, count = [], 0
        while True:
            remaining(deadline)
            if connection.sock is not None:
                connection.sock.settimeout(min(30, remaining(deadline)))
            chunk = response.read(min(64 * 1024, maximum + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            if count > maximum:
                raise ValueError('Collector reply exceeds bound')
        if content_length is not None and count != int(content_length):
            raise ValueError('Collector reply framing is incomplete')
        remaining(deadline)
        return b''.join(chunks), {'hostname': host, 'pathSha256': sha(path.encode()),
            'method': method, 'wireRequestSha256': sha(body), 'wireRequestBytes': str(len(body)),
            'status': response.status, 'responseBytes': str(count), 'eof': True,
            'peerCertificateSha256': sha(certificate), 'tlsVersion': tls_version}
    finally:
        connection.close()


def child_main(configuration_fd, token_fd):
    """Run only the inherited source-selected observation, with redacted errors."""
    with os.fdopen(configuration_fd, 'rb') as stream:
        raw = stream.read(MAX_REQUEST + MAX_HEADER + 1)
    if len(raw) > MAX_REQUEST + MAX_HEADER:
        raise ValueError('Collector configuration exceeds bound')
    selected = closed_json(raw)
    closed(selected, {'operation', 'request', 'scope', 'trust', 'deadline', 'maximum'})
    trust = immutable(selected['trust'])
    try:
        before = os.fstat(token_fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_mode & 0o077 or before.st_nlink != 1
                or not 0 < before.st_size <= MAX_TOKEN):
            raise ValueError('Collector protected authorization descriptor differs')
        token = os.pread(token_fd, MAX_TOKEN + 1, 0)
        after = os.fstat(token_fd)
        if len(token) != before.st_size or any(getattr(before, name) != getattr(after, name)
                for name in INODE_FIELDS):
            raise ValueError('Collector protected authorization descriptor changed')
    finally:
        os.close(token_fd)
    if not token or len(token) > MAX_TOKEN or re.fullmatch(rb'[A-Za-z0-9._~+/=-]+', token) is None:
        raise ValueError('Collector authorization input differs')
    request_raw = selected['request'].encode()
    request = closed_json(request_raw)
    host, path, method, body = destination(selected['operation'], request, selected['scope'])
    if body is None:
        body = request_raw
    maximum = selected['maximum']
    if type(maximum) is not int or not 1 <= maximum <= MAX_RESPONSE:
        raise ValueError('Collector selected bound differs')
    response, transport = https_read(host, path, method, body, token.decode('ascii'), trust,
                                    selected['deadline'], maximum)
    header = json.dumps({'transport': transport, 'responseSha256': sha(response)},
                        separators=(',', ':')).encode()
    sys.stdout.buffer.write(len(header).to_bytes(4, 'big') + header + response)
    sys.stdout.buffer.flush()


class Supervisor:
    """Hold actual invocation observations; supplied JSON cannot populate them."""

    def __init__(self, python, collector, trust, deadline, managed_reader=None):
        self.python = immutable(python)
        self.collector = immutable(collector)
        self.trust = immutable(trust)
        if self.collector != Path(__file__).resolve(strict=True):
            raise ValueError('Collector source pin selects another implementation')
        self.pins = {'python': python, 'collector': collector, 'trust': trust}
        self.managed_reader = managed_reader
        if managed_reader is not None:
            closed(managed_reader, {'executable', 'sourceSha256', 'querySourceSha256'})
            immutable(managed_reader['executable'])
            if any(not isinstance(managed_reader[key], str)
                   or re.fullmatch('[0-9a-f]{64}', managed_reader[key]) is None
                   for key in ('sourceSha256', 'querySourceSha256')):
                raise ValueError('Managed reader measured source binding differs')
        self.deadline = dict(deadline)
        closed(self.deadline, {'monotonic', 'unix'})
        if any(type(value) not in (int, float) or not math.isfinite(value) or value <= 0
               for value in self.deadline.values()):
            raise ValueError('Collector deadline differs')
        remaining(self.deadline)
        # Child work ends before the original total cutoff. Owned cancellation
        # uses this reserve rather than adding time after an expired window.
        self.work_deadline = {name: value - 2 for name, value in self.deadline.items()}
        remaining(self.work_deadline)
        self.parent = pin_process(os.getpid())
        self._observations = {}
        self._failures = []
        self._started = 0
        self._bytes = 0

    def collect(self, operation, request_raw, scope, authorization_fd, maximum=MAX_RESPONSE,
                *, _managed=None):
        """Observe one owned child and return exact byte images plus receipt.

        The inherited authorization descriptor is never read by the supervisor
        or included in receipts, stdout, environment or command arguments.
        """
        if (len(request_raw) > MAX_REQUEST or self._started >= MAX_CALLS
                or type(maximum) is not int or not 1 <= maximum <= MAX_RESPONSE):
            raise ValueError('Collector request or invocation bound differs')
        if _managed is None:
            destination(operation, closed_json(request_raw), scope)
        remaining(self.work_deadline)
        ordinal = self._started
        self._started += 1
        configuration = json.dumps({'operation': operation, 'request': request_raw.decode(),
            'scope': scope, 'trust': self.pins['trust'], 'deadline': self.work_deadline,
            'maximum': maximum}, separators=(',', ':')).encode()
        if len(configuration) > MAX_REQUEST + MAX_HEADER:
            raise ValueError('Collector configuration exceeds bound')
        read_fd, write_fd = os.pipe()
        configuration_owner = None
        managed_configuration_fd = None
        child = None
        selector = selectors.DefaultSelector()
        before_unix = str(time.time_ns())
        before_mono = str(time.monotonic_ns())
        output, errors = bytearray(), bytearray()
        child_pin = None
        try:
            if _managed is None:
                command = [str(self.python), '-B', '-E', str(self.collector),
                           '--observed-child', str(read_fd), str(authorization_fd)]
                inherited = (read_fd, authorization_fd)
                expected_executable = self.pins['python']['sha256']
            else:
                configuration_owner = tempfile.TemporaryDirectory(prefix='aos-managed-observation-')
                configuration_path = Path(configuration_owner.name) / 'configuration.json'
                descriptor = os.open(configuration_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(_managed['configuration'])
                    stream.flush()
                    os.fsync(stream.fileno())
                managed_configuration_fd = os.open(configuration_path, os.O_RDONLY | os.O_NOFOLLOW)
                command = [str(_managed['executable']), str(managed_configuration_fd),
                           str(authorization_fd), str(_managed['passwordFd']), str(read_fd)]
                inherited = (read_fd, managed_configuration_fd, authorization_fd, _managed['passwordFd'])
                expected_executable = _managed['pin']['sha256']
                configuration = b'\x01'
            remaining(self.work_deadline)
            child = subprocess.Popen(command,
                pass_fds=inherited, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True,
                env={'LANG': 'C.UTF-8', 'PATH': str(self.python.parent)})
            os.close(read_fd)
            read_fd = None
            # The child blocks on its inherited input until its actual lifetime
            # and executable have been independently sampled by the parent.
            child_pin = pin_process(child.pid)
            if child_pin['executableSha256'] != expected_executable:
                raise ValueError('Collector child executable differs')
            remaining(self.work_deadline)
            with os.fdopen(write_fd, 'wb') as stream:
                write_fd = None
                stream.write(configuration)
            for stream, buffer, bound in ((child.stdout, output, maximum + MAX_HEADER + 4),
                                           (child.stderr, errors, 4096)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, (buffer, bound))
            while selector.get_map():
                for key, _ in selector.select(min(0.1, remaining(self.work_deadline))):
                    chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffer, bound = key.data
                    if len(buffer) + len(chunk) > bound:
                        raise ValueError('Collector child output exceeds bound')
                    buffer.extend(chunk)
            result = child.wait(timeout=remaining(self.work_deadline))
            if result != 0 or errors:
                raise ValueError('Collector invocation refused or is incomplete')
            if len(output) < 4:
                raise ValueError('Collector child frame is incomplete')
            size = int.from_bytes(output[:4], 'big')
            if not 0 < size <= MAX_HEADER or len(output) < 4 + size:
                raise ValueError('Collector child header differs')
            header = closed_json(output[4:4 + size])
            response = bytes(output[4 + size:])
            if _managed is None:
                closed(header, {'transport', 'responseSha256'})
                valid = (header['responseSha256'] == sha(response)
                    and header['transport']['responseBytes'] == str(len(response))
                    and header['transport']['eof'] is True)
            else:
                closed(header, {'version', 'claim', 'connectionName', 'ipType', 'querySha256', 'rowsSha256',
                    'readerBefore', 'readerAfter', 'beforeUnixNanos', 'afterUnixNanos', 'elapsedNanos',
                    'querySourceSha256', 'connectorSourceSha256', 'remoteProcessCustody',
                    'peerCertificateObservation'})
                valid = (type(header['version']) is int and header['version'] == 1
                    and header['claim'] == 'source_checked_official_connector_snapshot'
                    and header['connectionName'] == scope['connectionName']
                    and header['ipType'] == scope['transport']['ipType']
                    and header['querySha256'] == sha(request_raw) and header['rowsSha256'] == sha(response)
                    and header['readerBefore'] == child_pin and header['readerAfter'] == child_pin
                    and header['connectorSourceSha256'] == scope['transport']['connectorSourceSha256']
                    and header['querySourceSha256'] == _managed['querySourceSha256']
                    and header['remoteProcessCustody'] is None
                    and header['peerCertificateObservation'] is None)
            if len(response) > maximum or not valid:
                raise ValueError('Collector supervised reply differs')
            self._bytes += len(response)
            if self._bytes > MAX_CORPUS:
                raise ValueError('Collector corpus exceeds bound')
            receipt = {'version': 1, 'claim': 'source_checked_live_supervised_tls',
                'operation': operation, 'requestSha256': sha(request_raw),
                'responseSha256': sha(response), 'scope': scope, 'pins': self.pins,
                'supervisor': self.parent, 'child': child_pin, 'exitCode': result,
                'beforeUnixNanos': before_unix, 'afterUnixNanos': str(time.time_ns()),
                'beforeMonotonicNanos': before_mono, 'afterMonotonicNanos': str(time.monotonic_ns()),
                'transport': header.get('transport'), 'observationOrdinal': str(ordinal)}
            if _managed is not None:
                rows = closed_json(response)
                receipt = {'version': 2, 'querySha256': sha(request_raw), 'rowsSha256': sha(response),
                    'exitCode': result, 'readerBefore': child_pin, 'readerAfter': child_pin,
                    'readerExecutableSha256': expected_executable,
                    'collectorSourceSha256': self.pins['collector']['sha256'],
                    'backend': {'pid': rows['backendPid'], 'connectionName': scope['connectionName'],
                        'database': rows['database'], 'role': rows['user'], 'snapshot': rows['snapshot']},
                    'beforeUnixNanos': header['beforeUnixNanos'], 'afterUnixNanos': header['afterUnixNanos'],
                    'sourceChild': scope['sourceChild'], 'transport': scope['transport']}
            receipt_raw = json.dumps(receipt, separators=(',', ':')).encode()
            key = (operation, sha(request_raw), sha(response), sha(receipt_raw))
            self._observations[key] = json.loads(json.dumps(scope))
            return request_raw, response, receipt_raw
        except Exception:
            self._failures.append({'operation': operation, 'observationOrdinal': str(ordinal),
                'requestSha256': sha(request_raw), 'capturedChildStdoutSha256': sha(output),
                'capturedChildStdoutBytes': str(len(output)), 'stderrSha256': sha(errors),
                'stderrBytes': str(len(errors)), 'child': child_pin,
                'observedExitCode': child.poll() if child is not None else None,
                'outcome': 'refused_or_unknown', 'providerReplyEof': None,
                'beforeUnixNanos': before_unix, 'afterUnixNanos': str(time.time_ns())})
            raise
        finally:
            for descriptor in (read_fd, write_fd, managed_configuration_fd):
                if descriptor is not None:
                    os.close(descriptor)
            selector.close()
            if child is not None:
                if child.poll() is None:
                    # An unreaped live Popen child remains ours even if its
                    # identity sample failed. Never leave it running because a
                    # custody check raised; this is not a provider drain claim.
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    wait = min(1, self.deadline['monotonic'] - time.monotonic(),
                               self.deadline['unix'] - time.time())
                    if wait > 0:
                        try:
                            child.wait(timeout=wait)
                        except subprocess.TimeoutExpired:
                            self._failures.append({'operation': operation,
                                'observationOrdinal': str(ordinal),
                                'outcome': 'owned_cleanup_unknown'})
                for stream in (child.stdout, child.stderr):
                    stream.close()
            if configuration_owner is not None:
                configuration_owner.cleanup()

    def verify(self, operation, request, response, receipt, scope):
        """Match only images actually observed by this live source supervisor."""
        key = (operation, sha(request), sha(response), sha(receipt))
        if key not in self._observations:
            return None
        if self._observations[key] != scope or pin_process(os.getpid()) != self.parent:
            raise ValueError('Collector supervision lifetime or selected scope differs')
        return {'operation': operation, 'requestSha256': sha(request),
                'responseSha256': sha(response), 'receiptSha256': sha(receipt), 'scope': scope}

    def collect_sql(self, connector, selected, query, query_source_sha256, scope,
                    google_credentials_fd, password_fd):
        """Invoke only a pinned official connector with the exact source query.

        The Go executable independently generates this query from its actual
        immutable AOS source. Secrets remain inherited private descriptors.
        Returned bytes carry no remote OS/process or earlier IAM claim.
        """
        if self.managed_reader is None:
            raise ValueError('No independently selected managed reader package')
        path = immutable(connector)
        closed(selected, {'version', 'connectionName', 'ipType', 'database', 'role', 'deployment',
                          'checkpoints', 'querySha256', 'cutoffUnixNanos', 'maximumWorkNanos'})
        transport = scope['transport']
        if (transport['kind'] != 'official_connector'
                or connector != self.managed_reader['executable']
                or transport['connectorSourceSha256'] != self.managed_reader['sourceSha256']
                or query_source_sha256 != self.managed_reader['querySourceSha256']
                or transport['connectorExecutableSha256'] != connector['sha256']
                or transport['ipType'] != selected['ipType']
                or selected['querySha256'] != sha(query)
                or any(selected[name] != scope[name] for name in ('connectionName', 'database', 'role'))
                or not isinstance(query_source_sha256, str)
                or re.fullmatch('[0-9a-f]{64}', query_source_sha256) is None):
            raise ValueError('Actual managed collector query or scope differs')
        # The outer controller keeps its original boot-monotonic cutoff even
        # if the child clock moves backwards. Never copy a later user deadline.
        if int(selected['cutoffUnixNanos']) > int(self.work_deadline['unix'] * 1000000000):
            raise ValueError('Managed collector cutoff extends the original window')
        raw = json.dumps(selected, separators=(',', ':')).encode()
        if len(raw) > 128 * 1024:
            raise ValueError('Managed source selection exceeds bound')
        return self.collect('cloud_sql_reader', query, scope, google_credentials_fd, 512 * 1024,
            _managed={'executable': path, 'pin': connector, 'configuration': raw,
                      'passwordFd': password_fd, 'querySourceSha256': query_source_sha256})

    def failures(self):
        """Return redacted failed invocation observations, never qualified replies."""
        return json.loads(json.dumps(self._failures))


def unavailable_verifier(*_):
    """Keep retained receipts unqualified without their actual live supervisor."""
    return None


if __name__ == '__main__':
    try:
        if len(sys.argv) != 4 or sys.argv[1] != '--observed-child':
            raise ValueError('Collector requires its source-bound supervisor')
        child_main(int(sys.argv[2]), int(sys.argv[3]))
    except Exception:
        # Provider exceptions can carry URLs and credentials. Keep only a
        # fixed refusal while the supervisor preserves exit and partial hashes.
        sys.stderr.write('Readonly provider collection refused or incomplete\n')
        raise SystemExit(1)
