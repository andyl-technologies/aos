"""Review one exact cold-clock plan under independent owner-private authorization.

This host process has no guest/provider transport and cannot create authorization.
The fresh reviewer seed is inspected only through lstat; the independently pinned
source authority CLI alone consumes it. Canonical originals are refused, not fixed.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time


POLICY_FIELDS = ('version', 'reviewer_key_id', 'reviewer_public_key',
    'resource_qualification_digest', 'clock_qualification_digest',
    'maximum_review_seconds', 'clock_uncertainty', 'clock_commit_latency')
PLAN_FIELDS = ('version', 'file', 'expected_head', 'expected_session', 'expected_floor',
    'expected_ceiling', 'policy_digest', 'successor_session', 'nonce', 'issued_at', 'expires_at')
AUTHORITY_FIELDS = ('authority_id', 'guard_namespace_id', 'physical_resource_evidence_digest',
    'qualification_digest', 'qualified_managed_prefix')
INSTALLATION_FIELDS = ('format_version', 'authority', 'issuer_resource_id', 'runtime_identity', 'executor_identity')
JOURNAL_FIELDS = ('authority', 'executor_identity', 'generation', 'admission_digest',
    'publication_digest', 'state', 'policy', 'last_sequence', 'largest_issued_expiry', 'clock_floor')
TIMING_FIELDS = ('profile_id', 'review_digest', 'maximum_lifetime', 'maximum_clock_uncertainty')
CLEANUP_SECONDS = 3
termination_requested = False


def request_termination(signum, frame):
    """Defer reviewer termination until its owned signer has been settled."""
    global termination_requested
    termination_requested = True


def stop_clock_signer(child, deadline):
    """Terminate and reap this direct child within the original cleanup reserve."""
    if child.poll() is not None:
        return {'waitObserved': True, 'exitCode': child.returncode}
    child.terminate()
    try:
        child.wait(timeout=max(0, min(0.2, deadline - time.monotonic())))
    except subprocess.TimeoutExpired:
        child.kill()
        try:
            child.wait(timeout=max(0, min(1, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            return {'waitObserved': False, 'exitCode': None}
    return {'waitObserved': True, 'exitCode': child.returncode}


def sign_clock_plan(argv, root, deadline):
    """Keep the signer in the reviewer's isolated group and always collect it."""
    work_deadline = deadline - CLEANUP_SECONDS
    if termination_requested or time.monotonic() >= work_deadline:
        raise ValueError('no original plan budget remains for signing and cleanup')
    started = time.monotonic()
    child, ownership = None, None
    category = 'launch_unknown'
    settled = {'waitObserved': False, 'exitCode': None}
    sizes = [0, 0]
    with (root / 'sign.stdout').open('xb') as output, (root / 'sign.stderr').open('xb') as error:
        os.chmod(root / 'sign.stdout', 0o600)
        os.chmod(root / 'sign.stderr', 0o600)
        try:
            # Inherit the reviewer's isolated group. Parent group termination
            # therefore reaches the signer even if reviewer cleanup is interrupted.
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=error)
            owner = Path('/proc') / str(child.pid)
            fields = (owner / 'stat').read_text().rpartition(') ')[2].split()
            if owner.stat().st_uid != os.getuid() or int(fields[2]) != os.getpgrp():
                raise ValueError('owned signer process group differs')
            ownership = {'pid': child.pid, 'startTicks': fields[19], 'uid': os.getuid(),
                'processGroup': os.getpgrp(), 'reviewerPid': os.getpid()}
            write_new(root / 'sign-process.json', json.dumps(ownership, separators=(',', ':')).encode())
            while child.poll() is None and time.monotonic() < work_deadline and not termination_requested:
                if any(os.fstat(stream.fileno()).st_size > 65536 for stream in (output, error)):
                    category = 'overflow_unknown'
                    break
                time.sleep(0.01)
            if child.poll() is not None and not termination_requested and time.monotonic() < work_deadline:
                category = 'success' if child.returncode == 0 else 'refused_or_unknown'
            elif category != 'overflow_unknown':
                category = 'termination_or_deadline_unknown'
        finally:
            if child is not None:
                try:
                    settled = stop_clock_signer(child, deadline)
                except OSError:
                    settled = {'waitObserved': False, 'exitCode': None}
                    category = 'cleanup_unobservable_unknown'
            sizes = [os.fstat(stream.fileno()).st_size for stream in (output, error)]
            output.flush()
            error.flush()
            os.fsync(output.fileno())
            os.fsync(error.fileno())
            write_new(root / 'sign-result.json', json.dumps({'version': 1, 'category': category,
                'ownedProcess': ownership, **settled, 'terminationRequested': termination_requested,
                'elapsedSeconds': time.monotonic() - started, 'stdoutBytes': sizes[0],
                'stderrBytes': sizes[1], 'cleanupInsideCutoff': time.monotonic() < deadline},
                separators=(',', ':')).encode())
    if (category != 'success' or not settled['waitObserved'] or settled['exitCode'] != 0
            or sizes != [0, 0] or termination_requested or time.monotonic() >= work_deadline):
        raise ValueError('signing has no bounded positive acknowledgment and child wait')
    return work_deadline


def closed_json(body):
    def pairs(values):
        result = {}
        for name, value in values:
            if name in result:
                raise ValueError('duplicate public field')
            result[name] = value
        return result
    return json.loads(body, object_pairs_hook=pairs)


def ordered(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError('source closed field schema differs')
    return {name: value[name] for name in fields}


def canonical_plan(body):
    plan = ordered(closed_json(body), PLAN_FIELDS)
    plan['file'] = ordered(plan['file'], ('device', 'inode', 'parent_device', 'parent_inode'))
    head = ordered(plan['expected_head'], ('installation', 'journal'))
    installation = ordered(head['installation'], INSTALLATION_FIELDS)
    installation['authority'] = ordered(installation['authority'], AUTHORITY_FIELDS)
    journal = ordered(head['journal'], JOURNAL_FIELDS)
    journal['authority'] = ordered(journal['authority'], AUTHORITY_FIELDS)
    policy = ordered(journal['policy'], ('timing_profile',))
    policy['timing_profile'] = ordered(policy['timing_profile'], TIMING_FIELDS)
    journal['policy'] = policy
    head['installation'], head['journal'] = installation, journal
    plan['expected_head'] = head
    if json.dumps(plan, ensure_ascii=False, separators=(',', ':')).encode() != body:
        raise ValueError('noncanonical source plan encoding')
    if type(plan['version']) is not int or plan['version'] != 1:
        raise ValueError('unsupported source plan version')
    return plan


def wiretime(value):
    if not isinstance(value, str) or not re.fullmatch(r'0|[1-9][0-9]{0,18}', value) or int(value) > 2**63 - 1:
        raise ValueError('noncanonical source integer')
    return int(value)


def review_predicates(plan_bytes, policy_bytes, authorization):
    """Check independently authorized current facts before opaque signing."""
    plan = canonical_plan(plan_bytes)
    policy = ordered(closed_json(policy_bytes), POLICY_FIELDS)
    if json.dumps(policy, ensure_ascii=False, separators=(',', ':')).encode() != policy_bytes:
        raise ValueError('noncanonical independent policy')
    if (type(policy['version']) is not int or policy['version'] != 1
            or not 1 <= wiretime(policy['maximum_review_seconds']) <= 30):
        raise ValueError('unsupported independent policy interval')
    basis = authorization['snapshot']
    if (authorization['version'] != 1 or type(authorization['version']) is not int
            or authorization['policySha256'] != hashlib.sha256(policy_bytes).hexdigest()
            or basis['clockRecoveryPolicy'] != policy
            or policy['reviewer_key_id'] == basis['issuerSigningKeyId']):
        raise ValueError('independent authorization or distinct reviewer differs')
    expected = basis['signedHead']
    head = plan['expected_head']
    if head['installation'] != expected['installation']:
        raise ValueError('permanent installation changed')
    for name in JOURNAL_FIELDS:
        if name != 'clock_floor' and head['journal'][name] != expected['journal'][name]:
            raise ValueError('epoch or retained issuance changed')
    if (plan['file'] != basis['journalFile']
            or hashlib.sha256(plan['expected_session'].encode()).hexdigest() != basis['clockSessionSha256']
            or plan['policy_digest'] != authorization['policySha256']
            or wiretime(head['journal']['clock_floor']) < wiretime(expected['journal']['clock_floor'])
            or wiretime(plan['expected_floor']) < max(wiretime(basis['clockFloor']), wiretime(head['journal']['clock_floor']))
            or wiretime(plan['expected_ceiling']) < max(wiretime(basis['clockCeiling']), wiretime(plan['expected_floor']))):
        raise ValueError('resource, session, policy or clock rollback')
    for name in ('expected_session', 'successor_session', 'nonce', 'policy_digest'):
        if not isinstance(plan[name], str) or not re.fullmatch(r'[0-9a-f]{64}', plan[name]):
            raise ValueError('invalid source commitment')
    total = wiretime(policy['clock_uncertainty']) + wiretime(policy['clock_commit_latency']) + 1
    issued, expires = wiretime(plan['issued_at']), wiretime(plan['expires_at'])
    if (wiretime(policy['clock_commit_latency']) < 1 or total > 2**63 - 1
            or total > wiretime(head['journal']['policy']['timing_profile']['maximum_clock_uncertainty'])
            or plan['successor_session'] == plan['expected_session']
            or not 0 < expires - issued <= wiretime(policy['maximum_review_seconds'])
            or issued - total < max(wiretime(plan['expected_ceiling']), wiretime(head['journal']['largest_issued_expiry']))):
        raise ValueError('plan is early, stale, uncertain or not a fresh successor')
    return plan, policy


def retained_refusal_predicates(refusal, basis):
    """Join actual stopped-owner/history facts to the independent ready basis."""
    resource, history = refusal['retainedResource'], refusal['retainedHistory']
    if (refusal['oldPid'] != basis['process']['pid']
            or refusal['oldStartTicks'] != basis['process']['startTicks']
            or refusal['executableSha256'] != basis['authorityExecutableSha256']
            or type(refusal['exitCode']) is not int or refusal['exitCode'] == 0
            or type(history['journalFormat']) is not int or history['journalFormat'] != 3
            or history['historySha256'] != basis['historySha256']
            or history['historyRows'] != basis['historyRows']
            or history['clockSessionSha256'] != basis['clockSessionSha256']
            or wiretime(history['clockFloor']) < wiretime(basis['clockFloor'])
            or wiretime(history['clockCeiling']) < wiretime(basis['clockCeiling'])
            or resource['files']['configuration.json'] != basis['configurationSha256']
            or resource['files']['issuer-public-key.hex'] != basis['publicKeySha256']
            or {'device': str(resource['journalDevice']), 'inode': str(resource['journalInode']),
                'parent_device': str(resource['journalParentDevice']), 'parent_inode': str(resource['journalParentInode'])}
                != basis['journalFile']):
        raise ValueError('actual cold refusal changed authorized owner, resource or history')
    for name, expected in basis['secretCustody'].items():
        actual = resource['files'][name]
        projected = {'device': str(actual['device']), 'inode': str(actual['inode']),
            'bytes': actual['bytes'], 'mtimeNs': actual['mtimeNs'],
            'owner': actual['owner'], 'mode': actual['mode'], 'links': actual['links']}
        if projected != expected:
            raise ValueError('original issuer secret custody changed')


def seed_metadata(path):
    """Return custody only; this function never opens seed content."""
    value = path.lstat()
    parent = path.parent.lstat()
    if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid()
            or stat.S_IMODE(value.st_mode) != 0o600 or value.st_nlink != 1 or value.st_size != 32
            or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
            or stat.S_IMODE(parent.st_mode) != 0o700 or path.parent.resolve() != path.parent):
        raise ValueError('fresh reviewer seed custody differs')
    return {'device': str(value.st_dev), 'inode': str(value.st_ino), 'uid': value.st_uid,
        'mode': '0600', 'links': value.st_nlink, 'bytes': value.st_size, 'mtimeNs': str(value.st_mtime_ns)}


def public_file(path, digest, limit, private=True):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit
                or private and (before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o600)):
            raise ValueError('public input custody differs')
        body = source.read(limit + 1)
        after = os.fstat(source.fileno())
    current = path.lstat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_mode, value.st_uid, value.st_nlink)
    if (len(body) != before.st_size or hashlib.sha256(body).hexdigest() != digest
            or identity(before) != identity(after) or identity(before) != identity(current)):
        raise ValueError('public input changed')
    return body


def receive_frame(stream, deadline, limit):
    body = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(stream, selectors.EVENT_READ)
        while time.monotonic() < deadline and not termination_requested:
            if not selector.select(max(0, min(0.05, deadline - time.monotonic()))):
                continue
            block = os.read(stream.fileno(), min(4096, limit + 1 - len(body)))
            if not block:
                raise ValueError('review pipe closed before complete frame')
            body.extend(block)
            if len(body) > limit:
                raise ValueError('review frame exceeds bound')
            if b'\n' in body:
                if not body.endswith(b'\n') or body.count(b'\n') != 1:
                    raise ValueError('multiple or malformed review frames')
                return closed_json(body[:-1])
    raise ValueError('review pipe deadline elapsed')


def write_new(path, body):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())


def run(arguments):
    signal.signal(signal.SIGTERM, request_termination)
    root = Path(arguments.output_directory)
    root.mkdir(mode=0o700, exist_ok=False)
    policy_bytes = public_file(Path(arguments.policy), arguments.policy_sha256, 32768)
    auth_bytes = public_file(Path(arguments.authorization), arguments.authorization_sha256, 65536)
    authorization = closed_json(auth_bytes)
    if set(authorization) != {'version', 'checkpoint', 'requestSha256', 'snapshotSha256', 'snapshot',
            'policySha256', 'reviewerSeedFile', 'reviewerSeedCustody'}:
        raise ValueError('independent authorization closed schema differs')
    snapshot_body = json.dumps(authorization['snapshot'], sort_keys=True, separators=(',', ':')).encode() + b'\n'
    if (type(authorization['version']) is not int or authorization['version'] != 1
            or authorization['checkpoint'] != 'external-issuer-cold-recovery-ready'
            or authorization['snapshotSha256'] != hashlib.sha256(snapshot_body).hexdigest()
            or authorization['policySha256'] != arguments.policy_sha256
            or authorization['reviewerSeedFile'] != arguments.seed):
        raise ValueError('independent authorization commitments differ')
    seed = seed_metadata(Path(arguments.seed))
    if seed != authorization['reviewerSeedCustody']:
        raise ValueError('fresh independently authorized seed metadata differs')
    public_file(Path(arguments.authority), arguments.authority_sha256, 128 * 1024 * 1024, private=False)
    policy = ordered(closed_json(policy_bytes), POLICY_FIELDS)
    if (json.dumps(policy, ensure_ascii=False, separators=(',', ':')).encode() != policy_bytes
            or type(policy['version']) is not int or policy['version'] != 1
            or not 1 <= wiretime(policy['maximum_review_seconds']) <= 30
            or authorization['snapshot']['clockRecoveryPolicy'] != policy
            or policy['reviewer_key_id'] == authorization['snapshot']['issuerSigningKeyId']):
        raise ValueError('independent policy is not source canonical, distinct or finite')
    ready = {'version': 1, 'category': 'ready', 'authorizationSha256': arguments.authorization_sha256}
    sys.stdout.buffer.write(json.dumps(ready, separators=(',', ':')).encode() + b'\n')
    sys.stdout.buffer.flush()
    idle_deadline = time.monotonic() + arguments.idle_seconds
    request = receive_frame(sys.stdin.buffer, idle_deadline, 49152)
    received = time.monotonic()
    if set(request) != {'version', 'planBase64', 'planSha256', 'deadlineMonotonicNs', 'refusalFile', 'refusalSha256'} or type(request['version']) is not int or request['version'] != 1:
        raise ValueError('plan request closed schema differs')
    plan_bytes = base64.b64decode(request['planBase64'], validate=True)
    deadline_ns = request['deadlineMonotonicNs']
    if (len(plan_bytes) > 32768 or hashlib.sha256(plan_bytes).hexdigest() != request['planSha256']
            or not isinstance(deadline_ns, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', deadline_ns)):
        raise ValueError('plan frame commitment or deadline differs')
    deadline = min(int(deadline_ns) / 1e9, received + wiretime(policy['maximum_review_seconds']))
    if time.monotonic() >= deadline:
        raise ValueError('actual review deadline elapsed before signing')
    expected_refusal = Path(authorization['snapshot']['flowDirectory']) / 'actual-issuer-cold-unreviewed.json'
    if request['refusalFile'] != str(expected_refusal):
        raise ValueError('cold-refusal coordinate differs from authorized current flow')
    refusal = closed_json(public_file(expected_refusal, request['refusalSha256'], 65536))
    retained_refusal_predicates(refusal, authorization['snapshot'])
    review_predicates(plan_bytes, policy_bytes, authorization)
    write_new(root / 'plan.json', plan_bytes)
    argv = [arguments.authority, 'sign-clock-resolution', '--policy', arguments.policy,
        '--plan', str(root / 'plan.json'), '--reviewer-seed', arguments.seed, '--output', str(root / 'review.json')]
    work_deadline = sign_clock_plan(argv, root, deadline)
    if seed_metadata(Path(arguments.seed)) != seed:
        raise ValueError('seed custody changed during opaque signing')
    public_file(Path(arguments.policy), arguments.policy_sha256, 32768)
    public_file(Path(arguments.authorization), arguments.authorization_sha256, 65536)
    public_file(Path(arguments.authority), arguments.authority_sha256, 128 * 1024 * 1024, private=False)
    path = root / 'review.json'
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or value.st_size > 32768 or value.st_uid != os.getuid() or stat.S_IMODE(value.st_mode) != 0o600 or value.st_nlink != 1:
        raise ValueError('source signed review custody differs')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        opened = os.fstat(source.fileno())
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1
                or opened.st_size > 32768 or (opened.st_dev, opened.st_ino) != (value.st_dev, value.st_ino)):
            raise ValueError('source signed review opened custody differs')
        body = source.read(32769)
        final = os.fstat(source.fileno())
    if (len(body) != opened.st_size or final.st_mtime_ns != opened.st_mtime_ns
            or (path.lstat().st_dev, path.lstat().st_ino) != (opened.st_dev, opened.st_ino)):
        raise ValueError('source signed review changed')
    review = closed_json(body)
    expected = (b'{"version":1,"plan":' + plan_bytes + b',"plan_digest":'
        + json.dumps(hashlib.sha256(plan_bytes).hexdigest()).encode()
        + b',"reviewer_key_id":' + json.dumps(policy['reviewer_key_id'], ensure_ascii=False).encode()
        + b',"signature":' + json.dumps(review.get('signature')).encode() + b'}')
    if body != expected or termination_requested or time.monotonic() >= work_deadline:
        raise ValueError('source review is noncanonical, changed or expired')
    result = {'version': 1, 'category': 'signed', 'planSha256': request['planSha256'],
        'reviewBase64': base64.b64encode(body).decode()}
    sys.stdout.buffer.write(json.dumps(result, separators=(',', ':')).encode() + b'\n')
    sys.stdout.buffer.flush()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ('authorization', 'authorization-sha256', 'policy', 'policy-sha256',
            'authority', 'authority-sha256', 'seed', 'output-directory'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--idle-seconds', required=True, type=int)
    selected = parser.parse_args()
    if not 1 <= selected.idle_seconds <= 600:
        raise ValueError('reviewer finite idle bound differs')
    try:
        run(selected)
    except (OSError, ValueError, KeyError, TypeError):
        # Arbitrary CLI errors and public coordinates remain in private files.
        sys.exit(1)
