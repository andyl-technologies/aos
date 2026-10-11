"""Arm one independently authorized host reviewer before creating a cold plan.

Readiness approval is a separate current observation checkpoint. The reviewer is
ready before the source inspect and handles exactly one finite request through
owned pipes. This module cannot create authorization or read reviewer seed bytes.
"""

import base64
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time


_CLOCK_REVIEW_CLEANUP_SECONDS = 3


def _stop_clock_review_group(child, process, deadline):
    """Signal only the isolated owned group; missing waits remain unknown."""
    outcome = {'groupSignalSent': False, 'groupKillSent': False, 'reviewerWaitObserved': False,
        'reviewerExitCode': child.returncode, 'cleanupInsideCutoff': False}
    if child.returncode is None:
        owner = Path('/proc') / str(child.pid)
        fields = (owner / 'stat').read_text().rpartition(') ')[2].split()
        if process is None:
            # Before READY there is no request or signer. The direct unreaped
            # child still supplies an unambiguous creator-owned PID identity.
            process = {'pid': child.pid, 'startTicks': fields[19], 'uid': os.getuid()}
        if (process['pid'] != child.pid or fields[19] != process['startTicks']
                or owner.stat().st_uid != process['uid'] or int(fields[2]) != child.pid):
            raise ValueError('reviewer cleanup group ownership is unobservable')
        # This is still our unreaped group leader. Its PID/group cannot be
        # recycled before the owned wait, and the signer inherits this group.
        os.killpg(child.pid, signal.SIGTERM)
        outcome['groupSignalSent'] = True
        try:
            child.wait(timeout=max(0, min(2, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            outcome['groupKillSent'] = True
            try:
                child.wait(timeout=max(0, min(1, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                pass
    outcome['reviewerWaitObserved'] = child.returncode is not None
    outcome['reviewerExitCode'] = child.returncode
    outcome['cleanupInsideCutoff'] = time.monotonic() < deadline
    return outcome


def _clock_signer_wait_record(path, reviewer_pid):
    """Project a bounded private signer wait without inventing a missing drain."""
    result = {'signerWaitObserved': False, 'signerExitCode': None, 'signerDrain': 'unknown'}
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return result
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or before.st_size > 16384):
            return result
        body = source.read(16385)
        after = os.fstat(source.fileno())
    current = path.lstat()
    if (len(body) != before.st_size or any(getattr(before, name) != getattr(other, name)
            for other in (after, current)
            for name in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_mode', 'st_uid', 'st_nlink'))):
        return result
    value = _closed_review_json(body)
    owned = value.get('ownedProcess')
    if (type(value.get('version')) is int and value['version'] == 1 and isinstance(owned, dict)
            and owned.get('reviewerPid') == reviewer_pid and owned.get('processGroup') == reviewer_pid
            and owned.get('uid') == os.getuid() and type(owned.get('pid')) is int
            and isinstance(owned.get('startTicks'), str) and value.get('waitObserved') is True
            and type(value.get('exitCode')) is int):
        result = {'signerWaitObserved': True, 'signerExitCode': value['exitCode'],
            'signerDrain': 'direct_child_wait_observed', 'signerPid': owned['pid'],
            'signerStartTicks': owned['startTicks'], 'signerReceiptSha256': hashlib.sha256(body).hexdigest()}
    return result


def _stop_clock_signer_after_reviewer(path, reviewer_pid, deadline):
    """Stop a recorded orphan by pidfd; this parent cannot invent its exit wait."""
    result = {'orphanSignerSignalSent': False, 'orphanSignerKillSent': False,
        'orphanSignerTerminalState': 'unknown'}
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return result
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or before.st_size > 4096):
            return result
        body = source.read(4097)
        after = os.fstat(source.fileno())
    current = path.lstat()
    if (len(body) != before.st_size or any(getattr(before, name) != getattr(other, name)
            for other in (after, current)
            for name in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_mode', 'st_uid', 'st_nlink'))):
        return result
    owned = _closed_review_json(body)
    if (set(owned) != {'pid', 'startTicks', 'uid', 'processGroup', 'reviewerPid'}
            or type(owned['pid']) is not int or owned['pid'] <= 0
            or owned['reviewerPid'] != reviewer_pid or owned['processGroup'] != reviewer_pid
            or owned['uid'] != os.getuid() or not isinstance(owned['startTicks'], str)):
        return result
    owner = Path('/proc') / str(owned['pid'])
    def observed_state():
        try:
            fields = (owner / 'stat').read_text().rpartition(') ')[2].split()
            uid = owner.stat().st_uid
        except FileNotFoundError:
            return 'absent'
        except PermissionError:
            return 'unobservable_unknown'
        if fields[19] != owned['startTicks'] or uid != owned['uid'] or int(fields[2]) != reviewer_pid:
            return 'identity_changed_unknown'
        return 'zombie' if fields[0] == 'Z' else 'live'
    state = observed_state()
    if state != 'live':
        result['orphanSignerTerminalState'] = state
        return result
    try:
        pidfd = os.pidfd_open(owned['pid'])
    except ProcessLookupError:
        result['orphanSignerTerminalState'] = 'absent'
        return result
    except PermissionError:
        return result
    try:
        if observed_state() != 'live':
            result['orphanSignerTerminalState'] = observed_state()
            return result
        signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        result['orphanSignerSignalSent'] = True
        grace = min(deadline, time.monotonic() + 0.2)
        while time.monotonic() < grace and observed_state() == 'live':
            time.sleep(0.01)
        if observed_state() == 'live':
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            result['orphanSignerKillSent'] = True
            while time.monotonic() < deadline and observed_state() == 'live':
                time.sleep(0.01)
        result['orphanSignerTerminalState'] = observed_state()
    except ProcessLookupError:
        result['orphanSignerTerminalState'] = observed_state()
    except PermissionError:
        result['orphanSignerTerminalState'] = 'unobservable_unknown'
    finally:
        os.close(pidfd)
    return result


def _retain_clock_review_cleanup(child, error, outcome, primary_failure):
    """Attempt every final retention step while preserving an active failure."""
    failures = []
    for stream in (child.stdin, child.stdout):
        if stream is not None:
            try:
                stream.close()
            except Exception as failure:
                failures.append(type(failure).__name__)
    for operation in (error.flush, lambda: os.fsync(error.fileno())):
        try:
            operation()
        except Exception as failure:
            failures.append(type(failure).__name__)
    try:
        outcome = {**outcome, 'stderrBytes': os.fstat(error.fileno()).st_size}
    except Exception as failure:
        failures.append(type(failure).__name__)
        outcome = {**outcome, 'stderrBytes': None}
    outcome = {**outcome, 'retentionFailureCategories': list(failures)}
    try:
        retain_direct_flow('issuer-clock-reviewer-outcome.json', outcome)
    except Exception as failure:
        failures.append(type(failure).__name__)
    if failures:
        note = 'owned reviewer cleanup retention failed: ' + ','.join(failures)
        if primary_failure is not None:
            # Exception classes are safe fixed dispositions; arbitrary error
            # text and private coordinates are not added to the primary trace.
            primary_failure.add_note(note)
        else:
            raise RuntimeError(note) from None


@contextmanager
def _clock_review_error_stream(descriptor):
    """Close the private error stream without replacing a primary exception."""
    error = os.fdopen(descriptor, 'wb')
    try:
        yield error
    finally:
        primary_failure = sys.exc_info()[1]
        try:
            error.close()
        except Exception as failure:
            note = 'owned reviewer error-stream close failed: ' + type(failure).__name__
            if primary_failure is not None:
                primary_failure.add_note(note)
            else:
                raise RuntimeError(note) from None


def _capture_direct_clock_ready(native, worker, tools, helper, authority):
    bootstrap = authority['exported']['bootstrap']
    head = exchange_direct_issuer(native, worker, tools, helper, bootstrap,
        {'kind': 'current'}, 'cold-ready-current')
    snapshot = json.loads(direct_guest_python(native, tools['python'], """
        import hashlib, os, sqlite3, stat
        from pathlib import Path

        root = Path('/var/lib/hybrid-authority')
        process = selected['process']
        owner = Path('/proc') / str(process['pid'])
        def pin():
            fields = (owner / 'stat').read_text().rpartition(') ')[2].split()
            expected = [selected['authority'], 'serve', '--configuration', str(root / 'configuration.json')]
            if (fields[0] == 'Z' or fields[19] != process['startTicks']
                    or owner.stat().st_uid != os.getuid()
                    or (owner / 'cmdline').read_bytes().split(b'\\x00')[:-1] != [os.fsencode(value) for value in expected]):
                raise ValueError('actual issuer ready owner differs')
            with (owner / 'exe').open('rb') as source:
                if hashlib.file_digest(source, 'sha256').hexdigest() != process['executableSha256']:
                    raise ValueError('actual issuer ready executable differs')
        def read_public(name, limit):
            descriptor = os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, 'rb') as source:
                value = os.fstat(source.fileno())
                if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid()
                        or stat.S_IMODE(value.st_mode) != 0o600 or value.st_nlink != 1 or value.st_size > limit):
                    raise ValueError('actual ready public custody differs')
                body = source.read(limit + 1)
                final = os.fstat(source.fileno())
            current = (root / name).lstat()
            if (len(body) != value.st_size or any(getattr(value, field) != getattr(other, field)
                    for other in (final, current)
                    for field in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_mode', 'st_uid', 'st_nlink'))):
                raise ValueError('actual ready public file changed')
            return body
        pin()
        configuration_bytes = read_public('configuration.json', 1048576)
        configuration = json.loads(configuration_bytes)
        verifier = read_public('issuer-public-key.hex', 64).decode()
        if (configuration['format_version'] != 2 or configuration['clock_recovery'] != selected['policy']
                or verifier != selected['publicKey']):
            raise ValueError('fresh format2 public policy or verifier differs')
        keys = {}
        for name in ('signing-seed.key', 'publisher.key', 'renewal.key'):
            value = (root / name).lstat()
            if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid()
                    or stat.S_IMODE(value.st_mode) != 0o600 or value.st_nlink != 1 or not 0 < value.st_size <= 65536):
                raise ValueError('actual ready secret custody differs')
            keys[name] = {'device': str(value.st_dev), 'inode': str(value.st_ino),
                'bytes': value.st_size, 'mtimeNs': str(value.st_mtime_ns),
                'owner': value.st_uid, 'mode': stat.S_IMODE(value.st_mode), 'links': value.st_nlink}
        journal = root / 'journal' / 'journal.sqlite'
        value, parent = journal.lstat(), journal.parent.lstat()
        if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid()
                or stat.S_IMODE(value.st_mode) != 0o600 or value.st_nlink != 1
                or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700):
            raise ValueError('actual ready journal custody differs')
        connection = sqlite3.connect('file:' + str(journal) + '?mode=ro', uri=True, timeout=2)
        try:
            connection.execute('BEGIN')
            if (connection.execute('PRAGMA application_id').fetchone()[0] != 0x414f534a
                    or connection.execute('PRAGMA user_version').fetchone()[0] != 3):
                raise ValueError('actual ready journal format differs')
            length = connection.execute('SELECT length(marker) FROM installation_marker').fetchone()[0]
            journal_length = connection.execute('SELECT length(journal) FROM authority_state').fetchone()[0]
            if length > 4096 or journal_length > 16384:
                raise ValueError('actual ready head exceeds source bound')
            installation = json.loads(connection.execute('SELECT marker FROM installation_marker').fetchone()[0])
            state = json.loads(connection.execute('SELECT journal FROM authority_state').fetchone()[0])
            if {'installation': installation, 'journal': state} != selected['head']:
                raise ValueError('actual readonly head differs from signed current')
            floor, session, ceiling = connection.execute('SELECT floor,session,ceiling FROM authority_clock').fetchone()
            if not isinstance(session, str) or len(session) != 64:
                raise ValueError('actual ready unresolved session absent')
            if any(connection.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0] != 0
                    for table in ('clock_resolutions', 'clock_resolution_consumptions')):
                raise ValueError('ready resource is not an unused resolution history')
            sizes = connection.execute('SELECT length(publication),length(receipt),length(operation) FROM publication_receipts LIMIT 1025').fetchall()
            if len(sizes) > 1024 or sum(sum(row) for row in sizes) > 16777216:
                raise ValueError('actual ready history exceeds retained bound')
            rows = connection.execute('SELECT generation,publication,receipt,operation FROM publication_receipts ORDER BY generation LIMIT 1025').fetchall()
            projection = [[row[0], *[hashlib.sha256(value).hexdigest() for value in row[1:]]] for row in rows]
        finally:
            connection.close()
        for original, path in ((value, journal), (parent, journal.parent)):
            current = path.lstat()
            if any(getattr(original, field) != getattr(current, field)
                    for field in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink')):
                raise ValueError('actual ready journal resource changed')
        pin()
        print(json.dumps({'version': 1, 'process': process, 'signedHead': selected['head'],
            'issuerSigningKeyId': configuration['signing_key_id'], 'issuerPublicKey': verifier,
            'clockRecoveryPolicy': selected['policy'],
            'configurationSha256': hashlib.sha256(configuration_bytes).hexdigest(),
            'publicKeySha256': hashlib.sha256(verifier.encode()).hexdigest(),
            'journalFile': {'device': str(value.st_dev), 'inode': str(value.st_ino),
                'parent_device': str(parent.st_dev), 'parent_inode': str(parent.st_ino)},
            'clockFloor': floor, 'clockCeiling': ceiling,
            'clockSessionSha256': hashlib.sha256(session.encode()).hexdigest(),
            'historySha256': hashlib.sha256(json.dumps(projection, separators=(',', ':')).encode()).hexdigest(),
            'historyRows': len(rows), 'secretCustody': keys,
            'authorityExecutableSha256': process['executableSha256'],
            'scope': 'actual ready public head/resource; independent recovery authorization pending'}))
    """, {'authority': tools['authority'], 'process': authority['issuerProcess'],
        'head': head['reply']['current'], 'publicKey': bootstrap['issuer_public_key'],
        'policy': authority['clockRecoveryPolicy']}, timeout=10))
    snapshot['flowDirectory'] = str(Path('external-direct-flow').resolve())
    return snapshot


def _clock_review_file(path, expected, limit, private=True):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        value = os.fstat(source.fileno())
        if (not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or value.st_size > limit
                or private and (value.st_uid != os.getuid() or stat.S_IMODE(value.st_mode) != 0o600)):
            raise ValueError('independent reviewer public input custody differs')
        body = source.read(limit + 1)
        final = os.fstat(source.fileno())
    current = path.lstat()
    if (len(body) != value.st_size or hashlib.sha256(body).hexdigest() != expected
            or any(getattr(value, name) != getattr(other, name) for other in (final, current)
                for name in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_mode', 'st_uid', 'st_nlink'))):
        raise ValueError('independent reviewer input changed')
    return body


def _clock_review_frame(stream, deadline):
    body = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(stream, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if not selector.select(max(0, deadline - time.monotonic())):
                break
            block = os.read(stream.fileno(), min(4096, 65537 - len(body)))
            if not block:
                raise ValueError('independent reviewer closed before acknowledgment')
            body.extend(block)
            if len(body) > 65536:
                raise ValueError('independent reviewer reply overflow')
            if b'\n' in body:
                if not body.endswith(b'\n') or body.count(b'\n') != 1:
                    raise ValueError('independent reviewer sent multiple frames')
                return _closed_review_json(body[:-1])
    raise ValueError('independent reviewer deadline elapsed')


@contextmanager
def arm_direct_clock_reviewer(tools, descriptor, snapshot, snapshot_sha, request_sha, idle_seconds):
    """Pin and ready the independent host child before any source inspect."""
    fields = {'version', 'pythonExecutable', 'pythonSha256', 'reviewerScript', 'reviewerScriptSha256',
        'authorityExecutable', 'authoritySha256', 'policyFile', 'policySha256',
        'authorizationFile', 'authorizationSha256', 'reviewerSeedFile'}
    if not isinstance(descriptor, dict) or set(descriptor) != fields or type(descriptor['version']) is not int or descriptor['version'] != 1:
        raise ValueError('independent reviewer descriptor closed schema differs')
    if (descriptor['authorityExecutable'] != tools['authority']
            or descriptor['authoritySha256'] != snapshot['authorityExecutableSha256']
            or descriptor['pythonExecutable'] != str(Path(tools['python']).resolve(strict=True))
            or descriptor['reviewerScript'] != tools['issuerClockReviewer']):
        raise ValueError('independent reviewer is not the actual installed source tuple')
    for field, limit in (('python', 128 * 1024 * 1024), ('authority', 128 * 1024 * 1024)):
        _clock_review_file(Path(descriptor[field + 'Executable']), descriptor[field + 'Sha256'], limit, private=False)
    _clock_review_file(Path(descriptor['reviewerScript']), descriptor['reviewerScriptSha256'], 65536, private=False)
    policy_bytes = _clock_review_file(Path(descriptor['policyFile']), descriptor['policySha256'], 32768)
    authorization = _closed_review_json(_clock_review_file(Path(descriptor['authorizationFile']), descriptor['authorizationSha256'], 65536))
    if (authorization['checkpoint'] != 'external-issuer-cold-recovery-ready'
            or authorization['requestSha256'] != request_sha or authorization['snapshotSha256'] != snapshot_sha
            or authorization['snapshot'] != snapshot or authorization['policySha256'] != descriptor['policySha256']
            or authorization['reviewerSeedFile'] != descriptor['reviewerSeedFile']
            or _closed_review_json(policy_bytes) != snapshot['clockRecoveryPolicy']):
        raise ValueError('independent authorization does not bind the actual current ready snapshot')
    root = Path('independent-direct-review/cold-reviewer-runtime')
    root.mkdir(mode=0o700, exist_ok=False)
    output_root = root.resolve() / 'operator'
    argv = [descriptor['pythonExecutable'], '-B', descriptor['reviewerScript'],
        '--authorization', descriptor['authorizationFile'], '--authorization-sha256', descriptor['authorizationSha256'],
        '--policy', descriptor['policyFile'], '--policy-sha256', descriptor['policySha256'],
        '--authority', descriptor['authorityExecutable'], '--authority-sha256', descriptor['authoritySha256'],
        '--seed', descriptor['reviewerSeedFile'], '--output-directory', str(output_root), '--idle-seconds', str(idle_seconds)]
    descriptor_fd = os.open(root / 'stderr.private', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with _clock_review_error_stream(descriptor_fd) as error:
        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=error, start_new_session=True)
        used, process = False, None
        cleanup_deadline = min(tools['fleetCutoffMonotonic'], time.monotonic() + idle_seconds + 5)
        try:
            owner = Path('/proc') / str(child.pid)
            actual_argv = (owner / 'cmdline').read_bytes().split(b'\x00')[:-1]
            with (owner / 'exe').open('rb') as executable:
                executable_sha = hashlib.file_digest(executable, 'sha256').hexdigest()
            if (owner.stat().st_uid != os.getuid() or actual_argv != [os.fsencode(value) for value in argv]
                    or executable_sha != descriptor['pythonSha256']):
                raise ValueError('independent reviewer actual process ownership differs')
            process = {'pid': child.pid, 'startTicks': (owner / 'stat').read_text().rpartition(') ')[2].split()[19],
                'uid': owner.stat().st_uid, 'pidNamespace': os.readlink(owner / 'ns/pid'),
                'authorizationSha256': descriptor['authorizationSha256'], 'scriptSha256': descriptor['reviewerScriptSha256'],
                'pythonExecutableSha256': executable_sha}
            retain_direct_flow('issuer-clock-reviewer-process.json', process)
            ready = _clock_review_frame(child.stdout, time.monotonic() + 5)
            if ready != {'version': 1, 'category': 'ready', 'authorizationSha256': descriptor['authorizationSha256']} or child.poll() is not None:
                raise ValueError('independent reviewer has no positive readiness')
            retain_direct_flow('issuer-clock-reviewer-ready.json', ready)
            def callback(plan_bytes, actual_policy, deadline):
                nonlocal used, cleanup_deadline
                deadline = min(deadline, tools['fleetCutoffMonotonic'])
                cleanup_deadline = deadline
                work_deadline = deadline - _CLOCK_REVIEW_CLEANUP_SECONDS
                if used or actual_policy != policy_bytes or time.monotonic() >= work_deadline or child.poll() is not None:
                    raise ValueError('independent reviewer unavailable, changed or already used')
                used = True
                request = {'version': 1, 'planBase64': base64.b64encode(plan_bytes).decode(),
                    'planSha256': hashlib.sha256(plan_bytes).hexdigest(), 'deadlineMonotonicNs': str(int(deadline * 1e9))}
                refusal_path = Path(snapshot['flowDirectory']) / 'actual-issuer-cold-unreviewed.json'
                metadata = refusal_path.lstat()
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 65536:
                    raise ValueError('actual retained cold-refusal record missing or oversized')
                descriptor_fd = os.open(refusal_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor_fd, 'rb') as original:
                    refusal_body = original.read(65537)
                request['refusalFile'] = str(refusal_path)
                request['refusalSha256'] = hashlib.sha256(refusal_body).hexdigest()
                frame = json.dumps(request, separators=(',', ':')).encode() + b'\n'
                if len(frame) > 49152:
                    raise ValueError('independent review request exceeds pipe bound')
                # A pipe-sized write is not assumed. Nonblocking writes obey the
                # same actual plan deadline rather than waiting for a dead child.
                os.set_blocking(child.stdin.fileno(), False)
                sent = 0
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdin, selectors.EVENT_WRITE)
                    while sent < len(frame) and time.monotonic() < work_deadline:
                        if not selector.select(max(0, work_deadline - time.monotonic())):
                            break
                        try:
                            sent += os.write(child.stdin.fileno(), frame[sent:])
                        except BlockingIOError:
                            pass
                if sent != len(frame):
                    raise ValueError('independent review request deadline elapsed')
                child.stdin.close()
                reply = _clock_review_frame(child.stdout, work_deadline)
                if set(reply) != {'version', 'category', 'planSha256', 'reviewBase64'} or reply['version'] != 1 or reply['category'] != 'signed' or reply['planSha256'] != request['planSha256']:
                    raise ValueError('independent reviewer has no exact one-request result')
                body = base64.b64decode(reply['reviewBase64'], validate=True)
                if len(body) > 32768:
                    raise ValueError('independent signed review overflow')
                child.wait(timeout=max(0, work_deadline - time.monotonic()))
                if child.returncode != 0 or time.monotonic() >= work_deadline:
                    raise ValueError('independent reviewer did not finish within actual plan window')
                return body
            yield callback
        finally:
            primary_failure = sys.exc_info()[1]
            try:
                cleanup = _stop_clock_review_group(child, process, cleanup_deadline)
            except (OSError, ValueError, IndexError):
                cleanup = {'groupSignalSent': False, 'groupKillSent': False,
                    'reviewerWaitObserved': False, 'reviewerExitCode': child.returncode,
                    'cleanupInsideCutoff': False, 'cleanupCategory': 'ownership_or_wait_unobservable'}
            try:
                signer = _clock_signer_wait_record(output_root / 'sign-result.json', child.pid)
            except (OSError, ValueError, KeyError, TypeError):
                signer = {'signerWaitObserved': False, 'signerExitCode': None, 'signerDrain': 'unknown'}
            orphan = {'orphanSignerSignalSent': False, 'orphanSignerKillSent': False,
                'orphanSignerTerminalState': 'not_required'}
            if not signer['signerWaitObserved']:
                try:
                    orphan = _stop_clock_signer_after_reviewer(output_root / 'sign-process.json', child.pid, cleanup_deadline)
                except (OSError, ValueError, KeyError, TypeError, IndexError):
                    orphan['orphanSignerTerminalState'] = 'unobservable_unknown'
            outcome = {'version': 1, 'exitCode': child.returncode,
                'requestUsed': used,
                **cleanup, **signer, **orphan,
                'scope': 'owned reviewer group and direct signer wait only; no issuer retry or rollback'}
            _retain_clock_review_cleanup(child, error, outcome, primary_failure)
            if primary_failure is None and (not cleanup['reviewerWaitObserved'] or used and not signer['signerWaitObserved']):
                raise RuntimeError('owned reviewer or signer cleanup remains unknown')


def run_reviewed_direct_issuer_cold_recovery(native, worker, tools, helper, authority):
    """Authorize a current finite reviewer, then run the frozen recovery helper."""
    cutoff = tools['fleetCutoffMonotonic']
    if type(cutoff) not in (int, float) or not math.isfinite(cutoff) or cutoff <= time.monotonic():
        raise ValueError('original full-fleet monotonic budget is absent or exhausted')
    snapshot = _capture_direct_clock_ready(native, worker, tools, helper, authority)
    snapshot_sha = retain_direct_flow('issuer-cold-ready-snapshot.json', snapshot)
    review_seconds = min(900, cutoff - time.monotonic())
    if review_seconds <= 0:
        raise ValueError('original full-fleet budget ended before readiness review')
    reviewed = await_direct_review('external-issuer-cold-recovery-ready',
        {'issuerColdReady': snapshot_sha}, {'clockRecoveryReviewer'}, timeout=review_seconds)
    maximum_wait = int(authority['exported']['bootstrap']['timing_profile']['maximum_lifetime'])
    total = int(authority['clockRecoveryPolicy']['clock_uncertainty']) + int(authority['clockRecoveryPolicy']['clock_commit_latency']) + 1
    maximum_wait += 2 * total + 1
    if not 0 < maximum_wait <= 545:
        raise ValueError('finite reviewer idle budget cannot cover installed lease bound')
    # Reserve the actual short plan interval within the existing fleet cutoff.
    # Readiness authorization never grants additional runtime to the invocation.
    idle_seconds = min(600, 45 + maximum_wait + 10)
    if idle_seconds + int(authority['clockRecoveryPolicy']['maximum_review_seconds']) >= cutoff - time.monotonic():
        raise ValueError('original fleet budget cannot cover this finite cold scenario')
    with arm_direct_clock_reviewer(tools, reviewed['selection']['clockRecoveryReviewer'], snapshot,
            snapshot_sha, reviewed['requestSha256'], idle_seconds) as callback:
        return run_direct_issuer_cold_recovery(native, worker, tools, helper, authority,
            authority['clockRecoveryPolicy'], callback, maximum_wait_seconds=maximum_wait)
