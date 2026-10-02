"""Collect the complete Managed business interval across actual process epochs.

Fixed proxy prefixes are retained independently from the scoped controllers.
Every original/received row must belong to exactly one stable epoch or an
explicit startup interval. Closed codecs, accepted contexts and physical proof
remain separate; no missing result is promoted to zero.
"""

import copy
import hashlib
import json
import os
import stat
from pathlib import Path
import re


MANAGED_WORKFLOW_PROXY_ROLES = ('nativeOutbound', 'workerReceived', 'workerOriginal', 'nativeReceived')
MANAGED_WORKFLOW_HEADER_ROLES = {
    'nativeOutbound': ('nativeHeaders', 'native-outbound'),
    'workerReceived': ('workerHeaders', 'worker-received'),
    'workerOriginal': ('workerOriginalHeaders', 'worker-original'),
    'nativeReceived': ('nativeReceivedHeaders', 'native-inbound'),
}
MANAGED_WORKFLOW_FILE_ROLES = tuple(MANAGED_WORKFLOW_PROXY_ROLES) + tuple(
    item[0] for item in MANAGED_WORKFLOW_HEADER_ROLES.values()) + ('nativeLog', 'workerLog')
MANAGED_WORKFLOW_MAX_EPOCHS = 16
MANAGED_WORKFLOW_REPORT_BYTES = 256 * 1024 * 1024
MANAGED_WORKFLOW_ROWS = 204704


def managed_workflow_require(condition, message):
    if not condition:
        raise ValueError(message)


def managed_workflow_encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def managed_workflow_bounded_encoded(value, maximum=None):
    """Bound the exact retained JSON bytes before collecting another aggregate."""
    maximum = MANAGED_WORKFLOW_REPORT_BYTES if maximum is None else maximum
    body = bytearray()
    encoder = json.JSONEncoder(ensure_ascii=False, separators=(',', ':'), allow_nan=False)
    for part in encoder.iterencode(value):
        encoded = part.encode()
        managed_workflow_require(len(body) + len(encoded) + 1 <= maximum,
                                 'Managed retained aggregate exceeds its exact JSON bound')
        body.extend(encoded)
    body.extend(b'\n')
    return bytes(body)


def retain_managed_workflow_conclusion(workflow, retain, name, producer_error=None):
    """Retain a bounded final gate without replacing a producer's failure."""
    conclusion = {'version': 1, 'assessment': workflow['assessment'],
        'producerFailureClass': type(producer_error).__name__ if producer_error else None,
        'captureFailureClass': workflow.get('captureFailureClass'),
        'scope': 'full raw corpus and epochs remain in the separate workflow receipt'}
    try:
        try:
            body = managed_workflow_bounded_encoded(conclusion)
        except ValueError:
            workflow['assessment'] = {'complete': False, 'nativeBulkBytes': None,
                'unresolved': [{'scope': 'global_capture', 'reason': 'assessment_report_overflow'}]}
            body = managed_workflow_bounded_encoded({**conclusion,
                'assessment': workflow['assessment']}, maximum=4096)
        return retain(name, body)
    except Exception as error:
        workflow['retentionFailureClass'] = type(error).__name__
        workflow['assessment'] = {'complete': False, 'nativeBulkBytes': None,
            'unresolved': [{'scope': 'global_capture', 'reason': 'conclusion_retention_failed'}]}
        if producer_error is None:
            raise
        # The sink may be unavailable; annotate the still-propagating original
        # with a bounded failure class instead of hiding it with the sink error.
        producer_error.add_note('Managed conclusion retention failed: ' + type(error).__name__)
        return None


def managed_workflow_rows(path, completion_parser, receipt=None):
    """Validate the real closed proxy records without a second full-log buffer."""
    rows = {}
    summary_bytes = 2
    raw_bytes = 0
    pathname_before = Path(path).lstat()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    digest = hashlib.sha256()
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        managed_workflow_require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and not before.st_mode & 0o077 and before.st_nlink == 1
            and (before.st_dev, before.st_ino) == (pathname_before.st_dev, pathname_before.st_ino)
            and before.st_size <= 512 * 1024 * 1024,
            'Managed retained proxy file lost private bounded custody')
        while line := stream.readline(48 * 1024 + 1):
            raw_bytes += len(line)
            digest.update(line)
            managed_workflow_require(len(line) <= 48 * 1024 and line.endswith(b'\n')
                and raw_bytes <= 512 * 1024 * 1024 and len(rows) < MANAGED_WORKFLOW_ROWS,
                'Managed whole-workflow proxy corpus is truncated or excessive')
            # Reuse the actual proxy framing validator one record at a time.
            values, _ = completion_parser(line.decode())
            managed_workflow_require(len(values) == 1, 'Managed proxy row is not one actual completion')
            row = values[0]
            identity = row['request_id']
            managed_workflow_require(identity not in rows, 'Managed proxy request ID is repeated')
            item = {'rowSha256': hashlib.sha256(line).hexdigest(),
                'originalRequestId': row.get('origin_request_id') or None,
                'transportCallId': row.get('transport_call_id') or None}
            item_bytes = len(managed_workflow_encoded({identity: item}))
            summary_bytes += item_bytes
            managed_workflow_require(item_bytes <= 1024
                and summary_bytes <= MANAGED_WORKFLOW_REPORT_BYTES,
                'Managed retained row summaries exceed their observation bound')
            rows[identity] = item
        after = os.fstat(stream.fileno())
        pathname_after = Path(path).lstat()
        managed_workflow_require((after.st_dev, after.st_ino)
            == (pathname_after.st_dev, pathname_after.st_ino) and all(getattr(before, field) == getattr(after, field) for field in
            ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')) and raw_bytes == before.st_size,
            'Managed retained proxy file changed during streaming')
    if receipt is not None:
        managed_workflow_require(receipt['file'] == str(path) and receipt['capturedBytes'] == raw_bytes
            and receipt['sha256'] == digest.hexdigest(), 'Managed retained proxy commitment changed')
    return rows


def join_managed_workflow_partition(root, epochs, startup):
    """Require exclusive byte ranges and exact membership in the full inventory."""
    assigned, starts, ends = {}, {}, {}
    for role in MANAGED_WORKFLOW_FILE_ROLES:
        receipt = root['rawWindowReceipts'][role]
        starts[role] = receipt['before']['byteSize']
        ends[role] = receipt['after']['byteSize']
        assigned[role] = {}
    intervals = sorted(epochs + startup, key=lambda item: item['sequence'])
    managed_workflow_require(0 < len(epochs) <= MANAGED_WORKFLOW_MAX_EPOCHS,
                             'Managed business epochs are missing or excessive')
    for interval in intervals:
        for role in MANAGED_WORKFLOW_FILE_ROLES:
            receipt = interval['rawWindowReceipts'][role]
            parent = root['rawWindowReceipts'][role]
            managed_workflow_require(all(receipt[side][field] == parent[side][field]
                for side in ('before', 'after') for field in ('path', 'device', 'inode')),
                'Managed epoch belongs to another retained proxy file')
            managed_workflow_require(receipt['before']['byteSize'] == starts[role]
                and receipt['after']['byteSize'] >= starts[role]
                and receipt['capturedBytes'] == receipt['after']['byteSize'] - starts[role],
                'Managed epoch has an omitted or overlapping proxy prefix')
            starts[role] = receipt['after']['byteSize']
            if role not in MANAGED_WORKFLOW_PROXY_ROLES:
                continue
            for identity, row in interval['rows'][role].items():
                managed_workflow_require(identity not in assigned[role],
                                         'Managed transport row belongs to multiple epochs')
                assigned[role][identity] = {**row, 'interval': interval['sequence'],
                    'scope': interval['scope']}
    managed_workflow_require(starts == ends, 'Managed complete root has an unassigned suffix')
    for role in MANAGED_WORKFLOW_PROXY_ROLES:
        expected = root['rows'][role]
        managed_workflow_require(set(expected) == set(assigned[role]) and all(
            expected[identity] == {key: value for key, value in row.items()
                if key not in {'interval', 'scope'}}
            for identity, row in assigned[role].items()),
            'Managed whole original/received membership was omitted or substituted')
    call_ids = {}
    for role in ('nativeOutbound', 'workerOriginal'):
        for identity, row in assigned[role].items():
            call = row['transportCallId']
            if call:
                managed_workflow_require(call not in call_ids,
                                         'Native transport call ID was reused across the corpus')
                call_ids[call] = role + ':' + identity
    return {'version': 1, 'complete': True, 'assigned': assigned,
        'transportCallOwners': call_ids,
        'inventorySha256': hashlib.sha256(managed_workflow_encoded(root['rows'])).hexdigest(),
        'scope': 'exact full transport membership only; no authority or zero inference'}


class ManagedWorkflowCapture:
    """Reuse the existing actual window callbacks and preserve every restart gap."""

    def __init__(self, native, worker, tools, prepared, processes, boundaries,
                 begin, finish, position, retain_window, parser, headers, retain):
        self.native, self.worker, self.tools = native, worker, tools
        self.prepared, self.boundaries = prepared, boundaries
        self.begin, self.finish = begin, finish
        self.position, self.retain_window = position, retain_window
        self.parser, self.headers, self.retain = parser, headers, retain
        self.epochs, self.startup, self.sequence = [], [], 0
        self.auxiliaryTransitions = []
        self.retainedSummaryBytes = 0
        self.failure = None
        self.root_before = None
        self.active = None
        self.last_end = None
        self.resume(processes)

    def resume(self, processes):
        managed_workflow_require(self.active is None, 'Managed epoch is already active')
        managed_workflow_require(len(self.epochs) < MANAGED_WORKFLOW_MAX_EPOCHS,
                                 'Managed epoch count exceeds its observation bound')
        label = 'managed-whole-' + str(len(self.epochs))
        token = copy.deepcopy(self.begin(self.native, self.worker, self.tools, self.prepared,
            processes, self.boundaries, label))
        if self.root_before is None:
            self.root_before = copy.deepcopy(token['positions'])
        else:
            receipts, rows = {}, {}
            for role in MANAGED_WORKFLOW_FILE_ROLES:
                machine = self.native if role.startswith('native') else self.worker
                before, after = self.last_end[role], token['positions'][role]
                path, receipt = self.retain_window(machine, self.tools['python'], before,
                    'managed-' + self.prepared['coordinates']['runId'] + '-startup-'
                    + str(self.sequence) + '-' + role + '.jsonl', after=after)
                receipts[role] = {'file': str(path), **receipt}
            rows = self.rows(receipts, 'startup-' + str(self.sequence))
            self.append_interval(self.startup, {'sequence': self.sequence, 'scope': 'startup',
                                 'rawWindowReceipts': receipts, 'rows': rows})
            self.sequence += 1
        self.active = token
        self.retain('managed-whole-epoch-begin-' + str(self.sequence) + '.json', token)

    def append_interval(self, destination, interval):
        encoded_bytes = len(managed_workflow_encoded(interval))
        managed_workflow_require(self.retainedSummaryBytes + encoded_bytes
            <= MANAGED_WORKFLOW_REPORT_BYTES, 'Managed epoch summaries exceed their aggregate bound')
        self.retainedSummaryBytes += encoded_bytes
        destination.append(interval)

    def rows(self, receipts, label):
        rows = {}
        summary_bytes = 2
        prefix = 'managed-' + self.prepared['coordinates']['runId'] + '-' + label
        for role in MANAGED_WORKFLOW_PROXY_ROLES:
            rows[role] = managed_workflow_rows(receipts[role]['file'],
                lambda text, role=role: self.parser(text, role), receipts[role])
            header_role, name = MANAGED_WORKFLOW_HEADER_ROLES[role]
            controls = self.headers(Path(receipts[header_role]['file']), name, prefix)
            managed_workflow_require(set(controls) == set(rows[role]),
                                     'Managed complete headers and request rows differ')
            for identity, row in rows[role].items():
                header = controls[identity]
                managed_workflow_require(row['originalRequestId'] == header['originalRequestId'],
                                         'Managed received original correlation changed')
                row['transportCallId'] = header['transportCallId']
                compact = {field: ({'sha256': value['sha256'], 'byteSize': value['byteSize']}
                    if value else None) for field, value in header['files'].items()}
                row['compactSha256'] = hashlib.sha256(managed_workflow_encoded(compact)).hexdigest()
                item_bytes = len(managed_workflow_encoded({identity: row}))
                summary_bytes += item_bytes
                managed_workflow_require(item_bytes <= 1024
                    and summary_bytes <= MANAGED_WORKFLOW_REPORT_BYTES,
                    'Managed complete role summaries exceed their observation bound')
        return rows

    def close(self, processes):
        managed_workflow_require(self.active is not None, 'Managed epoch has no live original')
        token = self.active
        try:
            window = self.finish(self.native, self.worker, self.tools, self.prepared,
                processes, self.boundaries, token, token['label'])
        except Exception as error:
            # A body/authentication refusal must not discard its real raw rows.
            # The root membership stays visible and the final result incomplete.
            receipts = {}
            for role, before in token['positions'].items():
                machine = self.native if role.startswith('native') else self.worker
                path, receipt = self.retain_window(machine, self.tools['python'], before,
                    'managed-' + self.prepared['coordinates']['runId'] + '-incomplete-'
                    + str(self.sequence) + '-' + role + '.jsonl')
                receipts[role] = {'file': str(path), **receipt}
            window = {'rawWindowReceipts': receipts, 'failureClass': type(error).__name__,
                      'nativeBulkBytes': None, 'beforeProcesses': token['beforeProcesses']}
            self.failure = type(error).__name__
        rows = self.rows(window['rawWindowReceipts'], 'epoch-' + str(self.sequence))
        epoch = {'sequence': self.sequence, 'scope': 'business', 'window': window,
                 'rawWindowReceipts': window['rawWindowReceipts'], 'rows': rows}
        # Raw Worker text is already retained by the fixed file receipt. Avoid
        # a second full log in the bounded aggregate representation.
        epoch['window'] = {**window, 'workerLogText': None}
        self.append_interval(self.epochs, epoch)
        self.sequence += 1
        self.last_end = {role: copy.deepcopy(window['rawWindowReceipts'][role]['after'])
                         for role in MANAGED_WORKFLOW_FILE_ROLES}
        self.active = None
        return epoch

    def auxiliary_transition(self, event, facts):
        managed_workflow_require(event in {'B-started', 'before-B-stop'}
            and self.active is None and isinstance(facts, dict)
            and isinstance(facts.get('process'), dict), 'Managed auxiliary transition has no actual pin')
        self.append_interval(self.auxiliaryTransitions, {'event': event, 'facts': facts})

    def complete(self, processes):
        final_epoch_live = self.active is not None
        if not final_epoch_live:
            self.failure = self.failure or 'MissingLiveFinalEpoch'
        if self.active is not None:
            try:
                self.close(processes)
            except Exception as error:
                self.failure = type(error).__name__
        receipts, rows = {}, {}
        # A failed producer may stop between stable epochs. Retain the actual
        # final proxy prefixes as well; an unassigned suffix remains incomplete.
        end = self.last_end if self.failure is None and self.active is None else None
        if end is None or self.active is None and not self.epochs:
            end = {}
            for role in MANAGED_WORKFLOW_FILE_ROLES:
                machine = self.native if role.startswith('native') else self.worker
                end[role] = self.position(machine, self.tools, self.root_before[role]['path'])
        for role in MANAGED_WORKFLOW_FILE_ROLES:
            machine = self.native if role.startswith('native') else self.worker
            path, receipt = self.retain_window(machine, self.tools['python'], self.root_before[role],
                'managed-' + self.prepared['coordinates']['runId'] + '-complete-' + role + '.jsonl',
                after=end[role])
            receipts[role] = {'file': str(path), **receipt}
        root = {'rawWindowReceipts': receipts, 'rows': None}
        try:
            root['rows'] = self.rows(receipts, 'complete')
            coverage = join_managed_workflow_partition(root, self.epochs, self.startup)
        except Exception as error:
            self.failure = type(error).__name__
            coverage = {'version': 1, 'complete': False, 'failureClass': self.failure}
        result = {'version': 1, 'root': root, 'epochs': self.epochs,
                  'startup': self.startup, 'auxiliaryTransitions': self.auxiliaryTransitions,
                  'coverage': coverage, 'failureClass': self.failure, 'nativeBulkBytes': None}
        try:
            final = managed_workflow_bounded_encoded(result)
        except ValueError:
            result = {'version': 1, 'coverage': {'complete': False}, 'nativeBulkBytes': None,
                'failureClass': 'RetainedReportOverflow',
                'scope': 'all fixed raw prefixes and scoped receipts remain retained'}
            final = managed_workflow_bounded_encoded(result)
        self.retain('managed-' + self.prepared['coordinates']['runId'] + '-complete-workflow.json', final)
        return result


def join_terminal_provider_read(window, original, physical_reply, subject_id, capture_id, backing_identity):
    """Join actual consumed EOF/hash/incarnation to the signed physical result."""
    managed_workflow_require(window['captureId'] == capture_id
        and window['backingIdentity'] == backing_identity and re.fullmatch(r'[0-9a-f]{128}', subject_id),
        'terminal provider read belongs to another capture/namespace/original request')
    key = original['placement_prefix'] + '/' + original['path']
    calls = [call for call in window['calls'] if call['method'] == 'get']
    managed_workflow_require(len(calls) == 1 and calls[0]['key'] == key and calls[0]['subjectId'] == subject_id,
                             'terminal provider read is absent or ambiguous')
    call = calls[0]
    read = call.get('read')
    object_identity = physical_reply['object']
    managed_workflow_require(isinstance(read, dict) and read['eof'] is True
        and read['consumed_bytes'] == original['size'] == object_identity['size']
        and read['sha256'] == original['sha256']
        and read['etag'] == object_identity['etag']
        and read['version'] == object_identity['provider_version']
        and object_identity['key'] == key,
        'conditional provider read does not match actual EOF/original/physical incarnation')
    return {'sdkCallId': call['callId'], 'subjectId': call['subjectId'],
        'consumedBytes': read['consumed_bytes'], 'eof': True, 'sha256': read['sha256'],
        'etagSha256': hashlib.sha256(read['etag'].encode()).hexdigest(),
        'versionSha256': hashlib.sha256(read['version'].encode()).hexdigest()}


def assess_managed_workflow(workflow, cleanup_accounting, *, source_digest, gc_windows=(),
                            gc_positive=None, read_retained=None, join_gc_positive=None):
    """Consume every actual row and retain a failed gate for missing producers.

    Decoder rows come only from the called current held-executable controller.
    Their payload partition is distinct from authenticated current authority,
    SQL and provider checks. This function accepts no readiness or zero flag.
    Public ingress acceptance still requires the separate production receipt.
    """
    report = {'version': 1, 'complete': False, 'nativeBulkBytes': None,
        'applicationPayloadBytes': None, 'unresolved': [],
        'scope': 'complete application-body inventory; no wire billing or Hosted qualification'}
    coverage = workflow.get('coverage', {})
    if coverage.get('complete') is not True or workflow.get('failureClass') is not None:
        report['unresolved'].append({'scope': 'global_capture', 'reason': 'incomplete_actual_partition'})
        return report
    if gc_positive is not None:
        report['gcPositiveEvidence'] = join_managed_gc_positive_evidence(
            gc_positive, gc_windows, source_digest, read_retained, join_gc_positive)
    decoded, current_sql, auth = {}, {}, {}
    for epoch in workflow['epochs']:
        window = epoch['window']
        for call in window.get('nativeAuthenticatedTransports', {}).get('joined', []):
            identity = ('nativeOutbound', call['nativeRequestId'])
            managed_workflow_require(identity not in auth, 'authenticated call is reused across epochs')
            auth[identity] = call
        for call in window.get('nativeFinalContextObservations', {}).get('joined', []):
            identity = ('nativeOutbound', call['nativeRequestId'])
            managed_workflow_require(identity not in current_sql, 'final context is reused across epochs')
            current_sql[identity] = call
        ingress = window.get('nativeIngressBoundary', {})
        if isinstance(ingress.get('decoded'), dict) and ingress['decoded'].get('complete') is True:
            for row in ingress['decoded']['observations']:
                identity = ('workerOriginal', row['requestId'])
                managed_workflow_require(identity not in decoded, 'ingress decoder ownership is repeated')
                decoded[identity] = row
    if isinstance(cleanup_accounting.get('decoded'), dict) and cleanup_accounting['decoded'].get('complete') is True:
        for row in cleanup_accounting['decoded']['observations']:
            identity = ('nativeOutbound', row['requestId'])
            managed_workflow_require(identity not in decoded, 'cleanup decoder ownership is repeated')
            decoded[identity] = row
    for window in gc_windows:
        for exchange in window.get('validatedExchanges', []):
            row = exchange['validationReceipt']['observation']
            completion = exchange['handlerCompletion']
            # GC shared decoding uses Worker request IDs; the original Native
            # ID comes from its independently correlated completion receipt.
            identity = ('nativeOutbound', completion['nativeRequestId'])
            managed_workflow_require(identity not in decoded, 'GC decoder ownership is repeated')
            decoded[identity] = row
    cleanup_evidence = {}
    for item in cleanup_accounting.get('checkedBodyPartitions', []):
        identity = 'nativeOutbound', item['nativeRequestId']
        managed_workflow_require(identity not in cleanup_evidence, 'cleanup accepted evidence reused')
        cleanup_evidence[identity] = item
    for role in MANAGED_WORKFLOW_PROXY_ROLES:
        for request_id, original in coverage['assigned'][role].items():
            if role not in {'nativeOutbound', 'workerOriginal'}:
                originals = coverage['assigned']['nativeOutbound' if role == 'workerReceived' else 'workerOriginal']
                if original['originalRequestId'] not in originals:
                    report['unresolved'].append({'role': role, 'requestId': request_id,
                        'reason': 'unassigned_independent_received_transport'})
                continue
            identity = role, request_id
            row = decoded.get(identity)
            reasons = []
            if original['scope'] != 'business':
                reasons.append('startup_or_auxiliary_actual_row_requires_its_own_join')
            if row is None:
                reasons.append('missing_current_closed_body_decoder')
            elif row['sourceDigest'] != source_digest:
                reasons.append('decoder_source_substitution')
            if role == 'workerOriginal':
                # Compact assertion shape, proxy 2xx and supplied hashes are not
                # the post-existing-auth/current-handler producer approved for
                # the separate ingress source increment.
                reasons.append('missing_production_ingress_accepted_context')
            else:
                evidence = cleanup_evidence.get(identity)
                if evidence is not None:
                    if (row is None or evidence['sourceDigest'] != source_digest
                            or row['requestSha256'] != evidence['requestSha256']
                            or row['replySha256'] != evidence['replySha256']
                            or evidence['transportCallIdSha256'] != hashlib.sha256(
                                original['transportCallId'].encode()).hexdigest()):
                        reasons.append('cleanup_body_sql_provider_correlation_substituted')
                else:
                    if identity not in auth:
                        reasons.append('missing_native_post_auth_consumption_receipt')
                    if identity not in current_sql:
                        reasons.append('missing_native_final_current_context')
                    reasons.append('independent_current_sql_purpose_provider_join_required')
            if reasons:
                report['unresolved'].append({'role': role, 'requestId': request_id, 'reasons': reasons})
    expected_originals = {(role, identity) for role in ('nativeOutbound', 'workerOriginal')
        for identity in coverage['assigned'][role]}
    managed_workflow_require(set(decoded) <= expected_originals,
        'a decoder row belongs to no original in the complete captured inventory')
    report['inventorySha256'] = coverage['inventorySha256']
    report['originalCount'] = sum(len(coverage['assigned'][role])
        for role in ('nativeOutbound', 'workerOriginal'))
    report['decodedOriginalCount'] = len(decoded)
    report['cleanupCurrentSqlJoins'] = cleanup_accounting.get('independentCurrentSql', [])
    # This gate is deliberately data-dependent. No missing producer or failed
    # row is removed so that a positive subset can yield a global zero.
    report['complete'] = not report['unresolved']
    if report['complete']:
        managed_workflow_require(report['originalCount'] > 0,
                                 'empty workflow cannot establish a business byte budget')
        raw, selected, semantic = 0, 0, 0
        for row in decoded.values():
            payload = row['payload']
            values = {}
            for field in ('requestRawObjectBytes', 'replyRawObjectBytes',
                          'selectedDataBytes', 'semanticOciProjectionBytes'):
                managed_workflow_require(isinstance(payload.get(field), str)
                    and re.fullmatch(r'0|[1-9][0-9]{0,19}', payload[field]),
                    'actual body payload partition count differs')
                values[field] = int(payload[field])
            raw += values['requestRawObjectBytes'] + values['replyRawObjectBytes']
            selected += values['selectedDataBytes']
            semantic += values['semanticOciProjectionBytes']
        report['nativeBulkBytes'] = raw
        report['applicationPayloadBytes'] = {'fullObjectBytes': raw,
            'selectedDataBytes': selected, 'semanticProjectionBytes': semantic}
    return report


def join_managed_gc_positive_evidence(positive, windows, source_digest, read_retained, join_positive):
    """Reopen the already-called SQL/SDK/guard join without manufacturing authority.

    This is the existing acknowledged action evidence. Its metadata join does
    not supply missing Native consumption or cover any other execute call.
    """
    managed_workflow_require(callable(read_retained) and callable(join_positive)
        and isinstance(positive, dict) and set(positive) == {'retainedReference', 'observations'},
        'GC positive evidence lacks its actual retained source-bound consumer')
    reference = positive['retainedReference']
    managed_workflow_require(isinstance(reference, dict) and set(reference) == {'file', 'sha256', 'byteSize'}
        and re.fullmatch(r'external-direct-flow/[a-z0-9][a-z0-9.-]{0,127}', reference['file'])
        and type(reference['byteSize']) is int and 0 < reference['byteSize'] <= 16 * 1024 * 1024,
        'GC positive report escaped its retained private file')
    raw = read_retained(reference)
    managed_workflow_require(len(raw) == reference['byteSize']
        and hashlib.sha256(raw).hexdigest() == reference['sha256']
        and json.loads(raw) == positive['observations'], 'GC positive report changed after actual retention')
    value = positive['observations']
    evidence = value['evidence']
    managed_workflow_require(isinstance(evidence, list) and 0 < len(evidence) <= 32
        and len({item['action']['id'] for item in evidence}) == len(evidence),
        'GC positive action ownership is missing or repeated')
    validated = [exchange for window in windows for exchange in window.get('validatedExchanges', [])]
    joins = []
    for item in evidence:
        actual = [exchange for exchange in validated if exchange == {
            field: item[field] for field in exchange}]
        managed_workflow_require(len(actual) == 1
            and item['validationReceipt']['sourceDigest'] == source_digest
            and item['validationReceipt']['observation']['sourceDigest'] == source_digest,
            'GC positive SQL/provider action lacks its exact current decoded captured exchange')
        joined = join_positive(item['action'], item['plan'], item['result'], value['sdkWindow'],
                               value['before'], value['after'])
        joins.append({'nativeRequestId': item['handlerCompletion']['nativeRequestId'],
            'requestSha256': item['validationReceipt']['requestSha256'],
            'replySha256': item['validationReceipt']['replySha256'], 'action': joined})
    managed_workflow_require([item['action'] for item in joins] == value['joins'],
        'GC positive independent SQL/SDK/guard joins changed')
    return {'retainedReference': reference, 'joins': joins, 'nativeBulkBytes': None,
        'scope': 'actual SQL action and local SDK/guard evidence; other Native consumption remains independent'}


def join_checked_cleanup_body_partitions(accounting, read_evidence, original, physical_reply,
                                        read_private_body):
    """Join actual current SQL and provider proof to closed consumed metadata.

    Each accepted call still requires the Native post-authentication counters,
    its separate final Delete check and an independently observed current SQL
    tuple. The provider result is the immutable physical result authenticated by
    the independently inventoried upstream helper. It is never used as a Native
    consumed-body observation of the intentionally lost call.
    """
    if (accounting.get('auxiliaryInventoryFailureClass') is not None
            or accounting.get('providerPartitionFailureClass') is not None):
        return []
    auxiliaries = accounting.get('auxiliaryHelperInventory', [])
    if len(auxiliaries) != 2 or any(item.get('nativeTransportObservation') is not None
                                 or item.get('process') is None for item in auxiliaries):
        return []
    decoded = accounting.get('decoded')
    if not isinstance(decoded, dict) or decoded.get('complete') is not True:
        return []
    sql_by_call = {}
    for checked in accounting.get('independentCurrentSql', []):
        call = hashlib.sha256(checked['transportCallId'].encode()).hexdigest()
        managed_workflow_require(call not in sql_by_call, 'cleanup current SQL call ownership repeated')
        sql_by_call[call] = checked
    rows = {row['requestId']: row for row in decoded['observations']}
    managed_workflow_require(len(rows) == len(decoded['observations']), 'cleanup decoder call repeated')
    profile = accounting.get('actualCheckedProfile')
    windows = accounting.get('actualSdkWindows')
    fingerprint = accounting.get('actualOriginalFingerprint')
    if (not isinstance(profile, dict) or not isinstance(windows, list)
            or not isinstance(fingerprint, str) or not re.fullmatch(r'[0-9a-f]{64}', fingerprint)):
        return []
    conclusions = []
    for call in accounting.get('transport', {}).get('joined', []):
        identifier = call['nativeRequestId']
        checked = sql_by_call.get(call['transportCallIdSha256'])
        row = rows.get(identifier)
        if checked is None or row is None:
            continue
        managed_workflow_require(row['sourceDigest'] == checked['sourceDigest']
            and row['operation'] == 'managed_oci_cleanup'
            and row['class'] == 'managed_oci_terminal_cleanup_metadata'
            and row['requestSha256'] == checked['requestSha256'] == call['requestSha256']
            and row['replySha256'] == checked['replySha256'] == call['replySha256']
            and row['payload'] == {'requestRawObjectBytes': '0', 'replyRawObjectBytes': '0',
                                  'selectedDataBytes': '0', 'semanticOciProjectionBytes': '0'},
            'cleanup consumed metadata codec/current Delete SQL exchange differs')
        subject = fingerprint + call['requestSha256']
        brackets = [(window, bracket) for window in windows for bracket in window['brackets']
            if bracket['scope'] == 'managed_terminal_cleanup' and bracket['subjectId'] == subject]
        managed_workflow_require(len(brackets) == 1 and brackets[0][1]['invoked'] == 0
            and brackets[0][0]['backingIdentity'] == profile['namespaceBackingIdentity']
            and profile['sourceDigest'] == row['sourceDigest']
            and not any(item['subjectId'] == subject for item in brackets[0][0]['calls']),
            'cleanup accepted replay lacks its fresh complete same-namespace zero-call SDK bracket')
        body = read_private_body(identifier, call['replySha256'], call['consumedReplyBytes'])
        managed_workflow_require(isinstance(body, bytes) and len(body) == call['consumedReplyBytes']
            and hashlib.sha256(body).hexdigest() == call['replySha256'],
            'cleanup consumed reply changed after its independently retained callback')
        # Shared source-bound decoding and actual post-MAC counts precede this
        # comparison of the independently retained physical result.
        actual = json.loads(body)
        managed_workflow_require(all(actual[field] == physical_reply[field]
            for field in ('object', 'receipt_digest', 'original_digest')) and actual['object']['key']
            == original['placement_prefix'] + '/' + original['path']
            and read_evidence['consumedBytes'] == actual['object']['size'] == original['size']
            and read_evidence['sha256'] == original['sha256'],
            'cleanup consumed physical result differs from its original verified EOF/incarnation')
        conclusions.append({'nativeRequestId': identifier,
            'transportCallIdSha256': call['transportCallIdSha256'], 'sourceDigest': row['sourceDigest'],
            'requestSha256': row['requestSha256'], 'replySha256': row['replySha256'],
            'payload': row['payload'], 'currentSql': checked, 'conditionalRead': read_evidence,
            'actualCheckedProfile': profile, 'freshSdkBracket': brackets[0][1],
            'permissionScope': 'existing authenticated physical cleanup and actual final Delete check',
            'scope': 'accepted metadata subset; every lost or unsupported call remains unclassified'})
    return conclusions
