"""Join the dedicated External lane's existing body and state observations.

Canonical body shape, actual Native application-frame observations, source-point
checks, current SQL association and the whole provider window are independent
dimensions. A later SQL row does not recreate an earlier claim or permission.
Private signatures and credentials are reopened only through retained custody;
the report contains hashes, counts and scoped associations.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat


BODY_ROLES = ('nativeOutbound', 'workerOriginal')
PAYLOAD_FIELDS = ('requestRawObjectBytes', 'replyRawObjectBytes',
                  'selectedDataBytes', 'semanticOciProjectionBytes')
CODEC_FIELDS = frozenset(('requestId', 'sourceDigest', 'requestSha256', 'replySha256',
    'codecSourceSha256', 'exchangeIdSha256', 'originalContextSha256',
    'operation', 'class', 'payload'))
SQL_MAXIMUM = 1024 * 1024
BODY_MAXIMUM = 8 * 1024 * 1024
ROW_MAXIMUM = 204704
PROVIDER_MAXIMUM = 512 * 1024 * 1024
PROVIDER_ROW_MAXIMUM = 48 * 1024
ASSESSMENT_MAXIMUM = 256 * 1024 * 1024
PARTITION_SUMMARY_MAXIMUM = 4096
PARTITION_TOTAL_MAXIMUM = 240 * 1024 * 1024
PROCESS_FIELDS = ('pid', 'startTicks', 'executableSha256')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode()


def closed_json(raw):
    def pairs(items):
        value = {}
        for name, item in items:
            require(name not in value, 'retained JSON has duplicate fields')
            value[name] = item
        return value

    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError('non-finite JSON')))


def count(value):
    require(type(value) in (str, int) and re.fullmatch(r'0|[1-9][0-9]{0,19}', str(value)),
            'observed byte count differs')
    result = int(value)
    require(result < 2**64, 'observed byte count exceeds its integer bound')
    return result


def retained_host_bytes(reference, maximum):
    """Reopen one actual private regular file without following a replacement."""
    require(isinstance(reference, dict) and isinstance(reference.get('file'), str)
        and re.fullmatch(r'[0-9a-f]{64}', reference.get('sha256', '')),
        'retained file reference differs')
    descriptor = os.open(reference['file'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and before.st_mode & 0o077 == 0 and before.st_size <= maximum,
            'retained file custody or size differs')
        raw = source.read(maximum + 1)
        after = os.fstat(source.fileno())
    require(len(raw) <= maximum and all(getattr(before, field) == getattr(after, field)
        for field in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
        and sha256(raw) == reference['sha256'], 'retained file changed')
    expected = reference.get('byteSize', reference.get('capturedBytes'))
    require(expected is not None and len(raw) == count(expected), 'retained file count differs')
    return raw


def retained_guest_bytes(machine, reference, maximum, read_private):
    require(isinstance(reference, dict), 'guest private file reference differs')
    if set(reference) == {'file', 'sha256', 'byteSize'}:
        path, size = reference['file'], reference['byteSize']
    elif set(reference) == {'path', 'sha256', 'bytes'}:
        path, size = reference['path'], reference['bytes']
    else:
        raise ValueError('guest private file reference differs')
    require(count(size) <= maximum, 'guest private file exceeds observation bound')
    raw = read_private(machine, path, maximum)
    require(isinstance(raw, bytes) and len(raw) == count(size)
        and sha256(raw) == reference['sha256'], 'guest private bytes changed')
    return raw


def sibling(name):
    """Load the selected installed sibling, without controller-global injection."""
    path = Path(__file__).with_name(name + '.py')
    specification = importlib.util.spec_from_file_location(name.replace('-', '_'), path)
    require(specification is not None and specification.loader is not None,
            'selected source module is missing')
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def append_summary(items, value, retained):
    """Bound each serialized summary before appending or retaining its object."""
    size = len(canonical(value)) + 1
    require(size <= PARTITION_SUMMARY_MAXIMUM
        and retained['bytes'] + size <= PARTITION_TOTAL_MAXIMUM,
        'External retained summaries exceed their observation bound')
    retained['bytes'] += size
    items.append(value)


def collect_external_body_rows(workflow, source_digest, codec_digest):
    """Require exclusive complete membership and the actual selected decoder rows."""
    coverage = workflow['coverage']
    require(coverage.get('complete') is True and workflow.get('failureClass') is None,
            'complete External capture is unavailable')
    expected = {(role, identity) for role in BODY_ROLES for identity in coverage['assigned'][role]}
    require(0 < len(expected) <= ROW_MAXIMUM, 'External original inventory is empty or excessive')
    decoded, bodies, observed, contexts = {}, {}, {}, {}
    call_owners = set()
    for epoch in workflow['epochs']:
        window = epoch['window']
        require(epoch['processRole'] in {'ordinary_native', 'controlled_external_oci_native'},
                'External process role differs')
        for role, bundle, result in (
            ('nativeOutbound', window['storageBoundary']['nativeOriginalBodies'],
             window.get('nativeOutboundDecoded')),
            ('workerOriginal', window['nativeIngressBoundary']['workerOriginalBodies'],
             window['nativeIngressBoundary'].get('decoded'))):
            for row in bundle['bodies']:
                identity = role, row['requestId']
                require(identity in expected and identity not in bodies,
                        'actual body is omitted or reused across process epochs')
                bodies[identity] = row
            if not isinstance(result, dict) or result.get('complete') is not True:
                continue
            for row in result['observations']:
                identity = role, row['requestId']
                require(identity in expected and identity not in decoded
                    and set(row) == CODEC_FIELDS and set(row['payload']) == set(PAYLOAD_FIELDS)
                    and row['sourceDigest'] == source_digest
                    and row['codecSourceSha256'] == codec_digest,
                    'closed decoder ownership or source differs')
                for value in row['payload'].values():
                    count(value)
                decoded[identity] = row
        for row in window.get('nativeAuthenticatedTransports', {}).get('joined', []):
            identity = 'nativeOutbound', row['nativeRequestId']
            require(identity not in observed and row['transportCallIdSha256'] not in call_owners,
                    'actual authenticated receipt or call is reused across epochs')
            call_owners.add(row['transportCallIdSha256'])
            observed[identity] = {'kind': 'authenticated_control', 'value': row}
        for row in window.get('nativeExecuteObservations', {}).get('joined', []):
            identity = 'nativeOutbound', row['nativeRequestId']
            call_sha = sha256(row['transportCallId'].encode())
            require(identity not in observed and call_sha not in call_owners,
                    'actual execute attempt or call is reused across epochs')
            call_owners.add(call_sha)
            observed[identity] = {'kind': 'typed_execute_attempt', 'value': row}
        executions = window.get('nativeExecuteObservations', {})
        require(not executions.get('unassignedAttemptCallIds')
            and not executions.get('unassignedFinalContextCallIds'),
            'actual execute attempt or context is unassigned to the complete corpus')
        ingress = window.get('nativeIngressBoundary', {}).get('applicationObservations')
        if isinstance(ingress, dict):
            require(not ingress.get('unassignedEventCount'),
                    'actual Native ingress event is unassigned to the complete corpus')
            for row in ingress['joined']:
                identity = 'workerOriginal', row['nativeRequestId']
                require(identity not in observed, 'actual ingress observation is reused')
                observed[identity] = {'kind': 'ingress_frames', 'value': row}
        for row in window.get('nativeFinalContextObservations', {}).get('joined', []):
            identity = 'nativeOutbound', row['nativeRequestId']
            require(identity not in contexts, 'actual final-check context is reused')
            contexts[identity] = row
        require(not window.get('nativeFinalContextObservations', {}).get('unassignedReceiptSha256'),
                'actual final-check receipt has no exclusive transport owner')
    require(set(decoded) <= expected and set(bodies) <= expected and set(observed) <= expected,
            'decoded or observed transport has no original in the full inventory')
    return expected, decoded, bodies, observed, contexts


def external_body_partition(decoded, original, observation, ingress_assessor):
    """Keep measured application frames separate from canonical body upper bounds."""
    require(decoded['requestId'] == original['requestId'], 'body original identity differs')
    for side, field in (('request', 'requestSha256'), ('response', 'replySha256')):
        reference = original['bodies'].get(side)
        require(isinstance(reference, dict) and reference['sha256'] == decoded[field]
            and count(reference['byteSize']) <= BODY_MAXIMUM,
            'captured body is missing or substituted')
    payload = {field: count(decoded['payload'][field]) for field in PAYLOAD_FIELDS}
    metadata = not any(payload[field] for field in PAYLOAD_FIELDS[:3])
    result = {'requestSha256': decoded['requestSha256'], 'replySha256': decoded['replySha256'],
        'capturedRequestBytes': count(original['bodies']['request']['byteSize']),
        'capturedReplyBytes': count(original['bodies']['response']['byteSize']),
        'canonicalPayload': payload, 'nativeApplicationObservation': None,
        'checkedOutcome': None, 'nativeObjectBytes': None, 'unresolved': []}
    if observation is None:
        if not metadata:
            result['unresolved'].append('content_body_has_no_native_consumption_observation')
        return result
    call = observation['value']
    if observation['kind'] == 'authenticated_control':
        mirror_controls = {'mirror_guard': 'mirror_guard_control',
            'mirror_guard_batch': 'mirror_guard_batch'}
        if decoded['operation'] in mirror_controls:
            require(call['operation'] == mirror_controls[decoded['operation']],
                'Mirror checked Native event belongs to another operation')
            require(call['planIdSha256'] == decoded['exchangeIdSha256'],
                'Mirror checked Native nonce belongs to another challenge')
        require((call['requestSha256'], call['replySha256'], call['offeredRequestBytes'],
                 call['consumedReplyBytes']) == (decoded['requestSha256'], decoded['replySha256'],
                 result['capturedRequestBytes'], result['capturedReplyBytes']),
                'Native authenticated consumption does not match independent bodies')
        result['nativeApplicationObservation'] = {
            'offeredRequestBytes': call['offeredRequestBytes'],
            'consumedReplyBytes': call['consumedReplyBytes'], 'replyEof': True,
            'transportCallIdSha256': call['transportCallIdSha256']}
        result['checkedOutcome'] = 'existing_control_mac_and_correlation_accepted'
    elif observation['kind'] == 'typed_execute_attempt':
        attempt = call['attempt']
        require(call['payload'] == decoded['payload']
            and attempt['offeredRequestSha256'] == decoded['requestSha256']
            and count(attempt['offeredRequestBytes']) == result['capturedRequestBytes'],
            'actual execute request or payload partition differs')
        if not metadata and not call['fullReplyConsumed']:
            result['unresolved'].append('partial_content_reply_has_no_field_offset_mapping')
        result['nativeApplicationObservation'] = {
            'offeredRequestBytes': count(attempt['offeredRequestBytes']),
            'consumedReplyBytes': count(call['nativeExposedReplyBytes']),
            'replyEof': attempt['replyEof'], 'outcome': attempt['outcome'],
            'replyMacAuthentication': None}
        result['checkedOutcome'] = attempt['outcome']
    else:
        require(observation['kind'] == 'ingress_frames', 'Native observation family differs')
        result['unresolved'].extend(ingress_assessor(decoded, call))
        frames = call['partitions']
        result['nativeApplicationObservation'] = {
            'consumedRequestBytes': count(frames['requestConsumed']['exposedBytes']),
            'offeredReplyBytes': count(frames['replyOffered']['exposedBytes']),
            'requestEof': frames['requestConsumed']['eof'],
            'replyEof': frames['replyOffered']['eof']}
        result['checkedOutcome'] = call['handlerOutcome']
    if not result['unresolved']:
        result['nativeObjectBytes'] = payload['requestRawObjectBytes'] + payload['replyRawObjectBytes']
    return result


def external_helper_purpose(native, worker, tools, business, read_private):
    """Bind already executed constructors to exact Direct and controlled OCI inputs.

    This observes the existing Native loader, not a new signature verifier or a
    production OCI acceptance. Guard material remains private and grants nothing
    through this function. Current IAM, SQL and provider effects are independent.
    """
    helper = business['helper']
    input_value = closed_json(retained_guest_bytes(native, helper['input'], 65536, read_private))
    identity = helper['readiness']['identity']
    process = helper['process']
    require(identity['inputSha256'] == helper['input']['sha256']
        and all(str(identity[field]) == str(process[field]) for field in PROCESS_FIELDS)
        and input_value['expectedExecutableSha256'] == process['executableSha256']
        and input_value['deploymentId'] == tools['deploymentId']
        and input_value['workerSourceDigest'] == sha256(tools['workerSourcePath'].encode())
        and identity['selectedWorkerSourceDigest'] == input_value['workerSourceDigest']
        and identity['selectedWorkerScriptVersion'] == input_value['workerScriptVersion'],
        'actual helper constructor input, process or source differs')
    ready_raw = read_private(native, input_value['readinessFile'], 65536)
    require(closed_json(ready_raw) == helper['readiness'], 'actual constructor readiness changed')
    direct = business['direct']['directReferences']
    require(direct['version'] == 1 and direct['audience'] == {
        'deploymentId': input_value['deploymentId'], 'publicOrigin': input_value['publicOrigin'],
        'sourceDigest': input_value['workerSourceDigest'], 'scriptVersion': input_value['workerScriptVersion']},
        'independent Direct audience differs from the actual helper')
    triplet = input_value['files']['direct']
    references = (('nativeArtifact', 'acceptanceFile'),
                  ('nativeReviewKeys', 'reviewKeysFile'), ('nativeGuardKey', 'guardKeyFile'))
    for field, selector in references:
        require(direct[field]['file'] == triplet[selector], 'Direct constructor file was substituted')
        retained_guest_bytes(native, direct[field], SQL_MAXIMUM, read_private)
    retained_guest_bytes(native, direct['nativeIndependentReview'], SQL_MAXIMUM, read_private)
    require(direct['nativeIndependentReview']['sha256'] == direct['reviewSha256'],
            'Direct independent review commitment differs')
    worker_raw = retained_guest_bytes(worker, direct['workerArtifact'], SQL_MAXIMUM, read_private)
    require(sha256(worker_raw) == direct['artifactSha256'] == direct['nativeArtifact']['sha256']
        == business['direct']['workerAcceptance']['artifactSha256'],
        'Worker installed Direct artifact differs from the independently loaded Native artifact')
    candidate_reference = business['candidate']['candidateReference']
    candidate = closed_json(retained_guest_bytes(native, candidate_reference, 4096, read_private))
    require(identity['candidateSha256'] == candidate_reference['sha256']
        and input_value['files']['candidateFile'] == candidate_reference['path']
        and candidate['deployment_id'] == input_value['deploymentId']
        and candidate['source_digest'] == input_value['workerSourceDigest']
        and candidate['script_version'] == input_value['workerScriptVersion']
        and candidate['placement_prefix'] == input_value['placementPrefix']
        and identity['expiresAt'] == candidate['expires_at'],
        'controlled OCI candidate differs from the actual loaded original')
    return {'helperProcess': {field: process[field] for field in PROCESS_FIELDS},
        'helperInputSha256': helper['input']['sha256'], 'readinessSha256': sha256(ready_raw),
        'directArtifactSha256': direct['artifactSha256'],
        'directIndependentReviewSha256': direct['nativeIndependentReview']['sha256'],
        'candidateSha256': candidate_reference['sha256'], 'profileDigest': candidate['profile_digest'],
        'scope': 'actual existing Direct loader and confined test-only OCI constructor; no Hosted or Managed acceptance'}


def sql_literal(value):
    require(isinstance(value, str) and len(value.encode()) <= 255
        and not any(ord(character) < 32 for character in value), 'SQL selector differs')
    return "'" + value.replace("'", "''") + "'"


def positive_id(value):
    parsed = count(value)
    require(0 < parsed < 2**63, 'SQL numeric selector differs')
    return parsed


def external_writer_query(writer, upload_id=None):
    """Select only current metadata for one actual shared-decoded writer original."""
    placement = positive_id(writer['placement_id'])
    binding = positive_id(writer['binding_id'])
    authority = positive_id(writer['authority_id'])
    upload = ('NULL' if upload_id is None else
        '(SELECT json_build_object(\'id\',u.id,\'registry_id\',u.registry_id,'
        "'repository_id',u.repository_id,'writer_id',u.writer_id,'token_id',u.token_id,"
        "'quota_reservation_id',u.quota_reservation_id,'publication_id',u.publication_id,"
        "'created_at',u.created_at,'expires_at',u.expires_at,'maximum_size',u.maximum_size,"
        "'resource_version',u.resource_version,'state',u.state) FROM oci_upload_sessions u WHERE u.id="
        + sql_literal(upload_id) + ')')
    return ("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; "
        "SELECT json_build_object('placement',row_to_json(p),'binding',row_to_json(b),"
        "'authority',row_to_json(a),'upload'," + upload + ") "
        "FROM surface_placements p JOIN bindings b ON b.id=p.binding_id "
        "JOIN surface_write_authorities a ON a.registry_id=p.registry_id "
        f"WHERE p.id={placement} AND b.id={binding} AND a.id={authority}; COMMIT;")


def join_current_external_writer(writer, upload, value):
    """Associate current rows; this does not reconstruct earlier IAM or claims."""
    require(isinstance(value, dict) and set(value) == {'placement', 'binding', 'authority', 'upload'},
            'current External writer SQL shape differs')
    placement, binding, authority = value['placement'], value['binding'], value['authority']
    for field, observed in (
        ('placement_id', placement['id']), ('binding_id', binding['id']),
        ('placement_resource_version', placement['resource_version']),
        ('write_spec_version', placement['write_spec_version']),
        ('binding_resource_version', binding['resource_version']),
        ('authority_id', authority['id']), ('authority_resource_version', authority['resource_version']),
        ('authority_generation', authority['observed_generation']),
        ('binding_write_revision', authority['observed_binding_write_revision'])):
        require(count(writer[field]) == count(observed), 'current writer generation is substituted')
    require(writer['placement_prefix'] == placement['prefix']
        and writer['binding_prefix'] == (binding['object_prefix'] or '')
        and writer['binding_stable_id'] == binding['stable_id']
        and writer['authority_incarnation'] == authority['incarnation_id']
        and placement['binding_id'] == binding['id']
        and authority['observed_placement_id'] == placement['id'],
        'current External writer address or incarnation differs')
    if upload is not None:
        current = value['upload']
        require(isinstance(current, dict) and current['id'] == upload['upload_id'],
                'retained OCI upload is missing or substituted')
        for field in ('registry_id', 'repository_id', 'created_at', 'expires_at', 'maximum_size'):
            require(count(upload[field]) == count(current[field]), 'immutable upload SQL field differs')
        for field in ('writer_id', 'token_id', 'quota_reservation_id', 'publication_id'):
            require(upload[field] == current[field], 'immutable upload SQL identity differs')
    return {'writerOriginalSha256': sha256(canonical(writer)),
        'currentRowsSha256': sha256(canonical(value)),
        'uploadOriginalSha256': sha256(canonical(upload)) if upload is not None else None,
        'scope': 'current independently read writer and immutable reservation association; not past IAM or completing claim'}


def capture_external_current_sql(native, processes, request, read_sql, read_private, label):
    """Bind an actual bounded read-only result to its query and current process."""
    original = request.get('original')
    writer = original.get('writer') if isinstance(original, dict) else request.get('writer')
    require(isinstance(writer, dict), 'shared-decoded request has no External writer')
    upload = original.get('upload') if isinstance(original, dict) else None
    query = external_writer_query(writer, upload['upload_id'] if upload is not None else request.get('upload_id'))
    selected = read_sql(query, label)
    require(isinstance(selected, dict) and set(selected) == {'value', 'receipt'},
            'actual SQL callback result differs')
    receipt = selected['receipt']
    require(receipt['querySha256'] == sha256(query.encode())
        and all(receipt['before'][field] == receipt['after'][field] == processes['native'][field]
            for field in PROCESS_FIELDS), 'SQL query or actual Native/helper process differs')
    reference = {field: receipt[field] for field in ('file', 'sha256', 'byteSize')}
    raw = retained_guest_bytes(native, reference, SQL_MAXIMUM, read_private)
    require(closed_json(raw) == selected['value'], 'SQL projection differs from actual retained output')
    association = join_current_external_writer(writer, upload, selected['value'])
    if upload is None and request.get('upload_id') is not None:
        current = selected['value']['upload']
        require(isinstance(current, dict) and current['id'] == request['upload_id'],
                'current private source upload selector differs')
        association['sourceUploadIdSha256'] = sha256(request['upload_id'].encode())
    return {**association, 'receipt': receipt,
        'databaseUrlSha256': receipt['databaseUrlSha256']}


def external_copy_association(native, process, business, read_private):
    """Reopen existing catalogue rows and match the genuine API workflows.

    Completed API inventories and exact original replay are associations to
    observed business outcomes. They do not recreate a prior SQL claim, grant
    provider permission or attribute one provider call to an application call.
    """
    copying = business['copy']
    validator = sibling('_hub-external-copy-window')
    before = copying['catalogueBefore']
    objects = validator.external_copy_catalog(before['objects'])
    indexed = before['sql']['indexed']
    registry = before['sql']['registry']
    require(registry['slug'] == before['registrySlug']
        and registry['stable_id'] == before['registryStableId']
        and indexed['registry_id'] == registry['id'] and indexed['state'] == 'fresh'
        and indexed['last_indexed_commit'] == before['sourceCommit']
        == business['publication']['signedSource']['sourceCommit']
        == business['reindex']['sourceCommit'], 'Copy publication or current catalogue differs')

    def catalogue_receipt(catalogue):
        receipt = catalogue['receipt']
        raw = retained_guest_bytes(native, {field: receipt[field]
            for field in ('file', 'sha256', 'byteSize')}, SQL_MAXIMUM, read_private)
        require(closed_json(raw) == catalogue['sql']
            and all(receipt['before'][field] == receipt['after'][field] == process[field]
                for field in PROCESS_FIELDS)
            and catalogue['sql'] == before['sql']
            and catalogue['objects'] == objects, 'Copy retained catalogue or process differs')
        rows = catalogue['sql']['objects']
        require(len(rows) == len(objects) and all(
            row['path'] == obj['path'] and count(row['size']) == obj['byteSize']
            and validator._catalogue_digest(row['digest']) == obj['sha256']
            for row, obj in zip(rows, objects)), 'Copy logical object rows differ')
        return {field: receipt[field] for field in ('sha256', 'byteSize',
            'databaseUrlSha256', 'psqlExecutableSha256', 'querySha256')}

    initial = catalogue_receipt(before)
    workflows = {}
    require(set(copying['workflows']) == {'replicate', 'repair'},
            'required Copy workflows are absent')
    for kind, value in copying['workflows'].items():
        facts = closed_json(value['completed']['detailJson'])
        source, destination = facts['copy']['source'], facts['copy']['destination']
        facts = validator.require_external_copy_operation(value['completed'], kind,
            source, destination, len(objects))
        require(value['controllerFacts'] == facts
            and value['original']['operationId'] == value['completed']['operation']['operationId']
            == value['replayedOriginal']['operationId']
            and value['apply']['planId'] == value['plan']['planId']
            and value['apply']['confirmationHash'] == value['plan']['confirmationHash'],
            'Copy original, review plan or exact replay differs')
        scan = closed_json(value['missingScan']['detailJson'])
        require(scan['catalogObjects'] == scan['missingObjects'] == len(objects),
                'Copy original destination was not the actual missing catalogue')
        validator.require_external_copy_presence(value['presenceBefore'], objects,
            source, destination, copied=False)
        validator.require_external_copy_presence(value['presenceAfter'], objects,
            source, destination, copied=True)
        workflows[value['original']['operationId']] = {
            'kind': kind + '_placement', 'factsSha256': sha256(canonical(facts)),
            'catalogueReceipt': catalogue_receipt(value['catalogueAfter'])}
    require(len(workflows) == 2, 'Copy replicate and repair reuse one operation')
    return {'catalogue': {row['path']: row for row in objects}, 'workflows': workflows,
        'registryId': count(registry['id']), 'initialCatalogueReceipt': initial,
        'scope': 'actual reopened logical catalogue and completed API inventory/replay association; not past claim or provider authority'}


def join_copy_original(request, association):
    """Associate a shared-decoded Copy original with its existing API inventory."""
    original = request.get('original', request)
    topology = original['topology']
    workflow = association['workflows'].get(topology['operation_id'])
    require(workflow is not None and workflow['kind'] == topology['operation_kind'],
            'Copy transport original belongs to another API operation')
    obj = association['catalogue'].get(original['path'])
    require(obj is not None, 'Copy transport path is outside the actual catalogue')
    for placement in ('source', 'destination'):
        require(count(original[placement]['registry_id']) == association['registryId']
            and original[placement]['cache_id'] is None,
            'Copy transport belongs to another registry or cache')
    if 'source_object' in original:
        require(count(original['source_object']['bytes']) == obj['byteSize']
            and (original['expected_sha256'] is None or original['expected_sha256'] == obj['sha256']),
            'Copy transport object differs from the independently retained catalogue')
    return {'operationIdSha256': sha256(topology['operation_id'].encode()),
        'objectPathSha256': sha256(original['path'].encode()),
        'catalogueObjectSha256': obj['sha256'], 'catalogueObjectBytes': obj['byteSize'],
        'apiOutcomeSha256': workflow['factsSha256'], 'scope': association['scope']}


def provider_window_partition(provider):
    """Reparse the complete retained provider window one bounded row at a time.

    This counts provider application bodies by observed caller. Repeated object
    paths remain whole-window facts; no transport-call attribution is invented.
    HTTP request/response totals are not application bytes or billing proof.
    """
    reference = provider['rawWindowReceipt']
    path = reference['file']
    start, finish = reference['before'], reference['after']
    require(all(start[field] == finish[field] for field in ('path', 'device', 'inode'))
        and count(finish['byteSize']) >= count(start['byteSize'])
        and count(finish['byteSize']) - count(start['byteSize']) == count(reference['capturedBytes']),
        'provider original log prefix is replaced, omitted or overlapping')
    expected = provider['observations']
    parser = sibling('_hub-direct-boundary')
    runtime_parser = sibling('_hub-direct-runtime-observations')
    parser._direct_runtime_integer = runtime_parser._direct_runtime_integer
    parser._direct_runtime_closed_json = runtime_parser._direct_runtime_closed_json
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    digest = hashlib.sha256()
    consumed, index, unknown = 0, 0, 0
    totals = {role: {'requestBodyBytes': 0, 'responseBodyBytes': 0, 'unknownRequestBodies': 0}
              for role in ('client', 'worker', 'native', 'provider')}
    native_calls = 0
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and before.st_mode & 0o077 == 0 and before.st_size <= PROVIDER_MAXIMUM,
            'provider retained file custody or size differs')
        while True:
            raw = source.readline(PROVIDER_ROW_MAXIMUM + 1)
            if not raw:
                break
            consumed += len(raw)
            require(len(raw) <= PROVIDER_ROW_MAXIMUM and raw.endswith(b'\n')
                and consumed <= PROVIDER_MAXIMUM and index < ROW_MAXIMUM,
                'provider window is truncated or exceeds its observation bound')
            digest.update(raw)
            parsed = parser.provider_boundary_observations(raw.decode(), provider['callers'])
            require(len(parsed['receipts']) == 1 and index < len(expected['receipts'])
                and parsed['receipts'][0] == expected['receipts'][index],
                'provider projection omits or substitutes an actual row')
            row = parsed['receipts'][0]
            unknown += parsed['unknownCallers']
            role = row['caller']
            native_calls += role == 'native'
            if role in totals:
                body = row['request_body_bytes']
                if body is None:
                    totals[role]['unknownRequestBodies'] += 1
                else:
                    totals[role]['requestBodyBytes'] += count(body)
                totals[role]['responseBodyBytes'] += count(row['response_body_bytes'])
            index += 1
        after = os.fstat(source.fileno())
    require(all(getattr(before, field) == getattr(after, field)
        for field in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
        and consumed == count(reference['capturedBytes'])
        and digest.hexdigest() == reference['sha256']
        and index == len(expected['receipts']) and unknown == expected['unknownCallers']
        and native_calls == expected['nativeProviderCalls'],
        'complete provider window changed or has omitted rows')
    return {'recordCount': index, 'rawWindowSha256': digest.hexdigest(), 'applicationBodies': totals,
        'unknownCallers': unknown, 'nativeProviderCalls': native_calls,
        'perCallAttribution': None,
        'scope': 'complete measured provider application-body window; no guessed per-control attribution or wire billing'}


def consume_external_workflow_evidence(native, worker, tools, prepared, processes,
                                      workflow, business, read_sql, *, read_private):
    """Consume the complete actual External inventory without promoting unknowns.

    The returned complete field describes supported canonical byte shape and
    observed Native content partitions. Independent current SQL and whole-window
    provider observations retain their own status; neither fabricates past IAM,
    per-call provider attribution or measured Native consumption.
    """
    report = {'version': 1, 'complete': False, 'nativeBulkBytes': None,
        'nativeConsumptionComplete': False, 'bodyPartitions': [], 'unresolved': [],
        'nativeControlBoundaryObjectBytes': None,
        'currentSqlAssociation': None, 'copyAssociation': None,
        'purposeObservation': None, 'providerPartition': None, 'outsideNativeLifetimes': [],
        'scope': 'complete External application-body assessment; separate source-point checks, current state association and provider window; no wire billing'}
    source_digest = sha256(tools['workerSourcePath'].encode())
    retained = {'bytes': 8}  # Brackets for the four bounded summary arrays.
    try:
        expected, decoded, bodies, observed, contexts = collect_external_body_rows(
            workflow, source_digest, tools['storageCodecSourceSha256'])
        body_module = sibling('_hub-managed-workflow-accounting')
        report['inventorySha256'] = workflow['coverage']['inventorySha256']
        report['originalCount'] = len(expected)
        for identity in sorted(expected):
            if identity not in decoded or identity not in bodies:
                append_summary(report['unresolved'], {'role': identity[0], 'requestId': identity[1],
                    'reason': 'missing_supported_actual_body_or_decoder'}, retained)
                continue
            partition = external_body_partition(decoded[identity], bodies[identity],
                observed.get(identity), body_module.assess_ingress_body_partition)
            partition.update(role=identity[0], requestId=identity[1])
            partition['existingFinalCheck'] = contexts.get(identity)
            append_summary(report['bodyPartitions'], partition, retained)
            for reason in partition['unresolved']:
                append_summary(report['unresolved'],
                    {'role': identity[0], 'requestId': identity[1], 'reason': reason}, retained)
        report['complete'] = not report['unresolved']
        report['nativeConsumptionComplete'] = report['complete'] and all(
            item['nativeApplicationObservation'] is not None for item in report['bodyPartitions'])
        if report['complete']:
            report['capturedObjectByteUpperBound'] = sum(
                row['canonicalPayload']['requestRawObjectBytes'] + row['canonicalPayload']['replyRawObjectBytes']
                for row in report['bodyPartitions'])
            report['semanticProjectionBytes'] = sum(
                row['canonicalPayload']['semanticOciProjectionBytes'] for row in report['bodyPartitions'])
            report['selectedDataBytes'] = sum(
                row['canonicalPayload']['selectedDataBytes'] for row in report['bodyPartitions'])
            report['capturedApplicationBodies'] = {
                'originalRequests': sum(row['capturedRequestBytes'] for row in report['bodyPartitions']),
                'fullReplies': sum(row['capturedReplyBytes'] for row in report['bodyPartitions'])}
        if report['nativeConsumptionComplete']:
            report['nativeControlBoundaryObjectBytes'] = sum(
                row['nativeObjectBytes'] for row in report['bodyPartitions'])
    except (KeyError, TypeError, ValueError, OSError) as error:
        report['complete'] = False
        report['nativeConsumptionComplete'] = False
        report['nativeBulkBytes'] = None
        report['unresolved'].append({'scope': 'body_inventory', 'reason': type(error).__name__})
    if business is None:
        report['associationFailures'] = ['business_producer_did_not_complete']
        return report
    report['associationFailures'] = []
    if business.get('issuerProcess') is not None:
        report['outsideNativeLifetimes'].append({'role': 'issuer',
            'process': {field: business['issuerProcess'][field] for field in PROCESS_FIELDS},
            'reason': 'dedicated issuer transport is outside the selected four proxy roles'})
    try:
        report['purposeObservation'] = external_helper_purpose(native, worker, tools, business, read_private)
    except (KeyError, TypeError, ValueError, OSError) as error:
        report['associationFailures'].append('purpose_' + type(error).__name__)
    copy_association = None
    try:
        copy_association = external_copy_association(native, processes['native'], business, read_private)
        report['copyAssociation'] = {key: value for key, value in copy_association.items() if key != 'catalogue'}
    except (KeyError, TypeError, ValueError, OSError) as error:
        report['associationFailures'].append('copy_' + type(error).__name__)
    mirror_accounting, mirror_cases, mirror_calls = None, {}, []
    if business is not None and business.get('mirror') is not None:
        try:
            mirror_accounting = sibling('_hub-external-mirror-accounting')
            mirror = business['mirror']
            profile_digest = mirror['purpose']['producer']['selection']['profileDigest']
            for mode, case in mirror['cases'].items():
                query = mirror_accounting.mirror_current_query(case)
                current = read_sql(query, 'external-mirror-current-' + mode.replace('_', '-'))
                require(isinstance(current, dict) and set(current) == {'value', 'receipt'},
                    'current Mirror SQL result lacks private custody')
                raw = retained_guest_bytes(native, current['receipt'], SQL_MAXIMUM, read_private)
                require(closed_json(raw) == current['value'], 'current Mirror SQL private result differs')
                mirror_cases[mode] = {**case, 'effects': {**case['effects'], 'sql': current}}
        except (KeyError, TypeError, ValueError, OSError) as error:
            report['associationFailures'].append('mirror_' + type(error).__name__)
    sql_associations, copy_calls, selected_queries = [], [], {}
    for item in report['bodyPartitions']:
        if item['role'] != 'nativeOutbound':
            continue
        identity = item['role'], item['requestId']
        decoded_row = decoded[identity]
        operation = decoded_row['operation']
        is_mirror = mirror_accounting is not None and operation in (
            mirror_accounting.MIRROR_WORK_OPERATIONS | mirror_accounting.MIRROR_GUARD_OPERATIONS)
        if not is_mirror and operation not in {'external_oci_control', 'external_oci_source',
                             'external_copy_control', 'external_copy_metadata'}:
            continue
        try:
            raw = retained_host_bytes(bodies[identity]['bodies']['request'],
                BODY_MAXIMUM if is_mirror else 64 * 1024)
            request = closed_json(raw)
            if is_mirror:
                require(len(mirror_cases) == 2, 'actual current Mirror destinations are unavailable')
                sources = mirror_accounting.mirror_request_sources(request, operation)
                require(isinstance(sources, list) and 0 < len(sources) <= 64,
                    'Mirror request source partition is empty or excessive')
                associations = [mirror_accounting.join_mirror_source_current(source,
                    mirror_cases, profile_digest) for source in sources]
                receipts = {sha256(canonical(row['currentSqlReceipt'])): row['currentSqlReceipt']
                    for row in associations}
                append_summary(mirror_calls, {'nativeRequestId': item['requestId'],
                    'sourceCount': len(sources), 'associationsSha256': sha256(canonical(associations)),
                    'currentSqlReceipts': list(receipts.values()),
                    'existingFinalContextSha256': sha256(canonical(item['existingFinalCheck']))
                        if item['existingFinalCheck'] is not None else None}, retained)
                continue
            if operation.startswith('external_copy_'):
                require(copy_association is not None, 'actual Copy API association is missing')
                append_summary(copy_calls, {'nativeRequestId': item['requestId'],
                    'association': join_copy_original(request, copy_association),
                    'existingFinalContextSha256': sha256(canonical(item['existingFinalCheck']))
                        if item['existingFinalCheck'] is not None else None}, retained)
                continue
            original = request.get('original')
            writer = original.get('writer') if isinstance(original, dict) else request.get('writer')
            upload = original.get('upload') if isinstance(original, dict) else None
            selector = sha256(canonical([writer, upload, request.get('upload_id')]))
            require(len(selected_queries) < 512 or selector in selected_queries,
                    'current SQL association selection exceeds its bound')
            if selector not in selected_queries:
                selected_queries[selector] = capture_external_current_sql(native, processes,
                    request, read_sql, read_private, 'external-accounting-' + str(len(selected_queries)))
            append_summary(sql_associations, {'nativeRequestId': item['requestId'],
                'association': selected_queries[selector],
                'existingFinalContextSha256': sha256(canonical(item['existingFinalCheck']))
                    if item['existingFinalCheck'] is not None else None}, retained)
        except (KeyError, TypeError, ValueError, OSError) as error:
            report['associationFailures'].append('current_sql_' + type(error).__name__)
    report['currentSqlAssociation'] = sql_associations
    report['mirrorCurrentSqlAssociation'] = mirror_calls
    if report['copyAssociation'] is not None:
        report['copyAssociation']['calls'] = copy_calls
    try:
        report['providerPartition'] = provider_window_partition(workflow['provider'])
    except (KeyError, TypeError, ValueError, OSError) as error:
        report['associationFailures'].append('provider_' + type(error).__name__)
    # No provider row is assigned to one repeated control without an independent
    # causal identifier. SQL rows are current associations, never past permission.
    report['independentAssociationsComplete'] = not report['associationFailures']
    # Selected proxy/frame totals exclude any dedicated issuer transport. No
    # matching outside-lifetime consumer is supplied through this interface;
    # keep whole-machine Native bytes unknown without discarding known totals.
    require(len(canonical(report)) <= ASSESSMENT_MAXIMUM, 'External assessment exceeds retained report bound')
    return report
