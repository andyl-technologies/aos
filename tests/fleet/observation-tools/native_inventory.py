"""Join exact Native frame records without promoting encoder hashes to authority.

The caller supplies messages from the selected public process/log reader. This
module verifies the source-owned chain and finite source asset projections.
Process/deployment custody and every unresolved original/auth/SQL join remain
separate. No response status, JSON shape or projection label grants metadata.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat


MARKER = 'native_application_body_inventory '
SQL_MARKER = 'native_application_sql_projection '
MAX_SQL_CHILD = 16 * 1024
MAX_RECORD = 4096
MAX_MEMBERS = 262144
BASE = {'version', 'event', 'windowId', 'policySha256', 'producerSha256'}
BEGIN = BASE | {'policy'}
END = BASE | {'started', 'terminal', 'pending', 'incomplete', 'overflow', 'chainSha256'}
MEMBER = BASE | {'admissionOrdinal', 'completionOrdinal', 'previousChainSha256',
                 'method', 'pathSha256', 'requestId', 'transportCallId', 'status',
                 'handlerReturned', 'requestConsumed', 'replyOffered',
                 'requestTrailers', 'replyTrailers', 'typedEvidence'}
FRAME = {'exposedBytes', 'exposedSha256', 'eof', 'failed', 'overflow'}
EVIDENCE = {'constructor', 'constructorSourceSha256', 'request', 'reply', 'requiredProjection'}
IMAGE = {'byteSize', 'sha256'}
ASSETS = {
    '/_assets/style.css': ('STYLESHEET', '&str', 'include_str', 'static_assets/style.css', 'stylesheet'),
    '/_assets/app.js': ('APP_JS', '&str', 'include_str', 'static_assets/app.js', 'app_js'),
    '/_assets/theme.js': ('THEME_JS', '&str', 'include_str', 'static_assets/theme.js', 'theme_js'),
    '/_assets/OFL.txt': ('FONT_LICENSE', '&str', 'include_str', 'static_assets/OFL.txt', 'font_license'),
    '/_assets/geist-sans-variable.woff2': (
        'FONT_SANS', '&[u8]', 'include_bytes', 'static_assets/Geist-Variable.woff2', 'font_sans'),
    '/_assets/geist-mono-variable.woff2': (
        'FONT_MONO', '&[u8]', 'include_bytes', 'static_assets/GeistMono-Variable.woff2', 'font_mono'),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def closed(value, names):
    if not isinstance(value, dict) or set(value) != names:
        raise ValueError('Closed inventory schema differs')


def digest(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError('Inventory digest differs')
    return value


def decimal(value):
    if not isinstance(value, str) or not re.fullmatch('0|[1-9][0-9]{0,19}', value):
        raise ValueError('Inventory count differs')
    number = int(value)
    if number > 2**64 - 1:
        raise ValueError('Inventory count exceeds bound')
    return number


def boolean(value):
    if type(value) is not bool:
        raise ValueError('Inventory boolean differs')
    return value


def policy_bytes(policy):
    """Encode only the independently checked four-field production Policy."""
    closed(policy, {'version', 'windowId', 'startUnixMillis', 'endUnixMillis'})
    if (type(policy['version']) is not int or policy['version'] != 1
            or not isinstance(policy['windowId'], str)
            or not re.fullmatch('[0-9a-f]{32}', policy['windowId'])):
        raise ValueError('Inventory policy identity differs')
    start, end = decimal(policy['startUnixMillis']), decimal(policy['endUnixMillis'])
    if end <= start or end - start > 3600000:
        raise ValueError('Inventory policy window differs')
    # All variable slots are closed ASCII hex/decimal. This is the actual
    # declared Rust field order, not a generic reserialization of member JSON.
    return ('{"version":1,"windowId":"' + policy['windowId']
            + '","startUnixMillis":"' + policy['startUnixMillis']
            + '","endUnixMillis":"' + policy['endUnixMillis'] + '"}').encode()


def producer(source, read_source):
    """Require the selected source's exact two-file producer and Policy order."""
    source = Path(source) / 'crates/aos-hub/src/server'
    body = read_source(source / 'body_inventory.rs', 1024 * 1024)
    expected = b'''struct Policy {
    version: u8,
    window_id: String,
    start_unix_millis: String,
    end_unix_millis: String,
}'''
    if (body.count(expected) != 1
            or body.count(b'hash.update(include_bytes!("body_frames.rs"));') != 1
            or body.count(b'hash.update(include_bytes!("body_inventory.rs"));') != 1):
        raise ValueError('Unsupported inventory producer schema/formula')
    return sha(read_source(source / 'body_frames.rs', 1024 * 1024) + body)


def frame(value):
    closed(value, FRAME)
    count = decimal(value['exposedBytes'])
    digest(value['exposedSha256'])
    for key in ('eof', 'failed', 'overflow'):
        boolean(value[key])
    if count == 0 and value['exposedSha256'] != sha(b''):
        raise ValueError('Zero frame count has a nonempty commitment')
    return value['eof'] and not value['failed'] and not value['overflow']


def evidence(value):
    if value is None:
        return
    closed(value, EVIDENCE)
    digest(value['constructorSourceSha256'])
    for key in ('constructor', 'requiredProjection'):
        if not isinstance(value[key], str) or len(value[key]) > 128:
            raise ValueError('Inventory constructor label differs')
    for key in ('request', 'reply'):
        image = value[key]
        if image is None and key == 'request':
            continue
        closed(image, IMAGE)
        decimal(image['byteSize'])
        digest(image['sha256'])


def validate(messages, policy, selected_producer, parse_json):
    """Verify raw source-owned membership; messages must retain their raw JSON."""
    policy_sha = sha(policy_bytes(policy))
    digest(selected_producer)
    members, seen, chain = [], set(), bytes(32)
    begun, ended, end = False, False, None
    children = []
    child_bytes = 0
    for message, _timestamp in messages:
        if isinstance(message, str) and SQL_MARKER in message:
            if message.count(SQL_MARKER) != 1:
                raise ValueError('Ambiguous SQL child marker')
            raw_child = message.split(SQL_MARKER, 1)[1].encode()
            if len(raw_child) > MAX_SQL_CHILD or child_bytes + len(raw_child) > 64 * 1024 * 1024:
                raise ValueError('SQL child capture exceeds bound')
            child = parse_json(raw_child)
            if isinstance(child, dict) and child.get('windowId') == policy['windowId']:
                children.append((child, raw_child))
                child_bytes += len(raw_child)
            continue
        if not isinstance(message, str) or MARKER not in message:
            continue
        if message.count(MARKER) != 1:
            raise ValueError('Ambiguous inventory marker')
        raw = message.split(MARKER, 1)[1].encode()
        if len(raw) > MAX_RECORD:
            raise ValueError('Inventory member exceeds record bound')
        row = parse_json(raw)
        if not isinstance(row, dict):
            raise ValueError('Inventory event is not an object')
        if row.get('windowId') != policy['windowId']:
            continue
        kind = row.get('event')
        names = {'begin': BEGIN, 'member': MEMBER, 'end': END}.get(kind, set())
        if kind == 'member' and 'sqlProjection' in row:
            names = names | {'sqlProjection'}
            closed(row['sqlProjection'], IMAGE)
            decimal(row['sqlProjection']['byteSize'])
            digest(row['sqlProjection']['sha256'])
            if decimal(row['sqlProjection']['byteSize']) > MAX_SQL_CHILD:
                raise ValueError('SQL child image exceeds source bound')
        closed(row, names)
        if (type(row['version']) is not int or row['version'] != 1
                or row['policySha256'] != policy_sha
                or row['producerSha256'] != selected_producer or ended):
            raise ValueError('Inventory source/window/event differs')
        if kind == 'begin':
            if begun or row['policy'] != policy:
                raise ValueError('Duplicate or changed inventory begin')
            begun = True
        elif kind == 'member':
            if not begun or len(members) >= MAX_MEMBERS:
                raise ValueError('Inventory lacks bounded begin')
            admission = decimal(row['admissionOrdinal'])
            if (admission == 0 or admission in seen
                    or decimal(row['completionOrdinal']) != len(members) + 1
                    or row['previousChainSha256'] != chain.hex()):
                raise ValueError('Inventory member ordinal/chain differs')
            seen.add(admission)
            digest(row['pathSha256'])
            if not isinstance(row['method'], str) or not re.fullmatch('[A-Z]{1,32}', row['method']):
                raise ValueError('Unsupported inventory method')
            for key in ('requestId', 'transportCallId'):
                if row[key] is not None and (not isinstance(row[key], str)
                        or not re.fullmatch('[0-9a-f]{32}', row[key])):
                    raise ValueError('Inventory correlation differs')
            if row['status'] is not None and (type(row['status']) is not int or not 100 <= row['status'] <= 599):
                raise ValueError('Inventory status differs')
            for key in ('handlerReturned', 'requestTrailers', 'replyTrailers'):
                boolean(row[key])
            frame(row['requestConsumed'])
            frame(row['replyOffered'])
            evidence(row['typedEvidence'])
            chain = hashlib.sha256(chain + len(raw).to_bytes(8, 'big') + raw).digest()
            members.append(row)
        else:
            if not begun:
                raise ValueError('Inventory end precedes begin')
            ended, end = True, row
    missing = []
    if not begun or not ended:
        missing.append('missing_actual_inventory_begin_or_settled_end')
    if end is not None:
        started, terminal = decimal(end['started']), decimal(end['terminal'])
        if started > MAX_MEMBERS:
            raise ValueError('Inventory final count exceeds reader bound')
        pending, incomplete = decimal(end['pending']), decimal(end['incomplete'])
        boolean(end['overflow'])
        digest(end['chainSha256'])
        if (terminal != len(members) or terminal != started
                or sorted(seen) != list(range(1, started + 1))
                or chain.hex() != end['chainSha256']):
            raise ValueError('Inventory final membership/chain differs')
        actual_incomplete = sum(not (row['handlerReturned']
            and frame(row['requestConsumed']) and frame(row['replyOffered'])
            and not row['requestTrailers'] and not row['replyTrailers']) for row in members)
        if incomplete != actual_incomplete:
            raise ValueError('Inventory incomplete count differs')
        if pending or incomplete or end['overflow']:
            missing.append('unsettled_unread_failed_overflow_or_trailer_frames')
    return {'inventoryComplete': not missing, 'members': members, 'missing': missing,
            'chainSha256': chain.hex(), 'nativeBulkBytes': None, 'sqlChildren': children}



def sql_child(member, children, source, read_source):
    """Match exact raw child bytes to one complete actual inventory member.

    This is source checkpoint evidence only. The independent SQL reader and
    earlier authority dimensions stay unresolved until separately observed.
    """
    expected = member.get('sqlProjection')
    if expected is None:
        return None
    candidates = [(value, raw) for value, raw in children
                  if value.get('admissionOrdinal') == member['admissionOrdinal']]
    if len(candidates) != 1:
        raise ValueError('SQL child is missing or duplicated for selected member')
    child, raw = candidates[0]
    closed(child, BASE | {'admissionOrdinal', 'method', 'pathSha256', 'requestId',
                         'transportCallId', 'status', 'typedEvidence', 'projection'})
    if (sha(raw) != expected['sha256'] or str(len(raw)) != expected['byteSize']
            or type(child['version']) is not int or child['version'] != 1
            or child['event'] != 'sql_projection'
            or any(child[key] != member[key] for key in (
                'windowId', 'policySha256', 'producerSha256', 'admissionOrdinal',
                'method', 'pathSha256', 'requestId', 'transportCallId', 'status', 'typedEvidence'))
            or member['status'] != 200 or not member['handlerReturned']
            or member['requestTrailers'] or member['replyTrailers']
            or not frame(member['requestConsumed']) or not frame(member['replyOffered'])):
        raise ValueError('SQL child actual source/body/member differs')
    projection = child['projection']
    closed(projection, {'version', 'producerSha256', 'checkpoints'})
    paths = (
        'crates/aos-hub-core/src/application_body_observation/sql_projection.rs',
        'crates/aos-hub-core/src/application_body_observation.rs',
        'crates/aos-hub-core/src/application_body_observation/rpc.rs',
        'crates/aos-hub-core/src/db/direct_upload.rs',
        'crates/aos-hub-core/src/db/publication_admission.rs',
    )
    actual_source = sha(b''.join(read_source(Path(source) / path, 1024 * 1024) for path in paths))
    if (type(projection['version']) is not int or projection['version'] != 1
            or projection['producerSha256'] != actual_source
            or not isinstance(projection['checkpoints'], list)
            or not 1 <= len(projection['checkpoints']) <= 32):
        raise ValueError('SQL checkpoint source/count differs')
    # The exact nested source image is already covered by the raw child hash.
    # Enforce the source's 12 KiB aggregate without a Python reserialization.
    decoder = json.JSONDecoder()
    nested_start = raw.find(b'"projection":')
    if nested_start < 0:
        raise ValueError('SQL projection source field is absent')
    nested = raw[nested_start + len(b'"projection":'):].decode()
    decoded, end = decoder.raw_decode(nested)
    if decoded != projection or len(nested[:end].encode()) > 12 * 1024:
        raise ValueError('SQL checkpoint aggregate exceeds source bound')
    kinds = set()
    common = {'kind', 'sourceBeforeUnixNanos', 'sourceAfterUnixNanos', 'sourceElapsedNanos'}
    fields = {
        'admission_checked_transaction': {'deploymentSha256', 'sessionId', 'admission',
            'ownerScopeSha256', 'owner', 'checkedAt', 'observedStatusResourceVersion',
            'observedState', 'retainedOriginal', 'iamPredicateCount'},
        'manifest_append_checked_transaction': {'publicationId', 'registryId', 'leaseTokenSha256',
            'manifestDigest', 'chunkIndex', 'chunkDigest', 'objectCount', 'checkedAt',
            'expectedResourceVersion', 'expectedAdmittedObjectCount', 'expectedLeaseExpiresAt'},
        'manifest_append_retained_receipt': {'publicationId', 'registryId', 'leaseTokenSha256',
            'manifestDigest', 'chunkIndex', 'chunkDigest', 'objectCount', 'observedSessionResourceVersion'},
    }
    for checkpoint in projection['checkpoints']:
        kind = checkpoint.get('kind')
        if kind not in fields:
            raise ValueError('Unsupported SQL checkpoint kind')
        closed(checkpoint, common | fields[kind])
        kinds.add(kind)
        for key in ('sourceBeforeUnixNanos', 'sourceAfterUnixNanos', 'sourceElapsedNanos'):
            decimal(checkpoint[key])
        if decimal(checkpoint['sourceAfterUnixNanos']) < decimal(checkpoint['sourceBeforeUnixNanos']):
            raise ValueError('SQL operation source clock rolled back')
    constructor = member['typedEvidence']['constructor'] if member['typedEvidence'] else None
    allowed = ({'admission_checked_transaction'} if constructor == 'direct_logical_validated'
               else {'manifest_append_checked_transaction', 'manifest_append_retained_receipt'}
               if constructor == 'publication_manifest_append' else set())
    if not kinds <= allowed or not allowed:
        raise ValueError('SQL checkpoint actual encoder constructor differs')
    return {'rawChildSha256': sha(raw), 'rawChildByteSize': str(len(raw)),
            'checkpoints': projection['checkpoints'], 'objectPayloadBytes': None,
            'readerAuthority': 'not_checked',
            'missing': ['independent_sql_reader_process_database_window_and_typed_original_join',
                        'prior_operation_authority_not_reconstructed_by_later_reader']}


def sql_reader_projection(checkpoint, codec, selected, readers, source, read_source, sidecar):
    """Match retained independent reader rows without attributing past fences.

    Source-checked collector invocation custody remains a separate dimension.
    No selected JSON value can assert that a live process or prior IAM was read.
    """
    if checkpoint is None or codec is None or selected is None:
        return None
    original_images = codec['codecProjection'].get('sqlOriginals')
    if original_images is None:
        return None
    collection = readers['closed_json'](readers['read_ref'](selected, 64 * 1024 * 1024))
    closed(collection, {'version', 'observations', 'objectPayloadBytes', 'missing'})
    if type(collection['version']) is not int or collection['version'] != 1 or collection['objectPayloadBytes'] is not None:
        raise ValueError('SQL reader collection schema differs')
    candidates = [value for value in collection['observations']
                  if value['controller']['sourceChild']['rawChildSha256'] == checkpoint['rawChildSha256']]
    if not candidates:
        return None
    if len(candidates) != 1:
        raise ValueError('SQL child has duplicated independent reader observations')
    bundle = candidates[0]
    closed(bundle, {'rows', 'receipt', 'codecImages', 'scope', 'objectPayloadBytes', 'controller'})
    if bundle['objectPayloadBytes'] is not None:
        raise ValueError('SQL reader observation invents payload accounting')
    receipt = bundle['receipt']
    closed(receipt, {'version', 'query', 'rows', 'stderrSha256', 'exitCode', 'readerProcess',
                     'psqlExecutableSha256', 'databaseUrlSha256', 'before', 'after', 'selection', 'backendProcess', 'redactedArgv', 'processesBefore', 'processesAfter'})
    if (type(receipt['version']) is not int or receipt['version'] != 2
            or type(receipt['exitCode']) is not int or receipt['exitCode'] != 0):
        raise ValueError('SQL reader process did not complete successfully')
    selection = receipt['selection']
    if receipt['redactedArgv'] != [selection['psql'], '-X', '--no-password', '-qAt', '-v', 'ON_ERROR_STOP=1']:
        raise ValueError('SQL reader argv differs from exact source command')
    closed(selection['databaseProcess'], {'pid', 'ownerUid', 'startTicks', 'executableSha256'})
    digest(selection['databaseProcess']['executableSha256'])
    for values in (receipt['processesBefore'], receipt['processesAfter']):
        closed(values, {'databaseProcess'})
        if values['databaseProcess'] != selection['databaseProcess']:
            raise ValueError('Database process lifetime changed across SQL read')
    controller = bundle['controller']
    closed(controller, {'nativeBefore', 'nativeAfter', 'databaseBefore', 'databaseAfter',
        'connectionMode', 'collectorSourceSha256', 'receivedImages', 'sourceChild'})
    if (controller['connectionMode'] != 'existing_select_only_role_over_database_loopback_trust'
            or controller['sourceChild'] != {'rawChildSha256': checkpoint['rawChildSha256'],
                'rawChildByteSize': checkpoint['rawChildByteSize']}):
        raise ValueError('SQL reader source child or trust mode differs')
    actual_native = sidecar.get('nativeProcess')
    if actual_native is None:
        return None
    for name in ('nativeBefore', 'nativeAfter'):
        closed(controller[name]['observed'], {'process', 'bootId', 'database', 'port', 'resolvedAddresses', 'connectionFileSha256'})
        digest(controller[name]['observed']['connectionFileSha256'])
        if controller[name]['observed']['database'] != selection['database']:
            raise ValueError('SQL Native actual database name differs')
        for key in ('pid', 'startTicks', 'executableSha256'):
            if controller[name]['observed']['process'][key] != actual_native.get(key):
                raise ValueError('SQL Native guest bracket differs from actual body/log process')
    if (controller['nativeBefore']['guestName'] != controller['nativeAfter']['guestName']
            or controller['databaseBefore']['guestName'] != controller['databaseAfter']['guestName']
            or controller['nativeBefore']['guestName'] == controller['databaseBefore']['guestName']):
        raise ValueError('SQL collector conflates Native and Database guests')
    for name in ('databaseBefore', 'databaseAfter'):
        closed(controller[name]['observed'], {'process', 'bootId', 'postmasterFileSha256', 'dataDirectory', 'port', 'resolvedAddresses'})
        digest(controller[name]['observed']['postmasterFileSha256'])
        if controller[name]['observed']['dataDirectory'] != '/var/lib/hybrid-postgres':
            raise ValueError('SQL selected fixture data directory differs')
    previous = None
    for name in ('nativeBefore', 'databaseBefore', 'databaseAfter', 'nativeAfter'):
        bracket = controller[name]
        closed(bracket, {'guestName', 'controllerBefore', 'controllerAfter', 'observed'})
        for field in ('controllerBefore', 'controllerAfter'):
            closed(bracket[field], {'wallNs', 'monotonicNs'})
            decimal(bracket[field]['wallNs']); decimal(bracket[field]['monotonicNs'])
        if (decimal(bracket['controllerAfter']['monotonicNs']) < decimal(bracket['controllerBefore']['monotonicNs'])
                or decimal(bracket['controllerAfter']['wallNs']) < decimal(bracket['controllerBefore']['wallNs'])
                or (previous is not None and decimal(bracket['controllerBefore']['monotonicNs']) < previous)):
            raise ValueError('Controller SQL guest observation bracket rolled back')
        previous = decimal(bracket['controllerAfter']['monotonicNs'])
    def read_image(reference, maximum):
        matches = [item for item in controller['receivedImages'] if item['guestReference'] == reference]
        if len(matches) != 1:
            raise ValueError('SQL guest image lacks unique controller-received commitment')
        received = matches[0]['controllerReference']
        if any(reference[key] != received[key] for key in ('sha256', 'byteSize')):
            raise ValueError('SQL controller bytes differ from Database guest bytes')
        return readers['read_ref'](received, maximum)
    closed(receipt['readerProcess'], {'pid', 'ownerUid', 'startTicks', 'executableSha256'})
    if receipt['readerProcess']['executableSha256'] != receipt['psqlExecutableSha256']:
        raise ValueError('SQL executed reader image differs from selected tool')
    for key in ('before', 'after'):
        closed(receipt[key], {'wallNs', 'monotonicNs'})
        decimal(receipt[key]['wallNs']); decimal(receipt[key]['monotonicNs'])
    before, after = receipt['before'], receipt['after']
    if (decimal(after['wallNs']) < decimal(before['wallNs'])
            or decimal(after['monotonicNs']) < decimal(before['monotonicNs'])
            or not decimal(selection['windowStartUnixNanos']) <= decimal(before['wallNs'])
                <= decimal(after['wallNs']) <= decimal(selection['windowEndUnixNanos'])):
        raise ValueError('SQL reader actual clock/window differs')
    # Execute only the selected immutable source collector's pure query/row
    # validators. It does not execute SQL, processes or supplied Python here.
    path = Path(source) / 'tests/fleet/_hub-native-sql-projection.py'
    namespace = {'__file__': str(path), '__name__': 'selected_sql_reader_contract'}
    raw_source = read_source(path, 1024 * 1024)
    if sha(raw_source) != controller['collectorSourceSha256'] or sha(raw_source) != selection['collectorSourceSha256']:
        raise ValueError('SQL collector source differs from selected immutable reader')
    exec(compile(raw_source, str(path), 'exec'), namespace)
    namespace['native_sql_topology'](controller['nativeBefore']['observed'], controller['nativeAfter']['observed'],
        controller['databaseBefore']['observed'], controller['databaseAfter']['observed'])
    if (controller['databaseBefore']['observed']['process'] != selection['databaseProcess']
            or controller['databaseBefore']['observed']['bootId'] != selection['databaseBootId']):
        raise ValueError('SQL backend selected Database differs from controller guest observation')
    query = namespace['native_sql_query'](checkpoint['checkpoints'], selection['deployment'], selection['role'])
    query_raw = read_image(receipt['query'], 32 * 1024)
    if query_raw != query.encode():
        raise ValueError('SQL retained query differs from exact source-selected keys')
    if receipt['backendProcess'] is None:
        return None
    closed(receipt['backendProcess'], {'pid', 'ownerUid', 'startTicks', 'executableSha256', 'parentPid'})
    if (receipt['backendProcess']['parentPid'] != selection['databaseProcess']['pid']
            or receipt['backendProcess']['executableSha256'] != selection['databaseProcess']['executableSha256']
            or receipt['backendProcess']['ownerUid'] != selection['databaseProcess']['ownerUid']):
        raise ValueError('SQL backend process differs from selected PostgreSQL executable/owner')
    rows_raw = read_image(receipt['rows'], 512 * 1024)
    rows = namespace['native_sql_rows'](rows_raw, selection, checkpoint['checkpoints'])
    if receipt['backendProcess']['pid'] != rows['backendPid']:
        raise ValueError('SQL actual queried backend differs from process receipt')
    if rows != bundle['rows']:
        raise ValueError('SQL selected rows differ from actual raw output')
    images = bundle['codecImages']
    closed(images, {'admissions', 'chunks'})
    candidates = [images['admissions']] + images['chunks']
    matches = [ref for ref in candidates if ref['sha256'] == codec['codecProjection']['sqlEvidenceSha256']]
    if len(matches) != 1:
        raise ValueError('Typed SQL codec is not bound to one actual reader image')
    codec_raw = read_image(matches[0], 512 * 1024)
    if rows['admissions']:
        parsed = [readers['closed_json'](line) for line in codec_raw.splitlines()]
        if parsed != rows['admissions']:
            raise ValueError('Core-decoded admissions differ from retained raw SQL rows')
    elif len(rows['chunks']) != 1 or readers['closed_json'](codec_raw) != rows['chunks'][0]:
        raise ValueError('Core-decoded chunk differs from retained raw SQL row')
    matched = []
    for operation in checkpoint['checkpoints']:
        admission = operation['kind'] == 'admission_checked_transaction'
        candidates = [row for row in original_images if (
            row.get('kind') == 'admission' and admission and row.get('sessionId') == operation['sessionId'])
            or (not admission and row.get('kind') == 'manifest_chunk'
                and row.get('publicationId') == operation['publicationId']
                and str(row.get('chunkIndex')) == operation['chunkIndex'])]
        if len(candidates) != 1:
            raise ValueError('SQL operation has missing or duplicated typed original')
        row = candidates[0]
        if admission:
            if operation['deploymentSha256'] != sha(selection['deployment'].encode()):
                raise ValueError('SQL selected deployment differs from actual source operation')
            if (row['admission'] != operation['admission'] or row['owner'] != operation['owner']
                    or row['ownerScopeSha256'] != operation['ownerScopeSha256']):
                raise ValueError('SQL immutable admission/owner differs from source operation')
        elif (row['chunkDigest'] != operation['chunkDigest']
              or str(row['objectCount']) != operation['objectCount']
              or row['registryId'] != operation['registryId']
              or row['manifestDigest'] != operation['manifestDigest']):
            raise ValueError('SQL immutable chunk differs from source operation')
        matched.append({'kind': operation['kind'], 'readerTimeOriginal': row})
    return {'class': 'matched_source_operation_and_independent_reader_time_values',
            'matched': matched, 'rawRowsSha256': sha(rows_raw), 'readerBackendPid': rows['backendPid'],
            'readerDatabase': rows['database'], 'readerRole': rows['user'],
            'readerSnapshot': rows['snapshot'], 'objectPayloadBytes': None,
            'missing': ['independent_collector_invocation_and_database_instance_custody',
                        'prior_operation_iam_or_lease_not_reconstructed_by_later_reader',
                        'cross_machine_clock_uncertainty_and_original_authenticated_body_join']}

def source_asset(member, source, read_source):
    """Match only a concrete source-embedded public asset, never dynamic HTML."""
    value = member['typedEvidence']
    if (value is None or member['method'] != 'GET' or member['status'] != 200
            or not member['handlerReturned'] or value['request'] is not None
            or member['requestConsumed']['exposedBytes'] != '0'
            or member['requestTrailers'] or member['replyTrailers']
            or not frame(member['requestConsumed']) or not frame(member['replyOffered'])
            or value['constructor'] != 'embedded_static_asset'
            or value['requiredProjection'] != 'exact_installed_console_asset_names_and_bytes'):
        return None
    directory = Path(source) / 'crates/aos-hub-core/src/web'
    code = read_source(directory / 'assets.rs', 1024 * 1024)
    if value['constructorSourceSha256'] != sha(code):
        return None
    routes = read_source(Path(source) / 'crates/aos-hub-core/src/connect.rs', 1024 * 1024)
    for path, (constant, kind, macro, relative, handler) in ASSETS.items():
        if member['pathSha256'] != sha(path.encode()):
            continue
        declaration = f'pub const {constant}: {kind} = {macro}!("{relative}");'.encode()
        route = f'.route("{path}", get(assets::{handler}))'.encode()
        if code.count(declaration) != 1 or routes.count(route) != 1:
            return None
        body = read_source(directory / relative, 8 * 1024 * 1024)
        image = {'byteSize': str(len(body)), 'sha256': sha(body)}
        reply = member['replyOffered']
        if (value['reply'] != image or reply['exposedBytes'] != image['byteSize']
                or reply['exposedSha256'] != image['sha256']):
            return None
        return {'class': 'exact_source_embedded_public_asset', 'requestDataBytes': '0',
                'replyDataBytes': '0', 'bodySha256': image['sha256']}
    return None


def codec_projection(member, report, manifest, authentication, source, read_source):
    """Match actual typed decoder output; missing authority dimensions stay null.

    The caller supplies its actual successful, source-pinned codec invocation.
    This function does not authenticate a supplied report or a SQL reader.
    """
    if report is None or member['requestId'] is None:
        return None
    closed(report, {'version', 'codecRevision', 'selectedSourceDigest', 'manifestSha256',
                    'selectedBodyBytes', 'maximumSelectedBodyBytes', 'maximumBodyBytes', 'captures'})
    if (type(report['version']) is not int or report['version'] != 1 or report['codecRevision'] != manifest['codecRevision']
            or report['selectedSourceDigest'] != manifest['sourceDigest']):
        raise ValueError('Inventory codec runtime differs')
    if not isinstance(report['captures'], list) or len(report['captures']) > MAX_MEMBERS:
        raise ValueError('Inventory codec capture bound differs')
    identifier = sha(member['requestId'].encode())
    rows = [row for row in report['captures'] if row['requestIdSha256'] == identifier]
    if not rows:
        return None
    if len(rows) != 1:
        raise ValueError('Inventory codec member ownership differs')
    row = rows[0]
    selected = [capture for capture in manifest['captures']
                if capture['requestId'] == member['requestId']]
    if len(selected) != 1:
        raise ValueError('Inventory selected capture ownership differs')
    capture = selected[0]
    if (type(capture['status']) is not int or capture['status'] != member['status']
            or capture['method'] != member['method'] or capture['procedure'] != row['procedure']
            or capture['phase'] != row['phase']):
        raise ValueError('Inventory selected capture status or route differs')
    value = member['typedEvidence']
    projection = row.get('immutableProjection')
    if value is None or projection is None:
        return None
    closed(projection, {'version', 'kind', 'originalRequestSha256', 'sqlEvidenceSha256',
                       'matchedOriginalCount', 'requestControlBytes', 'replyControlBytes',
                       'objectPayloadBytes', 'sqlReaderAuthority', 'missing'}
                       | ({'sqlOriginals'} if 'sqlOriginals' in projection else set()))
    if (not member['handlerReturned'] or member['requestTrailers'] or member['replyTrailers']
            or not frame(member['requestConsumed']) or not frame(member['replyOffered'])
            or row['method'] != member['method'] or sha(row['procedure'].encode()) != member['pathSha256']
            or row['authentication'] != 'not_checked_join_independent_authenticated_worker_receipt'):
        raise ValueError('Inventory codec frame or route differs')
    for direction, actual in (('request', 'requestConsumed'), ('response', 'replyOffered')):
        image = row[direction]
        closed(image, {'sha256', 'byteSize', 'typedSemanticSha256'})
        selected_image = capture['bodies'][direction]
        if (selected_image['sha256'] != image['sha256']
                or selected_image['byteSize'] != image['byteSize']):
            raise ValueError('Inventory selected capture image differs')
        if (image['sha256'] != member[actual]['exposedSha256']
                or image['byteSize'] != member[actual]['exposedBytes']
                or image['typedSemanticSha256'] != image['sha256']):
            raise ValueError('Inventory codec body differs from actual frames')
    if value['request'] != {'byteSize': row['request']['byteSize'], 'sha256': row['request']['sha256']}:
        raise ValueError('Inventory constructor request image differs')
    if value['reply'] != {'byteSize': row['response']['byteSize'], 'sha256': row['response']['sha256']}:
        raise ValueError('Inventory constructor reply image differs')
    if projection['kind'] == 'publication_manifest_append':
        files = ('crates/aos-hub-core/src/application_body_observation.rs',
                 'crates/aos-hub-core/src/application_body_observation/rpc.rs',
                 'crates/aos-hub-core/src/connect.rs')
        constructor, phase = 'publication_manifest_append', None
    elif projection['kind'] == 'direct_logical_admission':
        files = ('crates/aos-hub/src/direct_upload/mod.rs',)
        constructor, phase = 'direct_logical_validated', 'admission'
    else:
        raise ValueError('Unsupported immutable codec projection')
    expected = sha(b''.join(read_source(Path(source) / path, 1024 * 1024) for path in files))
    if value['constructor'] != constructor or value['constructorSourceSha256'] != expected or row['phase'] != phase:
        raise ValueError('Inventory actual constructor source/phase differs')
    if (type(projection['version']) is not int or projection['version'] != 1 or projection['objectPayloadBytes'] is not None
            or projection['originalRequestSha256'] != row['request']['sha256']
            or projection['requestControlBytes'] != row['request']['byteSize']
            or projection['replyControlBytes'] != row['response']['byteSize']
            or projection['sqlReaderAuthority'] != 'not_checked_join_measured_read_only_source_process_and_window'
            or projection['missing'] != ['independent_sql_reader_custody_and_temporal_current_fences']
            or not 0 < decimal(projection['matchedOriginalCount']) <= 256):
        raise ValueError('Immutable projection invents authority or byte accounting')
    digest(projection['sqlEvidenceSha256'])
    matches = [item for item in authentication.get('captures', []) if item['requestIdSha256'] == identifier]
    checked = (len(matches) == 1 and matches[0]['sourceCheckedAuthentication']
               == 'observed_native_checked_envelope_and_body')
    missing = list(projection['missing'])
    if not checked:
        missing.append('independent_actual_authenticated_control_or_ingress_join')
    return {'class': 'matched_immutable_codec_values', 'codecProjection': projection,
            'sourceCheckedIngress': checked, 'objectPayloadBytes': None, 'missing': missing}


def selected_messages(sidecar, readers):
    """Reuse the existing measured Native log reader and held private inode.

    Absent provider/process custody is an unresolved input. This function does
    not invent host process facts for a provider-managed container instance.
    """
    log, process = sidecar.get('nativeLog'), sidecar.get('nativeProcess')
    if log is None or process is None:
        return None, 'missing_actual_native_instance_executable_and_window_custody'
    if log.get('format') not in ('plain', 'journal'):
        return None, 'unsupported_provider_log_instance_custody'
    # This performs the unchanged process/epoch, source and private-log checks.
    readers['ingress_events'](sidecar)
    epoch = log['epoch']
    if epoch is None or (log['format'] == 'plain' and log['provenance'] is None):
        return None, 'missing_actual_native_log_epoch_brackets'

    def bracketed(messages):
        for message, timestamp in messages:
            if (timestamp is not None and not int(epoch['firstUnixMicros'])
                    <= int(timestamp) <= int(epoch['lastUnixMicros'])):
                raise ValueError('Inventory message lies outside actual selected epoch')
            yield message, timestamp

    if log['format'] == 'journal':
        source_reader = readers['source_readers']().__globals__['observed_native_messages']
        raw = readers['read_ref'](log['reference'], 256 * 1024 * 1024)
        return bracketed(source_reader(raw.decode(), process)), None

    def held_messages():
        reference = log['reference']
        descriptor = os.open(reference['file'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as held:
            before = os.fstat(held.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                    or before.st_mode & 0o077 or before.st_size > 256 * 1024 * 1024):
                raise ValueError('Inventory private log custody differs')
            raw = held.read(256 * 1024 * 1024 + 1)
            if (str(len(raw)) != reference['byteSize'] or sha(raw) != reference['sha256']
                    or log['provenance']['window']['sha256'] != reference['sha256']):
                raise ValueError('Inventory selected log commitment differs')
            source_reader = readers['source_readers'](
                (held.fileno(), reference['file'])).__globals__['observed_native_messages']
            yield from bracketed(source_reader(Path(reference['file']), process, log['provenance']))
            after = os.fstat(held.fileno())
            if any(getattr(before, key) != getattr(after, key) for key in
                   ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
                raise ValueError('Held inventory log changed across verified reads')
    return held_messages(), None


def assess(selection, source, readers, read_source, manifest, codec_report=None):
    """Assess one selected inbound window while preserving all unresolved joins."""
    closed(selection, {'policy', 'sidecar'}
           | ({'sqlReaderObservation'} if 'sqlReaderObservation' in selection else set()))
    policy_raw = readers['read_ref'](selection['policy'], 1024)
    policy = readers['closed_json'](policy_raw)
    if policy_bytes(policy) != policy_raw:
        raise ValueError('Selected Policy is not the exact production encoding')
    sidecar = readers['closed_json'](readers['read_ref'](selection['sidecar'], 1024 * 1024))
    # Reuse the full existing runtime/source/provenance validation with the
    # actual selected manifest. Its authentication result is never inferred
    # from inventory or used as a blanket member classification.
    authentication = readers['assess'](sidecar, manifest)
    messages, missing = selected_messages(sidecar, readers)
    if messages is None:
        return {'inventoryComplete': False, 'nativeBulkBytes': None,
                'inboundObjectPayloadBytes': None, 'members': [], 'missing': [missing]}
    result = validate(messages, policy, producer(source, read_source), readers['closed_json'])
    children = result.pop('sqlChildren', [])
    projections = []
    for member in result['members']:
        projection = source_asset(member, source, read_source)
        if projection is None:
            projection = codec_projection(member, codec_report, manifest, authentication or {}, source, read_source)
            if projection is not None:
                result['missing'].extend(projection['missing'])
        checkpoint = sql_child(member, children, source, read_source)
        reader_projection = sql_reader_projection(checkpoint, projection,
            selection.get('sqlReaderObservation'), readers, source, read_source, sidecar)
        projections.append({'admissionOrdinal': member['admissionOrdinal'],
                            'projection': projection, 'sqlCheckpoint': checkpoint,
                            'sqlReaderProjection': reader_projection})
        if reader_projection is not None:
            result['missing'].extend(reader_projection['missing'])
        if checkpoint is not None:
            result['missing'].extend(checkpoint['missing'])
        if projection is None:
            result['missing'].append('unjoined_original_body_auth_sql_or_template_projection:'
                                     + member['admissionOrdinal'])
    result['projections'] = projections
    # This number covers only fully projected inbound data frames. Existing
    # outbound receiver/control joins remain mandatory for the whole Native sum.
    result['inboundObjectPayloadBytes'] = ('0' if result['inventoryComplete']
        and all(row['projection'] is not None
                and row['projection']['class'] == 'exact_source_embedded_public_asset'
                for row in projections) else None)
    result['nativeBulkBytes'] = None
    result['missing'].extend([
        'loaded_window_to_native_utc_policy_bridge_and_clock_uncertainty',
        'independent_native_outbound_original_auth_sql_and_body_coverage',
    ])
    result['scope'] = 'selected_native_inbound_consumed_and_offered_data_frames'
    return result
