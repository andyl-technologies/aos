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
PHASE_MARKER = 'native_application_publication_phases '
MAX_SQL_CHILD = 96 * 1024
MAX_SQL_PROJECTION = 64 * 1024
MAX_SQL_CHECKPOINTS = 64
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
    phase_children = []
    child_bytes = 0
    for message, _timestamp in messages:
        if isinstance(message, str) and PHASE_MARKER in message:
            if message.count(PHASE_MARKER) != 1:
                raise ValueError('Ambiguous publication phase marker')
            phase_raw = message.split(PHASE_MARKER, 1)[1].encode()
            if len(phase_raw) > MAX_SQL_CHILD or child_bytes + len(phase_raw) > 64 * 1024 * 1024:
                raise ValueError('Publication phase capture exceeds existing child/corpus bound')
            phase_child = parse_json(phase_raw)
            if isinstance(phase_child, dict) and phase_child.get('windowId') == policy['windowId']:
                phase_children.append((phase_child, phase_raw))
                child_bytes += len(phase_raw)
            continue
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
        if kind == 'member' and 'queryClass' in row:
            names = names | {'queryClass'}
            if row['queryClass'] not in ('absent', 'present'):
                raise ValueError('Inventory query presence differs')
        if kind == 'member' and 'publicationPhases' in row:
            names = names | {'publicationPhases'}
            closed(row['publicationPhases'], IMAGE)
            decimal(row['publicationPhases']['byteSize'])
            digest(row['publicationPhases']['sha256'])
            if decimal(row['publicationPhases']['byteSize']) > MAX_SQL_CHILD:
                raise ValueError('Publication phase child image exceeds source bound')
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
            'chainSha256': chain.hex(), 'nativeBulkBytes': None, 'sqlChildren': children,
            'publicationPhaseChildren': phase_children}




def source_leaf_bound(path):
    """Allow only the two named existing giant producer source files."""
    return (2 * 1024 * 1024 if path in (
        'crates/aos-hub-core/src/service.rs', 'crates/aos-hub-core/src/db/mod.rs')
        else 1024 * 1024)


def encoded_image(value):
    closed(value, IMAGE)
    decimal(value['byteSize'])
    digest(value['sha256'])


def dynamic_observation(value):
    """Check the finite producer DTO without inventing independent authority."""
    families = {
        'publication_get': {'publicationId', 'registryId', 'ordinal', 'state',
            'manifestDigest', 'refsDigest', 'registryScopeSha256', 'actor', 'reply'},
        'direct_authorize': {'sessionId', 'requestContext', 'selectedOriginal', 'action',
            'completeStep', 'admission', 'returnedStatus', 'baselinePermissions',
            'observedState', 'observedResourceVersion'},
        'direct_commit': {'sessionId', 'deploymentSha256', 'admission', 'completeOriginal',
            'completionEvidence', 'finalGuards', 'expectedResourceVersion',
            'resultingResourceVersion', 'checkedStatements', 'checkedStatementCount', 'retainedOriginal'},
    }
    if not isinstance(value, dict) or value.get('operation') not in families:
        raise ValueError('Unsupported dynamic operation')
    operation = value['operation']
    closed(value, families[operation] | {'operation'})
    images = {
        'publication_get': ('actor', 'reply'),
        'direct_authorize': ('requestContext', 'selectedOriginal', 'admission', 'returnedStatus', 'baselinePermissions'),
        'direct_commit': ('admission', 'completeOriginal', 'completionEvidence', 'finalGuards'),
    }
    for field in images[operation]:
        encoded_image(value[field])
    identifier = 'publicationId' if operation == 'publication_get' else 'sessionId'
    if not isinstance(value[identifier], str) or not re.fullmatch('[A-Za-z0-9_-]{1,64}', value[identifier]):
        raise ValueError('Dynamic original identity differs')
    if operation == 'publication_get':
        if decimal(value['registryId']) == 0 or decimal(value['ordinal']) == 0:
            raise ValueError('Dynamic publication scalar differs')
        for field in ('manifestDigest', 'refsDigest', 'registryScopeSha256'):
            digest(value[field])
        if value['state'] not in ('preparing', 'writing_pointers', 'ready', 'failed', 'retired'):
            raise ValueError('Dynamic publication state differs')
    elif operation == 'direct_authorize':
        if value['action'] not in ('grant_parts', 'report_parts', 'complete', 'abort', 'status'):
            raise ValueError('Dynamic action differs')
        if value['completeStep'] not in (None, 'freeze', 'baseline', 'promote'):
            raise ValueError('Dynamic Complete step differs')
        if (value['completeStep'] is not None) != (value['action'] == 'complete'):
            raise ValueError('Dynamic action/step differs')
        if decimal(value['observedResourceVersion']) == 0 or value['observedState'] not in (
                'creating', 'staged_verified', 'committed', 'aborting',
                'aborted', 'blocked_unknown'):
            raise ValueError('Dynamic source status differs')
    else:
        digest(value['deploymentSha256'])
        expected = decimal(value['expectedResourceVersion'])
        retained = boolean(value['retainedOriginal'])
        count = value['checkedStatementCount']
        if expected == 0 or type(count) is not int or count < 0:
            raise ValueError('Dynamic checked batch scalar differs')
        if retained:
            if value['resultingResourceVersion'] is not None or value['checkedStatements'] is not None or count != 0:
                raise ValueError('Retained Commit invents a new checked batch')
        else:
            encoded_image(value['checkedStatements'])
            if count == 0 or decimal(value['resultingResourceVersion']) != expected + 1:
                raise ValueError('Checked Commit resulting version differs')


def publication_phases(member, children, source, read_source, report=None, manifest=None):
    """Retain partial phase facts joined to actual member bytes; never qualify them."""
    expected = member.get('publicationPhases')
    if expected is None:
        return None
    candidates = [(value, raw) for value, raw in children
                  if value.get('admissionOrdinal') == member['admissionOrdinal']]
    if len(candidates) != 1:
        raise ValueError('Publication phase child missing or duplicated')
    child, raw = candidates[0]
    joined = {'admissionOrdinal', 'method', 'pathSha256', 'requestId', 'transportCallId',
              'status', 'handlerReturned', 'requestConsumed', 'replyOffered',
              'requestTrailers', 'replyTrailers'}
    closed(child, BASE | joined | {'summary'})
    if (sha(raw) != expected['sha256'] or str(len(raw)) != expected['byteSize']
            or child['event'] != 'publication_phases'
            or any(child[field] != member[field] for field in joined | (BASE - {'event'}))
            or not member['handlerReturned']):
        raise ValueError('Publication phase actual member/raw bytes differ')
    summary = child['summary']
    # Preserve the actual nested encoding for the independent Core invocation.
    # JSON formatting must not be replaced by a Python reserialization.
    nested_start = raw.find(b'"summary":')
    if nested_start < 0:
        raise ValueError('Publication summary source field absent')
    nested = raw[nested_start + len(b'"summary":'):].decode()
    decoded, end = json.JSONDecoder().raw_decode(nested)
    summary_raw = nested[:end].encode()
    if decoded != summary or len(summary_raw) > 16 * 1024:
        raise ValueError('Publication summary exceeds source bound')
    closed(summary, {'version', 'producerSha256', 'publicationId', 'request',
        'sourceBeforeUnixNanos', 'sourceAfterUnixNanos', 'sourceElapsedNanos', 'terminalOutcome', 'phases'})
    paths = ('crates/aos-hub-core/src/application_body_observation/publication.rs',
             'crates/aos-hub-core/src/application_body_observation.rs',
             'crates/aos-hub-core/src/service.rs', 'crates/aos-hub-core/src/db/mod.rs',
             'crates/aos-hub-core/src/db/publication_delivery.rs')
    actual_source = sha(b''.join(read_source(Path(source) / name, source_leaf_bound(name)) for name in paths))
    if (type(summary['version']) is not int or summary['version'] != 1
            or summary['producerSha256'] != actual_source
            or summary['terminalOutcome'] not in ('returned_success', 'returned_error', 'incomplete')
            or not isinstance(summary['phases'], list) or len(summary['phases']) > 16):
        raise ValueError('Publication phase source/schema/bound differs')
    encoded_image(summary['request'])
    if not isinstance(summary['publicationId'], str) or not re.fullmatch('[A-Za-z0-9_-]{1,64}', summary['publicationId']):
        raise ValueError('Publication phase selected original differs')
    before = decimal(summary['sourceBeforeUnixNanos'])
    after = summary['sourceAfterUnixNanos']
    if summary['terminalOutcome'] == 'incomplete':
        if after is not None or summary['sourceElapsedNanos'] is not None:
            raise ValueError('Incomplete publication phase invents terminal clocks')
    elif after is None or summary['sourceElapsedNanos'] is None or decimal(after) < before:
        raise ValueError('Publication phase original clock differs')
    else:
        decimal(summary['sourceElapsedNanos'])
    status = member['status']
    if ((summary['terminalOutcome'] == 'returned_success' and status != 200)
            or (summary['terminalOutcome'] == 'returned_error'
                and (type(status) is not int or not 400 <= status < 600))):
        raise ValueError('Publication returned outcome differs from actual handler status')
    allowed = {'authorized', 'completeness_checked', 'pointer_phase_opened', 'pointer_advance_begun',
        'pointer_advance_finalized', 'mutable_objects_promoted', 'publication_ready', 'current_head_set',
        'delivery_refreshed', 'lease_release_returned', 'index_refresh_returned',
        'ready_evidence_restored', 'response_materialized'}
    seen = set()
    for phase in summary['phases']:
        closed(phase, {'phase', 'completedCalls', 'completedItems', 'chainSha256',
                      'firstCompletedUnixNanos', 'lastCompletedUnixNanos'})
        if phase['phase'] not in allowed or phase['phase'] in seen or decimal(phase['completedCalls']) == 0:
            raise ValueError('Publication phase kind/count duplicated or unsupported')
        seen.add(phase['phase'])
        decimal(phase['completedItems']); digest(phase['chainSha256'])
        first, last = decimal(phase['firstCompletedUnixNanos']), decimal(phase['lastCompletedUnixNanos'])
        if first < before or last < first or (after is not None and last > decimal(after)):
            raise ValueError('Publication phase lies outside actual source bracket')
    missing = ['independent_typed_original_auth_sql_and_full_body_coverage',
               'phase_counts_do_not_prove_atomic_commit_or_publication_visibility']
    request = member['requestConsumed']
    if (not frame(request) or summary['request'] != {
            'sha256': request['exposedSha256'], 'byteSize': request['exposedBytes']}):
        missing.append('partial_or_different_actual_request_encoding')
    if not frame(member['replyOffered']) or member['requestTrailers'] or member['replyTrailers']:
        missing.append('incomplete_or_trailer_body_frames')
    codec = publication_phase_codec(member, summary_raw, report, manifest)
    if codec is None:
        missing.append('missing_independent_Core_publication_summary_original_validation')
    return {'rawChildSha256': sha(raw), 'rawChildByteSize': str(len(raw)), 'summary': summary,
            'coreProjection': codec, 'objectPayloadBytes': None,
            'readerAuthority': 'not_checked', 'missing': missing}


def publication_phase_codec(member, summary_raw, report, manifest):
    """Join a real Core result while leaving reply/body/authority unclassified."""
    if report is None or manifest is None or member['requestId'] is None:
        return None
    if (report['version'] != 1 or report['codecRevision'] != manifest['codecRevision']
            or report['selectedSourceDigest'] != manifest['sourceDigest']):
        raise ValueError('Publication phase Core runtime differs')
    rows = [row for row in report['captures']
            if row['requestIdSha256'] == sha(member['requestId'].encode())]
    selected = [row for row in manifest['captures'] if row['requestId'] == member['requestId']]
    if not rows or not selected:
        return None
    if len(rows) != 1 or len(selected) != 1:
        raise ValueError('Publication phase Core selected ownership differs')
    row, capture = rows[0], selected[0]
    projection = row.get('publicationPhases')
    if projection is None:
        return None
    closed(projection, {'summarySha256', 'summaryByteSize', 'requestSha256',
                       'handlerStatus', 'objectPayloadBytes', 'sqlReaderAuthority', 'missing'})
    if (row['class'] != 'publication_phases_with_unclassified_reply'
            or row['procedure'] != '/aos.hub.v1.PublishService/CommitRegistryPublication'
            or sha(row['procedure'].encode()) != member['pathSha256']
            or row['method'] != member['method'] or row['phase'] is not None
            or capture['status'] != member['status'] or capture['method'] != member['method']
            or capture['procedure'] != row['procedure'] or capture['phase'] is not None
            or projection['summarySha256'] != sha(summary_raw)
            or projection['summaryByteSize'] != str(len(summary_raw))
            or capture.get('publicationPhases', {}).get('sha256') != sha(summary_raw)
            or capture.get('publicationPhases', {}).get('byteSize') != str(len(summary_raw))
            or projection['handlerStatus'] != member['status']
            or projection['objectPayloadBytes'] is not None or projection['sqlReaderAuthority'] != 'not_checked'
            or projection['missing'] != ['independent_source_log_authentication_and_sql_custody',
                'unclassified_reply_no_atomicity_or_visibility_claim']):
        raise ValueError('Publication phase Core original/member projection differs')
    for direction, frame_name in (('request', 'requestConsumed'), ('response', 'replyOffered')):
        image = row[direction]
        closed(image, {'sha256', 'byteSize', 'typedSemanticSha256'})
        selected_image = capture['bodies'][direction]
        if (image['sha256'] != selected_image['sha256'] or image['byteSize'] != selected_image['byteSize']
                or image['typedSemanticSha256'] != image['sha256']):
            raise ValueError('Publication selected original image differs')
        if (not frame(member[frame_name]) or member['requestTrailers'] or member['replyTrailers']):
            return None
        if (image['sha256'] != member[frame_name]['exposedSha256']
                or image['byteSize'] != member[frame_name]['exposedBytes']):
            raise ValueError('Publication Core input differs from actual consumed/offered frames')
    if projection['requestSha256'] != row['request']['sha256']:
        raise ValueError('Publication Core original request differs')
    return projection


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
        'crates/aos-hub-core/src/application_body_observation/sql_projection/dynamic.rs',
        'crates/aos-hub-core/src/direct_upload/service.rs',
        'crates/aos-hub-core/src/service.rs',
    )
    actual_source = sha(b''.join(read_source(Path(source) / path, source_leaf_bound(path)) for path in paths))
    if (type(projection['version']) is not int or projection['version'] != 1
            or projection['producerSha256'] != actual_source
            or not isinstance(projection['checkpoints'], list)
            or not 1 <= len(projection['checkpoints']) <= MAX_SQL_CHECKPOINTS):
        raise ValueError('SQL checkpoint source/count differs')
    # The exact nested source image is already covered by the raw child hash.
    # Enforce the source's 64 KiB aggregate without a Python reserialization.
    decoder = json.JSONDecoder()
    nested_start = raw.find(b'"projection":')
    if nested_start < 0:
        raise ValueError('SQL projection source field is absent')
    nested = raw[nested_start + len(b'"projection":'):].decode()
    decoded, end = decoder.raw_decode(nested)
    if decoded != projection or len(nested[:end].encode()) > MAX_SQL_PROJECTION:
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
        'dynamic': {'observation'},
    }
    for checkpoint in projection['checkpoints']:
        kind = checkpoint.get('kind')
        if kind not in fields:
            raise ValueError('Unsupported SQL checkpoint kind')
        closed(checkpoint, common | fields[kind])
        kinds.add(kind)
        if kind == 'dynamic':
            dynamic_observation(checkpoint['observation'])
        for key in ('sourceBeforeUnixNanos', 'sourceAfterUnixNanos', 'sourceElapsedNanos'):
            decimal(checkpoint[key])
        if decimal(checkpoint['sourceAfterUnixNanos']) < decimal(checkpoint['sourceBeforeUnixNanos']):
            raise ValueError('SQL operation source clock rolled back')
    constructor = member['typedEvidence']['constructor'] if member['typedEvidence'] else None
    allowed = ({'admission_checked_transaction', 'dynamic'} if constructor == 'direct_logical_validated'
               else {'manifest_append_checked_transaction', 'manifest_append_retained_receipt'}
               if constructor == 'publication_manifest_append' else {'dynamic'} if constructor == 'publication_get' else set())
    if not kinds <= allowed or not allowed:
        raise ValueError('SQL checkpoint actual encoder constructor differs')
    for checkpoint in projection['checkpoints']:
        if checkpoint['kind'] == 'dynamic':
            operation = checkpoint['observation']['operation']
            expected_constructor = ('publication_get' if operation == 'publication_get'
                                    else 'direct_logical_validated')
            if constructor != expected_constructor:
                raise ValueError('Dynamic checkpoint actual operation/constructor differs')
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
    if collection.get('kind') == 'cloud_sql':
        path = Path(source) / 'tests/fleet/_hub-native-sql-projection.py'
        namespace = {'__file__': str(path), '__name__': 'selected_managed_sql_contract'}
        raw_source = read_source(path, 1024 * 1024)
        exec(compile(raw_source, str(path), 'exec'), namespace)
        return readers['hosted_custody']()['cloud_sql'](
            collection, checkpoint, codec, readers, namespace,
            readers['PACKAGE']['runtime'], readers['HOSTED_EXPORT_VERIFIER'])
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
    namespace['native_sql_codec_image'](images, rows,
        codec['codecProjection']['sqlEvidenceSha256'], read_image)
    matched = []
    for operation in checkpoint['checkpoints']:
        if operation['kind'] == 'dynamic':
            matched.append(namespace['native_sql_match_dynamic'](operation, original_images))
            continue
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
                        'cross_machine_clock_uncertainty_and_original_authenticated_body_join']
                + [item for match in matched for item in match.get('missing', [])]}

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
    elif projection['kind'] == 'publication_get':
        files = ('crates/aos-hub-core/src/application_body_observation.rs',
                 'crates/aos-hub-core/src/application_body_observation/rpc.rs',
                 'crates/aos-hub-core/src/connect.rs')
        constructor, phase = 'publication_get', None
    elif projection['kind'] in ('direct_logical_admission', 'direct_authorize', 'direct_commit'):
        files = ('crates/aos-hub/src/direct_upload/mod.rs',)
        constructor, phase = 'direct_logical_validated', {
            'direct_logical_admission': 'admission', 'direct_authorize': 'authorize',
            'direct_commit': 'commit'}[projection['kind']]
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
    if log is not None and log.get('format') == 'cloud_run':
        result = readers['hosted_messages'](sidecar)
        if result['messages'] is None:
            return None, ';'.join(result['missing'])
        # A policy chain is scoped to an instance. Never concatenate chains from
        # two managed instances into a manufactured single Native process.
        return None, ';'.join(result['missing'] + [
            'hosted_per_instance_chain_assessment_required'])
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


def project_members(result, selection, sidecar, policy, source, readers, read_source,
                    manifest, codec_report, authentication, route_project):
    """Keep source/SQL and finite route projections scoped to one actual chain."""
    if route_project is not None:
        request_ids = [member['requestId'] for member in result['members'] if member['requestId'] is not None]
        if len(request_ids) != len(set(request_ids)):
            raise ValueError('Native inventory request ownership is ambiguous')
    children = result.pop('sqlChildren', [])
    phase_children = result.pop('publicationPhaseChildren', [])
    projections = []
    for member in result['members']:
        projection = source_asset(member, source, read_source)
        if projection is None and route_project is not None:
            projection = route_project(member)
            if projection is not None:
                result['missing'].extend(projection['missing'])
        if projection is None:
            projection = codec_projection(member, codec_report, manifest, authentication or {}, source, read_source)
            if projection is not None:
                result['missing'].extend(projection['missing'])
        checkpoint = sql_child(member, children, source, read_source)
        # Only the existing immutable original projection supplies SQL reader images.
        reader_projection = (sql_reader_projection(checkpoint, projection,
            selection.get('sqlReaderObservation'), readers, source, read_source, sidecar)
            if projection is not None and 'codecProjection' in projection else None)
        phases = publication_phases(member, phase_children, source, read_source, codec_report, manifest)
        projections.append({'admissionOrdinal': member['admissionOrdinal'],
                            'publicationPhases': phases,
                            'projection': projection, 'sqlCheckpoint': checkpoint,
                            'sqlReaderProjection': reader_projection})
        if phases is not None:
            result['missing'].extend(phases['missing'])
        if reader_projection is not None:
            result['missing'].extend(reader_projection['missing'])
        if checkpoint is not None:
            result['missing'].extend(checkpoint['missing'])
        if projection is None:
            result['missing'].append('unjoined_original_body_auth_sql_or_template_projection:'
                                     + member['admissionOrdinal'])
    result['projections'] = projections
    return result


def assess(selection, source, readers, read_source, manifest, codec_report=None, receiver_context=None):
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
    route_project = None
    if codec_report is not None and receiver_context is not None:
        path = Path(__file__).resolve(strict=True).parent / 'native_routes.py'
        raw = read_source(path, 1024 * 1024)
        namespace = {'__file__': str(path), '__name__': 'selected_route_reader'}
        exec(compile(raw, str(path), 'exec'), namespace)
        provenance = readers['closed_json'](readers['read_ref'](sidecar['runtimeProvenance'], 65536))
        context = namespace['prepare'](codec_report, manifest, authentication or {},
            sidecar, policy, receiver_context, provenance, source, read_source)
        route_project = lambda member: namespace['project'](member, context)
    if sidecar.get('nativeLog') is not None and sidecar['nativeLog'].get('format') == 'cloud_run':
        hosted = readers['hosted_messages'](sidecar)
        if hosted['messages'] is None:
            return {'inventoryComplete': False, 'nativeBulkBytes': None,
                    'inboundObjectPayloadBytes': None, 'members': [],
                    'missing': hosted['missing']}
        spec = readers['closed_json'](readers['read_ref'](
            sidecar['nativeLog']['selection'], 1024 * 1024))
        if readers['read_ref'](spec['policy'], 1024) != policy_raw:
            raise ValueError('Hosted revision policy differs from assessment policy')
        instances = {identifier: validate(rows, policy, producer(source, read_source),
                     readers['closed_json']) for identifier, rows in hosted['messages'].items()}
        # A selected request must belong to exactly one observed instance member.
        seen = set()
        for instance in instances.values():
            for member in instance['members']:
                identifier = member['requestId']
                if identifier is not None:
                    if route_project is not None and identifier in seen:
                        raise ValueError('Hosted inventory request ownership is ambiguous')
                    seen.add(identifier)
            project_members(instance, selection, sidecar, policy, source, readers, read_source,
                            manifest, codec_report, authentication, route_project)
        return {'inventoryComplete': False, 'nativeBulkBytes': None,
                'inboundObjectPayloadBytes': None, 'members': [], 'instances': instances,
                'missing': hosted['missing'] + [
                    'hosted_member_original_auth_sql_and_template_projection_join',
                    'independent_native_outbound_original_auth_sql_and_body_coverage']}
    messages, missing = selected_messages(sidecar, readers)
    if messages is None:
        return {'inventoryComplete': False, 'nativeBulkBytes': None,
                'inboundObjectPayloadBytes': None, 'members': [], 'missing': [missing]}
    result = validate(messages, policy, producer(source, read_source), readers['closed_json'])
    project_members(result, selection, sidecar, policy, source, readers, read_source,
                    manifest, codec_report, authentication, route_project)
    projections = result['projections']
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
