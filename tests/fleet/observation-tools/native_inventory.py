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
    for message, _timestamp in messages:
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
        closed(row, {'begin': BEGIN, 'member': MEMBER, 'end': END}.get(kind, set()))
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
            'chainSha256': chain.hex(), 'nativeBulkBytes': None}


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
                       'objectPayloadBytes', 'sqlReaderAuthority', 'missing'})
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
    closed(selection, {'policy', 'sidecar'})
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
    projections = []
    for member in result['members']:
        projection = source_asset(member, source, read_source)
        if projection is None:
            projection = codec_projection(member, codec_report, manifest, authentication or {}, source, read_source)
            if projection is not None:
                result['missing'].extend(projection['missing'])
        projections.append({'admissionOrdinal': member['admissionOrdinal'], 'projection': projection})
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
