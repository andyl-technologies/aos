"""Verify the finite Native dispatch window without assigning byte authority.

The existing live hosted collector supplies raw messages grouped by instance.
This reader checks separate process-epoch chains against the selected compiled
source roster. A closed dispatcher window never establishes whole egress,
authenticated replies, SQL authority, provider settlement or a bulk-byte zero.
"""

import hashlib
from pathlib import Path
import re


MARKER = 'native_remote_storage_inventory '
DOMAIN = b'aos.native.remote-storage-window-chain.v1\0'
MAX_RECORD = 4096
MAX_EVENTS = 262144
MAX_PENDING = 4096
BASE = {'version', 'event', 'runId', 'windowId', 'policySha256',
        'producerSha256', 'processEpoch', 'eventOrdinal'}
OFFER = {'dispatchOrdinal', 'owner', 'transportCallId', 'requestSha256',
         'offeredRequestBytes'}
TERMINAL = OFFER | {'replyStatus', 'exposedReplySha256', 'exposedReplyBytes',
                    'replyEof', 'outcome', 'elapsedMicros',
                    'replyMacAuthentication', 'finalSqlAuthority'}
END = {'offered', 'terminal', 'pending', 'incomplete', 'unfinishedSend',
       'overflowOrFailure', 'chainSha256'}
OWNERS = ('capabilities', 'binding_control', 'execute', 'frozen_head',
          'external_head', 'frozen_delete', 'external_copy', 'managed_cleanup',
          'external_oci_control', 'external_oci_source', 'mirror_guard',
          'credential_custody', 'storage_authority', 'mirror_guard_batch',
          'external_cleanup', 'oci_projection', 'direct_authority')
SOURCES = ('outbound_inventory.rs', 'outbound_inventory/policy.rs',
           'outbound_inventory/window.rs', 'outbound_inventory/guard.rs',
           'lib.rs', 'main.rs', 'storage_work.rs', 'storage_work/frozen_head.rs',
           'storage_work/external_observation.rs', 'storage_work/external_delete.rs',
           'storage_work/external_copy.rs', 'storage_work/oci_cleanup.rs',
           'storage_work/external_oci.rs', 'storage_work/mirror_guard.rs',
           'storage_work/binding_custody.rs', 'storage_work/authority.rs',
           'storage_work/mirror_guard/batch.rs', 'storage_work/external_oci/cleanup.rs',
           'storage_work/oci_projection/exchange.rs', 'direct_upload/authority/transport.rs')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def closed(value, names):
    if not isinstance(value, dict) or set(value) != names:
        raise ValueError('Outbound closed schema differs')


def hexadecimal(value, length=64):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is None:
        raise ValueError('Outbound commitment or identity differs')
    return value


def decimal(value):
    if not isinstance(value, str) or re.fullmatch('0|[1-9][0-9]{0,19}', value) is None:
        raise ValueError('Outbound count is not canonical')
    count = int(value)
    if count > 2**64 - 1:
        raise ValueError('Outbound count exceeds source bound')
    return count


def policy_bytes(value):
    """Encode the exact declared production Policy field order."""
    closed(value, {'version', 'runId', 'windowId', 'startUnixMillis', 'endUnixMillis'})
    if type(value['version']) is not int or value['version'] != 1:
        raise ValueError('Outbound policy version differs')
    hexadecimal(value['runId'])
    hexadecimal(value['windowId'], 32)
    start, end = decimal(value['startUnixMillis']), decimal(value['endUnixMillis'])
    if not start < end or end - start > 3600000:
        raise ValueError('Outbound policy interval differs')
    return ('{"version":1,"runId":"' + value['runId']
            + '","windowId":"' + value['windowId']
            + '","startUnixMillis":"' + value['startUnixMillis']
            + '","endUnixMillis":"' + value['endUnixMillis'] + '"}').encode()


def producer(source, read_source):
    """Recompute the actual include-bytes roster, rather than trust selection."""
    source = Path(source) / 'crates/aos-hub/src'
    images = {name: read_source(source / name, 1024 * 1024) for name in SOURCES}
    module = images['outbound_inventory.rs']
    macro = b'''hash.update($path.as_bytes());
                hash.update([0]);
                hash.update(include_bytes!($path));'''
    roster = tuple(value.decode() for value in re.findall(rb'source!\("([^"\n]+)"\);', module))
    if (module.count(macro) != 1 or roster != SOURCES
            or module.count(b'aos.native.remote-storage-dispatch-roster.v1\\0') != 1):
        raise ValueError('Unsupported outbound compiled roster formula')
    expected_policy = b'''pub(super) struct Policy {
    pub(super) version: u8,
    pub(super) run_id: String,
    pub(super) window_id: String,
    pub(super) start_unix_millis: String,
    pub(super) end_unix_millis: String,
}'''
    rust_owners = tuple(re.sub(r'(?<!^)(?=[A-Z])', '_', name.decode()).lower()
                        for name in re.findall(rb'^    ([A-Z][A-Za-z]+),$',
                            images['outbound_inventory/guard.rs'], re.MULTILINE))
    if (images['outbound_inventory/policy.rs'].count(expected_policy) != 1
            or rust_owners != OWNERS
            or b'aos.native.remote-storage-window-chain.v1\\0' not in images['outbound_inventory/window.rs']):
        raise ValueError('Unsupported outbound owner or policy schema')
    digest = hashlib.sha256(b'aos.native.remote-storage-dispatch-roster.v1\0')
    for name in SOURCES:
        digest.update(name.encode() + b'\0' + images[name])
    return digest.hexdigest()


def offered(row):
    ordinal = decimal(row['dispatchOrdinal'])
    if ordinal == 0 or row['owner'] not in OWNERS:
        raise ValueError('Outbound dispatch owner or ordinal differs')
    if row['transportCallId'] is not None:
        hexadecimal(row['transportCallId'], 32)
    secret = row['owner'] in ('binding_control', 'credential_custody')
    if secret:
        if row['requestSha256'] is not None:
            raise ValueError('Secret control includes a request hash')
    else:
        hexadecimal(row['requestSha256'])
    decimal(row['offeredRequestBytes'])
    return ordinal


def terminal(row):
    """Check transport-only terminal semantics; authentication stays absent."""
    offered(row)
    status = row['replyStatus']
    if status is not None and (type(status) is not int or not 100 <= status <= 599):
        raise ValueError('Outbound reply status differs')
    if type(row['replyEof']) is not bool:
        raise ValueError('Outbound EOF differs')
    count = decimal(row['exposedReplyBytes'])
    decimal(row['elapsedMicros'])
    secret = row['owner'] in ('binding_control', 'credential_custody')
    if secret:
        if row['exposedReplySha256'] is not None:
            raise ValueError('Secret control includes a response hash')
    else:
        hexadecimal(row['exposedReplySha256'])
        if count == 0 and row['exposedReplySha256'] != sha(b''):
            raise ValueError('Outbound empty prefix commitment differs')
    expected = ('reply_eof_unverified' if row['replyEof'] else
                'reply_unfinished' if status is not None else 'send_unfinished')
    if (row['outcome'] != expected or (row['replyEof'] and status is None)
            or row['replyMacAuthentication'] is not None or row['finalSqlAuthority'] is not None):
        raise ValueError('Outbound terminal contradicts source semantics')


def validate(messages, policy, selected_producer, parse_json):
    """Validate each separate epoch's exact raw chain within one instance."""
    policy_sha = sha(policy_bytes(policy))
    hexadecimal(selected_producer)
    epochs = {}
    count = 0
    for message, _timestamp in messages:
        if not isinstance(message, str) or MARKER not in message:
            continue
        if message.count(MARKER) != 1:
            raise ValueError('Ambiguous outbound marker')
        raw = message.split(MARKER, 1)[1].encode()
        if len(raw) > MAX_RECORD:
            raise ValueError('Outbound record exceeds source bound')
        row = parse_json(raw)
        if not isinstance(row, dict):
            raise ValueError('Outbound event is not an object')
        if row.get('windowId') != policy['windowId']:
            continue
        count += 1
        if count > MAX_EVENTS:
            raise ValueError('Outbound reader event bound exceeded')
        kind = row.get('event')
        extra = {'begin': {'policy', 'scope'}, 'offered': OFFER,
                 'terminal': TERMINAL, 'late_terminal': TERMINAL, 'end': END}.get(kind)
        if extra is None:
            raise ValueError('Unknown outbound event')
        closed(row, BASE | extra)
        if (type(row['version']) is not int or row['version'] != 1
                or row['runId'] != policy['runId'] or row['policySha256'] != policy_sha
                or row['producerSha256'] != selected_producer):
            raise ValueError('Outbound source, policy or run differs')
        epoch = hexadecimal(row['processEpoch'], 32)
        state = epochs.setdefault(epoch, {'sequence': 0, 'chain': bytes(32),
            'begin': False, 'end': None, 'pending': {}, 'dispatches': [],
            'incomplete': 0, 'unfinished': 0, 'late': []})
        ordinal = decimal(row['eventOrdinal'])
        if ordinal != state['sequence'] + 1:
            raise ValueError('Outbound event ordering or exported membership differs')
        state['sequence'] = ordinal
        if state['end'] is not None and kind != 'late_terminal':
            raise ValueError('Outbound event follows immutable cutoff')
        if kind == 'begin':
            if state['begin'] or ordinal != 1 or row['policy'] != policy or row['scope'] != 'remote_storage_dispatch_roster':
                raise ValueError('Outbound begin differs')
            state['begin'] = True
        elif not state['begin']:
            raise ValueError('Outbound event lacks actual begin')
        elif kind == 'offered':
            dispatch = offered(row)
            if dispatch != len(state['dispatches']) + 1 or len(state['pending']) >= MAX_PENDING:
                raise ValueError('Outbound offered membership exceeds source bound')
            entry = {'offered': row, 'terminal': None}
            state['dispatches'].append(entry)
            state['pending'][dispatch] = entry
        elif kind in ('terminal', 'late_terminal'):
            terminal(row)
            dispatch = decimal(row['dispatchOrdinal'])
            entry = state['pending'].get(dispatch)
            if entry is None or any(row[name] != entry['offered'][name] for name in OFFER):
                raise ValueError('Outbound terminal has no matching original offer')
            if kind == 'late_terminal':
                if state['end'] is None:
                    raise ValueError('Late outbound terminal precedes cutoff')
                if dispatch in state['late']:
                    raise ValueError('Duplicate late terminal')
                state['late'].append(dispatch)
            else:
                del state['pending'][dispatch]
                entry['terminal'] = row
                state['incomplete'] += not row['replyEof']
                state['unfinished'] += row['replyStatus'] is None
        elif kind == 'end':
            for name in ('offered', 'terminal', 'pending', 'incomplete', 'unfinishedSend'):
                decimal(row[name])
            if type(row['overflowOrFailure']) is not bool:
                raise ValueError('Outbound overflow differs')
            hexadecimal(row['chainSha256'])
            if (decimal(row['offered']) != len(state['dispatches'])
                    or decimal(row['pending']) != len(state['pending'])
                    or decimal(row['terminal']) != len(state['dispatches']) - len(state['pending'])
                    or decimal(row['incomplete']) != state['incomplete']
                    or decimal(row['unfinishedSend']) != state['unfinished']
                    or row['chainSha256'] != state['chain'].hex()):
                raise ValueError('Outbound final counters or raw chain differs')
            state['end'] = row
        if kind not in ('end', 'late_terminal'):
            state['chain'] = hashlib.sha256(DOMAIN + state['chain'] + raw).digest()

    result = {}
    for epoch, state in epochs.items():
        end = state['end']
        missing = []
        if end is None:
            missing.append('missing_actual_dispatcher_cutoff_end')
        elif (decimal(end['pending']) or decimal(end['incomplete'])
              or decimal(end['unfinishedSend']) or end['overflowOrFailure']):
            missing.append('pending_unread_failed_or_overflow_dispatches')
        result[epoch] = {'dispatcherWindowComplete': not missing,
            'dispatches': state['dispatches'], 'end': end,
            'chainSha256': state['chain'].hex(), 'lateTerminalOrdinals': state['late'],
            'missing': missing, 'nativeBulkBytes': None,
            'replyMacAuthentication': None, 'finalSqlAuthority': None}
    return result


def assess(selection, source, readers, read_source, manifest):
    """Reuse the live authenticated hosted export and preserve its missing facts."""
    closed(selection, {'policy', 'sidecar'})
    policy_raw = readers['read_ref'](selection['policy'], 1024)
    policy = readers['closed_json'](policy_raw)
    if policy_bytes(policy) != policy_raw:
        raise ValueError('Selected outbound policy encoding differs')
    sidecar = readers['closed_json'](readers['read_ref'](selection['sidecar'], 1024 * 1024))
    native_log = sidecar.get('nativeLog')
    if not isinstance(native_log, dict) or native_log.get('format') != 'cloud_run':
        raise ValueError('Outbound reader requires the existing hosted export')
    # Runtime/provenance validation remains independent of event completeness.
    readers['assess'](sidecar, manifest)
    log = readers['closed_json'](readers['read_ref'](sidecar['nativeLog']['selection'], 1024 * 1024))
    if log.get('outboundPolicy') != selection['policy']:
        raise ValueError('Outbound export selects another policy')
    hosted = readers['hosted_messages'](sidecar)
    expected = producer(source, read_source)
    missing = list(hosted['missing'])
    if (decimal(log['firstUnixMicros']) > decimal(policy['startUnixMillis']) * 1000
            or decimal(log['lastUnixMicros']) < decimal(policy['endUnixMillis']) * 1000):
        missing.append('export_interval_does_not_cover_original_outbound_policy')
    instances = {}
    if hosted['messages'] is not None:
        seen_epochs = set()
        for instance, messages in hosted['messages'].items():
            epochs = validate(messages, policy, expected, readers['closed_json'])
            if seen_epochs.intersection(epochs):
                raise ValueError('Outbound process epoch appears in multiple instances')
            seen_epochs.update(epochs)
            instances[instance] = epochs
            if not epochs:
                missing.append('selected_instance_missing_actual_outbound_begin_end')
            for state in epochs.values():
                missing.extend(state['missing'])
    missing.extend(['independent_outbound_receiver_original_auth_sql_and_body_classification',
                    'full_native_egress_outside_remote_storage_dispatch_roster'])
    return {'scope': 'remote_storage_dispatch_roster', 'inventoryComplete': False,
            'nativeBulkBytes': None, 'producerSha256': expected,
            'expectedOwnerRoster': list(OWNERS), 'instances': instances,
            'missing': list(dict.fromkeys(missing))}
