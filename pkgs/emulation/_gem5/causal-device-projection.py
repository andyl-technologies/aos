# SPDX-License-Identifier: MIT
"""Projects a structurally bounded, explicitly partial native device observation.

The process image retains all machine bytes. This new diagnostic contract emits
control geometry and complete original closed-UART rows, with commitments for
omitted native event payloads, ring caches, DMA spans and alias/RNG bodies.
"""

import hashlib
import json
import re


MAX_EVENTS = 4096
MAX_EVENT_BYTES = 384
MAX_FIELDS = 2048
MAX_FIELD_BYTES = 256
MAX_TERMINAL_ROWS = 32768
MAX_TERMINAL_ROW_BYTES = 56
MAX_METADATA_BYTES = 65536
MAX_OBJECT_BYTES = 4 * 1024**2
PROJECTION_SCOPE = 'native-event-metadata-device-control-fields-and-closed-terminal-fifo-v2'
CACHE_FIELD = re.compile(r'\.descriptor\[|\.available\.cached\[|\.used\.cached\[|\.span\[')
U64 = re.compile(r'0|[1-9][0-9]{0,19}')
I64 = re.compile(r'0|-?[1-9][0-9]{0,18}')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def commitment(value):
    body = canonical(value)
    return {'sha256': hashlib.sha256(body).hexdigest(), 'bytes': str(len(body))}


def decimal(value, signed=False):
    expression = I64 if signed else U64
    if not isinstance(value, str) or expression.fullmatch(value) is None:
        raise ValueError('native metadata lacks canonical bounded decimal geometry')
    number = int(value)
    if not (-(2**63) <= number < 2**63 if signed else 0 <= number < 2**64):
        raise ValueError('native metadata exceeds its integer extent')
    return value


def project(inventory, terminal_name, terminal_rows):
    """Emits one finite original partial object; no native callback is serviced."""
    if (inventory.get('schema') != 'crucible.gem5.causal-device-state.v1'
            or inventory.get('complete') is not False):
        raise ValueError('device projection cannot promote native diagnostic coverage')
    events = inventory['events']
    objects = inventory['objects']
    if len(events) > MAX_EVENTS or len(objects) != 5:
        raise ValueError('device projection exceeds its fixed source census')
    result = {key: inventory[key] for key in ('schema', 'complete', 'selected_names', 'native_tick')}
    result['diagnostic_scope'] = PROJECTION_SCOPE
    result['unsupported_domains'] = list(inventory['unsupported_domains']) + [
        'queued-event-text-and-polymorphic-payloads-commitment-only',
        'descriptor-and-available-used-ring-cache-fields-commitment-only',
        'frozen-request-dma-spans-commitment-only',
        'reference-alias-ledger-and-rng-bodies-commitment-only',
    ]
    result['event_fields'] = ['identity', 'alias', 'queue_ordinal', 'tick', 'priority',
                              'flags', 'native_type_sha256', 'description_sha256', 'modeled_fields_sha256']
    projected_events = []
    for event in events:
        if event['payload_complete'] is not False:
            raise ValueError('native event projection unexpectedly declares full coverage')
        row = [decimal(event['event_identity']), decimal(event['event_alias']),
               decimal(event['queue_ordinal']), decimal(event['tick']),
               decimal(event['priority'], signed=True), decimal(event['flags'])]
        row += [commitment(event[key])['sha256']
                for key in ('native_type', 'description', 'modeled_fields')]
        if len(canonical(row)) > MAX_EVENT_BYTES:
            raise ValueError('event metadata exceeds its pre-reserved row extent')
        projected_events.append(row)
    result['events'] = projected_events
    field_count = 0
    projected_objects = []
    for item in objects:
        if item['state_complete'] is not False or len(item['name'].encode()) > 256:
            raise ValueError('native object projection has unknown coverage/name geometry')
        fields = item['modeled_fields']
        included, omitted = {}, {}
        for key, value in fields.items():
            if CACHE_FIELD.search(key):
                omitted[key] = value
            else:
                if len(canonical({key: value})) > MAX_FIELD_BYTES:
                    raise ValueError('device control field exceeds its reserved extent')
                included[key] = value
                field_count += 1
                if field_count > MAX_FIELDS:
                    raise ValueError('device control census exceeds its reserved extent')
        projected_objects.append({
            'name': item['name'], 'native_type': item['native_type'],
            'object_alias': decimal(item['object_alias']), 'state_complete': False,
            'modeled_fields': included, 'omitted_modeled_fields': commitment(omitted),
            'omitted_modeled_field_count': str(len(omitted)),
        })
    result['objects'] = projected_objects
    result['rng_commitment'] = commitment(inventory['rng'])
    result['reference_ledger_commitment'] = commitment(inventory['reference_ledger'])
    if len(terminal_rows) > MAX_TERMINAL_ROWS:
        raise ValueError('closed UART projection exceeds original row custody')
    for row in terminal_rows:
        if len(canonical(row)) > MAX_TERMINAL_ROW_BYTES:
            raise ValueError('closed UART row exceeds its pre-reserved extent')
    result['original_closed_terminal_fifo'] = {
        'schema': 'crucible.gem5.closed-terminal-monitor.v1', 'terminal': terminal_name,
        'fields': ['native_id', 'tick', 'event_ordinal', 'tick_ordinal', 'causal_parent', 'byte'],
        'rows': terminal_rows, 'external_publication_admitted': False,
    }
    metadata = dict(result, events=[], objects=[], original_closed_terminal_fifo={})
    metadata['objects'] = [dict(item, modeled_fields={}) for item in projected_objects]
    if len(canonical(metadata)) > MAX_METADATA_BYTES:
        raise ValueError('device projection metadata exceeds its reserved extent')
    body = canonical(result)
    if len(body) > MAX_OBJECT_BYTES:
        raise ValueError('device projection exceeds its source-derived total reservation')
    return result


assert (MAX_EVENTS * MAX_EVENT_BYTES + MAX_FIELDS * MAX_FIELD_BYTES
        + MAX_TERMINAL_ROWS * MAX_TERMINAL_ROW_BYTES + MAX_METADATA_BYTES
        + MAX_EVENTS + MAX_TERMINAL_ROWS) < MAX_OBJECT_BYTES
