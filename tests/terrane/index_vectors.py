"""Reconstructs complete ordinary index field witnesses independently.

Literal field tables and CBOR primitives reproduce the published bounded
section byte-for-byte, including registered identities and detached lookup q.
Malformed wires bypass rejecting format encoders. Contextual controls retain
their declared role and source/predicate inputs; their finite mathematical
checks supplement the separately required owning contextual consumer.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

import index_vector_carriers as carrier
from index_vector_primitives import cbor, diagnostic as model, head, key_canonical


HEADING = "## Owner-bound index and occurrence-carrier field witnesses"


NEGATIVE_REASONS = {
    "executable-index-bad-duplicate": "duplicate argument keys",
    "executable-index-bad-legacy": "two operands and no registered arguments",
    "executable-index-bad-missing-arguments": "required arguments absent",
    "executable-index-bad-trailing": "trailing recipe bytes",
    "executable-index-bad-two-owner": "exactly one operand is required",
    "executable-index-bad-unknown-argument": "closed executable argument schema",
    "executable-index-bad-wrong-profile": "unregistered profile",
    "executable-index-bad-zero-owner": "exactly one completed owner operand is required",
    "index-entry-extra-field": "type7 mode field excluded by entry schema",
    "index-first-shared-nonzero": "TREE-18 first prefix count",
    "index-key-bad-duplicate": "duplicate map keys",
    "index-key-bad-float": "float excluded from deterministic profile",
    "index-key-bad-huge-bytes": "unbounded claimed value length",
    "index-key-bad-nonminimal": "nonminimal unsigned integer",
    "index-key-bad-trailing-value": "multiple values before digest",
    "index-key-deep-truncated": "4063 open arrays with no scalar leaf",
    "index-key-digest-31": "31 digest bytes after one canonical value",
    "index-key-digest-33": "33 digest bytes after one canonical value",
    "index-key-indefinite": "indefinite collection forbidden",
    "index-key-invalid-utf8": "invalid UTF-8 text",
    "index-key-order-unsorted": "TREE-17 leaf key order",
    "index-key-over-4097": "combined key exceeds TREE-6 4096 bytes",
    "index-key-tag": "tag excluded by deterministic profile",
    "index-key-unsorted-map": "map keys out of canonical encoded order",
    "index-root-in-ordinary-context": "TREE-32 index entry forbidden in ordinary namespace",
    "index-target-wrong-width": "digest32 target width",
    "index-targets-unsorted": "TREE-32 target ordering",
    "ordinary-graft-binding-override": "PROP-29 owner-only binding forbidden on graft override; requires property-placement consumer",
    "ordinary-owner-binding-on-nonroot": "TREE-33 nonroot properties forbidden",
    "ordinary-owner-extra-node-field": "TREE-26 unknown Node field",
    "owner-binding-bad-bare": "explicit property lacks exact noninherited wrapper",
    "owner-binding-bad-duplicate": "duplicate map keys",
    "owner-binding-bad-huge-map": "unbounded claimed collection",
    "owner-binding-bad-inherit": "inherit=true is forbidden",
    "owner-binding-bad-short": "digest text is not 64 bytes",
    "owner-binding-bad-trailing": "trailing bytes",
    "owner-binding-bad-truncated": "missing inheritance boolean",
    "owner-binding-bad-unknown": "unregistered attribute",
    "owner-binding-bad-unsorted": "noncanonical encoded-key order",
    "owner-binding-bad-uppercase": "uppercase hex"
}


def pair_map(pairs):
    """Retains the supplied encoded order and duplicate keys in negative inputs."""
    return head(5, len(pairs)) + b''.join(cbor(key) + item for key, item in pairs)


def wrapper(value, inherit=False):
    return pair_map([('value', value), ('inherit', cbor(inherit))])


def recipe(owners, arguments=None):
    fields = {1: 'index', 2: owners}
    encoded = head(5, 2 if arguments is None else 3) + cbor(1) + cbor('index') + cbor(2) + cbor(owners)
    if arguments is not None:
        encoded += cbor(3) + arguments
    return fields, encoded


def format_tables():
    """Assembles all 42 earlier primitives from explicit independent field tables."""
    rows = []
    node = '0123456789abcdef' * 4
    owner = bytes([1]) * 32
    obj = bytes([171]) * 32
    binding_value = cbor({'uid': node})
    arguments = cbor({'profile': 'terrane-index/v1', 'attribute': 'hash.sha256'})

    def add(name, family, encoded, positive, fields=None, assembly=None):
        rows.append({'name': name, 'family': family, 'positive': positive,
                     'wire_hex': encoded.hex(), 'model': fields,
                     'primitive_assembly': assembly})

    for label, values in [('uid', {'uid': node}), ('empty', {}), ('two', {'gid': node, 'uid': 'ab' * 32})]:
        fields = {'value': values, 'inherit': False}
        add('owner-binding-' + label, 'owner-binding', cbor(fields), True, model(fields))

    for label, encoded in [
        ('bare', binding_value),
        ('inherit', wrapper(binding_value, True)),
        ('uppercase', wrapper(cbor({'uid': 'AB' * 32}))),
        ('short', wrapper(cbor({'uid': 'a' * 63}))),
        ('unknown', wrapper(cbor({'unknown': node}))),
        ('duplicate', wrapper(pair_map([('uid', cbor(node)), ('uid', cbor(node))]))),
        ('unsorted', wrapper(pair_map([('uid', cbor(node)), ('gid', cbor(node))]))),
        ('huge-map', wrapper(bytes.fromhex('baffffffff'))),
        ('trailing', wrapper(binding_value) + cbor(0)),
        ('truncated', wrapper(binding_value)[:-1]),
    ]:
        add('owner-binding-bad-' + label, 'owner-binding', encoded, False,
            assembly={'literal_rule': label, 'inner_value_hex': binding_value.hex(),
                      'claimed_pair_count': 4294967295 if label == 'huge-map' else None})

    fields, encoded = recipe([owner], arguments)
    fields[3] = {'profile': 'terrane-index/v1', 'attribute': 'hash.sha256'}
    add('executable-index-sha256', 'closed-recipe', encoded, True, model(fields))
    fields, encoded = recipe([owner, bytes([2]) * 32])
    add('legacy-retained-index', 'retained-recipe', encoded, True, model(fields))
    for label, owners, args in [
        ('legacy', [owner, bytes([2]) * 32], None),
        ('zero-owner', [], arguments),
        ('two-owner', [owner, bytes([2]) * 32], arguments),
        ('missing-arguments', [owner], None),
        ('unknown-argument', [owner], cbor({'future': 0})),
        ('wrong-profile', [owner], cbor({'profile': 'other-index/v1', 'attribute': 'uid'})),
        ('duplicate', [owner], pair_map([('profile', cbor('terrane-index/v1')), ('profile', cbor('terrane-index/v1'))])),
        ('trailing', [owner], arguments),
    ]:
        fields, encoded = recipe(owners, args)
        if label == 'trailing':
            encoded += cbor(0)
        add('executable-index-bad-' + label, 'closed-recipe', encoded, False,
            assembly={'literal_rule': label, 'operands': model(owners),
                      'argument_wire_hex': None if args is None else args.hex()})

    values = [
        ('uint', cbor(24), model(24)),
        ('opaque-bytes', cbor(b'\0/\xff'), model(b'\0/\xff')),
        ('array', cbor([0, b'/', None]), model([0, b'/', None])),
        ('map', cbor({1: b'\0', 'uid': 0}), model({1: b'\0', 'uid': 0})),
        ('exact-4096', cbor(bytes(4061)), model(bytes(4061))),
        ('deep-valid-4096', b'\x81' * 4063 + cbor(0),
         {'repeated_singleton_array': {'count': 4063, 'leaf': 0}}),
    ]
    for label, value, fields in values:
        add('index-key-' + label, 'opaque-key', value + obj, True,
            {'value': fields, 'canonical_value_hex': value.hex(), 'object_O_hex': obj.hex(),
             'inclusive_lower_hex': (value + bytes(32)).hex(),
             'inclusive_upper_hex': (value + bytes([255]) * 32).hex()})

    for name, value, digest, rule in [
        ('index-key-bad-nonminimal', b'\x18\x00', obj, 'nonminimal integer'),
        ('index-key-bad-duplicate', b'\xa2\x01\x00\x01\x01', obj, 'duplicate map key'),
        ('index-key-bad-trailing-value', b'\x00\x01', obj, 'two value items'),
        ('index-key-bad-huge-bytes', bytes.fromhex('5affffffff'), obj, 'claimed bstr length 4294967295'),
        ('index-key-bad-float', bytes.fromhex('f90000'), obj, 'half-precision float'),
        ('index-key-over-4097', cbor(bytes(4062)), obj, 'combined key 4097 bytes'),
        ('index-key-digest-31', cbor(0), bytes([171]) * 31, '31-byte digest'),
        ('index-key-digest-33', cbor(0), bytes([171]) * 33, '33-byte digest'),
        ('index-key-invalid-utf8', bytes.fromhex('61ff'), obj, 'invalid UTF8'),
        ('index-key-indefinite', bytes.fromhex('9fff'), obj, 'indefinite array'),
        ('index-key-tag', bytes.fromhex('c000'), obj, 'tag'),
        ('index-key-unsorted-map', bytes.fromhex('a202000100'), obj, 'encoded map order'),
        ('index-key-deep-truncated', b'\x81' * 4063, obj, '4063 singleton arrays missing leaf'),
    ]:
        add(name, 'opaque-key', value + digest, False,
            assembly={'literal_rule': rule, 'value_wire_hex': value.hex(), 'object_bytes_hex': digest.hex()})
    assert len(rows) == 42
    return rows


def historical_tables(binary):
    """Reconstructs 16 historical containing models without closed-role activation."""
    obj = bytes([171]) * 32
    key = cbor(24) + obj
    index = {1: 0, 2: [[key, 0, {1: 7, 14: [obj]}]]}
    index_id = carrier.raw_digest(binary, 'terrane-node-v1', cbor(index))
    file = {1: 1, 2: 420, 3: 1, 4: [0, obj], 9: {'uid': 24}}
    binding = {'value': {'uid': index_id.hex()}, 'inherit': False}
    owner = {1: 0, 2: [[b'file', 0, file]], 3: {'index-roots': binding}}
    owner_id = carrier.raw_digest(binary, 'terrane-node-v1', cbor(owner))
    rows = [
        ('index-root-one-matching-object', index, 'index', True, True, None),
        ('ordinary-owner-with-index-binding', owner, 'ordinary', True, True, None),
        ('ordinary-root-explicit-empty-properties', {1: 0, 2: [], 3: {}}, 'ordinary', True, True, None),
        ('ordinary-root-absent-properties', {1: 0, 2: []}, 'ordinary', True, True, None),
        ('ordinary-owner-explicit-empty-binding', {1: 0, 2: [], 3: {'index-roots': {'value': {}, 'inherit': False}}}, 'ordinary', True, True, None),
        ('ordinary-owner-binding-on-nonroot', owner, 'ordinary', False, False, 'format-context'),
        ('ordinary-graft-binding-override', {1: 0, 2: [[b'graft', 0, {1: 4, 6: owner_id, 7: {'index-roots': binding}}]]}, 'ordinary', True, False, 'property-placement'),
        ('ordinary-owner-extra-node-field', owner | {4: 0}, 'ordinary', True, False, 'format'),
        ('index-target-wrong-width', {1: 0, 2: [[key, 0, {1: 7, 14: [obj[:-1]]}]]}, 'index', True, False, 'format'),
        ('index-targets-unsorted', {1: 0, 2: [[key, 0, {1: 7, 14: [bytes([255]) * 32, obj]}]]}, 'index', True, False, 'format'),
        ('index-key-order-unsorted', {1: 0, 2: [[key, 0, {1: 7, 14: [obj]}], [cbor(0) + obj, 0, {1: 7, 14: [obj]}]]}, 'index', True, False, 'format'),
        ('index-first-shared-nonzero', {1: 0, 2: [[key, 1, {1: 7, 14: [obj]}]]}, 'index', True, False, 'format'),
        ('index-entry-extra-field', {1: 0, 2: [[key, 0, {1: 7, 2: 420, 14: [obj]}]]}, 'index', True, False, 'format'),
        ('index-object-suffix-mismatch', {1: 0, 2: [[cbor(24) + bytes([170]) * 32, 0, {1: 7, 14: [obj]}]]}, 'index', True, True, None),
        ('index-generic-multiple-targets', {1: 0, 2: [[key, 0, {1: 7, 14: [obj, bytes([255]) * 32]}]]}, 'index', True, True, None),
        ('index-root-in-ordinary-context', index, 'ordinary', True, False, 'format-context'),
    ]
    return rows, {1: 'index', 2: [owner_id], 3: {'profile': 'terrane-index/v1', 'attribute': 'uid'}}


def immutable(row, binary, domain):
    """Assigns a descriptor only to complete positive immutable content."""
    wire = bytes.fromhex(row['wire_hex'])
    digest = carrier.raw_digest(binary, domain, wire)
    descriptor = ['blake3', domain, digest, len(wire)]
    row.update({'domain': domain, 'identity_hex': digest.hex(),
                'preimage_hex': (domain.encode() + b'\0' + wire).hex(),
                'descriptor': model(descriptor), 'descriptor_wire_hex': cbor(descriptor).hex()})


def lookup(row, binary):
    """Retains detached q only as a lookup key, never an immutable descriptor."""
    wire = bytes.fromhex(row['wire_hex'])
    row['lookup_q_hex'] = carrier.raw_digest(binary, 'terrane-memo-v1', wire).hex()
    row['lookup_preimage_hex'] = (b'terrane-memo-v1\0' + wire).hex()
    row['identity_note'] = 'Detached lookup q only; no immutable Recipe or Memo object identity.'


def negative_fields(row):
    """Retains full raw assembly even when no complete CBOR value can be decoded."""
    row['primitive_assembly']['complete_wire_hex'] = row['wire_hex']
    if row['family'] == 'owner-binding':
        node = '0123456789abcdef' * 4
        label = row['name'].removeprefix('owner-binding-bad-')
        values = {'uid': node}
        if label == 'uppercase':
            values = {'uid': 'AB' * 32}
        elif label == 'short':
            values = {'uid': 'a' * 63}
        elif label == 'unknown':
            values = {'unknown': node}
        if label == 'bare':
            row['model'] = model(values)
        elif label in ('inherit', 'uppercase', 'short', 'unknown'):
            row['model'] = model({'value': values, 'inherit': label == 'inherit'})
        elif label in ('duplicate', 'unsorted'):
            pairs = [('uid', node), ('uid' if label == 'duplicate' else 'gid', node)]
            row['model'] = {'map': [['value', {'map': [[key, item] for key, item in pairs]}], ['inherit', False]]}
        elif label == 'trailing':
            row['model'] = {'ordered_top_level_items': [model({'value': values, 'inherit': False}), 0]}
        else:
            row['model'] = {'raw_malformed_assembly': row['primitive_assembly']}
    else:
        row['model'] = {'raw_primitive_assembly': row['primitive_assembly']}


def classify_d104_negative(name):
    """Selects refusal ownership without promoting relationship failures to syntax."""
    format_names = {'primary-multiple-targets', 'primary-wrong-entry-kind'}
    relationship = {
        'primary-empty-continuation', 'route-omitted-repeated-graft', 'route-extra-source-key',
        'route-terminal-at-graft', 'terminal-forward-pointer-at-file',
        'missing-route-actually-present', 'terminal-wrong-O', 'primary-omitted-gap-binding',
        'primary-bound-empty-G', 'gap-extra-object',
    }
    if name in format_names:
        return 'format'
    if name == 'gap-binding-on-nonroot':
        return 'format-context'
    if name in relationship:
        return 'source-relationship'
    if name == 'gap-binding-on-namespace-owner':
        return 'property-placement'
    return 'carrier-role'


def corpus(binary):
    """Constructs complete fields without reading a codec or comparison artifact."""
    rows = format_tables()
    assert len(rows) == 42
    for row in rows:
        row['refusal_scope'] = None if row['positive'] else 'field-format'
        row['requirements'] = ['PROP-29'] if row['family'] == 'owner-binding' else (['TREE-6', 'TREE-25', 'TREE-32'] if row['family'] == 'opaque-key' else ['DRV-26'])
        if not row['positive']:
            negative_fields(row)
            row['reason'] = NEGATIVE_REASONS[row['name']]
            if row['family'] == 'closed-recipe' and row['name'] not in ('executable-index-bad-duplicate', 'executable-index-bad-trailing'):
                row['refusal_scope'] = 'closed-recipe'
        if row['family'] in ('closed-recipe', 'retained-recipe') and row['positive']:
            lookup(row, binary)
        if row['family'] == 'opaque-key' and row['positive']:
            value = bytes.fromhex(row['model']['canonical_value_hex'])
            key_canonical(value)
            assert 33 <= len(bytes.fromhex(row['wire_hex'])) <= 4096
        elif row['family'] == 'opaque-key':
            key = bytes.fromhex(row['wire_hex'])
            try:
                if not 33 <= len(key) <= 4096:
                    raise ValueError('key length')
                key_canonical(key[:-32])
            except (ValueError, UnicodeDecodeError):
                pass
            else:
                raise AssertionError('negative key unexpectedly canonical')

    containing, historical_recipe = historical_tables(binary)
    assert len(containing) == 16
    for name, fields, usage, root, positive, scope in containing:
        wire = cbor(fields)
        row = {'name': name, 'family': 'historical-node', 'positive': positive,
               'model': model(fields), 'wire_hex': wire.hex(), 'refusal_scope': scope,
               'context': {'tree_use': usage, 'is_root': root, 'minimum_chunk_size': 262144},
               'active_profile_claim': False}
        if positive:
            row['full_entries'] = [{'key_hex': key.hex(), 'entry': model(entry)} for key, entry in carrier.expanded(fields)]
            immutable(row, binary, 'terrane-node-v1')
            if usage == 'index':
                row['current_primary_role'] = 'refuses: current primary requires a sole forward occurrence pointer and matching object'
        else:
            row['reason'] = NEGATIVE_REASONS[row['name']]
        rows.append(row)

    historic_q = {'name': 'historical-owner-detached-index-recipe', 'family': 'historical-recipe',
                  'positive': True, 'model': model(historical_recipe),
                  'wire_hex': cbor(historical_recipe).hex(), 'active_profile_claim': False,
                  'result_note': 'The historical bound terminal-only I is not a completed current carrier.'}
    lookup(historic_q, binary)
    rows.append(historic_q)

    # Bare key/property values receive complete independent containing Nodes.
    for item in list(rows):
        if not item['positive'] or item['family'] not in ('owner-binding', 'opaque-key'):
            continue
        if item['family'] == 'owner-binding':
            values = {'uid': '0123456789abcdef' * 4} if item['name'].endswith('-uid') else (
                {} if item['name'].endswith('-empty') else {'gid': '0123456789abcdef' * 4, 'uid': 'ab' * 32})
            fields = {1: 0, 2: [], 3: {'index-roots': {'value': values, 'inherit': False}}}
            usage = 'ordinary'
        else:
            key = bytes.fromhex(item['wire_hex'])
            fields = {1: 0, 2: [[key, 0, {1: 7, 14: [bytes([171]) * 32]}]]}
            usage = 'index'
        wrapped = {'name': item['name'] + '-containing-node', 'family': 'primitive-containing-node',
                   'positive': True, 'model': model(fields), 'wire_hex': cbor(fields).hex(),
                   'context': {'tree_use': usage, 'is_root': True, 'minimum_chunk_size': 262144},
                   'wraps': item['name'], 'active_profile_claim': False}
        wrapped['full_entries'] = [{'key_hex': key.hex(), 'entry': model(entry)} for key, entry in carrier.expanded(fields)]
        immutable(wrapped, binary, 'terrane-node-v1')
        rows.append(wrapped)

    legacy_fields = {
        1: bytes([1]) * 32, 2: [],
        3: {1: 'issuer', 2: bytes([2]) * 16, 3: 'subject', 4: 2,
            6: 'fixture process', 7: 24, 8: 7, 9: 1},
        4: 24, 5: '',
        6: {1: 1, 2: 'cdc-1m', 3: {1: 'index', 2: [bytes([1]) * 32, bytes([2]) * 32]}},
    }
    legacy = {'name': 'index-legacy-complete-commit', 'family': 'historical-commit',
              'positive': True, 'model': model(legacy_fields), 'wire_hex': cbor(legacy_fields).hex(),
              'active_profile_claim': False,
              'authority_note': 'Opaque context and retained recipe data; no verified authority.'}
    immutable(legacy, binary, 'terrane-commit-v1')
    assert len(bytes.fromhex(legacy['wire_hex'])) == 197
    rows.append(legacy)

    data, owners, empty = carrier.fixture(binary)
    outcomes = carrier.verify(data, owners)
    negatives = carrier.controls(data, owners, empty)
    chunk = {'name': 'index-source-direct-chunk-O', 'family': 'source-chunk', 'positive': True,
             'model': {'plaintext_bytes_hex': carrier.SOURCE.hex()}, 'wire_hex': carrier.SOURCE.hex(),
             'content_note': 'Chunk content bytes, not CBOR or an encoded storage envelope.'}
    immutable(chunk, binary, 'terrane-chunk-v1')
    assert chunk['identity_hex'] == data.object_id.hex()
    rows.append(chunk)

    for item in data.records:
        row = {'name': 'carrier-' + item['name'], 'family': 'carrier-node', 'positive': True,
               'model': item['model'], 'wire_hex': item['wire_hex'],
               'identity_hex': item['node_id'], 'domain': 'terrane-node-v1',
               'preimage_hex': item['preimage_hex'], 'descriptor': item['descriptor'],
               'descriptor_wire_hex': item['descriptor_wire_hex'], 'full_entries': item['full_entries'],
               'construction_order': item['construction_order'], 'role_claim': item['role_claim'],
               'external_context': carrier.ACTIVE, 'minimum_chunk_size': carrier.MIN_CHUNK}
        rows.append(row)
    for item in data.recipes:
        rows.append({'name': 'carrier-' + item['name'], 'family': 'carrier-recipe', 'positive': True,
                     'model': item['model'], 'wire_hex': item['wire_hex'],
                     'lookup_q_hex': item['memo_lookup_key'], 'lookup_preimage_hex': item['preimage_hex'],
                     'owner_R_hex': item['owner_node_id'], 'result_I_hex': item['expected_result_node_id'],
                     'constructed_after_node_count': item['constructed_after_node_count'],
                     'identity_note': item['identity_note']})
    owner_pairs = {name: (owner, index) for name, owner, index in owners}
    for item in negatives:
        scope = item['scope']
        child_scope = scope == 'terminal source predicate'
        source_owner = owner_pairs['child' if child_scope else 'repeated-grafts'][0]
        missing = item['name'] == 'missing-route-actually-present' or scope.endswith('missing objects')
        role = ('missing-route' if missing else 'present-route') if child_scope or scope == 'present route' else (
            'gap' if scope == 'missing objects' or scope.endswith('missing objects') else 'primary')
        if 'route' in scope and scope.startswith('property placement'):
            role = 'present-route'
        if item['name'] == 'gap-binding-on-namespace-owner':
            role = 'ordinary-namespace'
        rows.append({'name': 'carrier-bad-' + item['name'], 'family': 'carrier-negative',
                     'positive': False, 'model': item['model'], 'wire_hex': item['wire_hex'],
                     'external_context': carrier.ACTIVE, 'refusal_scope': classify_d104_negative(item['name']),
                     'external_predicate_scope': item['scope'], 'reason': item['mathematical_refusal'],
                     'selected_role': role, 'source_owner_R_hex': source_owner.hex(),
                     'expected_object_O_hex': data.object_id.hex(),
                     'expected_value_hex': None if missing else cbor(carrier.VALUE).hex(),
                     'is_root': item['name'] != 'gap-binding-on-nonroot',
                     'finite_mathematical_refusal': True,
                     'application_note': 'Reproduce raw fields independently. Relationship tests must rehash mutated nodes and rewire auxiliary ancestors rather than merely fail an old hash.'})

    assert len({row['name'] for row in rows}) == len(rows)
    assert all('accepted_closed_profile_row' not in row for row in rows)
    for row in rows:
        wire = bytes.fromhex(row['wire_hex'])
        row['length'] = len(wire)
        row['artifact_sha256'] = hashlib.sha256(wire).hexdigest()
        if not row['positive']:
            assert 'identity_hex' not in row and 'descriptor' not in row
    assert len(data.records) == 70 and len(data.by_digest) == 67
    assert len(data.recipes) == 4 and len(negatives) == 32
    return rows, outcomes


def inventory(rows):
    """Computes actual section counts, including duplicate-byte purpose fixtures."""
    immutable_rows = [row for row in rows if 'identity_hex' in row]
    counts = Counter(row['family'] for row in rows)
    return {'wire_cases': len(rows), 'positive_cases': sum(row['positive'] for row in rows),
            'negative_cases': sum(not row['positive'] for row in rows),
            'unique_wire_values': len({row['wire_hex'] for row in rows}),
            'immutable_positive_cases': len(immutable_rows),
            'immutable_unique_domain_identities': len({(row['domain'], row['identity_hex']) for row in immutable_rows}),
            'node_cases': sum(row.get('domain') == 'terrane-node-v1' for row in rows),
            'node_unique_identities': len({row['identity_hex'] for row in rows if row.get('domain') == 'terrane-node-v1'}),
            'lookup_q_cases': sum('lookup_q_hex' in row for row in rows),
            'lookup_q_unique_values': len({row['lookup_q_hex'] for row in rows if 'lookup_q_hex' in row}),
            'family_counts': dict(sorted(counts.items())),
            'negative_scope_counts': dict(sorted(Counter(row['refusal_scope'] for row in rows if not row['positive']).items()))}


def render(rows, counts):
    """Renders one bounded additive section with complete named field models."""
    lines = [
        HEADING, '',
        'Independent field witnesses for TEST-1/2/3, TREE-25/35, PROP-29/30/31 and DRV-25..30.',
        'The fields are ordinary unverified data. No indexed lookup, admission, current producer/policy,',
        'authority, incremental maintenance or runtime complexity qualification is claimed.',
        'D-106 distinguishes malformed format inputs from controls that fail a declared contextual relationship.',
        'Existing format negatives still require their owning decoder to reject the exact wire.',
        'Contextual controls require the declared role/source context and the corresponding typed verifier.',
        'Generic historical acceptance does not activate the closed carrier profile. Carrier roles require',
        'the externally represented property/attribute/tree tuple 3/2/1; older revisions leave later metadata inert.',
        'Only full positive Nodes, the complete historical Commit and actual source Chunk have immutable identities.',
        'Detached q is a lookup key; bindings, keys, negative wires and recipes have no content descriptor.',
        '',
        'Carrier controls use physical Index TreeUse, the indicated root placement and a 262,144-byte',
        'minimum chunk size. The ordinary-namespace placement control uses Ordinary TreeUse. Their',
        'named attribute is uid; the present value is canonical uint 24, and the missing predicate',
        'is absence of inline uid. Source R, actual O and the selected role are supplied separately.',
        'A source-relationship refusal requires rehashing the changed Node and updating affected',
        'auxiliary ancestors; failure to match an old stored digest is insufficient.',
        '',
        'The four complete graphs exercise child (one present and one missing occurrence), repeated',
        'grafts (two present and two missing), zero candidates (one missing), and long local routes',
        '(one present through 17 graft hops, 4,355 composed bytes). Repeated grafts retain distinct',
        'ordinary ACL layers. These are field and recurrence witnesses, with no current-policy claim.',
        '',
        '```text', 'inventory = ' + json.dumps(counts, sort_keys=True), '```', '',
    ]
    for row in rows:
        lines.extend(['### ' + row['name'], '', '```text',
                      'family = ' + row['family'], 'positive = ' + str(row['positive']).lower(),
                      'model = ' + json.dumps(row.get('model'), sort_keys=True, separators=(',', ':')),
                      'wire = ' + row['wire_hex']])
        for key in ('refusal_scope', 'reason', 'role_claim', 'wraps', 'current_primary_role', 'selected_role', 'source_owner_R_hex', 'expected_object_O_hex', 'expected_value_hex', 'is_root'):
            if key in row:
                lines.append(key + ' = ' + str(row[key]))
        for key in ('context', 'external_context', 'external_predicate_scope', 'primitive_assembly', 'full_entries'):
            if row.get(key) is not None:
                lines.append(key + ' = ' + json.dumps(row[key], sort_keys=True, separators=(',', ':')))
        if 'identity_hex' in row:
            lines.extend(['domain = ' + row['domain'], 'identity = ' + row['identity_hex'],
                          'preimage = ' + row['preimage_hex'],
                          'descriptor = ' + json.dumps(row['descriptor'], separators=(',', ':')),
                          'descriptor wire = ' + row['descriptor_wire_hex']])
        if 'lookup_q_hex' in row:
            lines.extend(['lookup q = ' + row['lookup_q_hex'], 'lookup preimage = ' + row['lookup_preimage_hex']])
        lines.extend(['```', ''])
    lines.extend(['<!-- End owner-bound index and occurrence-carrier field witnesses. -->', ''])
    return '\n'.join(lines).encode('utf8')


def bounded_section(data):
    """Rejects missing, duplicate or split sections and preserves exact UTF-8 bytes."""
    data.decode('utf8')
    start = (HEADING + '\n').encode()
    end = b'<!-- End owner-bound index and occurrence-carrier field witnesses. -->\n'
    if data.count(start) != 1 or data.count(end) != 1:
        raise ValueError('missing or duplicate section bounds')
    left = data.index(start)
    if left and data[left - 1] != 10:
        raise ValueError('section heading does not begin a line')
    right = data.index(end, left) + len(end)
    if b'\n## ' in data[left + len(start):right]:
        raise ValueError('split bounded section')
    return data[left:right]


def self_check(rows, counts, section):
    """Exercises exact-byte section refusal and primitive ordering/bounds controls."""
    assert cbor({256: 0, b'': 0}).hex() == 'a2190100004000'
    contrast = 'a2400019010000'
    assert cbor({256: 0, b'': 0}).hex() != contrast
    assert counts['wire_cases'] == 176 and counts['positive_cases'] == 104 and counts['negative_cases'] == 72
    assert all('identity_hex' not in row for row in rows if not row['positive'])
    assert all('descriptor' not in row for row in rows if 'lookup_q_hex' in row)
    prefix, suffix = b'# Unchanged preceding content\n\n', b'\n## Following unrelated section\n'
    assert bounded_section(prefix + section + suffix) == section
    mutations = {
        'missing': prefix + suffix,
        'duplicate': section + section,
        'inline-heading': b'prefix' + section,
        'split': section.replace(b'### ', b'## injected\n### ', 1),
        'crlf': section.replace(b'\n', b'\r\n'),
        'space': section.replace(b'wire = ', b'wire =  ', 1),
        'tamper': section.replace(b'1818', b'1819', 1),
    }
    for name, mutation in mutations.items():
        try:
            valid = bounded_section(mutation) == section
        except ValueError:
            valid = False
        assert not valid, name


def main():
    """Runs reproduction, exact published-byte checking, or section emission."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--blake3-bin', type=Path, required=True)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--self-check', action='store_true')
    modes.add_argument('--emit', action='store_true')
    modes.add_argument('--check', type=Path)
    args = parser.parse_args()

    rows, outcomes = corpus(args.blake3_bin)
    counts = inventory(rows)
    section = render(rows, counts)
    self_check(rows, counts, section)
    assert len(outcomes) == 4
    if args.check and bounded_section(args.check.read_bytes()) != section:
        raise ValueError('published section bytes differ')
    if args.emit:
        sys.stdout.buffer.write(section)
    else:
        print(json.dumps(counts, sort_keys=True))
        print('section_bytes=' + str(len(section)))
        print('section_sha256=' + hashlib.sha256(section).hexdigest())


if __name__ == '__main__':
    main()
