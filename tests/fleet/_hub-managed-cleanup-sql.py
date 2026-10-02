"""Observe exact terminal cleanup SQL tuples without granting Delete permission.

The Native guest runs the existing confined read-only PostgreSQL capture. Two
independent snapshots must preserve the five arrays committed by the actual
post-check Native receipt; request/reply hashes come from its captured exchange.
The canonical arrays contain integers, UTF-8 strings, booleans and nulls only.
"""

import hashlib
import json
import re


CLEANUP_TUPLE_TYPES = {
    'uploadStateSha256': (str, int, str, str, (int, type(None)),
                         (int, type(None)), (int, type(None)), (int, type(None))),
    'chunkStateSha256': (int, int, int, str, str, int),
    'placementStateSha256': (int, int, int, int, str),
    'bindingStateSha256': (int, int, str, str, bool, int),
    'deleteCapabilitySha256': ((str, type(None)), int, int, str,
                              (int, type(None)), (str, type(None))),
}


def cleanup_sql_require(condition, message):
    if not condition:
        raise ValueError(message)


def cleanup_sql_hashes(value):
    """Hash closed SQL arrays using the Native compact UTF-8 JSON representation."""
    cleanup_sql_require(isinstance(value, dict) and set(value) == set(CLEANUP_TUPLE_TYPES),
                        'cleanup SQL tuple fields differ')
    hashes = {}
    for field, expected in CLEANUP_TUPLE_TYPES.items():
        row = value[field]
        cleanup_sql_require(isinstance(row, list) and len(row) == len(expected),
                            'cleanup SQL tuple length differs')
        for item, kind in zip(row, expected):
            allowed = kind if isinstance(kind, tuple) else (kind,)
            cleanup_sql_require(type(item) in allowed,
                                'cleanup SQL tuple type differs')
            if type(item) is int:
                cleanup_sql_require(-(2**63) <= item < 2**64,
                                    'cleanup SQL integer exceeds actual serialized bounds')
            if type(item) is str:
                cleanup_sql_require(len(item.encode()) <= 4096,
                                    'cleanup SQL string exceeds observation bound')
        encoded = json.dumps(row, ensure_ascii=False, separators=(',', ':'),
                             allow_nan=False).encode()
        hashes[field] = hashlib.sha256(encoded).hexdigest()
    return hashes


def managed_cleanup_sql_query(original, database, transaction):
    """Select only the actual retained upload/chunk and their current addresses."""
    cleanup_sql_require(isinstance(original, dict)
        and isinstance(original.get('upload_id'), str)
        and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', original['upload_id'])
        and type(original.get('ordinal')) is int and 0 <= original['ordinal'] < 2**32
        and type(original.get('placement_id')) is int and original['placement_id'] > 0
        and type(original.get('binding_id')) is int and original['binding_id'] > 0
        and type(original.get('binding_write_revision')) is int and original['binding_write_revision'] > 0,
        'actual cleanup original SQL selector differs')
    upload = original['upload_id']
    ordinal = original['ordinal']
    placement = original['placement_id']
    binding = original['binding_id']
    revision = original['binding_write_revision']
    query = f"""
        SELECT COALESCE(json_agg(row_to_json(selected)), '[]'::json) FROM (
          SELECT json_build_array(upload.id, upload.resource_version, upload.state,
                   upload.cleanup_state, upload.finished_at, upload.staging_placement_id,
                   upload.staging_binding_id, upload.staging_binding_write_revision)
                   AS "uploadStateSha256",
                 json_build_array(chunk.ordinal, chunk.byte_offset, chunk.byte_size,
                   chunk.digest, chunk.staging_object_key, chunk.created_at)
                   AS "chunkStateSha256",
                 json_build_array(placement.id, placement.resource_version,
                   placement.binding_id, placement.registry_id, placement.prefix)
                   AS "placementStateSha256",
                 json_build_array(binding.id, binding.resource_version, binding.stable_id,
                   binding.kind, binding.is_instance_default, writer.current_write_revision)
                   AS "bindingStateSha256",
                 json_build_array(capability.capability_fingerprint, capability.resource_version,
                   capability.binding_resource_version, capability.state,
                   capability.delete_credential_generation, capability.delete_credential_purpose)
                   AS "deleteCapabilitySha256"
          FROM oci_upload_sessions upload
          JOIN oci_upload_chunks chunk ON chunk.upload_id = upload.id
          JOIN surface_placements placement ON placement.id = {placement}
          JOIN bindings binding ON binding.id = placement.binding_id
          JOIN binding_write_state writer ON writer.binding_id = binding.id
          JOIN oci_conditional_delete_capabilities capability ON capability.binding_id = binding.id
            AND capability.binding_resource_version = binding.resource_version
            AND capability.binding_write_revision = {revision}
          WHERE upload.id = '{upload}' AND chunk.ordinal = {ordinal}
            AND placement.id = {placement} AND binding.id = {binding}
          LIMIT 2
        ) selected
    """
    # This existing builder supplies fixed READ ONLY, database identity, timeout
    # and one-result framing. It does not manufacture a capability from the row.
    return transaction(query, database)


def capture_managed_cleanup_sql(native, tools, prepared, processes, original, label, *,
                                transaction, observe_process, capture_rows, retain):
    """Capture actual rows and bind their query/source to the live Native process."""
    query = managed_cleanup_sql_query(original, prepared['coordinates']['database'], transaction)
    before = observe_process(native, tools, processes['native'])
    rows = capture_rows(native, tools, prepared, query, label)
    after = observe_process(native, tools, processes['native'])
    cleanup_sql_require(all(before[field] == after[field] for field in (
        'pid', 'startTicks', 'ownerUid', 'executableSha256', 'commandLineSha256',
        'environmentSha256')), 'cleanup SQL capture changed Native process')
    cleanup_sql_require(isinstance(rows, list) and len(rows) == 1,
                        'cleanup SQL original is absent or ambiguous')
    result = {'version': 1, 'querySha256': hashlib.sha256(query.encode()).hexdigest(),
        'sourceDigest': prepared['captureSelection']['sourceDigest'],
        'database': prepared['coordinates']['database'], 'beforeProcess': before,
        'afterProcess': after, 'tuples': rows[0], 'commitments': cleanup_sql_hashes(rows[0]),
        'sqlReceiptFile': label + '-sql.json',
        'scope': 'independent current SQL observation; no Delete permission'}
    retain(label + '-cleanup-current-sql.json', result)
    return result


def join_managed_cleanup_sql(before, after, context, source_digest, helper_process, *, settled=False):
    """Require exact independent tuple equality and actual final-check correlation."""
    cleanup_sql_require(before['sourceDigest'] == after['sourceDigest'] == source_digest
        and before['database'] == after['database']
        and context['contextKind'] == 'managed_oci_cleanup_delete_checked',
        'cleanup SQL changed or final checked context differs')
    cleanup_sql_require(cleanup_sql_hashes(before['tuples']) == before['commitments']
        and cleanup_sql_hashes(after['tuples']) == after['commitments'],
        'cleanup SQL tuple commitments were substituted')
    if settled:
        original, final = before['tuples']['uploadStateSha256'], after['tuples']['uploadStateSha256']
        cleanup_sql_require(final[0] == original[0] and final[1] > original[1]
            and final[2] == original[2] and final[3] == 'complete' and final[4] == original[4]
            and final[5:] == [None, None, None]
            and all(before['tuples'][field] == after['tuples'][field]
                for field in CLEANUP_TUPLE_TYPES if field != 'uploadStateSha256'),
            'cleanup settlement does not preserve its original and exact cleared locators')
    else:
        cleanup_sql_require(before['commitments'] == after['commitments'],
                            'cleanup SQL changed around the actual final check')
    for field, digest in before['commitments'].items():
        cleanup_sql_require(context['commitments'].get(field) == digest,
                            'actual final-check SQL tuple differs from independent snapshot')
    completed = int(context['completedAtUnixMicros']) * 1000
    cleanup_sql_require(int(before['afterProcess']['observedAtUnixMicros']) * 1000
        <= int(helper_process['started']['unixNs'])
        <= int(helper_process['finished']['unixNs'])
        <= int(after['beforeProcess']['observedAtUnixMicros']) * 1000,
        'cleanup helper is not bracketed by its actual independent SQL observations')
    cleanup_sql_require(int(helper_process['started']['unixNs']) <= completed
        <= int(helper_process['finished']['unixNs']),
        'cleanup final check belongs to a different helper lifetime')
    return {'sourceDigest': source_digest, 'database': before['database'],
        'tupleCommitments': before['commitments'], 'transportCallId': context['exchange']['transportCallId'],
        'requestSha256': context['exchange']['requestSha256'],
        'replySha256': context['exchange']['replySha256'],
        'helperProcess': {field: helper_process[field] for field in (
            'pid', 'startTicks', 'executableSha256')},
        'scope': 'observed identical current tuples and existing accepted Delete check'}
