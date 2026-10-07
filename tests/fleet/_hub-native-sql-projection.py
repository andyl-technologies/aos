"""Retain independent reader-time SQL facts for selected immutable originals.

The caller supplies actual process, database and window custody. This collector
never attributes its snapshot to a prior production transaction or treats an
unavailable checkpoint as zero payload. Credentials and row images stay private.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import selectors
import socket
import urllib.parse
import time


NATIVE_SQL_TABLES = (
    'direct_upload_sessions', 'registry_publication_manifest_sessions',
    'registry_publication_manifest_chunks',
)
NATIVE_SQL_MAX_ROWS = 64
NATIVE_SQL_MAX_CHILD = 96 * 1024
NATIVE_SQL_MAX_OUTPUT = 512 * 1024


def native_sql_closed(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError('Native SQL closed schema differs')


def native_sql_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('Native SQL duplicate field')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)


def native_sql_digest(raw):
    return hashlib.sha256(raw).hexdigest()


def native_sql_identifier(value):
    if not isinstance(value, str) or not re.fullmatch('[A-Za-z0-9_-]{1,64}', value):
        raise ValueError('Native SQL original selector differs')
    return "'" + value + "'"


def native_sql_selectors(checkpoints):
    """Select only keys emitted by the finite successful source checkpoints."""
    if not isinstance(checkpoints, list) or not 1 <= len(checkpoints) <= NATIVE_SQL_MAX_ROWS:
        raise ValueError('Native SQL checkpoint count exceeds source bound')
    admissions, chunks = set(), set()
    for row in checkpoints:
        kind = row.get('kind')
        if kind == 'admission_checked_transaction':
            native_sql_identifier(row['sessionId'])
            admissions.add(row['sessionId'])
        elif kind in ('manifest_append_checked_transaction', 'manifest_append_retained_receipt'):
            native_sql_identifier(row['publicationId'])
            index = row['chunkIndex']
            if not isinstance(index, str) or not re.fullmatch('0|[1-9][0-9]{0,9}', index):
                raise ValueError('Native SQL chunk selector differs')
            if int(index) > 2**31 - 1:
                raise ValueError('Native SQL chunk exceeds production bound')
            chunks.add((row['publicationId'], int(index)))
        elif kind == 'dynamic':
            native_sql_dynamic_selectors([row])
        else:
            raise ValueError('Native SQL checkpoint kind is unsupported')
    return sorted(admissions), sorted(chunks)



NATIVE_SQL_DYNAMIC_TABLES = (
    'registry_publications', 'registries',
    'direct_upload_completion_intents', 'direct_upload_completion_receipts',
)


def native_sql_dynamic_selectors(checkpoints):
    """Select exact dynamic originals, never all objects in a publication."""
    if not isinstance(checkpoints, list) or not 1 <= len(checkpoints) <= NATIVE_SQL_MAX_ROWS:
        raise ValueError('Native SQL dynamic checkpoint count exceeds source bound')
    publications, sessions = set(), set()
    for checkpoint in checkpoints:
        if checkpoint.get('kind') != 'dynamic':
            continue
        value = checkpoint.get('observation')
        if not isinstance(value, dict):
            raise ValueError('Native SQL dynamic original is absent')
        operation = value.get('operation')
        if operation == 'publication_get':
            native_sql_identifier(value.get('publicationId'))
            publications.add(value['publicationId'])
        elif operation in ('direct_authorize', 'direct_commit'):
            native_sql_identifier(value.get('sessionId'))
            sessions.add(value['sessionId'])
        else:
            raise ValueError('Native SQL dynamic operation is unsupported')
    return sorted(publications), sorted(sessions)


def native_sql_tables(checkpoints):
    publications, sessions = native_sql_dynamic_selectors(checkpoints)
    return NATIVE_SQL_TABLES + (NATIVE_SQL_DYNAMIC_TABLES if publications or sessions else ())


def native_sql_codec_image(images, rows, evidence_sha256, read_image):
    """Join one exact codec input family to its actual retained reader rows."""
    extra = {'publications', 'dynamicSessions'} if 'publications' in rows else set()
    native_sql_closed(images, {'admissions', 'chunks'} | extra)
    candidates = [(images['admissions'], rows['admissions'], True)]
    candidates.extend((reference, [row], False)
                      for reference, row in zip(images['chunks'], rows['chunks'], strict=True))
    if extra:
        candidates.extend((reference, [row], False)
                          for reference, row in zip(images['publications'], rows['publications'], strict=True))
        candidates.append((images['dynamicSessions'], rows['dynamicSessions'], True))
    matches = [item for item in candidates if item[0]['sha256'] == evidence_sha256]
    if len(matches) != 1:
        raise ValueError('Native SQL codec input lacks one exact reader image')
    reference, expected, lines = matches[0]
    raw = read_image(reference, NATIVE_SQL_MAX_OUTPUT)
    parsed = ([native_sql_json(line) for line in raw.splitlines()] if lines
              else [native_sql_json(raw)])
    if parsed != expected:
        raise ValueError('Native SQL Core-decoded input differs from retained reader rows')
    return raw


def native_sql_match_dynamic(checkpoint, originals):
    """Compare source commitments to Core-validated original images only.

    Omitted compact status, old authorization and executed checked statements
    cannot be recreated by a later reader. Their absence is explicit.
    """
    selected = checkpoint['observation']
    operation = selected['operation']
    key = 'publicationId' if operation == 'publication_get' else 'sessionId'
    candidates = [row['values'] for row in originals if row.get('kind') == 'dynamic'
                  and row.get('values', {}).get('operation') == operation
                  and row['values'].get(key) == selected[key]]
    if len(candidates) != 1:
        raise ValueError('Dynamic source operation lacks one Core-validated reader original')
    row = candidates[0]
    fields = {
        'publication_get': ('publicationId', 'registryId', 'ordinal', 'manifestDigest',
                            'refsDigest', 'registryScopeSha256', 'reply'),
        'direct_authorize': ('sessionId', 'requestContext', 'selectedOriginal', 'action',
                             'completeStep', 'admission', 'baselinePermissions'),
        'direct_commit': ('sessionId', 'deploymentSha256', 'admission', 'completeOriginal',
                          'completionEvidence', 'finalGuards'),
    }[operation]
    if any(row.get(field) != selected[field] for field in fields):
        raise ValueError('Dynamic typed original differs from actual source commitment')
    missing = ['prior_operation_authority_not_reconstructed_by_later_reader']
    if operation == 'publication_get':
        missing.append('source_actor_requires_independent_authenticated_context')
    elif operation == 'direct_authorize':
        if 'returnedStatus' in row:
            if any(row.get(field) != selected[field] for field in
                   ('returnedStatus', 'observedState', 'observedResourceVersion')):
                raise ValueError('Dynamic actual returned status differs from source commitment')
        else:
            missing.append('compact_authorize_reply_omits_prior_full_status_and_version')
    else:
        expected = int(selected['expectedResourceVersion'])
        actual = int(row['receiptResultingResourceVersion'])
        reply = int(row['replyResourceVersion'])
        if selected['retainedOriginal']:
            if expected != reply:
                raise ValueError('Retained Commit version differs from actual reply')
        elif expected + 1 != actual or int(selected['resultingResourceVersion']) != actual or reply != actual:
            raise ValueError('Checked Commit source CAS differs from retained receipt/reply')
        missing.append('checked_statement_image_is_source_observation_not_reader_transaction_proof')
    return {'kind': 'dynamic', 'readerTimeOriginal': row, 'missing': missing}


def native_sql_dynamic_query(publications, sessions, deployment):
    """Keep reader-time progress and original receipt documents distinct."""
    publication_filter = ','.join(native_sql_identifier(key) for key in publications) or 'NULL'
    session_filter = ','.join(native_sql_identifier(key) for key in sessions) or 'NULL'
    return (
        ",'publications',COALESCE((SELECT json_agg(row_to_json(p)) FROM (SELECT "
        "p.publication_id AS \"publicationId\",p.registry_id::text AS \"registryId\","
        "r.slug AS \"registrySlug\",p.ordinal::text AS ordinal,p.state,"
        "p.manifest_digest AS \"manifestDigest\",p.refs_digest AS \"refsDigest\","
        "r.scope_key AS \"registryScopeKey\" FROM registry_publications p "
        "JOIN registries r ON r.id=p.registry_id WHERE p.publication_id IN ("
        + publication_filter + ") ORDER BY p.publication_id) p),'[]'::json),"
        "'dynamicSessions',COALESCE((SELECT json_agg(row_to_json(d)) FROM (SELECT "
        "json_build_object('sessionId',s.session_id,'publicationId',s.publication_id,"
        "'state',s.state,'admission',s.admission_json::json,"
        "'resourceVersion',s.resource_version::text,'ownerScopeKey',s.owner_scope_key,"
        "'cacheId',s.cache_id::text,'cacheTicketId',s.cache_ticket_id) AS original,"
        "CASE WHEN i.session_id IS NULL THEN NULL ELSE json_build_object("
        "'operationId',i.operation_id,'expectedResourceVersion',i.expected_resource_version::text,"
        "'intentDigest',i.intent_digest,'intent',i.intent_json::json,'admittedAt',i.admitted_at::text) "
        "END AS \"completeIntent\","
        "CASE WHEN c.session_id IS NULL THEN NULL ELSE json_build_object("
        "'operationId',c.operation_id,'logicalFingerprint',c.logical_fingerprint,"
        "'evidenceDigest',c.evidence_digest,'evidence',c.evidence_json::json,"
        "'finalGuards',c.final_guards_json::json,'committedAt',c.committed_at::text,"
        "'resultingResourceVersion',c.resulting_resource_version::text) END AS \"completionReceipt\" "
        "FROM direct_upload_sessions s LEFT JOIN direct_upload_completion_intents i "
        "ON i.deployment_id=s.deployment_id AND i.session_id=s.session_id "
        "LEFT JOIN direct_upload_completion_receipts c "
        "ON c.deployment_id=s.deployment_id AND c.session_id=s.session_id "
        "WHERE s.deployment_id='" + deployment + "' AND s.session_id IN ("
        + session_filter + ") ORDER BY s.session_id) d),'[]'::json)"
    )

def native_sql_query(checkpoints, deployment, role):
    """Build one bounded read-only transaction, never a production mutation."""
    if not isinstance(deployment, str) or not re.fullmatch('[a-z0-9-]{1,128}', deployment):
        raise ValueError('Native SQL deployment differs')
    if not isinstance(role, str) or not re.fullmatch('[a-z][a-z0-9_]{0,62}', role):
        raise ValueError('Native SQL reader role differs')
    admissions, chunks = native_sql_selectors(checkpoints)
    publications, dynamic_sessions = native_sql_dynamic_selectors(checkpoints)
    dynamic = native_sql_dynamic_query(publications, dynamic_sessions, deployment) if publications or dynamic_sessions else ''
    session_filter = ','.join(native_sql_identifier(key) for key in admissions) or 'NULL'
    chunk_filter = ' OR '.join('(c.publication_id=' + native_sql_identifier(key)
        + ' AND c.chunk_index=' + str(index) + ')' for key, index in chunks) or 'FALSE'
    privileges = ','.join("json_build_object('table','" + table
        + "','select',has_table_privilege(current_user,'" + table
        + "','SELECT'),'mutate',has_table_privilege(current_user,'" + table
        + "','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))" for table in native_sql_tables(checkpoints))
    query = (
        "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; "
        "SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='5s'; "
        "SELECT json_build_object('database',current_database(),'databaseOid',(SELECT oid::text FROM pg_database WHERE datname=current_database()),'serverPort',inet_server_port(),'serverAddress',host(inet_server_addr()),'user',current_user,"
        "'backendPid',pg_backend_pid(),'readOnly',current_setting('transaction_read_only'),"
        "'isolation',current_setting('transaction_isolation'),'snapshot',pg_current_snapshot()::text,"
        "'snapshotAt',transaction_timestamp()::text,'observedAt',clock_timestamp()::text,"
        "'role',(SELECT json_build_object('superuser',rolsuper,'createDb',rolcreatedb,"
        "'createRole',rolcreaterole,'bypassRls',rolbypassrls) FROM pg_roles WHERE rolname=current_user),"
        "'privileges',json_build_array(" + privileges + "),"
        "'admissions',COALESCE((SELECT json_agg(row_to_json(a)) FROM (SELECT "
        "session_id AS \"sessionId\",publication_id AS \"publicationId\",state,"
        "admission_json::json AS admission,resource_version::text AS \"resourceVersion\","
        "owner_scope_key AS \"ownerScopeKey\",cache_id::text AS \"cacheId\","
        "cache_ticket_id AS \"cacheTicketId\" FROM direct_upload_sessions WHERE deployment_id='"
        + deployment + "' AND session_id IN (" + session_filter + ") ORDER BY session_id) a),'[]'::json),"
        "'chunks',COALESCE((SELECT json_agg(row_to_json(c)) FROM (SELECT c.publication_id AS \"publicationId\","
        "c.chunk_index AS \"chunkIndex\",c.chunk_digest AS \"chunkDigest\",c.object_count AS \"objectCount\","
        "c.accepted_at::text AS \"acceptedAt\",s.registry_id::text AS \"registryId\","
        "s.resource_version::text AS \"resourceVersion\",s.state,"
        "s.manifest_digest AS \"manifestDigest\",s.lease_expires_at::text AS \"leaseExpiresAt\" "
        "FROM registry_publication_manifest_chunks c JOIN registry_publication_manifest_sessions s "
        "ON s.publication_id=c.publication_id WHERE " + chunk_filter
        + " ORDER BY c.publication_id,c.chunk_index) c),'[]'::json)" + dynamic + ")::text; COMMIT;"
    )
    if len(query.encode()) > 32 * 1024:
        raise ValueError('Native SQL query exceeds bound')
    return query


def native_sql_process(pid):
    """Read the actual Linux process lifetime and executable, not an input flag."""
    if type(pid) is not int or pid <= 1:
        raise ValueError('Native SQL process PID differs')
    root = Path('/proc') / str(pid)
    fields = (root / 'stat').read_text().rpartition(') ')[2].split()
    if fields[0] == 'Z':
        raise ValueError('Native SQL process exited')
    with (root / 'exe').open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'pid': pid, 'ownerUid': root.stat().st_uid, 'startTicks': fields[19],
            'executableSha256': digest}



def native_sql_backend(pid, database_process):
    """Join the live queried backend to the selected local PostgreSQL parent."""
    pin = native_sql_process(pid)
    fields = (Path('/proc') / str(pid) / 'stat').read_text().rpartition(') ')[2].split()
    if (int(fields[1]) != database_process['pid']
            or pin['ownerUid'] != database_process['ownerUid']
            or pin['executableSha256'] != database_process['executableSha256']
            or native_sql_process(database_process['pid']) != database_process):
        raise ValueError('Native SQL backend does not belong to selected database process')
    return {**pin, 'parentPid': int(fields[1])}


def native_sql_private(path, maximum):
    """Read the same held owner-private inode through a complete hash bracket."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_mode & 0o077 or before.st_nlink != 1 or before.st_size > maximum):
            raise ValueError('Native SQL private input custody differs')
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key)
            for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
        raise ValueError('Native SQL private input changed')
    return raw


def native_sql_rows(raw, selection, checkpoints, *, server_address='127.0.0.1', server_port=5432,
                    managed_socket=False):
    """Check actual reader identity and exact selected coverage at reader time."""
    if not 0 < len(raw) <= NATIVE_SQL_MAX_OUTPUT or len(raw.splitlines()) != 1:
        raise ValueError('Native SQL output bound or framing differs')
    value = native_sql_json(raw)
    publications, dynamic_sessions = native_sql_dynamic_selectors(checkpoints)
    dynamic_fields = {'publications', 'dynamicSessions'} if publications or dynamic_sessions else set()
    native_sql_closed(value, {'database', 'databaseOid', 'serverPort', 'serverAddress', 'user', 'backendPid', 'readOnly', 'isolation',
        'snapshot', 'snapshotAt', 'observedAt', 'role', 'privileges', 'admissions', 'chunks'} | dynamic_fields)
    if type(managed_socket) is not bool:
        raise ValueError('Native SQL selected transport differs')
    if managed_socket and (server_address is not None or server_port is not None):
        raise ValueError('Native SQL selected socket facts differ')
    endpoint = (value['serverAddress'] is None and value['serverPort'] is None) if managed_socket else (
        value['serverAddress'] == server_address and type(value['serverPort']) is int
        and value['serverPort'] == server_port)
    if (value['database'] != selection['database'] or value['user'] != selection['role']
            or not isinstance(value['databaseOid'], str) or not re.fullmatch('[1-9][0-9]{0,9}', value['databaseOid'])
            or not endpoint
            or type(value['backendPid']) is not int or value['backendPid'] <= 1
            or value['readOnly'] != 'on' or value['isolation'] != 'repeatable read'):
        raise ValueError('Native SQL actual database/role/transaction differs')
    native_sql_closed(value['role'], {'superuser', 'createDb', 'createRole', 'bypassRls'})
    if any(flag is not False for flag in value['role'].values()):
        raise ValueError('Native SQL reader has elevated privileges')
    if (not isinstance(value['privileges'], list) or len(value['privileges']) != len(native_sql_tables(checkpoints))
            or {row.get('table') for row in value['privileges']} != set(native_sql_tables(checkpoints))):
        raise ValueError('Native SQL privilege coverage differs')
    for row in value['privileges']:
        native_sql_closed(row, {'table', 'select', 'mutate'})
        if row['select'] is not True or row['mutate'] is not False:
            raise ValueError('Native SQL reader is not SELECT-only')
    if not isinstance(value['snapshot'], str) or not re.fullmatch('[0-9]+:[0-9]+:[0-9,]*', value['snapshot']):
        raise ValueError('Native SQL snapshot identity differs')
    for key in ('snapshotAt', 'observedAt'):
        if not isinstance(value[key], str) or not re.fullmatch(r'[0-9:T .+\-]{10,64}', value[key]):
            raise ValueError('Native SQL actual clock field differs')
    admissions, chunks = native_sql_selectors(checkpoints)
    if (not isinstance(value['admissions'], list) or not isinstance(value['chunks'], list)
            or len(value['admissions']) != len(admissions) or len(value['chunks']) != len(chunks)
            or sorted(row.get('sessionId') for row in value['admissions']) != admissions
            or sorted((row.get('publicationId'), row.get('chunkIndex')) for row in value['chunks']) != chunks):
        raise ValueError('Native SQL original coverage differs')
    if dynamic_fields:
        if (not isinstance(value['publications'], list) or not isinstance(value['dynamicSessions'], list)
                or len(value['publications']) != len(publications)
                or len(value['dynamicSessions']) != len(dynamic_sessions)
                or sorted(row.get('publicationId') for row in value['publications']) != publications
                or sorted(row.get('original', {}).get('sessionId') for row in value['dynamicSessions']) != dynamic_sessions):
            raise ValueError('Native SQL dynamic original coverage differs')
    return value


def native_sql_environment(raw, role, root):
    """Use only the selected loopback trust binding; never discover a password."""
    if raw != ('postgresql://' + role + '@127.0.0.1:5432/postgres').encode():
        raise ValueError('SQL reader is not the exact selected loopback trust connection')
    environment = {key: value for key, value in os.environ.items() if not key.startswith('PG')}
    environment.update(PGHOST='127.0.0.1', PGPORT='5432', PGDATABASE='postgres', PGUSER=role,
                       PGSSLMODE='disable', PGPASSFILE=str(root / 'password-not-selected'))
    if (root / 'password-not-selected').exists():
        raise ValueError('SQL reader unexpectedly has a password selection')
    return environment


def native_sql_collect(selection, checkpoints):
    """Retain one actual local psql process and its reader-time snapshot.

    The reader and PostgreSQL backend are measured on the Database guest.
    Native observations are independently controller-bracketed on Native.
    """
    native_sql_closed(selection, {'root', 'psql', 'psqlSha256', 'databaseUrlFile',
        'database', 'role', 'deployment', 'databaseProcess', 'databaseBootId',
        'windowStartUnixNanos', 'windowEndUnixNanos', 'collectorSourceSha256', 'runtimeSourcePath'})
    executable = Path(selection['psql']).resolve(strict=True)
    if (not str(executable).startswith('/nix/store/') or '..' in Path(selection['psql']).parts
            or native_sql_digest(executable.read_bytes()) != selection['psqlSha256']):
        raise ValueError('Native SQL source-built executable custody differs')
    processes_before = {}
    for key in ('databaseProcess',):
        processes_before[key] = native_sql_process(selection[key]['pid'])
        if processes_before[key] != selection[key]:
            raise ValueError('Native SQL selected live process differs')
    if Path('/proc/sys/kernel/random/boot_id').read_text().strip() != selection['databaseBootId']:
        raise ValueError('SQL selected Database boot changed')
    before = {'wallNs': str(time.time_ns()), 'monotonicNs': str(time.monotonic_ns())}
    query = native_sql_query(checkpoints, selection['deployment'], selection['role'])
    database = native_sql_private(selection['databaseUrlFile'], 8192)
    root = Path(selection['root']); root.mkdir(mode=0o700, exist_ok=False)
    def retain(name, raw):
        fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(raw); output.flush(); os.fsync(output.fileno())
        return {'file': str(root / name), 'sha256': native_sql_digest(raw), 'byteSize': str(len(raw))}
    query_ref = retain('query.sql', query.encode())
    environment = native_sql_environment(database, selection['role'], root)
    argv = [str(executable), '-X', '--no-password', '-qAt', '-v', 'ON_ERROR_STOP=1']
    with (root / 'rows.private.json').open('xb') as output, (root / 'stderr.private').open('xb') as errors:
        os.chmod(output.name, 0o600); os.chmod(errors.name, 0o600)
        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=environment)
        backend = None
        stdout_image = bytearray()
        try:
            pin = native_sql_process(child.pid)
            if pin['executableSha256'] != selection['psqlSha256']:
                raise ValueError('Native SQL executed process differs from selected psql')
            # Hold the read-only transaction open only long enough to measure
            # its live backend. Production transactions and leases are untouched.
            child.stdin.write(query.removesuffix(' COMMIT;').encode() + b'\n')
            child.stdin.flush()
            counts = {'stdout': 0, 'stderr': 0}
            deadline = time.monotonic() + 25
            with selectors.DefaultSelector() as selected:
                selected.register(child.stdout, selectors.EVENT_READ, ('stdout', output, NATIVE_SQL_MAX_OUTPUT))
                selected.register(child.stderr, selectors.EVENT_READ, ('stderr', errors, 65536))
                while selected.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('Native SQL original observation cutoff elapsed')
                    for key, _ in selected.select(min(remaining, 1)):
                        name, destination, bound = key.data
                        block = os.read(key.fd, 65536)
                        if not block:
                            selected.unregister(key.fileobj)
                            continue
                        room = bound - counts[name]
                        destination.write(block[:room])
                        counts[name] += min(len(block), room)
                        if name == 'stdout':
                            stdout_image.extend(block[:room])
                            if backend is None and b'\n' in stdout_image:
                                observed = native_sql_rows(bytes(stdout_image), selection, checkpoints)
                                backend = native_sql_backend(observed['backendPid'], selection['databaseProcess'])
                                child.stdin.write(b'COMMIT;\n'); child.stdin.close()
                        if len(block) > room:
                            raise ValueError('Native SQL output exceeds retained bound')
            child.wait(timeout=max(0.001, deadline - time.monotonic()))
        except BaseException as error:
            if child.poll() is None:
                child.kill()
            child.wait()
            retain('interrupted.private.json', json.dumps({'state': 'unknown',
                'reason': type(error).__name__, 'exitCode': child.returncode}).encode())
            raise
        finally:
            if not child.stdin.closed:
                child.stdin.close()
            child.stdout.close(); child.stderr.close()
        output.flush(); os.fsync(output.fileno()); errors.flush(); os.fsync(errors.fileno())
    after = {'wallNs': str(time.time_ns()), 'monotonicNs': str(time.monotonic_ns())}
    processes_after = {}
    for key in ('databaseProcess',):
        processes_after[key] = native_sql_process(selection[key]['pid'])
        if processes_after[key] != processes_before[key]:
            raise ValueError('Native SQL authority process changed across read')
    raw = native_sql_private(root / 'rows.private.json', NATIVE_SQL_MAX_OUTPUT)
    errors = native_sql_private(root / 'stderr.private', 65536)
    if Path('/proc/sys/kernel/random/boot_id').read_text().strip() != selection['databaseBootId']:
        raise ValueError('SQL selected Database boot changed')
    receipt = {'version': 2, 'query': query_ref, 'rows': {'file': str(root / 'rows.private.json'),
        'sha256': native_sql_digest(raw), 'byteSize': str(len(raw))},
        'stderrSha256': native_sql_digest(errors), 'exitCode': child.returncode,
        'readerProcess': pin, 'backendProcess': backend, 'redactedArgv': argv, 'psqlExecutableSha256': selection['psqlSha256'],
        'databaseUrlSha256': native_sql_digest(database), 'before': before, 'after': after,
        'processesBefore': processes_before, 'processesAfter': processes_after,
        'selection': {key: value for key, value in selection.items() if key not in ('databaseUrlFile', 'root')}}
    retain('receipt.private.json', json.dumps(receipt, separators=(',', ':')).encode())
    if (child.returncode or int(after['wallNs']) < int(before['wallNs'])
            or not int(selection['windowStartUnixNanos']) <= int(before['wallNs'])
                <= int(after['wallNs']) <= int(selection['windowEndUnixNanos'])):
        raise ValueError('Native SQL query failed or lies outside selected current window')
    rows = native_sql_rows(raw, selection, checkpoints)
    admissions = b''.join(json.dumps(row, separators=(',', ':')).encode() + b'\n'
                          for row in rows['admissions'])
    # This is retained PostgreSQL JSON formatting, not a Core canonical digest.
    codec_images = {'admissions': retain('admissions.codec.jsonl', admissions),
                    'chunks': [retain('chunk-%02d.codec.json' % index,
                        json.dumps(row, separators=(',', ':')).encode())
                        for index, row in enumerate(rows['chunks'])]}
    if 'publications' in rows:
        codec_images['publications'] = [retain('publication-%02d.codec.json' % index,
            json.dumps(row, separators=(',', ':')).encode()) for index, row in enumerate(rows['publications'])]
        codec_images['dynamicSessions'] = retain('dynamic-sessions.codec.jsonl', b''.join(
            json.dumps(row, separators=(',', ':')).encode() + b'\n' for row in rows['dynamicSessions']))
    return {'rows': rows, 'receipt': receipt, 'codecImages': codec_images,
            'scope': 'independent reader-time snapshot; prior IAM/lease/current fence not reconstructed',
            'objectPayloadBytes': None}


def native_sql_native_context(selected):
    """Measure Native and its configured DB endpoint without exposing credentials."""
    before = native_sql_process(selected['nativeProcess']['pid'])
    if any(before[key] != selected['nativeProcess'][key]
           for key in ('pid', 'startTicks', 'executableSha256')):
        raise ValueError('Native source/body-window lifetime differs')
    environment = (Path('/proc') / str(before['pid']) / 'environ').read_bytes().split(b'\0')
    values = [entry.split(b'=', 1)[1] for entry in environment
              if entry.startswith(b'HUB_DATABASE_URL_FILE=')]
    if any(entry.startswith(b'HUB_DATABASE_URL=') for entry in environment):
        raise ValueError('Native direct connection override is unsupported')
    if len(values) != 1 or os.fsdecode(values[0]) != selected['nativeDatabaseUrlFile']:
        raise ValueError('Native current database-file configuration differs')
    raw = native_sql_private(selected['nativeDatabaseUrlFile'], 8192)
    url = urllib.parse.urlsplit(raw.decode().strip())
    addresses = sorted({entry[4][0] for entry in socket.getaddrinfo(url.hostname, None)})
    expected = sorted({entry[4][0] for entry in socket.getaddrinfo(selected['databaseHost'], None)})
    database = urllib.parse.unquote(url.path.removeprefix('/'))
    if (url.scheme not in ('postgres', 'postgresql') or url.query or url.fragment
            or database != 'postgres' or (url.port or 5432) != 5432 or addresses != expected):
        raise ValueError('Native selected fixture database endpoint differs')
    if native_sql_process(before['pid']) != before:
        raise ValueError('Native lifetime changed during private connection observation')
    return {'process': before, 'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'database': database, 'port': url.port or 5432, 'resolvedAddresses': addresses,
            'connectionFileSha256': native_sql_digest(raw)}


def native_sql_database_context(selected):
    """Measure the selected local postmaster rather than inventing remote /proc."""
    path = Path('/var/lib/hybrid-postgres/postmaster.pid')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        raw = stream.read(8193)
        after = os.fstat(stream.fileno())
    if (not stat.S_ISREG(before.st_mode) or before.st_mode & 0o077 or before.st_nlink != 1
            or len(raw) != before.st_size or len(raw) > 8192
            or any(getattr(before, key) != getattr(after, key) for key in
                   ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))):
        raise ValueError('Selected postmaster file custody differs')
    lines = raw.decode().splitlines()
    if len(lines) < 6 or lines[1] != '/var/lib/hybrid-postgres' or lines[3] != '5432':
        raise ValueError('Selected fixture postmaster file differs')
    pin = native_sql_process(int(lines[0]))
    addresses = sorted({entry[4][0] for entry in socket.getaddrinfo(selected['databaseHost'], None)})
    if before.st_uid != pin['ownerUid'] or path.read_bytes() != raw or native_sql_process(pin['pid']) != pin:
        raise ValueError('Selected postmaster changed during observation')
    return {'process': pin, 'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'postmasterFileSha256': native_sql_digest(raw), 'dataDirectory': lines[1],
            'port': int(lines[3]), 'resolvedAddresses': addresses}


def native_sql_topology(native_before, native_after, database_before, database_after):
    """Join independently measured endpoints and lifetimes, never URL strings."""
    if native_before != native_after or database_before != database_after:
        raise ValueError('Selected SQL topology lifetime changed')
    if (native_before['bootId'] == database_before['bootId']
            or native_before['resolvedAddresses'] != database_before['resolvedAddresses']
            or native_before['port'] != database_before['port']):
        raise ValueError('Selected separate-machine database mapping differs')


def capture_native_sql_projection(native, database_machine, tools, checkpoints,
                                  reader, native_process, database_host, *, capture_namespace=None):
    """Select the ordinary five-VM reader explicitly and retain both host brackets."""
    if (capture_namespace is not None
            and (not isinstance(capture_namespace, str)
                 or re.fullmatch(r'queue-fault-[0-9a-f]{64}', capture_namespace) is None)):
        raise ValueError('SQL capture namespace is not an exact queue fault original')
    prefix = '' if capture_namespace is None else capture_namespace + '-'
    if not checkpoints:
        return {'version': 1, 'observations': [], 'objectPayloadBytes': None,
                'missing': ['absent_or_capped_source_sql_projection_child']}
    if native.name == database_machine.name:
        raise ValueError('Five-machine SQL collector received the same guest twice')
    script = Path(tools['nativeSqlProjectionCollector']).read_text()
    script_sha = native_sql_digest(script.encode())
    def observe(machine, function, document):
        before = {'wallNs': str(time.time_ns()), 'monotonicNs': str(time.monotonic_ns())}
        raw = direct_guest_python(machine, tools['python'], script + '\n'
            + 'print(json.dumps(' + function + '(selected)))\n', document, timeout=40)
        after = {'wallNs': str(time.time_ns()), 'monotonicNs': str(time.monotonic_ns())}
        return {'guestName': machine.name, 'controllerBefore': before,
                'controllerAfter': after, 'observed': native_sql_json(raw)}
    selected = {'nativeProcess': native_process, 'nativeDatabaseUrlFile': tools['nativeDatabaseUrlFile'],
                'databaseHost': database_host}
    observations = []
    retained_bytes = 0
    for index, batch in enumerate(checkpoints):
        operations = batch['checkpoints']
        native_before = observe(native, 'native_sql_native_context', selected)
        database_before = observe(database_machine, 'native_sql_database_context', selected)
        root = '/var/lib/hybrid-worker/' + prefix + 'native-sql-projection-%04d' % index
        local = {'root': root, 'role': reader['role'], 'deployment': tools['deploymentId'],
                 'database': 'postgres', 'psql': tools['postgres'] + '/psql',
                 'collectorSourceSha256': script_sha, 'runtimeSourcePath': tools['workerSourcePath'],
                 'databaseUrlFile': root + '-connection.private',
                 'databaseProcess': database_before['observed']['process'],
                 'databaseBootId': database_before['observed']['bootId']}
        body = script + "\n" + """
Path(selected['selection']['root']).parent.mkdir(mode=0o700, exist_ok=True)
connection = 'postgresql://' + selected['selection']['role'] + '@127.0.0.1:5432/postgres'
fd = os.open(selected['selection']['databaseUrlFile'], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'wb') as output:
    output.write(connection.encode()); output.flush(); os.fsync(output.fileno())
selection = selected['selection']
selection['psqlSha256'] = native_sql_digest(Path(selection['psql']).read_bytes())
selection['windowStartUnixNanos'] = str(time.time_ns())
selection['windowEndUnixNanos'] = str(int(selection['windowStartUnixNanos']) + 30_000_000_000)
print(json.dumps(native_sql_collect(selection, selected['checkpoints'])))
"""
        raw = direct_guest_python(database_machine, tools['python'], body,
                                  {'selection': local, 'checkpoints': operations}, timeout=40)
        result = native_sql_json(raw)
        database_after = observe(database_machine, 'native_sql_database_context', selected)
        native_after = observe(native, 'native_sql_native_context', selected)
        native_sql_topology(native_before['observed'], native_after['observed'],
                            database_before['observed'], database_after['observed'])
        images = []
        references = [result['receipt']['query'], result['receipt']['rows'],
                      result['codecImages']['admissions'], *result['codecImages']['chunks']]
        if 'publications' in result['codecImages']:
            references.extend(result['codecImages']['publications'])
            references.append(result['codecImages']['dynamicSessions'])
        for position, reference in enumerate(references):
            if not reference['file'].startswith(root + '/'):
                raise ValueError('SQL image escaped the selected Database private root')
            encoded = direct_guest_python(database_machine, tools['python'], script + '\n'
                + "raw=native_sql_private(selected['file'],512*1024)\n"
                + "if native_sql_digest(raw)!=selected['sha256'] or str(len(raw))!=selected['byteSize']:raise ValueError('SQL received image differs')\n"
                + "print(base64.b64encode(raw).decode())\n", reference, timeout=30)
            image = base64.b64decode(encoded.strip(), validate=True)
            if native_sql_digest(image) != reference['sha256'] or str(len(image)) != reference['byteSize']:
                raise ValueError('Transferred Database SQL image commitment differs')
            name = prefix + 'native-sql-%04d-image-%02d.private' % (index, position)
            retain_direct_flow(name, image)
            received = {'file': str((Path('external-direct-flow') / name).resolve()),
                        'sha256': native_sql_digest(image), 'byteSize': str(len(image))}
            images.append({'guestReference': reference, 'controllerReference': received})
        result['controller'] = {'nativeBefore': native_before, 'nativeAfter': native_after,
            'databaseBefore': database_before, 'databaseAfter': database_after,
            'connectionMode': 'existing_select_only_role_over_database_loopback_trust',
            'collectorSourceSha256': script_sha, 'receivedImages': images,
            'sourceChild': {key: batch[key] for key in ('rawChildSha256', 'rawChildByteSize')}}
        retained_bytes += len(json.dumps(result).encode()) + sum(int(item['controllerReference']['byteSize']) for item in images)
        if retained_bytes > 64 * 1024 * 1024:
            raise ValueError('Selected SQL reader corpus exceeds retained bound')
        observations.append(result)
    return {'version': 1, 'observations': observations, 'objectPayloadBytes': None,
            'missing': ['independent_prior_operation_iam_lease_and_cross_machine_clock_bounds']}


def native_sql_checkpoints(messages, maximum=4096):
    """Return finite source keys without claiming log or body custody.

    The reader performs member/raw-child/source joins separately. A collector
    may use these keys for a SELECT; arbitrary supplied keys grant no authority.
    """
    values = []
    for message, _ in messages:
        marker = 'native_application_sql_projection '
        if not isinstance(message, str) or marker not in message:
            continue
        if message.count(marker) != 1:
            raise ValueError('Ambiguous Native SQL source message')
        raw = message.split(marker, 1)[1].encode()
        if len(raw) > NATIVE_SQL_MAX_CHILD:
            raise ValueError('Native SQL source child exceeds bound')
        child = native_sql_json(raw)
        projection = child['projection']
        if (type(child['version']) is not int or child['version'] != 1
                or child['event'] != 'sql_projection' or child['status'] != 200
                or type(projection['version']) is not int or projection['version'] != 1
                or not isinstance(projection['checkpoints'], list)
                or not 1 <= len(projection['checkpoints']) <= NATIVE_SQL_MAX_ROWS):
            raise ValueError('Native SQL source aggregate differs')
        if len(values) >= maximum:
            raise ValueError('Native SQL selected child corpus exceeds collector bound')
        native_sql_selectors(projection['checkpoints'])
        values.append({'checkpoints': projection['checkpoints'],
                       'rawChildSha256': native_sql_digest(raw), 'rawChildByteSize': str(len(raw))})
    return values
