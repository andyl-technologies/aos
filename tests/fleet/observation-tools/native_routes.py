"""Join two actual Native constructors to independently retained origin frames.

Inputs come from the installed assessment's successful codec invocation, checked
Native authenticator and exported_receipt locals. This pure join neither opens
credentials nor authenticates a caller-supplied JSON report. It preserves actual
control/query-output counts; SQL authority and whole-body totals remain unknown.
"""

import hashlib
from pathlib import Path
import re


MAX_CAPTURES = 4096
MAX_RECEIPTS = 262144
RPC_SOURCES = ('crates/aos-hub-core/src/application_body_observation.rs',
               'crates/aos-hub-core/src/application_body_observation/rpc.rs',
               'crates/aos-hub-core/src/connect.rs')
BROWSER_SOURCE = 'crates/aos-hub-core/src/web/console/handlers.rs'
ROUTES = {
    ('GET', '/-/instance'): (
        'authenticated_instance_app_shell_html', 'authenticated_management_app',
        'current_console_template_and_bounded_chrome_projection'),
    ('POST', '/aos.hub.v1.IdentityService/WhoAmI'): (
        'public_protojson_control_metadata', 'identity_who_am_i',
        'bounded_original_and_current_sql_projection'),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def count(value):
    if not isinstance(value, str) or not re.fullmatch('0|[1-9][0-9]{0,19}', value):
        raise ValueError('Route proof count differs')
    result = int(value)
    if result > 2**64 - 1:
        raise ValueError('Route proof count exceeds bound')
    return result


def indexed(rows, key, maximum):
    if not isinstance(rows, list) or len(rows) > maximum:
        raise ValueError('Route proof input exceeds bound')
    result = {}
    for row in rows:
        identifier = key(row)
        if identifier in result:
            raise ValueError('Route proof input ownership differs')
        result[identifier] = row
    return result


def prepare(report, manifest, authentication, sidecar, policy, receiver_context,
            provenance, source, read_source):
    """Index already verified local inputs once, without inventing missing data."""
    if report is None or receiver_context is None:
        return None
    if (type(report['version']) is not int or report['version'] != 1
            or report['codecRevision'] != manifest['codecRevision']
            or report['selectedSourceDigest'] != manifest['sourceDigest']):
        raise ValueError('Route proof codec runtime differs')
    capture_policy = receiver_context['policy']
    if (capture_policy['windowId'] != policy['windowId']
            or capture_policy['sourceCommit'] != manifest['codecRevision']
            or capture_policy['workerSourceDigest'] != manifest['sourceDigest']
            or capture_policy['runtimeSourceDigest'] != manifest['sourceDigest']
            or capture_policy['nativeExecutableSha256'] != sidecar['nativeExecutableSha256']):
        raise ValueError('Route proof receiver window or runtime differs')
    first, last = count(policy['startUnixMillis']), count(policy['endUnixMillis'])
    if not first <= capture_policy['startsAt'] * 1000 < capture_policy['expiresAt'] * 1000 <= last:
        raise ValueError('Route proof capture policy exceeds original Native window')

    rows = indexed(report['captures'], lambda row: row['requestIdSha256'], MAX_CAPTURES)
    captures = indexed(manifest['captures'], lambda row: row['requestId'], MAX_CAPTURES)
    auth = indexed(authentication.get('captures', []), lambda row: row['requestIdSha256'], MAX_CAPTURES)
    retained = receiver_context['receipts']
    if not isinstance(retained, list) or len(retained) > MAX_RECEIPTS:
        raise ValueError('Route proof receiver inventory exceeds bound')
    receipts = indexed([row for row in retained if row['requestId'] is not None],
                       lambda row: (row['requestId'], row['direction']), MAX_RECEIPTS)
    constructors = {
        'identity_who_am_i': sha(b''.join(read_source(Path(source) / name, 1024 * 1024)
                                        for name in RPC_SOURCES)),
        'authenticated_management_app': sha(read_source(Path(source) / BROWSER_SOURCE, 1024 * 1024)),
    }
    return {'rows': rows, 'captures': captures, 'authentication': auth, 'receipts': receipts,
            'compacts': sidecar['ingressCompacts'], 'capturePolicy': capture_policy,
            'constructors': constructors, 'browserSource': provenance['browserSource'],
            'first': first, 'last': last}


def complete(frame):
    return (frame['eof'] is True and frame['failed'] is False and frame['overflow'] is False)


def image_matches(image, frame):
    return (image['byteSize'] == frame['exposedBytes']
            and image['sha256'] == frame['exposedSha256'])


def receiver(row, member, image, context, procedure, direction):
    """Require one complete original-window image; partial frames prove nothing."""
    image_kind = ('complete_received_image' if direction == 'received_request'
                  else 'complete_wrapper_reply_image')
    if (row['state'] != 'eof' or row['eof'] is not True
            or row['frameState'] != 'bounded' or row['capturePersistence'] != 'written'
            or row['imageKind'] != image_kind):
        return False
    policy = context['capturePolicy']
    for name in ('corpusId', 'windowId', 'sourceCommit', 'sourceTree', 'runtimeSourceDigest',
                 'nativeExecutableSha256', 'workerSourceDigest', 'captureImplementationSha256'):
        if row[name] != policy[name]:
            raise ValueError('Route proof individual receiver context differs')
    purposes = [route['purpose'] for route in policy['originRoutes']
                if route['method'] == member['method'] and route['path'] == procedure]
    if len(purposes) != 1 or row['purpose'] != purposes[0]:
        raise ValueError('Route proof receiver purpose differs')
    expected_provenance = ('independent_wrapper_received_bytes' if direction == 'received_request'
                           else 'wrapper_exposed_reply_bytes')
    if (row['role'] != 'origin_proxy' or row['requestId'] != member['requestId']
            or row['transportCallId'] is not None or row['method'] != member['method']
            or row['pathSha256'] != sha(procedure.encode()) or row['queryClass'] != 'absent'
            or row['provenance'] != expected_provenance
            or row['qualificationClaim'] is not False or row['instrumentationTraffic'] is not True
            or row['responseConsumptionClaim'] is not False):
        raise ValueError('Route proof receiver correlation differs')
    if row['status'] != (None if direction == 'received_request' else member['status']):
        raise ValueError('Route proof receiver status differs')
    start, finish = count(row['startedAtMillis']), count(row['finishedAtMillis'])
    if (not context['first'] <= start <= finish <= context['last']
            or not policy['startsAt'] * 1000 <= start <= finish < policy['expiresAt'] * 1000):
        raise ValueError('Route proof receiver lies outside original windows')
    images = indexed(row['privateImages'], lambda item: item['name'], 4)
    body = images.get('body')
    if (body is None or body['sha256'] != image['sha256'] or body['bytes'] != image['byteSize']
            or row['observedBytes'] != image['byteSize'] or row['retainedBytes'] != image['byteSize']):
        raise ValueError('Route proof receiver body differs')
    if direction == 'received_request':
        compact = context['compacts'].get(member['requestId'])
        retained = images.get('x-aos-hybrid-ingress')
        if compact is None or retained is None:
            return False
        if retained['sha256'] != compact['sha256'] or retained['bytes'] != compact['byteSize']:
            raise ValueError('Route proof received compact differs from checked Native header')
    return True


def project(member, context):
    """Project only exact joined constructors; absent evidence remains unavailable."""
    if context is None or member['requestId'] is None or member.get('queryClass') != 'absent':
        return None
    identifier = sha(member['requestId'].encode())
    row = context['rows'].get(identifier)
    if row is None:
        return None
    route = ROUTES.get((row['method'], row['procedure']))
    if route is None:
        return None
    value = member['typedEvidence']
    capture = context['captures'].get(member['requestId'])
    if value is None or capture is None:
        return None
    kind, constructor, required = route
    if (row['class'] != kind or row['method'] != member['method']
            or member['pathSha256'] != sha(row['procedure'].encode()) or row['phase'] is not None
            or capture['method'] != row['method'] or capture['procedure'] != row['procedure']
            or capture['phase'] is not None or capture['status'] != 200 or member['status'] != 200
            or row['authentication'] != 'not_checked_join_independent_authenticated_worker_receipt'):
        raise ValueError('Route proof codec route or class differs')
    if (not member['handlerReturned'] or member['requestTrailers'] or member['replyTrailers']
            or not complete(member['requestConsumed']) or not complete(member['replyOffered'])):
        return None
    if (value['constructor'] != constructor or value['requiredProjection'] != required
            or value['constructorSourceSha256'] != context['constructors'][constructor]):
        raise ValueError('Route proof actual constructor differs')
    for name, frame_name in (('request', 'requestConsumed'), ('response', 'replyOffered')):
        image = row[name]
        selected = capture['bodies'][name]
        if (not image_matches(image, member[frame_name]) or image['typedSemanticSha256'] != image['sha256']
                or selected['sha256'] != image['sha256'] or selected['byteSize'] != image['byteSize']):
            raise ValueError('Route proof selected codec image differs from actual Native frames')
    if value['reply'] != {'sha256': row['response']['sha256'], 'byteSize': row['response']['byteSize']}:
        raise ValueError('Route proof reply constructor image differs')
    if constructor == 'identity_who_am_i':
        if value['request'] != {'sha256': row['request']['sha256'], 'byteSize': row['request']['byteSize']}:
            raise ValueError('Route proof request constructor image differs')
        if row['browserSource'] is not None:
            raise ValueError('Identity control unexpectedly carries browser evidence')
    else:
        if value['request'] is not None or row['request']['byteSize'] != '0':
            raise ValueError('Instance shell request differs')
        browser = row['browserSource']
        if (not isinstance(browser, dict) or browser != context['browserSource']
                or browser['handlerSourceSha256'] != context['constructors'][constructor]):
            raise ValueError('Route proof selected browser source differs')

    auth = context['authentication'].get(identifier)
    if (auth is None or auth['sourceCheckedAuthentication'] != 'observed_native_checked_envelope_and_body'
            or auth['compactCustody'] != 'retained_bytes_match_native_checked_header'
            or auth['checkedContexts'] is None or auth['checkedContexts']['incomplete'] is not False):
        return None
    request = context['receipts'].get((member['requestId'], 'received_request'))
    response = context['receipts'].get((member['requestId'], 'exposed_response'))
    if request is None or response is None:
        return None
    if request['captureId'] != response['captureId']:
        raise ValueError('Route proof receiver directions belong to different calls')
    if (not receiver(request, member, row['request'], context, row['procedure'], 'received_request')
            or not receiver(response, member, row['response'], context, row['procedure'], 'exposed_response')):
        return None

    identity = constructor == 'identity_who_am_i'
    return {'class': 'matched_bounded_identity_control' if identity else 'matched_bounded_instance_shell',
            'requestIdSha256': identifier, 'receiverCaptureId': request['captureId'],
            'sourceCheckedIngress': True, 'independentMacVerification': False,
            'requestControlBytes': row['request']['byteSize'],
            'replyControlBytes': row['response']['byteSize'] if identity else None,
            'replyQueryOutputBytes': None if identity else row['response']['byteSize'],
            'objectPayloadBytes': None, 'nativeBulkBytes': None, 'currentSqlAuthority': None,
            'missing': ['independent_current_actor_session_and_sql_reader_authority',
                        'loaded_window_to_native_utc_policy_bridge_and_clock_uncertainty',
                        'complete_native_inbound_and_outbound_semantic_coverage']}
