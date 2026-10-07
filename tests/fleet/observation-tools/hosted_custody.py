"""Match hosted receiver custody without manufacturing managed process facts.

Inputs are private references to raw provider responses and read-only SQL
images. A source-bound collector supplies the transport verifier in code;
selected JSON cannot supply that callable or assert authentication. Missing
collector verification leaves the observation unavailable. This adapter never
produces a Native bulk total or reconstructs an earlier authorization fence.
"""

from datetime import datetime, timezone
import hashlib
import inspect
import ipaddress
import re


MAX_EXPORT = 256 * 1024 * 1024
MAX_PAGE = 16 * 1024 * 1024
MAX_PAGES = 4096
MAX_ENTRIES = 262144
MAX_MESSAGE = 100 * 1024


def closed(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError('Hosted custody closed schema differs')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decimal(value):
    if not isinstance(value, str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}', value):
        raise ValueError('Hosted custody decimal differs')
    return int(value)


def timestamp(value):
    """Read exact provider UTC microseconds without float rounding."""
    if not isinstance(value, str) or not re.fullmatch(
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z', value):
        raise ValueError('Provider timestamp differs')
    seconds, _, fraction = value[:-1].partition('.')
    instant = datetime.strptime(seconds, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = instant - epoch
    return (delta.days * 86400 + delta.seconds) * 1000000 + int((fraction + '000000')[:6])


def log_filter(selection):
    """Select all message classes for the exact resource and export interval."""
    def utc(value):
        seconds, micros = divmod(decimal(value), 1000000)
        return datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + f'.{micros:06d}Z'

    values = [
        ('resource.type', 'cloud_run_revision'),
        ('resource.labels.project_id', selection['project']),
        ('resource.labels.location', selection['location']),
        ('resource.labels.service_name', selection['serviceName'].rsplit('/', 1)[-1]),
        ('resource.labels.revision_name', selection['revisionName'].rsplit('/', 1)[-1]),
    ]
    if any(not re.fullmatch('[a-z][a-z0-9_-]{0,127}', value) for _, value in values):
        raise ValueError('Hosted resource filter slot differs')
    return ' AND '.join([key + '="' + value + '"' for key, value in values] + [
        'timestamp>="' + utc(selection['firstUnixMicros']) + '"',
        'timestamp<="' + utc(selection['lastUnixMicros']) + '"'])


def image(reference, readers, maximum):
    raw = readers['read_ref'](reference, maximum)
    return raw, readers['closed_json'](raw)


def verified_response(exchange, readers, verifier, operation, maximum, scope):
    """Require collector authentication of the exact request and response.

    The verifier is an independently installed, source-selected collector
    function. It must verify actual transport/invocation custody, not inspect a
    supplied boolean. There is deliberately no JSON fallback or import slot.
    """
    closed(exchange, {'request', 'response', 'collectorReceipt'})
    request_raw, request = image(exchange['request'], readers, 64 * 1024)
    response_raw, response = image(exchange['response'], readers, maximum)
    receipt_raw = readers['read_ref'](exchange['collectorReceipt'], 64 * 1024)
    if verifier is None:
        return None, 'missing_source_bound_authenticated_export_collector'
    binding = verifier(operation, request_raw, response_raw, receipt_raw, scope)
    if binding is None:
        return None, 'missing_source_bound_authenticated_export_collector'
    # The implementation returns byte commitments, so it cannot accidentally
    # authenticate another response or silently ignore a substituted receipt.
    expected = {'operation': operation, 'requestSha256': sha(request_raw),
                'responseSha256': sha(response_raw), 'receiptSha256': sha(receipt_raw), 'scope': scope}
    if binding != expected:
        raise ValueError('Authenticated export byte or operation binding differs')
    return (request, response), None


def cloud_run(selection, readers, runtime, verifier=None):
    """Read a selected revision export while retaining instance coverage gaps."""
    closed(selection, {'version', 'kind', 'runtime', 'serviceName', 'revisionName',
        'project', 'location', 'service', 'revision', 'imageDigest', 'policy',
        'pages', 'instances', 'firstUnixMicros', 'lastUnixMicros'})
    if type(selection['version']) is not int or selection['version'] != 1:
        raise ValueError('Hosted log version differs')
    if selection['kind'] != 'cloud_run' or selection['runtime'] != runtime:
        raise ValueError('Hosted log runtime differs')
    first, last = decimal(selection['firstUnixMicros']), decimal(selection['lastUnixMicros'])
    if first > last:
        raise ValueError('Hosted export window is reversed')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', selection['imageDigest']):
        raise ValueError('Hosted resolved image digest differs')
    prefix = 'projects/' + selection['project'] + '/locations/' + selection['location'] + '/'
    if (not selection['serviceName'].startswith(prefix + 'services/')
            or not selection['revisionName'].startswith(prefix + 'services/')):
        raise ValueError('Hosted resource selection differs')
    outputs = []
    scope = {key: selection[key] for key in ('runtime', 'serviceName', 'revisionName',
        'imageDigest', 'firstUnixMicros', 'lastUnixMicros')}
    for name in ('service', 'revision'):
        value, missing = verified_response(selection[name], readers, verifier,
                                           'cloud_run_' + name, 1024 * 1024, scope)
        if missing:
            return {'messages': None, 'missing': [missing], 'nativeBulkBytes': None}
        request, response = value
        selected_name = selection[name + 'Name']
        if request != {'name': selected_name} or response.get('name') != selected_name:
            raise ValueError('Hosted resource readback differs')
        outputs.append(response)
    service, revision = outputs
    containers = revision.get('containers')
    if (service.get('latestReadyRevision') != selection['revisionName']
            or revision.get('service') != selection['serviceName']
            or not service.get('uid') or not revision.get('uid')
            or not isinstance(containers, list) or len(containers) != 1
            or containers[0].get('image', '').rsplit('@', 1)[-1] != selection['imageDigest']):
        raise ValueError('Hosted revision or resolved image readback differs')
    # Policy bytes remain the real Rust encoding. The inventory reader verifies
    # its declared field order and each instance's complete raw-byte chain.
    policy_raw = readers['read_ref'](selection['policy'], 1024)
    environment = containers[0].get('env', [])
    policies = [row for row in environment if row.get('name') == 'AOS_NATIVE_BODY_INVENTORY']
    if len(policies) != 1 or policies[0] != {
            'name': 'AOS_NATIVE_BODY_INVENTORY', 'value': policy_raw.decode()}:
        raise ValueError('Hosted actual revision inventory policy differs')
    instances = selection['instances']
    if (not isinstance(instances, list) or not instances
            or len(set(instances)) != len(instances)
            or any(not isinstance(value, str) or not re.fullmatch('[A-Za-z0-9_-]{1,256}', value)
                   for value in instances)):
        raise ValueError('Hosted instance selection differs')
    pages = selection['pages']
    if not isinstance(pages, list) or not 1 <= len(pages) <= MAX_PAGES:
        raise ValueError('Hosted pagination bound differs')
    groups = {instance: [] for instance in instances}
    unknown = []
    tokens, identifiers, consumed, count = set(), set(), 0, 0
    previous = None
    query = None
    for index, exchange in enumerate(pages):
        consumed += decimal(exchange['response']['byteSize'])
        if consumed > MAX_EXPORT:
            raise ValueError('Hosted export corpus exceeds bound')
        value, missing = verified_response(exchange, readers, verifier,
                                          'logging_entries_list', MAX_PAGE, scope)
        if missing:
            return {'messages': None, 'missing': [missing], 'nativeBulkBytes': None}
        request, response = value
        closed(request, {'resourceNames', 'filter', 'orderBy', 'pageSize'}
               | ({'pageToken'} if 'pageToken' in request else set()))
        if (request['resourceNames'] != ['projects/' + selection['project']]
                or request['filter'] != log_filter(selection)
                or request['orderBy'] != 'timestamp asc'
                or type(request['pageSize']) is not int or not 1 <= request['pageSize'] <= 1000):
            raise ValueError('Hosted log request scope differs')
        current = {key: request[key] for key in ('resourceNames', 'filter', 'orderBy', 'pageSize')}
        if query is None:
            query = current
        if current != query or request.get('pageToken') != previous:
            raise ValueError('Hosted page query or token linkage differs')
        closed(response, {'entries'} | ({'nextPageToken'} if 'nextPageToken' in response else set()))
        following = response.get('nextPageToken')
        if following is not None:
            if (not isinstance(following, str) or not following or len(following) > 8192
                    or following in tokens or index == len(pages) - 1):
                raise ValueError('Hosted pagination is repeated or incomplete')
            tokens.add(following)
        elif index != len(pages) - 1:
            raise ValueError('Hosted pages continue after terminal page')
        previous = following
        if (not isinstance(response['entries'], list)
                or len(response['entries']) > request['pageSize']):
            raise ValueError('Hosted entries differ')
        for entry_index, entry in enumerate(response['entries']):
            count += 1
            if count > MAX_ENTRIES:
                raise ValueError('Hosted entry count exceeds bound')
            if not isinstance(entry, dict):
                raise ValueError('Hosted log entry is not an object')
            resource = entry.get('resource', {})
            labels = resource.get('labels', {})
            if (resource.get('type') != 'cloud_run_revision'
                    or any(labels.get(key) != selection[selected] for key, selected in (
                        ('project_id', 'project'), ('location', 'location')))
                    or labels.get('service_name') != selection['serviceName'].rsplit('/', 1)[-1]
                    or labels.get('revision_name') != selection['revisionName'].rsplit('/', 1)[-1]):
                raise ValueError('Hosted log resource differs')
            instance_labels = entry.get('labels')
            instance = instance_labels.get('instanceId') if isinstance(instance_labels, dict) else None
            identifier = entry.get('insertId')
            if identifier is not None:
                if (not isinstance(identifier, str) or not 0 < len(identifier) <= 256
                        or (instance, identifier) in identifiers):
                    raise ValueError('Hosted duplicate event or identifier differs')
                identifiers.add((instance, identifier))
            observed = timestamp(entry.get('timestamp'))
            if not first <= observed <= last:
                raise ValueError('Hosted event is outside selected export window')
            payloads = [key for key in ('textPayload', 'jsonPayload', 'protoPayload') if key in entry]
            message = entry.get('textPayload')
            missing = []
            if instance not in groups:
                missing.append('unselected_or_missing_instance')
            if identifier is None:
                missing.append('missing_insert_id')
            if payloads != ['textPayload'] or not isinstance(message, str):
                missing.append('unsupported_payload_envelope')
            elif len(message.encode()) > MAX_MESSAGE:
                missing.append('message_exceeds_source_bound')
            if missing:
                # The page is the authenticated byte image; an entry index is
                # a location in its parsed values, never a reserialized image.
                unknown.append({'page': exchange['response'], 'entryIndex': entry_index,
                    'insertId': identifier, 'instanceId': instance, 'payloadKinds': payloads,
                    'timestamp': entry['timestamp'], 'missing': missing})
                continue
            groups[instance].append((message, str(observed)))
    absent = [instance for instance, values in groups.items() if not values]
    return {'messages': groups, 'unknownEntries': unknown, 'absentSelectedInstances': absent,
            'nativeBulkBytes': None,
            'missing': ['independent_active_instance_inventory_and_current_image_to_native_artifact_custody',
                        'provider_export_completeness_and_clock_uncertainty']
                + (['unclassified_provider_entries'] if unknown else [])
                + (['selected_instance_has_no_supported_messages'] if absent else [])}


def cloud_sql(selection, checkpoint, codec, readers, source_contract, runtime, verifier=None):
    """Match managed reader-time rows, never local postmaster or prior IAM."""
    tool_field = 'readerExecutableSha256' if selection.get('version') == 2 else 'psqlExecutableSha256'
    closed(selection, {'version', 'kind', 'runtime', 'instanceName', 'connectionName',
        'instance', 'database', 'role', 'serverAddress', 'serverPort', 'deployment',
        'sourceChild', 'query', 'rows', 'readerReceipt', 'codecImages',
        'collectorSourceSha256', tool_field, 'firstUnixNanos', 'lastUnixNanos'}
        | ({'transport'} if selection.get('version') == 2 else set()))
    if (type(selection['version']) is not int or selection['version'] not in (1, 2)
            or selection['kind'] != 'cloud_sql' or selection['runtime'] != runtime
            or selection['sourceChild'] != {'rawChildSha256': checkpoint['rawChildSha256'],
                'rawChildByteSize': checkpoint['rawChildByteSize']}):
        raise ValueError('Managed SQL runtime or source checkpoint differs')
    scope = {key: selection[key] for key in ('runtime', 'instanceName', 'connectionName',
        'database', 'role', 'serverAddress', 'serverPort', 'sourceChild')}
    transport = selection.get('transport', {'kind': 'tcp'})
    if not isinstance(transport, dict):
        raise ValueError('Managed transport schema differs')
    if transport.get('kind') == 'tcp':
        closed(transport, {'kind'})
    elif transport.get('kind') == 'official_connector':
        closed(transport, {'kind', 'connectionName', 'ipType', 'connectorSourceSha256', 'connectorExecutableSha256'})
        if (transport['connectionName'] != selection['connectionName'] or any(
                not isinstance(transport[key], str) or re.fullmatch('[0-9a-f]{64}', transport[key]) is None
                for key in ('connectorSourceSha256', 'connectorExecutableSha256'))):
            raise ValueError('Managed connector source or instance selection differs')
        if transport['ipType'] not in ('public', 'private', 'psc'):
            raise ValueError('Managed connector network selection differs')
        if transport['connectorExecutableSha256'] != selection[tool_field]:
            raise ValueError('Managed reader and actual connector executable differ')
    else:
        raise ValueError('Managed transport is unsupported')
    if selection['version'] == 2:
        scope['transport'] = transport
    value, missing = verified_response(selection['instance'], readers, verifier,
                                      'cloud_sql_instance', 1024 * 1024, scope)
    if missing:
        return {'objectPayloadBytes': None, 'missing': [missing]}
    request, instance = value
    if (request != {'name': selection['instanceName']}
            or instance.get('name') != selection['instanceName'].rsplit('/', 1)[-1]
            or instance.get('project') != selection['instanceName'].split('/')[1]
            or instance.get('connectionName') != selection['connectionName']):
        raise ValueError('Managed SQL instance or actual endpoint differs')
    socket = selection['serverAddress'] is None and selection['serverPort'] is None
    if socket:
        if transport['kind'] != 'official_connector':
            raise ValueError('Managed SQL socket endpoint is unavailable')
    elif (not isinstance(selection['serverAddress'], str)
            or type(selection['serverPort']) is not int or not 1 <= selection['serverPort'] <= 65535):
        raise ValueError('Managed SQL observed endpoint differs')
    else:
        ipaddress.ip_address(selection['serverAddress'])
        if (transport['kind'] == 'tcp' and (selection['serverAddress'] not in
                [row.get('ipAddress') for row in instance.get('ipAddresses', [])]
                or selection['serverPort'] != 5432)):
            raise ValueError('Managed SQL TCP endpoint differs')
    query_raw = readers['read_ref'](selection['query'], 32 * 1024)
    expected = source_contract['native_sql_query'](checkpoint['checkpoints'],
                                                  selection['deployment'], selection['role'])
    if query_raw != expected.encode():
        raise ValueError('Managed SQL query differs from exact source-selected originals')
    rows_raw = readers['read_ref'](selection['rows'], 512 * 1024)
    parameters = inspect.signature(source_contract['native_sql_rows']).parameters
    required = {'server_address', 'server_port'} | ({'managed_socket'} if socket else set())
    if not required <= set(parameters):
        return {'objectPayloadBytes': None,
                'missing': ['selected_source_sql_validator_lacks_managed_transport']}
    endpoint = {'server_address': selection['serverAddress'], 'server_port': selection['serverPort']}
    if socket:
        endpoint['managed_socket'] = True
    rows = source_contract['native_sql_rows'](rows_raw, selection, checkpoint['checkpoints'],
                                             **endpoint)
    receipt_raw = readers['read_ref'](selection['readerReceipt'], 64 * 1024)
    if verifier is None:
        return {'objectPayloadBytes': None, 'missing': ['missing_source_bound_managed_reader_invocation']}
    binding = verifier('cloud_sql_reader', query_raw, rows_raw, receipt_raw, scope)
    if binding is None:
        return {'objectPayloadBytes': None, 'missing': ['missing_source_bound_managed_reader_invocation']}
    if binding != {'operation': 'cloud_sql_reader', 'requestSha256': sha(query_raw),
                   'responseSha256': sha(rows_raw), 'receiptSha256': sha(receipt_raw), 'scope': scope}:
        raise ValueError('Managed SQL reader invocation differs')
    receipt = readers['closed_json'](receipt_raw)
    closed(receipt, {'version', 'querySha256', 'rowsSha256', 'exitCode', 'readerBefore',
        'readerAfter', tool_field, 'collectorSourceSha256', 'backend',
        'beforeUnixNanos', 'afterUnixNanos', 'sourceChild'}
        | ({'transport'} if selection['version'] == 2 else set()))
    if (type(receipt['version']) is not int or receipt['version'] != selection['version']
            or type(receipt['exitCode']) is not int or receipt['exitCode'] != 0
            or receipt['querySha256'] != sha(query_raw) or receipt['rowsSha256'] != sha(rows_raw)
            or receipt['sourceChild'] != selection['sourceChild']
            or any(receipt[key] != selection[key] for key in
                   (tool_field, 'collectorSourceSha256'))
            or (selection['version'] == 2 and receipt['transport'] != transport)):
        raise ValueError('Managed SQL source, tool, exit or image receipt differs')
    for key in (tool_field, 'collectorSourceSha256'):
        if not isinstance(receipt[key], str) or not re.fullmatch('[0-9a-f]{64}', receipt[key]):
            raise ValueError('Managed SQL reader source commitment differs')
    pin = receipt['readerBefore']
    closed(pin, {'pid', 'ownerUid', 'startTicks', 'executableSha256'})
    if (receipt['readerAfter'] != pin or type(pin['pid']) is not int or pin['pid'] <= 1
            or type(pin['ownerUid']) is not int or pin['ownerUid'] < 0
            or decimal(pin['startTicks']) == 0
            or pin['executableSha256'] != receipt[tool_field]):
        raise ValueError('Managed SQL actual local reader lifetime differs')
    backend = receipt['backend']
    closed(backend, {'pid', 'connectionName', 'database', 'role', 'snapshot'})
    if (backend != {'pid': rows['backendPid'], 'connectionName': selection['connectionName'],
                    'database': rows['database'], 'role': rows['user'], 'snapshot': rows['snapshot']}):
        raise ValueError('Managed SQL actual backend or connector instance differs')
    if not (decimal(selection['firstUnixNanos']) <= decimal(receipt['beforeUnixNanos'])
            <= decimal(receipt['afterUnixNanos']) <= decimal(selection['lastUnixNanos'])):
        raise ValueError('Managed SQL reader observation lies outside selected window')
    # The collector must bind its actual reader PID/UID/start/executable, official
    # connector instance, backend PID, transaction and window to these bytes.
    # Their independent verification cannot be supplied by selected JSON flags.
    images = selection['codecImages']
    source_contract['native_sql_codec_image'](images, rows,
        codec['codecProjection']['sqlEvidenceSha256'], readers['read_ref'])
    dynamic = [source_contract['native_sql_match_dynamic'](operation,
        codec['codecProjection'].get('sqlOriginals', []))
        for operation in checkpoint['checkpoints'] if operation['kind'] == 'dynamic']
    return {'class': 'matched_managed_reader_time_codec_images', 'rawRowsSha256': sha(rows_raw),
            'readerBackendPid': rows['backendPid'], 'readerSnapshot': rows['snapshot'],
            'dynamicOriginals': dynamic,
            'objectPayloadBytes': None,
            'missing': ['source_operation_to_reader_time_immutable_original_and_current_fence_join',
                        'prior_operation_iam_or_lease_not_reconstructed_by_later_reader',
                        'native_instance_body_window_and_independent_database_clock_custody']
                + [item for match in dynamic for item in match['missing']]}
