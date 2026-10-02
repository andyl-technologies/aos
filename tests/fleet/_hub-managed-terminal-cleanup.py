"""Call actual SQL, response-loss, cold-replay and normal cleanup recovery.

Fleet includes this helper alongside the existing Managed pair/capture helpers.
All source and process selections are independently reviewed inputs. Missing
transport, signed-reply or healthy SDK evidence refuses; no configured zero is
returned for Native bulk bytes or unobserved provider operations.
"""

import base64
import hashlib
import json
from pathlib import Path
import time


def cleanup_require(condition, message):
    if not condition:
        raise ValueError(message)


def cleanup_guest(machine, tools, operation, selected):
    return json.loads(direct_guest_python(machine, tools['python'], """
        import importlib.util, json
        specification=importlib.util.spec_from_file_location('managed_cleanup_runtime',selected['module'])
        runtime=importlib.util.module_from_spec(specification)
        specification.loader.exec_module(runtime)
        print(json.dumps(runtime.execute(selected['operation'],selected['parameters'])))
    """, {'module':tools['managedCleanupRuntime'], 'operation':operation,
        'parameters':selected}, timeout=150))


def prepare_managed_cleanup_loss(native, tools, prepared, worker_address):
    """Freeze the listener selection before any pair runtime observations."""
    coordinates=prepared['coordinates']
    required=('managedCleanupLossListener','managedCleanupNativeHelper',
              'managedCleanupNativeHelperProvenance','managedCleanupRuntime','commonSourceStorePath')
    cleanup_require(all(isinstance(tools.get(name),str) and tools[name].startswith('/nix/store/')
        for name in required), 'cleanup requires reviewed installed same-source helpers')
    return json.loads(direct_guest_python(native,tools['python'], """
        import hashlib, json, os, re
        from pathlib import Path

        root=Path(selected['root'])/'cleanup-loss'
        root.mkdir(mode=0o700,exist_ok=False)
        proof=json.loads(Path(selected['provenance']).read_bytes())
        if (set(proof)!={'version','commonSourceStorePath','workerFilteredSourceStorePath',
                        'testExecutableSha256','testExecutableBytes'} or type(proof['version']) is not int
                or proof['version']!=1 or not isinstance(proof['testExecutableBytes'],str)
                or not re.fullmatch(r'[1-9][0-9]{0,8}',proof['testExecutableBytes'])
                or int(proof['testExecutableBytes'])>512*1024*1024
                or proof['commonSourceStorePath']!=selected['commonSource']
                or proof['workerFilteredSourceStorePath']!=selected['workerSource']):
            raise ValueError('cleanup ELF common source differs')
        with open(selected['helper'],'rb') as source:
            helper_sha=hashlib.file_digest(source,'sha256').hexdigest()
        if (helper_sha!=proof['testExecutableSha256']
                or str(Path(selected['helper']).stat().st_size)!=proof['testExecutableBytes']):
            raise ValueError('cleanup actual ELF differs from reviewed selection')
        ca=Path(selected['ca']).read_bytes()
        config={'version':1,'root':str(root),'workerAddress':selected['address'],
            'caFile':selected['ca'],'caSha256':hashlib.sha256(ca).hexdigest(),
            'nativeHelper':selected['helper'],'nativeHelperSha256':helper_sha,
            'armFile':str(root/'once.private.json')}
        body=json.dumps(config,separators=(',',':')).encode()
        path=root/'configuration.json'
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as output:
            output.write(body);output.flush();os.fsync(output.fileno())
        with open(selected['python'],'rb') as source:
            executable_sha=hashlib.file_digest(source,'sha256').hexdigest()
        print(json.dumps({'version':1,'configurationFile':str(path),
            'configurationSha256':hashlib.sha256(body).hexdigest(),
            'arguments':[selected['python'],selected['listener'],'--configuration',str(path)],
            'executableSha256':executable_sha,'root':str(root),
            'readyFile':str(root/'ready.json'),
            'listenerSourceSha256':hashlib.sha256(Path(selected['listener']).read_bytes()).hexdigest(),
            'route':'/_internal/storage/managed-oci-cleanup/v1',
            'listenAddress':'127.0.0.1:4660','upstreamAddress':selected['address']+':4643',
            'scope':'initial confined transport; no provider or SQL effects'}))
    """, {'root':coordinates['nativeRoot'],'provenance':tools['managedCleanupNativeHelperProvenance'],
        'commonSource':tools['commonSourceStorePath'],'workerSource':tools['workerSourcePath'],
        'helper':tools['managedCleanupNativeHelper'],'ca':tools['issuerCertificate'],
        'python':tools['python'],'listener':tools['managedCleanupLossListener'],
        'address':worker_address}, timeout=30))


def await_managed_cleanup_loss(native, tools, prepared, process):
    """Require the actual post-bind record before observing pair readiness."""
    listener = prepared['cleanupLoss']
    return cleanup_guest(native, tools, 'readiness', {
        'lossProcess': process, 'readyFile': listener['readyFile'],
        'configurationSha256': listener['configurationSha256'],
        'listenerSourceSha256': listener['listenerSourceSha256'],
    })


def account_managed_cleanup_windows(native, tools, prepared, boundaries, result):
    """Execute current closed codecs over the complete service/helper inventory.

    The loss listener's completed reply is deliberately excluded from Native
    consumption. Missing helper lifetimes, SQL, purpose or provider joins remain
    explicit even when the positive subset has fully correlated metadata bodies.
    """
    run = prepared['captureSelection']['run']
    source_digest = prepared['captureSelection']['sourceDigest']
    prefix = 'managed-cleanup-accounting-' + run
    originals, received, authenticated, contexts, numeric, helpers = [], [], [], [], [], []
    original_headers, received_headers = {}, {}
    report = {'version': 1, 'complete': False, 'nativeBulkBytes': None,
        'actorEvidence': None, 'purposeEvidence': None, 'providerPartition': None,
        'auxiliaryHelperInventory': [
            {'kind': 'lost_upstream_authenticator', 'proof': result['completedResponseLoss']['receipt'],
                'invocation': None, 'scope': 'upstream completion only; helper lifetime unjoined'},
            {'kind': 'replay_upstream_authenticator',
                'proof': result['replayAuthentication']['authentication']['proofFile'],
                'invocation': None, 'scope': 'upstream completion only; helper lifetime unjoined'}],
        'scope': 'actual application payload observations; no TLS billing, fresh permission or whole-machine zero'}
    try:
        module = managed_fixture_module(tools['managedCleanupAccounting'], 'cleanup_accounting')
        selections = (
            ('original', 'select-real-sql', 'select_original', None),
            ('unknown', 'lost-response', 'dispatch_unknown', 0),
            ('replay', 'cold-positive', 'replay_positive', 1),
            ('settlement', 'normal-recovery', 'settle', 2),
        )
        process_owners, call_owners = set(), set()
        for field, label, phase, window_index in selections:
            window = result['windows'][window_index or 0]
            pin = window['processObservations']['native']
            projected = json.loads(direct_guest_python(native, tools['python'], """
                import hashlib, importlib.util, json
                from pathlib import Path

                spec=importlib.util.spec_from_file_location('cleanup_accounting',selected['module'])
                module=importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                with Path(selected['proof']).open('rb') as source:
                    proof_body=source.read(65537)
                if len(proof_body)>65536:
                    raise ValueError('cleanup helper provenance exceeds bound')
                proof=module.cleanup_accounting_json(proof_body)
                if (set(proof)!={'version','commonSourceStorePath','workerFilteredSourceStorePath',
                        'testExecutableSha256','testExecutableBytes'} or type(proof['version']) is not int
                        or proof['version']!=1
                        or proof['commonSourceStorePath']!=selected['commonSource']
                        or proof['workerFilteredSourceStorePath']!=selected['workerSource']):
                    raise ValueError('cleanup helper current source differs')
                import re
                if (not isinstance(proof['testExecutableBytes'],str)
                        or not re.fullmatch(r'[1-9][0-9]{0,8}',proof['testExecutableBytes'])
                        or int(proof['testExecutableBytes'])>512*1024*1024
                        or Path(selected['executable']).stat().st_size!=int(proof['testExecutableBytes'])):
                    raise ValueError('cleanup helper actual ELF size differs')
                with Path(selected['executable']).open('rb') as source:
                    actual=hashlib.file_digest(source,'sha256').hexdigest()
                if actual!=proof['testExecutableSha256']:
                    raise ValueError('cleanup helper actual ELF differs')
                selection={'root':selected['root'],'label':selected['label'],'phase':selected['phase'],
                    'commonSourceStorePath':selected['commonSource'],
                    'workerFilteredSourceStorePath':selected['workerSource'],
                    'testExecutableSha256':actual,
                    'provenanceSha256':hashlib.sha256(proof_body).hexdigest(),'servicePid':selected['servicePid']}
                print(json.dumps(module.read_managed_cleanup_invocation(selected['helper'],selection)))
            """, {'module': tools['managedCleanupAccounting'], 'proof': tools['managedCleanupNativeHelperProvenance'],
                'executable': tools['managedCleanupNativeHelper'], 'commonSource': tools['commonSourceStorePath'],
                'workerSource': tools['workerSourcePath'], 'root': prepared['coordinates']['nativeRoot'],
                'helper': result[field], 'label': label, 'phase': phase, 'servicePid': pin['pid']}, timeout=30))
            process_id = (projected['process']['pid'], projected['process']['startTicks'])
            cleanup_require(process_id not in process_owners, 'cleanup helper lifetime reused across invocations')
            process_owners.add(process_id)
            if window_index is not None:
                bracket = window['rawWindowReceipts']['nativeOutbound']
                cleanup_require(int(bracket['collectionStartedAtUnixMicros'])
                    <= int(projected['process']['started']['unixNs']) // 1000
                    <= int(projected['process']['finished']['unixNs']) // 1000
                    <= int(bracket['collectionFinishedAtUnixMicros']),
                    'cleanup helper lies outside its complete actual capture window')
            rows = module.cleanup_invocation_events(projected,
                validate_storage_authenticated_value, validate_storage_final_sql_value)
            for row in rows['numeric']:
                cleanup_require(row['transport_call_id'] not in call_owners,
                    'cleanup transport call reused across helper lifetimes')
                call_owners.add(row['transport_call_id'])
            numeric.extend(rows['numeric'])
            authenticated.extend(rows['authenticated'])
            contexts.extend(rows['contexts'])
            helpers.append({name: value for name, value in projected.items() if name != 'events'})
        summary_bytes = 0
        def append_summary(destination, rows):
            nonlocal summary_bytes
            for row in rows:
                summary_bytes += len(native_corpus_json(row))
                cleanup_require(len(destination) < PROTECTED_HEADER_RECORD_LIMIT
                    and summary_bytes <= PROTECTED_HEADER_SUMMARY_BYTE_LIMIT,
                    'cleanup complete summary exceeds observation bound')
                destination.append(row)

        for index, window in enumerate(result['windows']):
            boundary = window['storageBoundary']
            selected = boundary['captureProvenance']
            cleanup_require(selected['sourceDigest'] == source_digest and selected['run'] == run,
                'cleanup capture source or run differs')
            for destination, key in ((originals, 'nativeOriginalBodies'), (received, 'workerReceivedBodies')):
                append_summary(destination, boundary[key]['bodies'])
            append_summary(authenticated, window['nativeServiceAuthenticatedRows'])
            append_summary(contexts, window['nativeServiceFinalSqlRows'])
            for destination, name, role in (
                    (original_headers, 'nativeHeaders', 'native-outbound'),
                    (received_headers, 'workerHeaders', 'worker-received')):
                raw = window['rawWindowReceipts'][name]
                # Reopen and hash the retained complete row file before its
                # streaming parser. No completed upstream body is substituted.
                module.verify_cleanup_retained_window({'path': raw['file'], 'sha256': raw['sha256'],
                    'byteSize': raw['capturedBytes']}, PROTECTED_HEADER_LOG_BYTE_LIMIT)
                rows = capture_protected_headers(Path(raw['file']), role,
                    'managed-' + run + '-cleanup-accounting-' + str(index))
                cleanup_require(not destination.keys() & rows.keys(), 'cleanup proxy request ID reused across windows')
                summary_bytes += sum(len(native_corpus_json(row)) for row in rows.values())
                cleanup_require(len(destination) + len(rows) <= PROTECTED_HEADER_RECORD_LIMIT
                    and summary_bytes <= PROTECTED_HEADER_SUMMARY_BYTE_LIMIT,
                    'cleanup global header summary exceeds observation bound')
                destination.update(rows)
        owners = {}
        for identifier, row in original_headers.items():
            if row['transportCallId'] is not None:
                owners.setdefault(row['transportCallId'], []).append(identifier)
        cleanup_require(all(len(ids) == 1 for ids in owners.values()),
            'cleanup call ID reused across complete original inventory')
        transport = join_authenticated_storage_transports(originals, received,
            original_headers, received_headers, authenticated)
        final_sql = join_storage_final_sql(transport, contexts)
        codec_input = prepare_storage_codec_segment_bundle(transport, originals, received,
            source_digest, tools['deploymentId'])
        report.update(helperInventory=helpers, numericObservations=numeric,
            transport=transport, finalSql=final_sql,
            completeOriginalInventory=codec_input['completeOriginalInventory'],
            unresolvedNativeRequestIds=codec_input['unresolvedNativeRequestIds'],
            unassignedAuthenticatedCallIdSha256=[hashlib.sha256(row['transportCallId'].encode()).hexdigest()
                for row in authenticated if hashlib.sha256(row['transportCallId'].encode()).hexdigest()
                not in {call['transportCallIdSha256'] for call in transport['joined']}],
            unassignedReceivedRequestIds=sorted({row['requestId'] for row in received}
                - {call['receivedRequestId'] for call in transport['joined']}),
            businessProcessWindows=[window['processObservations'] for window in result['windows']],
            unassignedNumericCallIdSha256=[hashlib.sha256(row['transport_call_id'].encode()).hexdigest()
                for row in numeric if row['transport_call_id'] not in owners],
            inboundWindows=[{'rawWindowReceipts': {name: window['rawWindowReceipts'][name]
                for name in ('workerOriginal', 'nativeReceived', 'workerOriginalHeaders', 'nativeReceivedHeaders')},
                'completeOriginalInventorySha256': hashlib.sha256(native_corpus_json(
                    window['nativeIngressBoundary']['codecInput']['completeOriginalInventory'])).hexdigest(),
                'unresolvedOriginalRequestIds': window['nativeIngressBoundary']['codecInput']['unresolvedOriginalRequestIds'],
                'unselectedReceivedRequestIds': window['nativeIngressBoundary']['codecInput']['unselectedReceivedRequestIds']}
                for window in result['windows']],
            retainedBodySummaryBytes=summary_bytes, decoded=None)
        bundle = codec_input['selectedCodecSegments']
        if bundle is not None:
            provenance = validate_managed_codec_selection(boundaries['codecSelection'],
                boundaries['codecProvenance'], source_digest,
                result['windows'][0]['processObservations']['native']['executableSha256'])
            report['decoded'] = run_storage_workflow_codec_segments(boundaries['codecSelection'],
                bundle, provenance['codecSourceSha256'], source_digest,
                artifact_namespace='managed-codec-cleanup-' + run)
        # Current SQL/API, accepted purpose and provider partitions are still
        # independently required. Positive decoding cannot complete these joins.
    except Exception as error:
        report['failureClass'] = type(error).__name__
        report['helperInventory'] = helpers
    encoded = native_corpus_json(report) + b'\n'
    if len(encoded) > NATIVE_SEGMENT_REPORT_BYTE_LIMIT:
        report = {'version': 1, 'complete': False, 'nativeBulkBytes': None,
            'failureClass': 'RetainedReportOverflow', 'attemptedReportBytes': len(encoded),
            'scope': 'all original windows remain retained; this aggregate is incomplete'}
        encoded = native_corpus_json(report) + b'\n'
    retain_direct_flow(prefix + '.json', encoded)
    return report


def run_managed_terminal_cleanup_window(native,worker,client,tools,prepared,processes,
        boundaries,controls,setup,container_source,publication,installation,refresh_token):
    """Run the required confined terminal-cleanup path on the real fresh pair."""
    coordinates=prepared['coordinates']
    cleanup_require(coordinates['cleanupPrefix']==coordinates['gcPrefix']
        and coordinates['cleanupPrefix']=='qualification/oci-terminal-cleanup/'+coordinates['runId']
        and publication['containerPublication']['verification']=='verified'
        and publication['signedSource']['sourceCommit'], 'cleanup requires its normally published pair prefix')
    require_managed_gc_current_tuple(prepared,processes,tools,boundaries)
    listener=prepared['cleanupLoss']
    cleanup_require(set(listener)>= {'configurationFile','configurationSha256','process'}
        and listener['process']['executableSha256']==listener['executableSha256'],
        'cleanup listener must be initially launched and pinned')
    profile_result=json.loads(direct_guest_python(worker,tools['python'], """
        import hashlib,json,subprocess
        from pathlib import Path
        body=Path(selected['artifact']).read_bytes()
        if hashlib.sha256(body).hexdigest()!=selected['artifactSha256']:
            raise ValueError('actual installed OCI artifact changed')
        arguments=[selected['reviewer'],'oci-sdk-verify','--artifact-file',selected['artifact'],
            '--reviewer-public-key-file',selected['publicKey'],'--reviewer-key-id',selected['keyId'],
            '--deployment-id',selected['deployment'],'--public-origin',selected['origin'],
            '--source-digest',selected['source'],'--script-version','emulated-'+selected['source']]
        result=subprocess.run(arguments,stdin=subprocess.DEVNULL,capture_output=True,check=False,timeout=30)
        if result.returncode or result.stdout.decode().strip()!=selected['artifactSha256']:
            raise ValueError('shared Rust verification of current artifact failed')
        artifact=json.loads(body)
        print(json.dumps({'profile':artifact['profile'],'expiresAt':artifact['expiresAt'],
            'artifactSha256':selected['artifactSha256']}))
    """, {'artifact':installation['artifactFile'],'artifactSha256':installation['artifactSha256'],
        'publicKey':installation['publicKeyFile'],'keyId':installation['reviewerKeyId'],
        'reviewer':tools['reviewer'],'deployment':coordinates['deploymentId'],
        'origin':coordinates['workerOrigin'],'source':prepared['captureSelection']['sourceDigest']}, timeout=45))
    profile=profile_result['profile']
    common={'nativeRoot':coordinates['nativeRoot'],'nativeHelper':tools['managedCleanupNativeHelper'],
        'helperProvenance':tools['managedCleanupNativeHelperProvenance'],
        'commonSourceStorePath':tools['commonSourceStorePath'],'workerSourcePath':tools['workerSourcePath']}
    files=prepared['nativeFiles']
    parameters={'version':1,'phase':'select_original','databaseUrlFile':files['database'],
        'workKeyFile':files['HUB_STORAGE_WORK_KEY'],'guardKeyFile':files['HUB_DIRECT_UPLOAD_GUARD_KEY'],
        'tlsRootFile':tools['issuerCertificate'],'outputFile':'',
        'placementPrefix':coordinates['cleanupPrefix'],'uploadId':'','ordinal':0,
        'expectedOriginalSha256':None,'profile':profile,'lostRequestFile':None,
        'lostRequestSignatureFile':None,'lostReplyFile':None,'lostReplySignatureFile':None}
    selected=cleanup_guest(native,tools,'helper',{**common,'input':parameters,'label':'select-real-sql'})
    original=selected['value']
    cleanup_require(original['outcome']=='observed_sql_only' and original['sqlClaimUnchangedAfterAttempt'],
        'normal workflow has no current independently admissible terminal chunk')
    parameters={**parameters,'phase':'observe','uploadId':original['original']['upload_id'],
        'ordinal':original['original']['ordinal'],'expectedOriginalSha256':original['originalSha256']}
    runner={'workerRoot':coordinates['workerRoot'],'namespaceObserver':tools['ociNamespaceObserver'],
        'workerProcess':processes['worker']}
    issued=int(time.time())
    selection={'deploymentId':coordinates['deploymentId'],'placementPrefix':coordinates['cleanupPrefix'],
        'protectedProfileDigest':original['protectedProfileDigest'],
        'sourceDigest':profile['workerSourceDigest'],'scriptVersion':profile['workerScriptVersion'],
        'uncertaintySeconds':int(profile['clockPolicy']['uncertaintySeconds']),
        'issuedAt':issued,'expiresAt':min(issued+600,profile_result['expiresAt'])}
    record=json.dumps({'version':1,'selection':selection,'profile':profile},
        separators=(',',':'),ensure_ascii=False).encode()
    cleanup_require(0<len(record)<=4096,'actual serialized Managed fixture record exceeds 4096 bytes')
    installed=cleanup_guest(worker,tools,'runner_command',{**runner,'label':'install-real-profile',
        'request':{'version':1,'kind':'managed-oci-cleanup-fixture-install',
            'recordBase64':base64.b64encode(record).decode(),'recordSha256':hashlib.sha256(record).hexdigest()}})
    cleanup_require(installed['recordSha256']==hashlib.sha256(record).hexdigest()
        and int(installed['byteSize'])==len(record)
        and base64.b64decode(installed['recordBase64'],validate=True)==record,
        'actual MF fixture record readback differs')
    armed=cleanup_guest(native,tools,'arm',{'nativeRoot':coordinates['nativeRoot'],
        'lossProcess':listener['process'],'lossConfiguration':listener['configurationFile'],
        'lossConfigurationSha256':listener['configurationSha256'],
        'arm':{'version':1,'originalSha256':original['originalSha256'],
            'protectedProfileDigest':original['protectedProfileDigest'],'helperInput':parameters,
            'expiresAt':min(int(time.time())+60,selection['expiresAt'])}})
    before=begin_managed_storage_window(native,worker,tools,prepared,processes,boundaries,'managed-terminal-lost')
    unknown=cleanup_guest(native,tools,'helper',{**common,'input':{**parameters,'phase':'dispatch_unknown'},'label':'lost-response'})
    lost=cleanup_guest(native,tools,'lost_receipt',{'nativeRoot':coordinates['nativeRoot'],
        'originalSha256':original['originalSha256']})
    lost_window=finish_managed_storage_window(native,worker,tools,prepared,processes,boundaries,before,'managed-terminal-lost')
    cleanup_require(unknown['value']['outcome']=='exchange_unknown', 'selected completed response was not lost to Native')
    cold=cleanup_guest(worker,tools,'cold_restart',{**runner,'configuration':prepared['configurationFile'],
        'configurationSha256':prepared['configurationSha256'],'workerd':tools['workerd']})
    processes['worker']=cold['new']
    await_managed_tls(native,tools,coordinates['workerOrigin'])
    # The installed bytes/window remain immutable across this restart.
    before=begin_managed_storage_window(native,worker,tools,prepared,processes,boundaries,'managed-terminal-replay')
    replay=cleanup_guest(native,tools,'helper',{**common,'input':{**parameters,'phase':'replay_positive'},'label':'cold-positive'})
    replay_window=finish_managed_storage_window(native,worker,tools,prepared,processes,boundaries,before,'managed-terminal-replay')
    cleanup_require(replay['value']['outcome']=='authenticated_positive_reply'
        and replay['value']['originalSha256']==original['originalSha256']
        and replay['value']['sqlClaimUnchangedAfterAttempt'], 'cold replay changed its SQL original')
    # Exact fresh request/reply bodies from the transparent listener establish
    # the replay subject. Ordinary Nginx/whole-window capture remains retained.
    replay_exchange=cleanup_guest(native,tools,'forwarded_receipt',{'nativeRoot':coordinates['nativeRoot'],
        'originalSha256':original['originalSha256'],'helperInput':parameters,
        'protectedProfileDigest':original['protectedProfileDigest'],
        'listenerConfiguration':listener['configurationFile'],
        'listenerModule':tools['managedCleanupLossListener']})
    first_proof=lost['value']['authentication']['proof']
    replay_proof=replay_exchange['authentication']['proof']
    cleanup_require(first_proof['physicalReply']['object']==replay_proof['physicalReply']['object']
        and first_proof['physicalReply']['receipt_digest']==replay_proof['physicalReply']['receipt_digest'],
        'cold replay changed the actual opaque object/positive physical receipt')
    sdk=[]
    for window,process,proof in ((lost_window,cold['old'],first_proof),(replay_window,cold['new'],replay_proof)):
        records=managed_gc_sdk_records(window['workerLogText'])
        terminal=[row for row in records if row['scope']=='managed_terminal_cleanup']
        collector=managed_fixture_module(tools['managedGcCollector'],'cleanup_sdk_collector')
        backing=hashlib.sha256(json.dumps({name:profile[name] for name in
            ('namespaceId','namespaceObjectId','namespaceUniqueKey')},separators=(',',':')).encode()).hexdigest()
        key=original['original']['placement_prefix']+'/'+original['original']['path']
        sdk.append(collector.collect(terminal,coordinates['runId'],backing,[{
            'scope':'managed_terminal_cleanup','key':key,
            'subject_id':original['originalFingerprint']+proof['authenticatedRequestSha256']}]))
    cleanup_require([call['method'] for call in sdk[0]['calls']]==['head','get','delete']
        and not sdk[1]['calls'] and len(sdk[1]['brackets'])==1
        and sdk[1]['brackets'][0]['invoked']==0, 'actual cleanup/replay SDK brackets differ or remain unknown')
    settle_begin=begin_managed_storage_window(native,worker,tools,prepared,processes,boundaries,'managed-terminal-settle')
    settlement=cleanup_guest(native,tools,'helper',{**common,'input':{**parameters,'phase':'settle'},'label':'normal-recovery'})
    settle_window=finish_managed_storage_window(native,worker,tools,prepared,processes,boundaries,settle_begin,'managed-terminal-settle')
    cleanup_require(settlement['value']['outcome']=='normal_recovery_completed'
        and settlement['value']['sqlCleanupSettled'], 'normal recovery did not settle actual SQL')
    result={'version':1,'original':selected,'recordBytes':len(record),'installation':installed,
        'arm':armed,'unknown':unknown,'completedResponseLoss':lost,'cold':cold,
        'replay':replay,'replayAuthentication':replay_exchange,'sdk':sdk,'settlement':settlement,
        'windows':[lost_window,replay_window,settle_window],'nativeBulkBytes':None,
        'scope':'actual confined Managed emulator window; independent whole-window accounting remains required'}
    result['nativeApplicationAccounting'] = account_managed_cleanup_windows(
        native, tools, prepared, boundaries, result)
    retain_direct_flow('managed-terminal-'+coordinates['runId']+'.json',result)
    return result
