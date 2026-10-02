"""Connect actual Managed publication to live index, read and cache parity.

References come from the ordinary publisher's retained signed surface and OCI
layout. Companion registries use the same bytes, normal controls and independent
stores. The read window executes before either companion is stopped. Provider
permission, body accounting and Hosted acceptance remain separate observations.
"""

import hashlib
import json
from pathlib import Path
import re
import shlex
import time
import urllib.parse


def select_managed_read_objects(client, tools, prepared, source, publication):
    """Retain one genuine small object of each fixed production read class."""
    commit = publication["signedSource"]["sourceCommit"]
    require_managed_pair(re.fullmatch(r"[0-9a-f]{64}", commit),
        "Managed read corpus requires its actual signed source commit")
    return json.loads(direct_guest_python(client, tools["python"], """
        import hashlib, os, re, stat
        from pathlib import Path

        root = Path(selected['root'])/'read-originals'
        root.mkdir(mode=0o700,parents=True,exist_ok=False)
        def read(path, maximum=4*1024*1024):
            descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(descriptor,'rb') as source:
                before=os.fstat(source.fileno())
                if not stat.S_ISREG(before.st_mode) or not 16<=before.st_size<=maximum:
                    raise ValueError('Actual read object is not bounded')
                body=source.read(maximum+1)
                after=os.fstat(source.fileno())
            if len(body)!=before.st_size or any(getattr(before,name)!=getattr(after,name)
                    for name in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')):
                raise ValueError('Actual read object changed')
            return body
        def retain(kind, relative, path):
            body=read(path)
            descriptor=os.open(root/kind,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(descriptor,'wb') as output:
                output.write(body); output.flush(); os.fsync(output.fileno())
            return {'relativePath':relative,'file':str(root/kind),
                'sha256':hashlib.sha256(body).hexdigest(),'byteSize':len(body)}
        surface=Path(selected['surface'])
        commit=selected['commit']
        git_relative='objects/'+commit[:2]+'/'+commit[2:]
        metadata_relative=Path(selected['helper']).name.split('-',1)[0]+'.narinfo'
        metadata=read(surface/metadata_relative,65536)
        urls=[line[5:] for line in metadata.decode().splitlines() if line.startswith('URL: ')]
        if len(urls)!=1 or not re.fullmatch(r'nar/[A-Za-z0-9._-]+\\.nar(?:\\.(?:xz|zst|bz2|gz))?',urls[0]):
            raise ValueError('Actual small helper narinfo URL differs')
        layout=Path(selected['layout'])
        index_digest=selected['indexDigest'].removeprefix('sha256:')
        index=read(layout/'blobs/sha256'/index_digest)
        if hashlib.sha256(index).hexdigest()!=index_digest:
            raise ValueError('Actual signed OCI index changed')
        value=json.loads(index)
        candidates=[]
        for descriptor in value['manifests']:
            digest=descriptor['digest'].removeprefix('sha256:')
            manifest=read(layout/'blobs/sha256'/digest)
            if hashlib.sha256(manifest).hexdigest()!=digest or len(manifest)!=descriptor['size']:
                raise ValueError('Actual signed child manifest changed')
            config=json.loads(manifest).get('config')
            if config is not None:
                candidates.append(config)
        if not candidates:
            raise ValueError('Actual signed graph has no image configuration blob')
        config=sorted(candidates,key=lambda item:item['digest'])[0]
        digest=config['digest'].removeprefix('sha256:')
        container=retain('container','v2/aos/blobs/sha256:'+digest,layout/'blobs/sha256'/digest)
        if container['sha256']!=digest or container['byteSize']!=config['size']:
            raise ValueError('Actual OCI configuration identity changed')
        document=selected['document']
        result={'git':retain('git',git_relative,surface/git_relative),
            'package':retain('package',urls[0],surface/urls[0]),
            'metadata':retain('metadata',metadata_relative,surface/metadata_relative),
            'document':retain('document',document['relativePath'],document['file']),
            'container':container}
        if result['document']['sha256']!=document['sha256'] or result['document']['byteSize']!=document['byteSize']:
            raise ValueError('Published documentation reference changed')
        directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
        print(json.dumps(result))
    """, {"root": prepared["coordinates"]["clientRoot"], "surface": source["surfaceRoot"],
        "commit": commit, "helper": tools["helperStorePath"], "document": source["document"],
        "layout": source["finalized"]["layout"], "indexDigest": source["finalized"]["index_digest"]}))


class ManagedIndexReader:
    """Query the fresh Managed database with retained read-only statements."""

    def __init__(self, native, tools, prepared):
        self.native, self.tools, self.prepared = native, tools, prepared
        self.sequence = 0

    def __call__(self, query):
        require_managed_pair(isinstance(query, str) and len(query.encode()) <= 32768
            and query.lstrip().upper().startswith("SELECT ")
            and not any(marker in query for marker in (";", "--", "/*", "*/", "\x00")),
            "Managed index projection is not one bounded read-only query")
        label = "read-query-" + str(self.sequence)
        self.sequence += 1
        return json.loads(direct_guest_python(self.native, self.tools["python"], """
            import hashlib, os, subprocess
            from pathlib import Path

            root=Path(selected['root'])/'index-queries'/selected['label']
            root.mkdir(mode=0o700,parents=True,exist_ok=False)
            url=Path(selected['database']).read_text().strip()
            if url!=selected['expectedUrl']:
                raise ValueError('Managed index database differs from initial configuration')
            wrapped="SELECT COALESCE(json_agg(row_to_json(observation)), '[]') FROM ("+selected['query']+") observation"
            sql="BEGIN TRANSACTION READ ONLY; SET LOCAL statement_timeout='20s'; "+wrapped+"; COMMIT;"
            def retain(name,body):
                descriptor=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(descriptor,'wb') as output:
                    output.write(body); output.flush(); os.fsync(output.fileno())
            retain('original.sql',sql.encode())
            result=subprocess.run([selected['psql'],'-X','-q','-A','-t','-v','ON_ERROR_STOP=1',
                '-d',url,'-c',sql],stdin=subprocess.DEVNULL,capture_output=True,timeout=25,check=False)
            retain('stdout.private',result.stdout); retain('stderr.private',result.stderr)
            if result.returncode or len(result.stdout)>8*1024*1024 or len(result.stderr)>65536:
                raise ValueError('Actual Managed read-only index query refused')
            rows=json.loads(result.stdout)
            print(json.dumps([list(row.values()) for row in rows]))
        """, {"root": self.prepared["coordinates"]["nativeRoot"], "label": label,
            "database": self.prepared["nativeFiles"]["database"], "psql": self.tools["postgres"] + "/psql",
            "query": query, "expectedUrl": "postgresql://postgres@" + self.tools["parityTools"]["postgres_host"]
                + ":5432/" + self.prepared["coordinates"]["database"]}, timeout=35))


def observe_managed_cache_installation(worker, tools, prepared, process):
    """Derive cache identity from actual installed APIs and the selected live runner."""
    node_program = """
            const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
            const {createRequire}=require('node:module');
            const selected=JSON.parse(fs.readFileSync(0,'utf8'));
            const options=JSON.parse(fs.readFileSync(selected.configuration));
            const observer=require(options.publicDocumentCacheObserverPath);
            const load=createRequire(path.join(selected.miniflare,'lib/node_modules/wrangler/node_modules/fleet-runner.cjs'));
            const api=observer.installedCacheApi(load);
            const key=observer.publicDocumentCacheKey(options.bindings,options.publicDocumentCacheCase);
            const sha=body=>crypto.createHash('sha256').update(body).digest('hex');
            process.stdout.write(JSON.stringify({cacheObserverSha256:sha(fs.readFileSync(options.publicDocumentCacheObserverPath)),
              miniflareVersion:api.version,miniflareModuleSha256:api.moduleSha256,
              cacheWorkerSha256:api.cacheWorkerSha256,cacheEntrySha256:api.cacheEntrySha256,
              shimSha256:sha(fs.readFileSync(options.scriptPath)),workerName:options.name,
              documentUrlSha256:sha(key.url),cacheKeySha256:sha(key.key)}));
    """
    return json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, subprocess
        from pathlib import Path

        pin=selected['process']
        def lifetime():
            proc=Path('/proc')/str(pin['pid'])
            fields=(proc/'stat').read_text().rpartition(') ')[2].split()
            with (proc/'exe').open('rb') as source: executable=hashlib.file_digest(source,'sha256').hexdigest()
            if fields[0]=='Z' or fields[19]!=pin['startTicks'] or proc.stat().st_uid!=pin['ownerUid'] or executable!=pin['executableSha256']:
                raise ValueError('Cache runner lifetime changed')
            for file,expected in (('cmdline',pin['commandLineSha256']),('environ',pin['environmentSha256'])):
                body=(proc/file).read_bytes()
                if len(body)>65536 or hashlib.sha256(body).hexdigest()!=expected:
                    raise ValueError('Cache runner invocation changed')
        lifetime()
        configuration=Path(selected['configuration']).read_bytes()
        if hashlib.sha256(configuration).hexdigest()!=selected['configurationSha256']:
            raise ValueError('Initial cache configuration changed')
        program=selected['nodeProgram']
        result=subprocess.run([selected['node'],'-e',program],input=json.dumps(selected).encode(),
            capture_output=True,timeout=20,check=False)
        if result.returncode or len(result.stdout)>65536:
            raise ValueError('Selected installed cache API identity refused')
        lifetime()
        value=json.loads(result.stdout)
        print(json.dumps({**value,'runnerPid':pin['pid'],'runnerStartTicks':pin['startTicks'],
            'configurationSha256':selected['configurationSha256']}))
    """, {"configuration": prepared["configurationFile"],
        "configurationSha256": prepared["configurationSha256"], "process": process,
        "miniflare": tools["miniflare"], "node": tools["node"], "nodeProgram": node_program}, timeout=30))


def retain_managed_read_credentials(client, tools, prepared, token):
    """Retain the real current bearer and cookie as private bounded header files."""
    return json.loads(direct_guest_python(client, tools["python"], """
        import http.cookiejar, os
        from pathlib import Path

        root=Path(selected['root'])/'read-credentials'
        root.mkdir(mode=0o700,exist_ok=False)
        jar=http.cookiejar.MozillaCookieJar(selected['cookieJar'])
        jar.load(ignore_discard=True,ignore_expires=False)
        cookies=[cookie for cookie in jar if cookie.domain.lstrip('.')=='localhost'
            and cookie.path=='/' and cookie.secure and not cookie.is_expired()]
        if not cookies or any(any(char in cookie.name+cookie.value for char in '\\r\\n;') for cookie in cookies):
            raise ValueError('Actual Managed browser cookies are absent or ambiguous')
        values={'bearerHeaderFile':'Authorization: Bearer '+selected['token'],
            'cookieHeaderFile':'Cookie: '+'; '.join(cookie.name+'='+cookie.value for cookie in cookies)}
        result={}
        for name,value in values.items():
            if len(value.encode())>16384 or '\\n' in value or '\\r' in value:
                raise ValueError('Actual browser header exceeds its private bound')
            path=root/name
            descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(descriptor,'w') as output:
                output.write(value); output.flush(); os.fsync(output.fileno())
            result[name]=str(path)
        print(json.dumps(result))
    """, {"root": prepared["coordinates"]["clientRoot"], "token": token,
        "cookieJar": prepared["coordinates"]["clientRoot"] + "/session/cookies"}))


def managed_read_process_pin(process):
    """Select the exact lifetime fields consumed by the fixed read adapter."""
    return {field: process[field] for field in (
        "pid", "startTicks", "ownerUid", "executableSha256", "commandLineSha256", "commandLineBytes")}


def observe_managed_companion_process(machine, tools, root, pid_file, executable):
    """Join the existing companion pin to its complete live invocation bytes."""
    original = direct_parity_process(machine, tools, root, pid_file, executable)
    extra = json.loads(direct_guest_python(machine, tools["python"], """
        import hashlib
        from pathlib import Path

        proc=Path('/proc')/str(selected['pin']['pid'])
        before=(proc/'stat').read_text().rpartition(') ')[2].split()
        body=(proc/'cmdline').read_bytes()
        after=(proc/'stat').read_text().rpartition(') ')[2].split()
        if before[0]=='Z' or before[19]!=after[19] or before[19]!=selected['pin']['startTicks'] or len(body)>65536:
            raise ValueError('Companion lifetime changed during invocation readback')
        print(json.dumps({'commandLineSha256':hashlib.sha256(body).hexdigest(),
            'commandLineBytes':str(len(body))}))
    """, {"pin": original}))
    return {**original, **extra}


def stop_managed_companion_process(machine, tools, process):
    """Stop the originally recorded companion without changing its stop contract."""
    original = {field: value for field, value in process.items()
        if field not in {"commandLineSha256", "commandLineBytes"}}
    return direct_parity_process(machine, tools, process["root"], process["pidFile"],
        process["executable"], stop=original)


def observe_managed_companion_listener(machine, tools, process, origin, configuration_file):
    """Observe real verified TLS health inside one exact companion lifetime."""
    return json.loads(direct_guest_python(machine, tools["python"], """
        import hashlib, os, subprocess
        from pathlib import Path

        root=Path(selected['pin']['root'])/'endpoint-tls'
        root.mkdir(mode=0o700,exist_ok=False)
        def lifetime():
            pin=selected['pin']; proc=Path('/proc')/str(pin['pid'])
            fields=(proc/'stat').read_text().rpartition(') ')[2].split()
            command=(proc/'cmdline').read_bytes()
            with (proc/'exe').open('rb') as source: executable=hashlib.file_digest(source,'sha256').hexdigest()
            if fields[0]=='Z' or fields[19]!=pin['startTicks'] or proc.stat().st_uid!=pin['ownerUid'] or executable!=pin['executableSha256']:
                raise ValueError('Companion endpoint process changed')
            if len(command)>65536 or hashlib.sha256(command).hexdigest()!=pin['commandLineSha256']:
                raise ValueError('Companion endpoint invocation changed')
            return {'pid':pin['pid'],'startTicks':fields[19],'executableSha256':executable,
                'commandLineSha256':hashlib.sha256(command).hexdigest()}
        before=lifetime()
        configuration=None if selected['configuration'] is None else Path(selected['configuration']).read_bytes()
        result=subprocess.run(selected['curl']+['--silent','--show-error','--max-time','5',
            '--max-filesize','262144','--output',str(root/'body'),
            '--dump-header',str(root/'headers'),'--write-out','%{http_code}',selected['origin']+'/healthz'],
            stdin=subprocess.DEVNULL,capture_output=True,timeout=8,check=False)
        for name in ('body','headers'):
            os.chmod(root/name,0o600)
        if result.returncode or result.stdout!=b'200':
            raise ValueError('Actual companion TLS health exchange refused')
        after=lifetime()
        if after!=before or configuration is not None and Path(selected['configuration']).read_bytes()!=configuration:
            raise ValueError('Companion endpoint configuration or process changed')
        files={}
        for name in ('body','headers'):
            body=(root/name).read_bytes()
            if len(body)>262144: raise ValueError('Companion TLS evidence exceeded bound')
            files[name]={'file':str(root/name),'sha256':hashlib.sha256(body).hexdigest(),'byteSize':len(body)}
        print(json.dumps({'version':1,'origin':selected['origin'],'status':200,'before':before,'after':after,
            'files':files,'configurationSha256':None if configuration is None else hashlib.sha256(configuration).hexdigest(),
            'scope':'actual TLS listener and process observation only'}))
    """, {"pin": process, "origin": origin, "configuration": configuration_file,
        "curl": shlex.split(tools["curl"])}, timeout=20))


def setup_managed_companion_registry(controls, selection, tools):
    """Create the same named public registry through fresh normal operator plans."""
    run = selection["coordinates"]["runId"]
    organization = controls.reviewed("OrganizationService", "PlanCreateOrganization", "CreateOrganization", {
        "slug": "managed-" + run, "displayName": "Managed SDK qualification",
        "expectedResourceVersion": "",
    }, selection["mode"] + "-organization")["organization"]
    organization = controls.call("OrganizationService", "GetOrganization", {"slug": organization["slug"]})["organization"]
    if selection["mode"] == "worker_only":
        controls.reviewed("BindingService", "PlanCreateBinding", "CreateBinding", {
            "stableId": "instance-default", "ownerScopeKey": "instance", "expectedResourceVersion": "",
            "spec": {"name": "default", "deploymentR2": {"bucketBinding": "REGISTRY_BUCKET"}},
        }, "worker-only-default-binding")
    binding = controls.call("BindingService", "GetBinding", {"binding": {"instanceDefault": True}})["binding"]
    expected_provider = "localFilesystem" if selection["mode"] == "native_only" else "deploymentR2"
    require_managed_pair(expected_provider in binding["spec"] and binding["ownerScopeKey"] == "instance",
        "Companion default storage differs from its actual configured topology")
    controls.reviewed("BindingService", "PlanGrantBindingScope", "GrantBindingScope", {
        "resourceKind": "binding", "resourceStableId": binding["stableId"], "resourceGeneration": "0",
        "consumerScopeKey": organization["ownerScopeKey"], "expectedResourceVersion": "",
    }, selection["mode"] + "-binding-grant")
    registry = controls.reviewed("RegistryService", "PlanCreateRegistry", "CreateRegistry", {
        "orgSlug": organization["slug"], "projectPath": "", "name": "containers", "visibility": "public",
        "trustKeys": [selection["source"]["trustKey"]], "expectedResourceVersion": "",
    }, selection["mode"] + "-registry")["registry"]
    surface = {"registrySlug": registry["slug"]}
    prefix = "qualification/parity/" + run + "/" + selection["mode"]
    controls.reviewed("TopologyService", "PlanCreatePlacement", "CreatePlacement", {
        "surface": surface, "name": "primary", "bindingId": binding["stableId"], "prefix": prefix,
        "kind": "complete", "desiredState": "active", "desiredReadEnabled": True, "readOrder": "0",
        "requiresConditionalWrites": True, "expectedResourceVersion": "",
    }, selection["mode"] + "-placement")
    placement = controls.call("TopologyService", "GetPlacement", {"surface": surface, "name": "primary"})["placement"]
    scan = controls.reviewed("TopologyService", "PlanScanPlacement", "ScanPlacement", {
        "surface": surface, "placementName": "primary", "expectedResourceVersion": placement["resourceVersion"],
    }, selection["mode"] + "-scan")["operation"]
    controls.wait_operation(scan["operationId"], {"succeeded"})
    placement = controls.call("TopologyService", "GetPlacement", {"surface": surface, "name": "primary"})["placement"]
    require_managed_pair(placement["prefix"] == prefix and placement["observation"]["state"] == "ready"
        and placement["observation"]["completeness"] == "complete", "Actual companion scan is incomplete")
    controls.reviewed("TopologyService", "PlanPromotePlacement", "PromotePlacement", {
        "surface": surface, "placementName": "primary", "expectedResourceVersion": placement["resourceVersion"],
    }, selection["mode"] + "-promote")
    deadline = time.monotonic() + 120
    while True:
        authority = controls.call("TopologyService", "GetWriteAuthority", {"surface": surface})["authority"]
        if authority["reconciliationState"] == "ready":
            break
        require_managed_pair(authority["reconciliationState"] != "failed" and time.monotonic() < deadline,
            "Actual companion writer reconciliation did not complete")
        time.sleep(0.5)
    require_managed_pair(authority["desiredPlacementName"] == "primary"
        and authority["observedPlacementName"] == "primary"
        and authority["desiredGeneration"] == authority["observedGeneration"]
        and authority["desiredBindingWriteRevision"] == authority["observedBindingWriteRevision"],
        "Actual companion writer selected another placement or revision")
    placement = controls.call("TopologyService", "GetPlacement", {"surface": surface, "name": "primary"})["placement"]
    require_managed_pair(placement["status"]["observedWriter"] is True
        and placement["status"]["effectiveWriteEnabled"] is True, "Actual companion writer is not effective")
    setup = {"registry": registry, "binding": binding, "placement": placement, "authority": authority}
    current = controls.call("RegistryService", "GetRegistry", {"slug": setup["registry"]["slug"]})["registry"]
    public = controls.reviewed("RegistryService", "PlanUpdateRegistry", "UpdateRegistry", {
        "slug": current["slug"], "visibility": "public", "updateMask": ["visibility"],
        "expectedResourceVersion": current["resourceVersion"],
    }, selection["mode"] + "-public")["registry"]
    require_managed_pair(public["slug"] == selection["registrySlug"] and public["visibility"] == "public",
        "Normal companion registry differs from the signed read corpus")
    return {**setup, "registry": public}


def run_managed_read_window(client, native, worker, tools, prepared, processes,
                            setup, source, publication, refresh_token):
    """Publish the identical corpus in live companions, then call fixed reads/cache."""
    coordinates = prepared["coordinates"]
    run = coordinates["runId"]
    selected_source = {**source, "sourceCommit": publication["signedSource"]["sourceCommit"]}
    objects = select_managed_read_objects(client, tools, prepared, source, publication)
    credentials = retain_managed_read_credentials(client, tools, prepared, refresh_token())
    cache_identity = observe_managed_cache_installation(worker, tools, prepared, processes["worker"])
    adapter = managed_fixture_module(tools["readWindowModule"], "called_reads_" + run)
    assertions = managed_fixture_module(tools["readParityModule"], "read_assertions_" + run)
    projector = managed_fixture_module(tools["readIndexModule"], "read_indexes_" + run)
    selected_tools = {**tools, **tools["parityTools"]}
    fixture = {**tools["parityFixture"], "probe_signers": prepared["probeManifest"],
        "container_index_digest": source["finalized"]["index_digest"]}
    query = ManagedIndexReader(native, tools, prepared)
    retain = lambda label, value: retain_direct_flow("managed-" + run + "-" + label, value)

    def publication_setup(**case):
        mode = case["mode"]
        client_root = coordinates["clientRoot"] + "/companion-" + mode
        private_guest_command(client, tools["parityTools"]["coreutils"] + "/install -d -m 0700 " + shlex.quote(client_root))
        companion_coordinates = {**coordinates, "clientRoot": client_root, "workerOrigin": case["origin"],
            "endpointId": coordinates["endpointId"] + "-" + mode.replace("_", "-"),
            "probeSecretRef": coordinates["probeSecretRef"] + "-" + mode.replace("_", "-")}
        controls = DirectBootstrapControls(client, tools["curl"], tools["python"], case["token"],
            private_guest_command, case["refresh_token"], origin=case["origin"],
            evidence_root=client_root + "/controls")
        companion_prepared = {**prepared, "coordinates": companion_coordinates,
            "listenerConfigurationRef": "hub-" + mode.replace("_", "-") + ":" + run}
        selection = {"version": 1, "mode": mode, "origin": case["origin"],
            "registrySlug": setup["registry"]["slug"], "source": selected_source,
            "coordinates": companion_coordinates}

        def configure_route(current_controls, current_setup, selected):
            return configure_managed_distribution(client, case["machine"], tools,
                companion_prepared, {}, current_controls, current_setup,
                endpoint_origin=case["origin"], ingress_kind="ENDPOINT_INGRESS_KIND_HUB",
                listener_observer=lambda: observe_managed_companion_listener(case["machine"], tools,
                    case["process"], case["origin"], case["configuration_file"]))

        return adapter.setup_selected_companion(client, tools=tools, selection=selection, controls=controls,
            setup_registry=lambda current, selected: setup_managed_companion_registry(current, selected, tools),
            configure_route=configure_route, refresh_token=case["refresh_token"], retain=retain)

    def snapshot_assert(readers, slug, **options):
        require_managed_pair(options["container_index_digest"] == source["finalized"]["index_digest"],
            "Actual companion signed graph differs from the selected publication")
        snapshots = {mode: projector.registry_index_observations(reader, slug) for mode, reader in readers.items()}
        retain("complete-index-snapshots.private.json", snapshots)
        return assertions.assert_direct_full_index_parity(snapshots, selected_source["sourceCommit"])

    def read_window(**live):
        def selected_module(path):
            body = Path(path).read_bytes()
            require_managed_pair(path.startswith("/nix/store/") and len(body) <= 1048576,
                "Read module is not the selected bounded installed source")
            return hashlib.sha256(body).hexdigest()

        context = {"version": 1, "registrySlug": setup["registry"]["slug"],
            "sourceCommit": selected_source["sourceCommit"], "packageName": "aos-hub",
            "origins": {"hybrid": coordinates["workerOrigin"], **live["origins"]}, "objects": objects,
            "privateRegistrySlug": "managed-" + run + "/private-docs", "credentials": credentials,
            "cache": {"socketFile": coordinates["workerRoot"] + "/control.sock", "identity": cache_identity},
            "curlArgv": shlex.split(tools["curl"]), "evidenceRoot": coordinates["workerRoot"] + "/reads",
            "processes": {role: {"machine": machine, "pin": managed_read_process_pin(pin)} for role, machine, pin in (
                ("hybrid_native", "native", processes["native"]), ("hybrid_worker", "worker", processes["worker"]),
                ("native_only", "native", live["processes"]["native_only"]),
                ("worker_only", "worker", live["processes"]["worker_only"]))},
            "workerConfigurationFile": prepared["configurationFile"],
            "workerConfigurationSha256": prepared["configurationSha256"],
            "parityModuleFile": tools["readParityModule"], "parityModuleSha256": selected_module(tools["readParityModule"]),
            "indexModuleFile": tools["readIndexModule"], "indexModuleSha256": selected_module(tools["readIndexModule"])}
        native_ip = prepared["captureSelection"]["nativeAddress"]
        context["curlArgv"] += ["--resolve", "aos.staging.andyl.org:8453:" + native_ip,
            "--resolve", "aos.andyl.org:8453:127.0.0.1", "--resolve", "localhost:4643:127.0.0.1"]
        return adapter.run_direct_read_window(client, native, worker, tools=tools,
            context=context, index_readers=live["index_readers"], retain=retain)

    return qualify_registry_runtime_parity(
        DirectPrivateParityMachine(client, "managed-client-" + run),
        DirectPrivateParityMachine(native, "managed-native-" + run),
        DirectPrivateParityMachine(worker, "managed-worker-" + run), tools=selected_tools, fixture=fixture,
        corpus_fixture={name: value for name, value in {
            "surfaceRoot": source["surfaceRoot"], "registrySlug": setup["registry"]["slug"],
            "trustKey": source["trustKey"], "sourceCommit": selected_source["sourceCommit"]}.items()},
        process_observer=lambda machine, root, pid_file, executable: observe_managed_companion_process(
            machine, selected_tools, root, pid_file, executable),
        process_stop=lambda machine, pin: stop_managed_companion_process(machine, selected_tools, pin),
        run_id=run, hybrid_reader=query, publication_setup=publication_setup,
        snapshot_assert=snapshot_assert, read_window=read_window)
