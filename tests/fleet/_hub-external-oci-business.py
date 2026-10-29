"""Read the actual signed External OCI graph and retain ordinary replay results."""

import hashlib
import json
import re
import shlex
import time


def wait_external_oci_signed_index(controls, registry, source_commit, label):
    """Retain the genuine reindexer's exact signed source head."""
    deadline = time.monotonic() + 240
    attempts = []
    while True:
        current = controls.call("RegistryService", "GetRegistry", {"slug": registry["registry"]["slug"]})["registry"]
        attempts.append({name: current.get(name) for name in ("indexState", "indexError", "lastIndexedCommit")})
        if current.get("indexState") == "fresh" and current.get("lastIndexedCommit") == source_commit:
            return {"sourceCommit": source_commit, "observations": attempts}
        if time.monotonic() >= deadline:
            retain_direct_flow(label + "-current-index-timeout.json", attempts)
            raise RuntimeError("External signed index did not reach its actual source head")
        time.sleep(1)


def read_external_oci_signed_graph(client, tools, coordinates, source, publication, refresh):
    """Read every reachable descriptor and replay the actual final publish once."""
    return json.loads(direct_guest_python(client, tools["python"], """
        import hashlib, os, subprocess, urllib.request, urllib.parse
        from pathlib import Path

        os.umask(0o077)
        root=Path(selected['coordinates']['clientRoot'])/'graph-readback'
        root.mkdir(mode=0o700,exist_ok=False)
        layout=Path(selected['source']['finalized']['layout'])
        origin=selected['coordinates']['workerOrigin']
        token=selected['token']
        root_digest=selected['source']['finalized']['index_digest']
        pending=[(root_digest,'manifest')]; seen={}; rows=[]
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args): return None
        opener=urllib.request.build_opener(NoRedirect())
        while pending:
            digest,kind=pending.pop(0)
            if digest in seen:
                if seen[digest]!=kind: raise ValueError('Actual graph changed descriptor kind')
                continue
            if len(seen)>=512: raise ValueError('Actual External graph exceeds bounded complete inventory')
            seen[digest]=kind
            if not digest.startswith('sha256:') or len(digest)!=71:
                raise ValueError('Actual OCI descriptor digest differs')
            expected_file=layout/'blobs/sha256'/digest[7:]
            before=expected_file.stat()
            if (expected_file.is_symlink() or not expected_file.is_file()
                    or not 0<before.st_size<=536870912):
                raise ValueError('Actual signed graph source exceeds its fixture bound')
            with expected_file.open('rb') as stream:
                expected_sha=hashlib.file_digest(stream,'sha256').hexdigest()
            if expected_sha!=digest[7:]: raise ValueError('Actual signed graph source changed')
            leaf=root/str(len(rows)); leaf.mkdir(mode=0o700)
            path='/v2/aos/'+('manifests/' if kind=='manifest' else 'blobs/')+digest
            request=urllib.request.Request(origin+path,method='GET',headers={'Authorization':'Bearer '+token,
                'Accept':'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json'})
            count=0; sha=hashlib.sha256(); document=bytearray()
            with opener.open(request,timeout=60) as reply, (leaf/'body.private').open('xb') as output:
                headers=list(reply.headers.items())
                if reply.status!=200: raise ValueError('Actual External graph read refused')
                while chunk:=reply.read(65536):
                    count+=len(chunk)
                    if count>before.st_size: raise ValueError('Actual graph read exceeds selected signed source')
                    sha.update(chunk); output.write(chunk)
                    if kind=='manifest':
                        document.extend(chunk)
                        if len(document)>4194304: raise ValueError('Actual OCI document exceeds bound')
                output.flush(); os.fsync(output.fileno())
            after=expected_file.stat()
            if (count!=before.st_size or sha.hexdigest()!=expected_sha or any(getattr(before,name)!=getattr(after,name)
                    for name in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns'))):
                raise ValueError('Actual graph returned bytes differ from the retained signed original')
            row={'digest':digest,'kind':kind,'url':origin+path,'status':200,'headers':headers,
                'byteSize':str(count),'sha256':sha.hexdigest(),'file':str(leaf/'body.private')}
            (leaf/'receipt.private.json').write_text(json.dumps(row))
            rows.append(row)
            if kind=='manifest':
                value=json.loads(document)
                children=value.get('manifests')
                if children is not None:
                    pending.extend((child['digest'],'manifest') for child in children)
                else:
                    pending.append((value['config']['digest'],'blob'))
                    pending.extend((child['digest'],'blob') for child in value['layers'])
        finalized=selected['source']['finalized']
        slug='external-'+selected['coordinates']['runId']+'/containers'
        authority=urllib.parse.urlsplit(origin).netloc
        arguments=[selected['aos'],'--json','--progress','off','--color','never','container','publish','aos',
            authority+'/aos:managed-'+selected['coordinates']['runId'],'--release',finalized['release'],
            '--release-layout',finalized['layout'],'--signature-input',finalized['signature_input'],
            '--registry',slug,'--registry-origin',origin,'--registry-token',token,'--hub',origin,'--token',token,
            '--idempotency-key','managed-'+selected['coordinates']['runId']+'-publish']
        environment=dict(os.environ)
        environment.update(json.loads(Path(selected['source']['privateEnvironmentPath']).read_bytes()))
        with (root/'replay.stdout').open('xb') as stdout,(root/'replay.stderr').open('xb') as stderr:
            result=subprocess.run(arguments,env=environment,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,
                timeout=240,check=False)
        if result.returncode: raise ValueError('Actual exact publication replay refused; retain output')
        replay=json.loads((root/'replay.stdout').read_bytes())
        original=selected['publication']['containerPublication']
        if (replay['index_digest']!=root_digest or replay['publication_id']!=original['publication_id']
                or replay['verified_release_root']!=root_digest or replay['verification']!='verified'):
            raise ValueError('Actual replay changed its ready publication or signed root')
        print(json.dumps({'version':1,'rootDigest':root_digest,'objects':rows,'replay':replay,
            'nativeBulkBytes':None,'replayProviderDispatches':None}))
    """, {"coordinates": coordinates, "source": source, "publication": publication,
        "token": refresh(), "aos": tools["aos"]}, timeout=900))


def switch_external_oci_native(native, tools, prepared, processes, registry, candidate, acceptance, *, ownership=None):
    """Switch the stock process to the separately pinned confined helper once."""
    coordinates = prepared["coordinates"]
    root = coordinates["nativeRoot"]
    files = prepared["nativeFiles"]
    tls = install_direct_guest_file(native, tools["python"], root + "/helper-tls-ca.pem", tools["fleetCaPem"].encode())
    provenance = json.loads(read_direct_guest_file(native, tools["python"],
        tools["managedCleanupNativeHelperProvenance"], 65536))
    if (provenance["commonSourceStorePath"] != tools["commonSourceStorePath"]
            or provenance["workerFilteredSourceStorePath"] != tools["workerSourcePath"]):
        raise ValueError("External serving helper is not from the final common source")
    offered = {"version": 1, "runId": coordinates["runId"], "listen": coordinates["listen"],
        "publicOrigin": coordinates["publicOrigin"], "controlOrigin": coordinates["controlOrigin"],
        "deploymentId": tools["deploymentId"], "workerSourceDigest": candidate["input"]["sourceDigest"],
        "workerScriptVersion": candidate["input"]["scriptVersion"], "clockUncertaintySeconds": 1,
        "placementId": candidate["placementId"], "placementPrefix": coordinates["placementPrefix"],
        "expectedExecutableSha256": provenance["testExecutableSha256"],
        "readinessFile": root + "/helper-ready.json", "terminalFile": root + "/helper-terminal.json",
        "shutdownFile": root + "/helper-shutdown.json", "files": {"direct": acceptance,
            "databaseUrlFile": files["database"], "jwtSecretFile": files["jwt"], "sealKeyFile": files["seal"],
            "routeKeysFile": files["route_keys"], "secretVersionManifestFile": files["secrets"],
            "domainProbeSignerManifestFile": files["probeManifest"], "tlsRootFile": tls["file"],
            "workKeyFile": files["HUB_STORAGE_WORK_KEY"], "ingressKeyFile": files["HUB_HYBRID_INGRESS_KEY"],
            "guardKeyFile": files["HUB_EXTERNAL_OBJECT_GUARD_KEY"],
            "candidateKeyFile": files["HUB_EXTERNAL_OCI_CANDIDATE_KEY"],
            "candidateFile": candidate["candidateFile"], "candidateSignatureFile": candidate["candidateSignatureFile"],
            "profileFile": candidate["profileFile"]["path"], "release": {
                "publicationKeyId": "staging-publication-v1", "publicationSeedFile": files["release_seed"],
                "channelKeyId": "staging-channel-v1", "channelSeedFile": files["channel_seed"],
                "publicationKeysFile": files["publication_keys"], "qualificationKeysFile": files["qualification_keys"]}}}
    input_file = root + "/helper-input.json"
    input_ref = install_direct_guest_file(native, tools["python"], input_file,
        json.dumps(offered, separators=(",", ":")).encode())
    stopped = stop_external_oci_process(native, tools, root, processes["native"], "native-bootstrap")
    process = launch_managed_process(native, tools, root, "native-controlled", [tools["managedCleanupNativeHelper"],
        "storage_work::external_oci::tests::fleet::actual_external_oci_fleet_origin", "--exact", "--ignored", "--nocapture"],
        {"AOS_EXTERNAL_OCI_FLEET_INPUT": input_file, "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt"})
    if ownership is not None:
        ownership["processes"] = {**processes, "native": process}
        ownership["partialHelperInput"] = input_ref
    if process["executableSha256"] != provenance["testExecutableSha256"]:
        raise ValueError("Actual External helper executable differs from the selected final ELF")
    ready = await_external_oci_helper(native, tools, prepared, process, input_ref,
        candidate["candidateReference"]["sha256"])
    if str(ready["identity"]["executableBytes"]) != provenance["testExecutableBytes"]:
        raise ValueError("Actual External helper size differs from the selected installed ELF")
    return {"process": process, "readiness": ready, "stoppedStockNative": stopped,
        "input": input_ref, "inputValue": offered,
        "scope": "separate actual controlled Native helper; stock-service byte inventory remains separate"}


def external_inventory_restart_input(original, native_root):
    """Change only private observation destinations for the second Native epoch."""
    if (not isinstance(native_root, str)
            or not re.fullmatch(r"/var/lib/hybrid-native/external-oci/[0-9a-f]{32}", native_root)):
        raise ValueError("inventory restart root is outside the actual selected run")
    changed = dict(original)
    for field, suffix in (("readinessFile", "ready"), ("terminalFile", "terminal"),
            ("shutdownFile", "shutdown")):
        if original[field] != native_root + "/helper-" + suffix + ".json":
            raise ValueError("inventory restart original does not name the first helper epoch")
        changed[field] = native_root + "/inventory-restart-" + suffix + ".json"
    return changed


def restart_external_inventory_native(native, tools, prepared, processes, helper,
                                      workflow, artifacts, ownership, *, observe_restart_fence):
    """Restart the real maintenance owner with unchanged business configuration.

    The caller must retain a live collecting checkpoint before invoking this
    transition. Process exit and task registration are separate from provider
    settlement and the later resumed-range/final-inventory observations.
    """
    root = prepared["coordinates"]["nativeRoot"]
    raw = read_direct_guest_file(native, tools["python"], helper["input"]["file"], 1048576)
    if hashlib.sha256(raw).hexdigest() != helper["input"]["sha256"]:
        raise ValueError("inventory restart original private input changed")
    offered = json.loads(raw)
    if offered != helper["inputValue"]:
        raise ValueError("inventory restart input no longer matches the actual serving epoch")
    successor = external_inventory_restart_input(offered, root)
    input_ref = install_direct_guest_file(native, tools["python"], root + "/inventory-restart-input.json",
        json.dumps(successor, separators=(",", ":")).encode())

    workflow.close(processes)
    old_exit = shutdown_external_oci_helper(native, tools, prepared, helper)
    ownership["helper"] = None
    ownership["inventoryNativeExit"] = old_exit
    ownership["processes"] = {key: value for key, value in processes.items() if key != "native"}
    before_launch = {role: managed_private_log_position(
        native if role.startswith("native") else workflow.worker, tools, position["path"])
        for role, position in workflow.last_end.items()}
    launch_boundary = int(private_guest_command(native, shlex.join([tools["python"], "-c",
        "import time; print(time.time_ns() // 1000000)"])).strip())
    process = launch_managed_process(native, tools, root, "native-inventory-restart", [tools["managedCleanupNativeHelper"],
        "storage_work::external_oci::tests::fleet::actual_external_oci_fleet_origin", "--exact", "--ignored", "--nocapture"],
        {"AOS_EXTERNAL_OCI_FLEET_INPUT": input_ref["file"], "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt"})
    ownership["processes"] = {**processes, "native": process}
    if process["executableSha256"] != helper["process"]["executableSha256"]:
        raise ValueError("inventory Native restart changes the selected actual executable")
    # Controllers are registered before readiness is emitted. Observe their real
    # current lease before a fast continuation can finish or review can await.
    restarted_fence = observe_restart_fence({**processes, "native": process})
    ready = await_external_oci_helper(native, tools, prepared, process, input_ref,
        helper["readiness"]["identity"]["candidateSha256"], readiness_file=successor["readinessFile"])
    if (ready["identity"]["expiresAt"] != helper["readiness"]["identity"]["expiresAt"]
            or ready["backgroundControllers"] != helper["readiness"]["backgroundControllers"]):
        raise ValueError("inventory restart changes its accepted lifetime or collector selection")
    current = {"process": process, "readiness": ready, "input": input_ref, "inputValue": successor,
        "previousEpochExit": old_exit, "launchBoundaryUnixMillis": launch_boundary,
        "beforeLaunchProxyPositions": before_launch, "renewedCollectorFence": restarted_fence,
        "providerEffectsSettled": None, "remoteDrain": None}
    current_processes = {**processes, "native": process}
    ownership.update(helper=current, processes=current_processes)
    codec = select_external_storage_codec(tools, artifacts, process, prepared["coordinates"]["runId"],
        "controlled_external_oci_native", epoch="inventory-restart")
    workflow.boundaries = {**workflow.boundaries, **codec}
    workflow.resume(prepared, current_processes, "controlled_external_oci_native")
    capture = begin_managed_storage_window(native, workflow.worker, tools, workflow.prepared,
        external_capture_processes(current_processes), workflow.boundaries, "external-inventory-resume")
    # Start the independent subwindow after the old owner exited. The new
    # exclusive log begins at byte zero, including controller calls before ready.
    capture["positions"].update(before_launch)
    capture["positions"]["nativeLog"]["byteSize"] = 0
    current["restartCapture"] = capture
    retain_direct_flow("external-oci-" + prepared["coordinates"]["runId"] + "-inventory-new-epoch.json", capture)
    return {"helper": current, "processes": current_processes, "oldExit": old_exit}
