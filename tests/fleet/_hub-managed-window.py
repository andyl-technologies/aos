"""Run the fresh Managed R2 business window beside the External workload.

The initial configuration binds the actual namespace and Rust-derived OCI slot
before any observation. Ordinary Hub plans create its independent organization,
registry and writer. The signed OCI artifact supplies only OCI SDK purpose;
inventory and deletion retain their separate current SQL and physical guard
requirements. Every producer runs through the configured Worker-fronted origin.
"""

import importlib.util
import hashlib
import json
import secrets
import shlex
import re
import time
from pathlib import Path


def managed_fixture_module(path, name):
    """Load the selected public fixture from its immutable closure path."""
    selected = Path(path)
    require_managed_pair(str(selected).startswith("/nix/store/") and selected.is_file(),
            "Managed fixture must be an installed source-bound module")
    specification = importlib.util.spec_from_file_location(name, selected)
    require_managed_pair(specification is not None and specification.loader is not None,
            "Managed fixture module cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def select_managed_storage_codec(artifacts, source_digest):
    """Require the independently selected decoder for this actual runtime tuple."""
    reviewed = await_direct_review("managed-storage-codec", {
        "installedArtifacts": retain_direct_flow("managed-codec-installed-inputs.json", artifacts),
    }, {"observerExecutable", "runtimeCodecRevision", "runtimeProvenance"})
    selection = reviewed["selection"]
    provenance = _closed_review_json(direct_selected_bytes(selection["runtimeProvenance"], 65536))
    require_managed_pair(isinstance(provenance, dict) and set(provenance) == {
            "version", "runtimeCodecRevision", "nativeExecutableSha256", "workerSourceDigest",
            "sourceArchiveSha256", "codecSourceSha256",
        } and type(provenance["version"]) is int and provenance["version"] == 1
        and provenance["runtimeCodecRevision"] == selection["runtimeCodecRevision"]
        and re.fullmatch(r"[0-9a-f]{40}", provenance["runtimeCodecRevision"])
        and provenance["nativeExecutableSha256"] == artifacts["files"]["nativeHub"]["sha256"]
        and provenance["workerSourceDigest"] == source_digest
        and all(re.fullmatch(r"[0-9a-f]{64}", provenance[field])
            for field in ("sourceArchiveSha256", "codecSourceSha256")),
        "Managed decoder must match the independently selected current runtime tuple")
    return {"codecSelection": selection, "codecProvenance": provenance}


def managed_document_cache_selection(client, tools, coordinates, source):
    """Fix the canonical document and actual embedded asset identity before startup."""
    document = source.get("document", {})
    require_managed_pair(set(document) == {"file", "sha256", "byteSize", "relativePath", "identity"}
        and re.fullmatch(r"[0-9a-f]{64}", document["sha256"])
        and document["relativePath"] == "-/api/v1/documentation/sha256:" + document["sha256"]
        and type(document["byteSize"]) is int and 16 <= document["byteSize"] <= 262144,
        "Initial Managed cache requires the real published canonical documentation")
    body = read_direct_guest_file(client, tools["python"], document["file"], 262144)
    require_managed_pair(len(body) == document["byteSize"]
        and hashlib.sha256(body).hexdigest() == document["sha256"]
        and json.loads(body).get("options"), "Prepared canonical documentation changed")
    inputs = tools["consoleAssetInputs"]
    require_managed_pair(isinstance(inputs, list) and len(inputs) == 6
        and all(isinstance(path, str) and path.startswith("/nix/store/") for path in inputs),
        "Cache version requires the selected production source and installed console bodies")
    assets = json.loads(direct_guest_python(client, tools["python"], """
        import hashlib, os, stat
        from pathlib import Path

        digest = hashlib.sha256()
        files = []
        for path in selected:
            descriptor = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(descriptor,'rb') as source:
                before = os.fstat(source.fileno())
                if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 16*1024*1024:
                    raise ValueError('Selected embedded console input is not bounded')
                content = hashlib.sha256()
                count = 0
                while chunk := source.read(65536):
                    count += len(chunk)
                    content.update(chunk)
                    digest.update(chunk)
                after = os.fstat(source.fileno())
            if count!=before.st_size or any(getattr(before,field)!=getattr(after,field)
                    for field in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')):
                raise ValueError('Selected embedded console input changed')
            files.append({'file':path,'sha256':content.hexdigest(),'byteSize':count})
        digest.update(b'bootstrap-api=object-v1\\n')
        print(json.dumps({'assetVersion':digest.hexdigest()[:8],
            'fullInputSha256':digest.hexdigest(),'files':files}))
    """, inputs))
    retain_direct_flow("managed-" + coordinates["runId"] + "-initial-cache-inputs.json", {
        "document": document, "assets": assets,
        "scope": "Actual canonical source and embedded asset inputs; no cache admission observation",
    })
    return {"registrySlug": "managed-" + coordinates["runId"] + "/containers",
        "documentSha256": document["sha256"], "bodyBytes": document["byteSize"],
        "assetVersion": assets["assetVersion"]}


def publish_managed_private_documents(client, tools, coordinates, controls, setup, source, refresh_token):
    """Publish the independently signed hidden document and wait for its current index."""
    slug = setup["registry"]["slug"]
    require_managed_pair(slug == "managed-" + coordinates["runId"] + "/private-docs"
        and setup["registry"]["visibility"] == "private"
        and re.fullmatch(r"[0-9a-f]{64}", source["sourceCommit"]),
        "Private documented registry must match its normal signed source")
    publication = json.loads(direct_guest_python(client, tools["python"], """
        import hashlib, os, subprocess
        from pathlib import Path

        root = Path(selected['root'])/'private-document-publication'
        root.mkdir(mode=0o700,parents=True,exist_ok=False)
        arguments = [selected['aos'],'--json','--progress','off','--color','never',
            'hub','registry','publish','upload',selected['slug'],'--root',selected['surface'],
            '--hub',selected['origin'],'--token',selected['token']]
        request = json.dumps(arguments,separators=(',',':')).encode()
        descriptor = os.open(root/'arguments.private.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(descriptor,'wb') as output:
            output.write(request); output.flush(); os.fsync(output.fileno())
        outputs = [os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            for name in ('stdout.private','stderr.private')]
        with os.fdopen(outputs[0],'wb') as stdout, os.fdopen(outputs[1],'wb') as stderr:
            result = subprocess.run(arguments,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,
                timeout=300,check=False)
            for output in (stdout,stderr):
                output.flush(); os.fsync(output.fileno())
                if os.fstat(output.fileno()).st_size>1048576:
                    raise ValueError('Private publication output exceeded its retained bound')
        if result.returncode:
            raise ValueError('Ordinary private document publication refused; do not replay')
        raw = (root/'stdout.private').read_bytes()
        value = json.loads(raw)['data']
        if value['state']!='ready':
            raise ValueError('Private document publication did not become ready')
        print(json.dumps({'publication':value,'stdout':{'file':str(root/'stdout.private'),
            'sha256':hashlib.sha256(raw).hexdigest(),'byteSize':len(raw)},
            'argumentsSha256':hashlib.sha256(request).hexdigest(),'exitCode':result.returncode}))
    """, {"root": coordinates["clientRoot"], "aos": tools["aos"], "slug": slug,
        "surface": source["surfaceRoot"], "origin": coordinates["workerOrigin"],
        "token": refresh_token()}, timeout=330))
    deadline = time.monotonic() + 240
    observations = []
    while True:
        current = controls.call("RegistryService", "GetRegistry", {"slug": slug})["registry"]
        observations.append({"indexState": current.get("indexState"),
            "indexError": current.get("indexError"), "lastIndexedCommit": current.get("lastIndexedCommit")})
        if current.get("indexState") == "fresh" and current.get("lastIndexedCommit") == source["sourceCommit"]:
            break
        if time.monotonic() >= deadline:
            retain_direct_flow("managed-" + coordinates["runId"] + "-private-index-refusal.json", observations)
            raise ValueError("Private documentation index did not reach its exact signed commit")
        time.sleep(2)
    return {**publication, "sourceCommit": source["sourceCommit"], "indexObservations": observations}


def run_managed_pair_window(client, native, worker, database, tools, database_host,
                            original_configuration, artifacts):
    """Execute the separate actual setup, purpose and business workflow in order."""
    require_managed_pair(tools["separateDatabase"] is True,
            "Final Managed window requires the selected independent PostgreSQL machine")
    source_digest = hashlib.sha256(tools["workerSourcePath"].encode()).hexdigest()
    codec = select_managed_storage_codec(artifacts, source_digest)
    run_id = secrets.token_hex(16)
    coordinates = managed_pair_coordinates(run_id)
    producer = managed_fixture_module(tools["managedContainerProducer"], "managed_container_" + run_id)
    producer_coordinates = {**coordinates, "clientRoot": coordinates["clientRoot"] + "/producer"}
    source = producer.prepare_managed_container_source(client, tools, producer_coordinates)
    documents = managed_fixture_module(tools["readParityModule"], "managed_documentation_" + run_id)
    documents.prepare_direct_signed_surface = prepare_direct_signed_surface
    documents.direct_guest_python = direct_guest_python
    documented_tools = {**tools, "openssh": tools["opensshBin"], "nix": tools["nixBin"],
        "cacheUrl": coordinates["workerOrigin"] + "/managed-" + run_id + "/private-docs",
        "hubPackage": tools["documentedPackage"]["storePath"],
        "hubVersion": tools["documentedPackage"]["version"]}
    private_source = documents.prepare_direct_documented_surface(client, documented_tools,
        tools["documentedPackage"]["baseLib"])
    require_managed_pair(private_source["document"]["sha256"] == source["document"]["sha256"]
        and private_source["document"]["byteSize"] == source["document"]["byteSize"],
        "Public and independently signed private registries must retain the same canonical document")
    tools = {**tools, "publicDocumentCacheCase": managed_document_cache_selection(
        client, tools, coordinates, source), "ociProfileLoadObserverSelection": {
            "version": 1, "capture_id": run_id, "placement_prefix": coordinates["gcPrefix"],
            "document_digest": source["finalized"]["index_digest"],
        }}
    native_address = private_guest_command(worker, tools["python"] + " -c " + shlex.quote(
        "import socket; print(socket.gethostbyname('native'))")).strip()
    worker_address = private_guest_command(native, tools["python"] + " -c " + shlex.quote(
        "import socket; print(socket.gethostbyname('worker'))")).strip()
    prepared = provision_managed_pair(worker, native, database, tools, original_configuration,
        run_id, database_host, native_address)
    prepared = {**prepared, "captureSelection": {
        "run": run_id, "sourceDigest": source_digest, "nativeAddress": native_address,
    }}
    tools = {**tools, "deploymentId": prepared["coordinates"]["deploymentId"]}
    profile_fixture = managed_fixture_module(tools["ociProfileController"], "managed_profile_" + run_id)
    profile_listener = profile_fixture.prepare_profile_listener(worker, tools, prepared)
    profile_process = launch_managed_process(worker, tools, profile_listener["root"],
        "profile-listener", profile_listener["arguments"], {})
    profile_readiness = profile_fixture.await_profile_listener(worker, tools,
        profile_listener, profile_process)
    prepared = {**prepared, "profileHold": {"listener": profile_listener,
        "process": profile_process, "readiness": profile_readiness}}
    cleanup_loss = prepare_managed_cleanup_loss(native, tools, prepared, worker_address)
    prepared = {**prepared, "cleanupLoss": cleanup_loss}
    boundaries = install_managed_storage_boundaries(native, worker, tools, run_id, worker_address, native_address)
    boundaries = {**boundaries, **codec,
        "ingressObservationSources": tools["managedIngressObservationSources"]}
    startup = start_managed_pair(native, worker, client, tools, prepared,
        native_address, worker_address, boundaries)
    prepared = {**prepared, "cleanupLoss": startup["cleanupLoss"]}
    processes = {name: startup[name] for name in (
        "native", "worker", "nativeProxy", "workerProxy",
    )}
    observed = observe_managed_pair(native, worker, tools, prepared, processes)
    candidate = prepare_managed_oci_candidate(worker, tools, prepared, observed, artifacts)
    installation = install_managed_oci_candidate(native, worker, tools, prepared,
        observed, candidate, processes)
    processes = {**processes, "native": installation["native"]}
    retain_direct_flow("managed-" + run_id + "-installation.json", {
        "prepared": prepared, "boundaries": boundaries, "processes": processes,
        "startup": startup,
        "observations": observed, "candidate": candidate, "installation": installation,
    })

    coordinates = prepared["coordinates"]
    login_root = coordinates["clientRoot"] + "/session"
    token = direct_root_browser_token(client, tools["curl"], tools["python"], private_guest_command,
        origin=coordinates["workerOrigin"], evidence_root=login_root)
    refresh_token = lambda: direct_root_browser_token(client, tools["curl"], tools["python"],
        private_guest_command, True, origin=coordinates["workerOrigin"], evidence_root=login_root)
    controls = DirectBootstrapControls(client, tools["curl"], tools["python"], token,
        private_guest_command, refresh_token, origin=coordinates["workerOrigin"],
        evidence_root=coordinates["clientRoot"] + "/controls")
    organization = controls.reviewed("OrganizationService", "PlanCreateOrganization", "CreateOrganization", {
        "slug": "managed-" + run_id, "displayName": "Managed SDK qualification",
        "expectedResourceVersion": "",
    }, "managed-" + run_id + "-organization")["organization"]
    require_managed_pair(organization["slug"] == "managed-" + run_id,
            "Managed organization differs from its actual original")

    organization = controls.call("OrganizationService", "GetOrganization", {
        "slug": organization["slug"],
    })["organization"]
    binding = controls.call("BindingService", "GetBinding", {"binding": {"instanceDefault": True}})["binding"]
    controls.reviewed("BindingService", "PlanGrantBindingScope", "GrantBindingScope", {
        "resourceKind": "binding", "resourceStableId": binding["stableId"], "resourceGeneration": "0",
        "consumerScopeKey": organization["ownerScopeKey"], "expectedResourceVersion": "",
    }, "managed-binding-grant-" + run_id)

    gc = managed_fixture_module(tools["managedGcHelper"], "managed_gc_" + run_id)
    setup = gc.prepare_managed_registry(controls, organization, "containers", [source["trustKey"]],
        coordinates["gcPrefix"], "managed-" + run_id)
    current = controls.call("RegistryService", "GetRegistry", {"slug": setup["registry"]["slug"]})["registry"]
    public = controls.reviewed("RegistryService", "PlanUpdateRegistry", "UpdateRegistry", {
        "slug": current["slug"], "visibility": "public", "updateMask": ["visibility"],
        "expectedResourceVersion": current["resourceVersion"],
    }, "managed-public-documents-" + run_id)["registry"]
    require_managed_pair(public["visibility"] == "public", "Managed document registry remained private")
    setup = {**setup, "registry": public}
    private_setup = gc.prepare_managed_registry(controls, organization, "private-docs", [private_source["trustKey"]],
        "qualification/parity-private/" + run_id, "managed-private-" + run_id)
    route = configure_managed_distribution(client, worker, tools, prepared, processes, controls, setup)
    accounting = managed_fixture_module(tools["managedWorkflowAccounting"], "managed_workflow_" + run_id)
    def parse_workflow_completion(text, role):
        if role in {"workerOriginal", "nativeReceived"}:
            values, completed, _ = managed_ingress_completion_receipts(text, role == "nativeReceived")
            return values, completed
        return direct_storage_completion_receipts(text, role == "workerReceived")

    workflow = accounting.ManagedWorkflowCapture(native, worker, tools, prepared, processes,
        boundaries, begin_managed_storage_window, finish_managed_storage_window,
        managed_private_log_position, retain_direct_log_window, parse_workflow_completion,
        capture_protected_headers, retain_direct_flow)

    def transition(event, facts):
        if event == "before-A-stop":
            require_managed_pair(facts["process"] == processes["worker"],
                "Profile stop names another actual Worker lifetime")
            workflow.close(processes)
        elif event in {"B-started", "before-B-stop"}:
            workflow.auxiliary_transition(event, facts)
        elif event == "A-restored":
            processes["worker"] = facts["process"]
            workflow.resume(processes)
        else:
            raise ValueError("Unknown actual Worker epoch transition")

    gc_result, cleanup_result = None, None
    producer_failure = None
    producer_error = None
    try:
        publication = producer.publish_managed_container(client, tools, controls,
            producer_coordinates, setup["registry"], source, refresh_token)
        private_publication = publish_managed_private_documents(client, tools, coordinates,
            controls, private_setup, private_source, refresh_token)
        retain_direct_flow("managed-" + run_id + "-container-publication.json", {
            "source": source, "setup": setup, "route": route, "publication": publication,
            "privateDocuments": {"source": private_source, "setup": private_setup,
                "publication": private_publication},
            "controlObservations": controls.observations,
        })
        reads = run_managed_read_window(client, native, worker, tools, prepared, processes,
            setup, source, publication, refresh_token)
        profile_context = profile_fixture.select_profile_context(worker, tools=tools,
            prepared=prepared, processes=processes,
            namespace_file=observed["namespaceObservation"]["path"],
            artifact_sha256=installation["artifactSha256"],
            source_identity_file=coordinates["workerRoot"] + "/clock-0/source-identity.json",
            listener=profile_listener)
        mismatch = profile_fixture.run_profile_origin_mismatch(worker, tools=tools,
            context=profile_context, listener=profile_listener, listener_process=profile_process,
            root_mutation=lambda: producer.root_mutation(client, tools, producer_coordinates,
                setup["registry"], source, refresh_token),
            check_original=lambda original, held: capture_managed_profile_original(
                native, tools, prepared, original, held),
            observe_worker=lambda pin, origin, configuration: observe_managed_profile_worker(
                worker, tools, prepared, pin, origin, configuration),
            transition=transition,
            retain=lambda name, value: retain_direct_flow("managed-" + run_id + "-" + name, value))
        # The owner has restored A only after B and the genuine producer terminate.
        # Later windows must bind this new lifetime rather than the startup PID.
        processes["worker"] = mismatch["restoredWorker"]
        retain_direct_flow("managed-" + run_id + "-profile-origin-mismatch.json", mismatch)
        require_managed_pair(mismatch["outcome"] == "same_source_origin_refused_before_sdk_in_loader_bracket",
            "Required actual profile-origin refusal remains unknown or failed")
        gc_result = run_managed_gc_window(native, worker, client, database, tools, prepared,
            processes, boundaries, controls, setup, source, publication, producer_coordinates, refresh_token)
        cleanup_result = run_managed_terminal_cleanup_window(native, worker, client, tools,
            prepared, processes, boundaries, controls, setup, source, publication,
            installation, refresh_token, workflow=workflow)
    except BaseException as error:
        producer_error = error
        producer_failure = type(error).__name__
        workflow.failure = producer_failure
        raise
    finally:
        try:
            whole_workflow = workflow.complete(processes)
            whole_workflow["assessment"] = accounting.assess_managed_workflow(
                whole_workflow, (cleanup_result or {}).get("nativeApplicationAccounting", {}),
                source_digest=prepared["captureSelection"]["sourceDigest"],
                gc_windows=(gc_result or {}).get("transportWindows", []),
                gc_positive=(gc_result or {}).get("completed", {}).get("actualPositiveEvidence"),
                read_retained=lambda reference: direct_selected_bytes(
                    {"path": reference["file"], "sha256": reference["sha256"]}, 16 * 1024 * 1024),
                join_gc_positive=gc.join_managed_deletion)
        except Exception as error:
            # Preserve the business exception while retaining a separate failed
            # capture gate. Neither failure may disappear into a positive subset.
            whole_workflow = {"version": 1, "producerFailureClass": producer_failure,
                "captureFailureClass": type(error).__name__, "assessment": {"complete": False,
                    "nativeBulkBytes": None, "unresolved": [{"scope": "global_capture",
                        "reason": "capture_or_join_failed"}]}}
        accounting.retain_managed_workflow_conclusion(whole_workflow, retain_direct_flow,
            "managed-" + run_id + "-whole-assessment.json", producer_error)
    require_managed_pair(whole_workflow["assessment"]["complete"] is True,
        "Required whole Managed application-body assessment is incomplete; actual evidence retained")
    return {"runId": run_id, "coordinates": coordinates, "processes": processes,
        "installation": installation, "registry": setup, "container": publication, "gc": gc_result,
        "terminalCleanup": cleanup_result, "readParity": reads, "wholeWorkflow": whole_workflow,
        "profileOriginMismatch": mismatch,
        "scope": "actual Managed R2 emulator workflow; Hosted qualification remains separate"}
