"""Own the fresh External pair's exact configuration and process transitions."""

import base64
import hashlib
import json
import re
import shlex
import time


def install_external_oci_consumers(worker, tools, prepared, consumers, issuer_binding, label, *, candidate_binding=None):
    """Create one selected configuration while preserving physical resources."""
    if label not in {"oci", "staging", "final"}:
        raise ValueError("External configuration generation differs")
    root = prepared["coordinates"]["workerRoot"]
    original = read_direct_guest_file(worker, tools["python"], prepared["configurationFile"], 1048576)
    if hashlib.sha256(original).hexdigest() != prepared["configurationSha256"]:
        raise ValueError("External previous configuration changed")
    configuration = json.loads(original)
    physical = {name: configuration.get(name) for name in (
        "name", "scriptPath", "resourcePersistencePath", "r2Buckets", "durableObjects",
        "kvNamespaces", "queueProducers", "queueConsumers")}
    allowed = {"HUB_EXTERNAL_OBJECT_CONSUMER", "HUB_EXTERNAL_COPY_CONSUMER",
        "HUB_EXTERNAL_OCI_CONSUMER", "HUB_EXTERNAL_STAGING_CONSUMER", "HUB_PROVIDER_CAPACITY_POLICY"}
    if not consumers or not set(consumers).issubset(allowed):
        raise ValueError("External consumer selection contains an unsupported domain")
    for name, value in consumers.items():
        configuration["bindings"][name] = json.dumps(value, separators=(",", ":"))
    configuration.setdefault("serviceBindings", {})["HUB_AUTHORITY_ISSUER"] = issuer_binding
    if candidate_binding is not None:
        if (set(candidate_binding) != {"candidate", "signature"}
                or not isinstance(candidate_binding["candidate"], str)
                or len(candidate_binding["candidate"].encode()) > 4096
                or not isinstance(candidate_binding["signature"], str)):
            raise ValueError("External candidate binding differs from its retained original")
        configuration["bindings"]["HUB_EXTERNAL_OCI_CANDIDATE"] = candidate_binding["candidate"]
        configuration["bindings"]["HUB_EXTERNAL_OCI_CANDIDATE_SIGNATURE"] = candidate_binding["signature"]
    if any(configuration.get(name) != value for name, value in physical.items()):
        raise ValueError("External installation changed its actual physical resources")
    body = json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()
    path = root + "/configuration-" + label + ".json"
    install_direct_guest_file(worker, tools["python"], path, body)
    return {**prepared, "configurationFile": path,
        "configurationSha256": hashlib.sha256(body).hexdigest()}


def stop_external_oci_process(machine, tools, root, process, label):
    """Signal only the selected owned lifetime, then retain the observed exit."""
    if re.fullmatch(r"[a-z][a-z0-9-]{0,31}", label) is None:
        raise ValueError("External process transition label differs")
    return json.loads(direct_guest_python(machine, tools["python"], """
        import hashlib, os, select, signal
        from pathlib import Path

        expected=selected['process']
        proc=Path('/proc')/str(expected['pid'])
        fd=os.pidfd_open(expected['pid'])
        try:
            fields=(proc/'stat').read_text().rpartition(') ')[2].split()
            with (proc/'exe').open('rb') as stream:
                executable=hashlib.file_digest(stream,'sha256').hexdigest()
            argv=(proc/'cmdline').read_bytes(); environment=(proc/'environ').read_bytes()
            if (fields[19]!=expected['startTicks'] or proc.stat().st_uid!=expected['ownerUid']
                    or executable!=expected['executableSha256']
                    or hashlib.sha256(argv).hexdigest()!=expected['commandLineSha256']
                    or hashlib.sha256(environment).hexdigest()!=expected['environmentSha256']):
                raise ValueError('External process changed; do not signal or replace')
            signal.pidfd_send_signal(fd,signal.SIGTERM)
            poll=select.poll(); poll.register(fd,select.POLLIN)
            if not poll.poll(40000): raise ValueError('External process exit remains unknown')
            receipt={'version':1,'pid':expected['pid'],'startTicks':expected['startTicks'],
                'pidfdReadable':True,'persistenceRemoved':False}
            path=Path(selected['root'])/(selected['label']+'-stop.json')
            descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(descriptor,'w') as output:
                json.dump(receipt,output); output.flush(); os.fsync(output.fileno())
            print(json.dumps(receipt))
        finally: os.close(fd)
    """, {"root": root, "process": process, "label": label}, timeout=50))


def restart_external_oci_worker(worker, tools, prepared, processes, label):
    """Retain both old and new actual pins without reusing an old measurement."""
    coordinates = prepared["coordinates"]
    root = coordinates["workerRoot"]
    terminal = stop_external_oci_process(worker, tools, root, processes["worker"], label)
    process = launch_managed_process(worker, tools, root, label, [tools["node"], tools["runner"],
        tools["miniflare"], prepared["configurationFile"]], {
            "NODE_EXTRA_CA_CERTS": "/etc/ssl/certs/ca-certificates.crt",
            "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
            "MINIFLARE_WORKERD_PATH": tools["workerd"]})
    process = {**process, "generation": label, "configurationFile": prepared["configurationFile"],
        "configurationSha256": prepared["configurationSha256"]}
    ready = await_external_oci_tls(worker, tools, prepared["coordinates"]["publicOrigin"])
    retain_direct_flow(label + "-" + coordinates["runId"] + "-transition.json", {"old": processes["worker"], "terminal": terminal,
        "new": process, "readiness": ready})
    return {**processes, "worker": process}


def retain_external_oci_native_file(native, worker, tools, path, source, maximum):
    """Copy exact private public setup documents; never move provider material."""
    body = read_direct_guest_file(worker, tools["python"], source, maximum)
    reference = install_direct_guest_file(native, tools["python"], path, body)
    return reference


def require_external_background_controllers(ready, run_id):
    """Require the source-owned task registration without claiming completion."""
    identity = "external-oci-inventory-" + run_id
    expected = {"placementScan": {"intervalSeconds": 2, "maximumPlacements": 5},
        "ociInventory": {"collectorId": identity, "idempotencyPrefix": identity,
            "maximumPlacements": 100, "dispatchBudget": "native"}}
    if ready.get("backgroundControllers") != expected:
        raise ValueError("External helper lacks its selected real controller task registrations")
    return expected


def await_external_oci_helper(native, tools, prepared, process, input_ref, candidate_sha, *, readiness_file=None):
    """Verify the actual post-bind helper record against this separate helper pin."""
    root = prepared["coordinates"]["nativeRoot"]
    path = readiness_file or root + "/helper-ready.json"
    if path not in {root + "/helper-ready.json", root + "/inventory-restart-ready.json"}:
        raise ValueError("External helper readiness leaves its selected process epoch")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        ready = json.loads(direct_guest_python(native, tools["python"], """
            import hashlib, os
            from pathlib import Path

            proc=Path('/proc')/str(selected['process']['pid'])
            fields=(proc/'stat').read_text().rpartition(') ')[2].split()
            if fields[0]=='Z' or fields[19]!=selected['process']['startTicks']:
                raise ValueError('External helper exited before readiness')
            with (proc/'exe').open('rb') as stream:
                actual_sha=hashlib.file_digest(stream,'sha256').hexdigest()
            if actual_sha!=selected['process']['executableSha256']:
                raise ValueError('External helper executable changed')
            path=Path(selected['path'])
            if not path.exists(): print('null')
            else:
                metadata=path.lstat()
                if (path.is_symlink() or not path.is_file() or metadata.st_uid!=os.getuid()
                        or metadata.st_mode&0o077 or metadata.st_size>65536):
                    raise ValueError('External helper readiness custody differs')
                print(path.read_text())
        """, {"process": process, "path": path}))
        if ready is None:
            time.sleep(0.1)
            continue
        identity = ready["identity"]
        if (ready["version"] != 1 or ready["scope"] != "controlled_external_oci_native_origin"
                or ready["listen"] != "127.0.0.1:4676"
                or identity["pid"] != process["pid"]
                or str(identity["startTicks"]) != process["startTicks"]
                or identity["executableSha256"] != process["executableSha256"]
                or identity["inputSha256"] != input_ref["sha256"]
                or identity["candidateSha256"] != candidate_sha
                or identity["publicOrigin"] != prepared["coordinates"]["publicOrigin"]):
            raise ValueError("External helper readiness changes its input, audience or process")
        require_external_background_controllers(ready, prepared["coordinates"]["runId"])
        return ready
    raise RuntimeError("Actual External helper readiness remains unknown")


def read_external_oci_sql(native, tools, prepared, process, query, label):
    """Run the supplied bounded read-only transaction against this pair's DB."""
    if (re.fullmatch(r"[a-z][a-z0-9-]{0,95}", label) is None
            or not query.startswith("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;")
            or not query.rstrip().endswith("COMMIT;")):
        raise ValueError("External SQL observation requires its actual read-only transaction")
    return json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, subprocess
        from pathlib import Path

        os.umask(0o077)
        root=Path(selected['root'])/'sql-observations'/selected['label']
        root.mkdir(mode=0o700,parents=True,exist_ok=False)
        def pin():
            proc=Path('/proc')/str(selected['process']['pid'])
            fields=(proc/'stat').read_text().rpartition(') ')[2].split()
            if (fields[0]=='Z' or fields[19]!=selected['process']['startTicks']
                    or proc.stat().st_uid!=selected['process']['ownerUid']):
                raise ValueError('External SQL authority process lifetime changed')
            with (proc/'exe').open('rb') as stream:
                digest=hashlib.file_digest(stream,'sha256').hexdigest()
            if digest!=selected['process']['executableSha256']:
                raise ValueError('External SQL authority executable changed')
            return {'pid':selected['process']['pid'],'startTicks':fields[19],'executableSha256':digest}
        before=pin()
        url=Path(selected['database']).read_bytes()
        if len(url)>8192: raise ValueError('External database URL exceeds private bound')
        with (root/'query.sql').open('x') as output: output.write(selected['query'])
        arguments=[selected['psql'],'-d',url.decode().strip(),'-X','-qAt','-v','ON_ERROR_STOP=1']
        with (root/'rows.private.json').open('xb') as stdout, (root/'stderr.private').open('xb') as stderr:
            result=subprocess.run(arguments,input=selected['query'].encode(),stdout=stdout,stderr=stderr,
                check=False,timeout=30)
        after=pin()
        raw=(root/'rows.private.json').read_bytes()
        if result.returncode or not 0<len(raw)<=1048576 or before!=after:
            raise ValueError('Current External SQL read refused; retain all private outputs')
        value=json.loads(raw)
        with Path(selected['psql']).open('rb') as stream:
            psql_sha=hashlib.file_digest(stream,'sha256').hexdigest()
        print(json.dumps({'value':value,'receipt':{'file':str(root/'rows.private.json'),
            'sha256':hashlib.sha256(raw).hexdigest(),'byteSize':str(len(raw)),
            'databaseUrlSha256':hashlib.sha256(url).hexdigest(),'psqlExecutableSha256':psql_sha,
            'querySha256':hashlib.sha256(selected['query'].encode()).hexdigest(),'before':before,'after':after}}))
    """, {"root": prepared["coordinates"]["nativeRoot"], "label": label,
        "database": prepared["nativeFiles"]["database"], "psql": tools["postgres"] + "/psql",
        "query": query, "process": process}, timeout=45))


def prepare_external_oci_profile_input(native, worker, tools, prepared, credentials,
                                        exports, copy_contract, files, observed, *, profile_role=None):
    """Supply genuine exports and provider originals to the existing Rust builder."""
    coordinates = prepared["coordinates"]
    root = coordinates["nativeRoot"]
    if profile_role not in {None, "destination"}:
        raise ValueError("External profile role differs")
    destination = profile_role == "destination"
    filename_prefix = "destination-" if destination else ""
    provider_root = coordinates["workerRoot"] + (
        "/destination-provider-observation" if destination else "/provider-observation")
    for name, source in (("bootstrap.json", exports["bootstrapFile"]["path"]),
            ("list-cohort.json", exports["listFile"]["path"]),
            ("provider-report.json", provider_root + "/observations.json"),
            ("private-policy.json", provider_root + "/private-policy.json")):
        retain_external_oci_native_file(native, worker, tools,
            root + "/" + filename_prefix + name, source, 1048576)
    source_digest = hashlib.sha256(tools["workerSourcePath"].encode()).hexdigest()
    value = {"version": 1, "phase": "profile", "runId": coordinates["runId"],
        "deploymentId": tools["deploymentId"], "sourceDigest": source_digest,
        "scriptVersion": None,
        "bindingId": int(credentials["currentSqlPins"]["bindingId"]), "placementId": None,
        "placementPrefix": (coordinates["placementPrefix"].rsplit("/", 1)[0] + "/destination/registry"
            if destination else coordinates["placementPrefix"]),
        "databaseUrlFile": prepared["nativeFiles"]["database"],
        "issuerConfigurationFile": root + "/issuer/configuration.json",
        "bootstrapFile": root + "/" + filename_prefix + "bootstrap.json",
        "listCohortFile": root + "/" + filename_prefix + "list-cohort.json",
        "privatePolicyFile": root + "/" + filename_prefix + "private-policy.json",
        "providerReviewFile": root + "/" + filename_prefix + "provider-report.json",
        "providerReviewSha256": copy_contract["value"]["report_sha256"],
        "versionlessConditionalReads": True, "maximumBlobBytes": 536870912,
        "clockUncertaintySeconds": 1, "lifetimeSeconds": 900, "expectedProfileSha256": None,
        "candidateKeyFile": prepared["nativeFiles"]["HUB_EXTERNAL_OCI_CANDIDATE_KEY"],
        "workKeyFile": tools["nativeStorageWorkKeyFile"],
        "guardKeyFile": prepared["nativeFiles"]["HUB_EXTERNAL_OBJECT_GUARD_KEY"],
        "outputDirectory": root + "/" + filename_prefix + "profile"}
    if destination:
        value["profileRole"] = "destination"
    # The script identity is compiled from the source path; the actual protected
    # Clock response supplies its exact spelling rather than a guessed version.
    identity = read_direct_guest_file(worker, tools["python"],
        coordinates["workerRoot"] + "/observations-installed/selected-source.json", 65536)
    identity = json.loads(identity)
    if identity["sourceDigest"] != source_digest:
        raise ValueError("External source identity changed before profile preparation")
    value["scriptVersion"] = identity["scriptVersion"]
    reference = install_direct_guest_file(native, tools["python"], root + "/" + filename_prefix + "profile-input.json",
        json.dumps(value, separators=(",", ":")).encode())
    return {**reference, "value": value}


def prepare_external_oci_candidate(native, tools, prepared, original, profile, registry, setup, process):
    """Resolve the genuine admitted placement before assembling a fresh candidate."""
    if original["value"].get("profileRole") is not None:
        raise ValueError("External candidate requires the original source profile")
    slug = registry["registry"]["slug"]
    stable = registry["registry"]["stableId"]
    name = registry["placement"]["name"]
    if any(re.fullmatch(r"[A-Za-z0-9/_.:-]{1,255}", value) is None for value in (slug, stable, name)):
        raise ValueError("External candidate SQL selector differs")
    query = ("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; "
        "SELECT json_build_object('placementId',p.id,'registryStableId',r.stable_id,'prefix',p.prefix) "
        "FROM surface_placements p JOIN registries r ON r.id=p.registry_id WHERE r.slug='" + slug
        + "' AND r.stable_id='" + stable + "' AND p.name='" + name + "'; COMMIT;")
    rows = read_external_oci_sql(native, tools, prepared, process, query, "candidate-placement")
    if (rows["value"]["registryStableId"] != stable
            or rows["value"]["prefix"] != prepared["coordinates"]["placementPrefix"]):
        raise ValueError("Actual candidate placement belongs to another registry or namespace")
    value = {**original["value"], "phase": "candidate",
        "placementId": rows["value"]["placementId"], "expectedProfileSha256": profile["profileFile"]["sha256"],
        "outputDirectory": prepared["coordinates"]["nativeRoot"] + "/candidate"}
    path = prepared["coordinates"]["nativeRoot"] + "/candidate-input.json"
    install_direct_guest_file(native, tools["python"], path, json.dumps(value, separators=(",", ":")).encode())
    candidate = setup.invoke_external_oci_preparation(native, tools, prepared["coordinates"], path,
        "candidate", private_guest_command)
    return {**candidate, "input": value, "placementId": rows["value"]["placementId"], "placementSql": rows}
