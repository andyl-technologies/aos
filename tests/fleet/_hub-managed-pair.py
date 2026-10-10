"""Prepare a separate Managed R2 pair within the five-machine qualification.

The pair uses a fresh PostgreSQL database and current deployment default binding.
Its localhost origins terminate TLS at the actual Native and Worker processes;
pinned capture proxies cross the Native/Worker VM boundary; the client uses a
transparent TCP forward. Configuration is frozen before
Clock, namespace and anchor observations. OCI acceptance and GC authority remain
separate, and this preparation conveys neither of them.
"""

import copy
import hashlib
import ipaddress
import json
import re
import shlex


WORKER_PORT = 4643
NATIVE_PORT = 4644
WORKER_INTERNAL_PORT = 4645
NATIVE_INTERNAL_PORT = 4646
WORKER_ORIGIN = "https://localhost:4643"
NATIVE_ORIGIN = "https://localhost:4644"
PRIVATE_ROLES = (
    "HUB_STORAGE_WORK_KEY", "HUB_HYBRID_INGRESS_KEY",
    "HUB_DIRECT_UPLOAD_GUARD_KEY", "HUB_DIRECT_UPLOAD_CONFORMANCE_KEY",
    "HUB_DIRECT_UPLOAD_JOURNAL_KEY",
)


def require_managed_pair(condition, message):
    if not condition:
        raise ValueError(message)


def managed_pair_coordinates(run_id):
    """Name fresh database, process roots and the actual dedicated namespace."""
    require_managed_pair(isinstance(run_id, str) and re.fullmatch(r"[0-9a-f]{32}", run_id),
            "Managed pair requires a fresh 32-hex run identity")
    return {
        "runId": run_id,
        "database": "fleet_managed_" + run_id,
        "deploymentId": "fleet-managed-" + run_id,
        "workerName": "fleet-managed-" + run_id,
        "namespaceId": "oci-sdk-qualification-" + run_id,
        "endpointId": "managed-endpoint-" + run_id,
        "probeSecretRef": "managed-probe-" + run_id,
        "nativeRoot": "/var/lib/hybrid-managed-native/" + run_id,
        "workerRoot": "/var/lib/hybrid-managed-worker/" + run_id,
        "clientRoot": "/var/lib/hybrid-client/managed-" + run_id,
        "gcPrefix": "qualification/oci-terminal-cleanup/" + run_id,
        "cleanupPrefix": "qualification/oci-terminal-cleanup/" + run_id,
        "workerOrigin": WORKER_ORIGIN,
        "nativeOrigin": NATIVE_ORIGIN,
    }


def managed_worker_configuration(original, selected, roles, registry_key,
                                 reviewer_key_id, reviewer_public_key, clock_policy):
    """Create initial namespace and OCI slot configuration without acceptance."""
    coordinates = managed_pair_coordinates(selected["runId"])
    require_managed_pair(set(roles) == set(PRIVATE_ROLES)
            and len(set(roles.values())) == len(PRIVATE_ROLES)
            and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                    for value in roles.values()), "Managed role keys must be independent")
    require_managed_pair(re.fullmatch(r"oci-sdk-emulator-v1-[0-9a-f]{64}", registry_key),
            "Managed OCI slot must come from the selected Rust registry-key command")
    require_managed_pair(re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", reviewer_key_id)
            and re.fullmatch(r"[0-9a-f]{64}", reviewer_public_key),
            "Managed reviewer identity differs")
    policy = clock_policy.get("policy", {})
    require_managed_pair(set(clock_policy) == {"policy", "commitment"}
            and set(policy) == {"version", "mode", "uncertaintySeconds"}
            and policy["version"] == 1 and policy["mode"] == "bounded_utc"
            and isinstance(policy["uncertaintySeconds"], str)
            and re.fullmatch(r"[1-9][0-9]?", policy["uncertaintySeconds"])
            and 1 <= int(policy["uncertaintySeconds"]) <= 29
            and re.fullmatch(r"[0-9a-f]{64}", clock_policy["commitment"]),
            "Managed clock requires the installed shared policy encoder")
    require_managed_pair(all(isinstance(selected.get(field), str) and selected[field].startswith("/nix/store/")
                for field in ("shim", "wasm", "workerSourcePath", "workerd", "managedGcObserver", "managedCleanupInstaller")),
            "Managed pair requires selected immutable runtime inputs")
    require_managed_pair(original["scriptPath"] == selected["shim"],
            "Managed and External pair must select the same actual Worker distribution")

    root = coordinates["workerRoot"]
    # Preserve the exact selected TLS leaf and script compatibility settings;
    # remove External credentials, consumers, queues and acceptance inputs.
    configuration = {field: copy.deepcopy(original[field]) for field in (
        "scriptPath", "compatibilityDate", "certificatePath", "privateKeyPath",
    )}
    if "compatibilityFlags" in original:
        configuration["compatibilityFlags"] = copy.deepcopy(original["compatibilityFlags"])
    configuration.update({
        "name": coordinates["workerName"], "host": "127.0.0.1", "port": WORKER_INTERNAL_PORT,
        "resourcePersistencePath": root + "/state",
        "r2Buckets": {"REGISTRY_BUCKET": coordinates["namespaceId"]},
        "durableObjects": {name: {"className": class_name, "useSQLite": True}
            for name, class_name in (
                ("HYBRID_OBJECT_GUARD", "HybridObjectGuard"),
                ("HYBRID_BINDING_STATE", "HybridBindingState"),
                ("HYBRID_DIRECT_UPLOAD", "HybridDirectUpload"),
            )},
        "kvNamespaces": {"HUB_OCI_SDK_EMULATOR_ACCEPTANCE": coordinates["namespaceId"] + "-oci"},
        "acceptanceSocketPath": root + "/control.sock",
        "ociSdkNamespaceObservation": {
            "sourceStorePath": selected["workerSourcePath"], "wasmPath": selected["wasm"],
            "workerdPath": selected["workerd"],
        },
        "ociSdkAnchorEnabled": True,
        "managedGcObserverPath": selected["managedGcObserver"],
        "managedCleanupInstallerPath": selected["managedCleanupInstaller"],
        "managedGcObserverSelection": {"version": 1, "captureId": coordinates["runId"],
            "prefix": coordinates["gcPrefix"]},
        "ociSdkAcceptanceRegistryKey": registry_key,
        "bindings": {
            **roles, "HUB_TOPOLOGY": "hybrid",
            "HUB_DEPLOYMENT_ID": coordinates["deploymentId"],
            "HUB_EXTERNAL_URL": WORKER_ORIGIN,
            "HUB_HYBRID_ORIGIN_URL": NATIVE_ORIGIN,
            "HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN": WORKER_ORIGIN,
            "HUB_DIRECT_UPLOAD_MANAGED_R2": "false",
            "HUB_DIRECT_UPLOAD_QUALIFICATION_ENABLED": "true",
            "HUB_DIRECT_QUALIFY_MAX_PROVIDER_REQUESTS": "2",
            "HUB_DIRECT_QUALIFY_MAX_OBJECT_BYTES": "1024",
            "HUB_DIRECT_UPLOAD_CLOCK_MODE": "bounded_utc",
            "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS": policy["uncertaintySeconds"],
            "HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION": clock_policy["commitment"],
            # This enables only the distinct OCI loader. An absent slot refuses
            # dispatch until independently reviewed bytes are staged and verified.
            "HUB_OCI_SDK_EMULATOR_ENABLED": "true",
            "HUB_OCI_SDK_EMULATOR_PUBLIC_ORIGIN": WORKER_ORIGIN,
            "HUB_OCI_SDK_EMULATOR_REVIEWER_KEY_ID": reviewer_key_id,
            "HUB_OCI_SDK_EMULATOR_REVIEWER_PUBLIC_KEY": reviewer_public_key,
            "HUB_OCI_SDK_EMULATOR_MAX_PROVIDER_REQUESTS": "2",
            "HUB_MANAGED_OCI_CLEANUP_FIXTURE_PREFIX": coordinates["cleanupPrefix"],
            "HUB_MANAGED_OCI_CLEANUP_FIXTURE_NAMESPACE": coordinates["namespaceId"],
            "HUB_MANAGED_OCI_CLEANUP_SDK_OBSERVER": json.dumps({
                "version": 1, "capture_id": coordinates["runId"],
                "prefix": coordinates["cleanupPrefix"],
            }, separators=(",", ":")),
            "HUB_MANAGED_GC_SDK_OBSERVER": json.dumps({
                "version": 1, "capture_id": coordinates["runId"],
                "prefix": coordinates["gcPrefix"],
            }, separators=(",", ":")),
        },
    })
    cache_case = selected.get("publicDocumentCacheCase")
    if cache_case is not None:
        require_managed_pair(isinstance(cache_case, dict) and set(cache_case) == {
                "registrySlug", "documentSha256", "bodyBytes", "assetVersion"}
            and cache_case["registrySlug"] == "managed-" + coordinates["runId"] + "/containers"
            and re.fullmatch(r"[0-9a-f]{64}", cache_case["documentSha256"])
            and type(cache_case["bodyBytes"]) is int and 16 <= cache_case["bodyBytes"] <= 262144
            and re.fullmatch(r"[0-9a-f]{8}", cache_case["assetVersion"])
            and isinstance(selected.get("publicDocumentCacheObserver"), str)
            and selected["publicDocumentCacheObserver"].startswith("/nix/store/"),
            "Managed initial cache selection requires the actual canonical document and installed observer")
        configuration["publicDocumentCacheCase"] = copy.deepcopy(cache_case)
        configuration["publicDocumentCacheObserverPath"] = selected["publicDocumentCacheObserver"]
    profile_observer = selected.get("ociProfileLoadObserverSelection")
    if profile_observer is not None:
        require_managed_pair(isinstance(profile_observer, dict) and set(profile_observer) == {
                "version", "capture_id", "placement_prefix", "document_digest"}
            and type(profile_observer["version"]) is int and profile_observer["version"] == 1
            and profile_observer["capture_id"] == coordinates["runId"]
            and profile_observer["placement_prefix"] == coordinates["gcPrefix"]
            and re.fullmatch(r"sha256:[0-9a-f]{64}", profile_observer["document_digest"]),
            "Initial profile observer must select the retained graph and reserved placement")
        # The fresh upload key is allocated by the normal producer later. The
        # observer grants no admission and must join that emitted key to SQL.
        configuration["bindings"]["HUB_OCI_PROFILE_LOAD_OBSERVER"] = json.dumps(
            profile_observer, separators=(",", ":"))
    return configuration


def managed_native_arguments(hub, coordinates, files, *, acceptance=False):
    """Select ordinary init/serve inputs for the fresh authoritative database."""
    require_managed_pair(coordinates == managed_pair_coordinates(coordinates["runId"]),
            "Managed pair coordinates changed")
    evidence_files = {
        "release_seed", "channel_seed", "publication_keys", "qualification_keys", "route_keys",
    }
    require_managed_pair(evidence_files <= set(files)
            and all(isinstance(files[name], str) and files[name].startswith(
                coordinates["nativeRoot"] + "/materials/") for name in evidence_files),
            "Managed Native requires the complete private release and route key configuration")
    arguments = [hub, "--root", coordinates["nativeRoot"] + "/hub",
        "--database-url-file", files["database"], "serve", "--listen", "127.0.0.1:4646",
        "--topology", "hybrid", "--external-url", WORKER_ORIGIN,
        # This pair exercises the R2 SDK without a presigning endpoint.
        "--hybrid-upload-mode", "worker_proxy",
        "--hybrid-worker-url", WORKER_ORIGIN, "--hybrid-origin-url", NATIVE_ORIGIN,
        "--deployment-id", coordinates["deploymentId"], "--reindex-interval", "0",
        "--release-receipt-key-id", "staging-publication-v1",
        "--release-receipt-key-file", files["release_seed"],
        "--channel-receipt-key-id", "staging-channel-v1",
        "--channel-receipt-key-file", files["channel_seed"],
        "--release-publication-keys-file", files["publication_keys"],
        "--qualification-keys-file", files["qualification_keys"],
        "--route-reservation-keys-file", files["route_keys"],
        "--hybrid-ingress-key-file", files["HUB_HYBRID_INGRESS_KEY"],
        "--storage-work-key-file", files["HUB_STORAGE_WORK_KEY"],
        "--jwt-secret-file", files["jwt"],
        "--domain-probe-signer-manifest-file", files["probeManifest"],
        "--tls-certificate-file", files["certificate"], "--tls-private-key-file", files["privateKey"]]
    if acceptance:
        arguments += ["--oci-sdk-emulator-acceptance-file", files["acceptance"],
            "--oci-sdk-emulator-review-keys-file", files["reviewers"],
            "--oci-sdk-emulator-guard-key-file", files["HUB_DIRECT_UPLOAD_GUARD_KEY"]]
    return arguments


def managed_forward_arguments(socat, target_address, port):
    """Forward exact TCP bytes to one selected VM, preserving end-to-end TLS."""
    address = ipaddress.IPv4Address(target_address)
    require_managed_pair(address.is_private and not address.is_loopback and not address.is_unspecified,
            "Managed forward requires an actual private peer VM address")
    require_managed_pair(type(port) is int and port in {WORKER_PORT, NATIVE_PORT},
            "Managed forward port differs from the confined pair")
    return [socat, "TCP4-LISTEN:" + str(port) + ",bind=127.0.0.1,reuseaddr,fork",
        "TCP4:" + str(address) + ":" + str(port)]


def prepare_managed_oci_materials(worker, tools, coordinates):
    """Create fresh role keys and encode the provider slot with the installed reviewer."""
    return json.loads(direct_guest_python(worker, tools["python"], """
        import base64, os, secrets, subprocess
        from pathlib import Path

        root = Path(selected['root'])
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        material = root / 'materials'
        material.mkdir(mode=0o700)
        roles = {name:secrets.token_hex(32) for name in selected['roles']}
        if len(set(roles.values())) != len(roles):
            raise ValueError('Managed role entropy collided')
        for name,value in roles.items():
            fd = os.open(material/name, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            with os.fdopen(fd,'w') as output:
                output.write(value)
                output.flush()
                os.fsync(output.fileno())
        def review(arguments):
            result = subprocess.run([selected['reviewer']]+arguments,
                stdin=subprocess.DEVNULL,capture_output=True,check=False,timeout=60)
            if result.returncode:
                raise ValueError('Managed shared reviewer preparation refused')
            return result.stdout.decode().strip()
        public = review(['oci-sdk-fixture-key','--private-output',str(material/'reviewer.seed'),
            '--public-output',str(material/'reviewer.hex')])
        probe_public = review(['oci-sdk-fixture-key','--private-output',str(material/'probe.seed'),
            '--public-output',str(material/'probe.hex')])
        probe_seed = (material/'probe.seed').read_bytes()
        if len(probe_seed)!=32 or probe_seed==(material/'reviewer.seed').read_bytes():
            raise ValueError('Managed probe signer is not an independent fresh key')
        probe = {'endpointId':selected['endpointId'],'endpointGeneration':1,
            'signerSecretRef':selected['probeSecretRef'],
            'signingSeed':base64.urlsafe_b64encode(probe_seed).decode().rstrip('=')}
        probe_manifest = [probe] + [{**probe,
            'endpointId':selected['endpointId']+'-'+mode,
            'signerSecretRef':selected['probeSecretRef']+'-'+mode}
            for mode in ('native-only','worker-only')]
        probe_public = base64.urlsafe_b64encode(bytes.fromhex(probe_public)).decode().rstrip('=')
        slot = review(['oci-sdk-registry-key','--deployment-id',selected['deployment'],
            '--source-digest',selected['source'],'--script-version','emulated-'+selected['source']])
        clock = json.loads(review(['clock-policy','--uncertainty-seconds','1']))
        print(json.dumps({'roles':roles,'reviewerPublicKey':public,'registryKey':slot,
            'clockPolicy':clock,'probeManifest':probe_manifest,'probePublicKey':probe_public,'reviewerPrivateFile':str(material/'reviewer.seed'),
            'reviewerPublicFile':str(material/'reviewer.hex')}))
    """, {"root": coordinates["workerRoot"], "deployment": coordinates["deploymentId"],
            "source": hashlib.sha256(tools["workerSourcePath"].encode()).hexdigest(),
            "reviewer": tools["reviewer"], "roles": list(PRIVATE_ROLES),
            "endpointId": coordinates["endpointId"], "probeSecretRef": coordinates["probeSecretRef"]}, timeout=260))


def provision_managed_pair(worker, native, database, tools, original_configuration,
                           run_id, database_host, native_address):
    """Freeze fresh role keys, Rust-derived slot and ordinary Native init files."""
    coordinates = managed_pair_coordinates(run_id)
    fixture = tools["parityFixture"]
    evidence_names = ("release_seed", "channel_seed", "publication_keys", "qualification_keys", "route_keys")
    require_managed_pair(all(isinstance(fixture.get(name), str)
            and fixture[name].startswith("/nix/store/") for name in evidence_names),
            "Managed release and route inputs require selected source-built fixture files")
    require_managed_pair(re.fullmatch(r"[a-z][a-z0-9-]{0,63}", database_host),
            "Managed database must be the selected separate VM")
    prepared = prepare_managed_oci_materials(worker, tools, coordinates)
    original_bytes = read_direct_guest_file(worker, tools["python"], original_configuration, 1024 * 1024)
    configuration = managed_worker_configuration(json.loads(original_bytes),
        {**tools, "runId": run_id}, prepared["roles"], prepared["registryKey"],
        "managed-oci-" + run_id, prepared["reviewerPublicKey"], prepared["clockPolicy"])
    body = json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()
    configuration_file = coordinates["workerRoot"] + "/configuration.json"
    install_direct_guest_file(worker, tools["python"], configuration_file, body)
    database_receipt = create_managed_database(database, tools, coordinates, native_address)

    native_root = coordinates["nativeRoot"]
    files = {name: native_root + "/materials/" + name for name in PRIVATE_ROLES}
    files.update({"database": native_root + "/materials/database.url",
        "jwt": native_root + "/materials/jwt.key", "seal": native_root + "/materials/seal.key",
        "certificate": tools["issuerCertificate"], "privateKey": tools["issuerPrivateKey"],
        "acceptance": native_root + "/acceptance.json",
        "reviewers": native_root + "/materials/reviewers.json",
        "probeManifest": native_root + "/materials/probe-manifest.json"})
    # Native's deployment identity requires the complete release authority group.
    # Copy the selected fixture bytes into this pair's owner-private custody.
    release_configuration = {}
    for name in evidence_names:
        files[name] = native_root + "/materials/" + name
        original = read_direct_guest_file(native, tools["python"], fixture[name], 65536)
        release_configuration[name] = install_direct_guest_file(
            native, tools["python"], files[name], original)
    for name, value in prepared["roles"].items():
        install_direct_guest_file(native, tools["python"], files[name], value.encode())
    install_direct_guest_file(native, tools["python"], files["database"],
        ("postgresql://postgres@" + database_host + ":5432/" + coordinates["database"] + "\n").encode())
    install_direct_guest_file(native, tools["python"], files["probeManifest"],
        json.dumps(prepared["probeManifest"], separators=(",", ":")).encode())
    reviewers = {"managed-oci-" + run_id: prepared["reviewerPublicKey"]}
    install_direct_guest_file(native, tools["python"], files["reviewers"], json.dumps(reviewers).encode())
    initialized = json.loads(direct_guest_python(native, tools["python"], """
        import os, secrets, subprocess
        from pathlib import Path

        for name in ('jwt','seal'):
            fd = os.open(selected['files'][name], os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as output:
                output.write(secrets.token_hex(32))
                output.flush()
                os.fsync(output.fileno())
        tls = subprocess.run([selected['openssl'],'x509','-noout','-in',
            selected['files']['certificate'],'-checkhost','localhost'],
            capture_output=True,check=False,timeout=20)
        if tls.returncode:
            raise ValueError('Managed actual TLS leaf does not cover localhost')
        environment = dict(os.environ)
        environment.update(HUB_DATABASE_URL_FILE=selected['files']['database'],
            AOS_HUB_SECRET_KEY_FILE=selected['files']['seal'])
        argv = [selected['hub'],'--root',selected['root']+'/hub','init',
            '--root-email','fleet-root@example.test','--root-password','fleet-root-password']
        result = subprocess.run(argv,env=environment,stdin=subprocess.DEVNULL,
            capture_output=True,check=False,timeout=180)
        for name,value in (('init.stdout',result.stdout),('init.stderr',result.stderr)):
            fd = os.open(Path(selected['root'])/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as output:
                output.write(value)
                output.flush()
                os.fsync(output.fileno())
        if result.returncode:
            raise ValueError('Managed ordinary init refused; retain new database and logs')
        print(json.dumps({'version':1,'exitCode':result.returncode,'root':selected['root'],
            'scope':'ordinary fresh initialization; no accepted OCI or GC authority'}))
    """, {"files": files, "root": native_root, "hub": tools["hub"],
            "openssl": tools["openssl"]}, timeout=240))
    return {"coordinates": coordinates, "configurationFile": configuration_file,
        "configurationSha256": hashlib.sha256(body).hexdigest(), "nativeFiles": files,
        "reviewerKeyId": "managed-oci-" + run_id,
        "reviewerPublicKey": prepared["reviewerPublicKey"],
        "reviewerPrivateFile": prepared["reviewerPrivateFile"],
        "reviewerPublicFile": prepared["reviewerPublicFile"],
        "registryKey": prepared["registryKey"], "clockPolicy": prepared["clockPolicy"],
        "probePublicKey": prepared["probePublicKey"], "probeManifest": prepared["probeManifest"],
        "databaseReceipt": database_receipt, "initialization": initialized,
        "releaseConfiguration": release_configuration}


def start_managed_pair(native, worker, client, tools, prepared, native_address, worker_address, boundaries):
    """Start pinned pair proxies and the transparent client TLS forward."""
    coordinates = prepared["coordinates"]
    root = coordinates["workerRoot"]
    trust = "/etc/ssl/certs/ca-certificates.crt"
    forwards = []
    for machine, path, target, port, label in (
        (client, coordinates["clientRoot"], worker_address, WORKER_PORT, "worker-forward"),
    ):
        forwards.append(launch_managed_process(machine, tools, path, label,
            managed_forward_arguments(tools["socat"], target, port), {}))
    cleanup_loss = prepared["cleanupLoss"]
    loss_process = launch_managed_process(native, tools, coordinates["nativeRoot"],
        "cleanup-loss", cleanup_loss["arguments"], {})
    require_managed_pair(loss_process["executableSha256"] == cleanup_loss["executableSha256"],
            "Managed cleanup listener differs from its selected actual executable")
    cleanup_loss = {**cleanup_loss, "process": loss_process}
    loss_readiness = await_managed_cleanup_loss(native, tools,
        {**prepared, "cleanupLoss": cleanup_loss}, loss_process)
    proxies = {}
    for role, machine in (("native", native), ("worker", worker)):
        selected = boundaries[role + "Proxy"]
        observation = {name: selected[name] for name in (
            "configurationFile", "configurationSha256", "invocationObservationMode", "expectedMasterTitle")}
        proxies[role] = launch_managed_process(machine, tools,
            coordinates[role + "Root"], "boundary", selected["invocationArguments"], {},
            nginx_observation=observation)
    worker_process = launch_managed_process(worker, tools, root, "worker", [
        tools["node"], tools["runner"], tools["miniflare"], prepared["configurationFile"]], {
        "NODE_EXTRA_CA_CERTS": trust, "SSL_CERT_FILE": trust,
        "MINIFLARE_WORKERD_PATH": tools["workerd"],
    })
    # Native startup checks the actual Worker console/storage capabilities;
    # wait on the TLS listener rather than treating the child PID as ready.
    readiness = await_managed_tls(native, tools, WORKER_ORIGIN)
    native_process = launch_managed_process(native, tools, coordinates["nativeRoot"], "native",
        managed_native_arguments(tools["hub"], coordinates, prepared["nativeFiles"]), {
            "AOS_HUB_SECRET_KEY_FILE": prepared["nativeFiles"]["seal"],
            "SSL_CERT_FILE": trust, "HUB_DNS_JSON_ENDPOINT": tools["managedDnsJsonEndpoint"],
            "HUB_OCI_PULL_ENABLED": "true",
            "HUB_OCI_PUSH_ENABLED": "true", "HUB_OCI_GC_ENABLED": "true",
        })
    native_readiness = await_managed_tls(native, tools, NATIVE_ORIGIN)
    return {"forwards": forwards, "cleanupLoss": cleanup_loss, "cleanupLossReadiness": loss_readiness,
        "nativeProxy": proxies["native"], "workerProxy": proxies["worker"],
        "worker": worker_process, "native": native_process,
        "workerTlsStatus": readiness["status"], "nativeTlsStatus": native_readiness["status"],
        "scope": "actual pair listeners answered TLS; business readiness pending"}


def await_managed_tls(machine, tools, origin):
    """Wait for a real TLS response while retaining every read-only probe result."""
    require_managed_pair(origin in {WORKER_ORIGIN, NATIVE_ORIGIN},
            "Managed readiness targets a fixed configured origin")
    return json.loads(direct_guest_python(machine, tools["python"], """
        import subprocess, time

        deadline = time.monotonic() + 60
        probes = []
        while True:
            result = subprocess.run(selected['curl']+[
                '--silent','--show-error','--max-time','3','--output','/dev/null',
                '--write-out','%{http_code}','--request',selected['method'],selected['url']],
                stdin=subprocess.DEVNULL,capture_output=True,check=False,timeout=5)
            status = result.stdout.decode('ascii').strip()
            probes.append({'exitCode':result.returncode,'httpStatus':status})
            if result.returncode == 0 and status == selected['expectedStatus']:
                print(json.dumps({'version':1,'status':int(status),'probes':probes,
                    'scope':'actual TLS response only; no business readiness'}))
                break
            if len(probes)>=64 or time.monotonic()>=deadline:
                raise ValueError('Managed TLS listener did not answer within its startup bound')
            time.sleep(1)
    """, {"curl": shlex.split(tools["curl"]),
        "url": origin + ("/_internal/storage/v1/capabilities" if origin == WORKER_ORIGIN else "/-/health"),
        "method": "POST" if origin == WORKER_ORIGIN else "GET",
        "expectedStatus": "401" if origin == WORKER_ORIGIN else "200"}, timeout=75))


def observe_managed_pair(native, worker, tools, prepared, processes):
    """Retain current Native, signed Clock, namespace and one-shot anchor evidence."""
    coordinates = prepared["coordinates"]
    root = coordinates["workerRoot"]
    source = hashlib.sha256(tools["workerSourcePath"].encode()).hexdigest()
    identity_file = root + "/build-selected-identity.json"
    install_direct_guest_file(worker, tools["python"], identity_file, json.dumps({
        "sourceDigest": source, "scriptVersion": "emulated-" + source,
        "publicOrigin": coordinates["workerOrigin"],
    }, separators=(",", ":")).encode())
    native_observation = coordinates["nativeRoot"] + "/native-observation.json"
    native_configuration = coordinates["nativeRoot"] + "/native-observed-configuration.json"
    observer_arguments = [
        tools["reviewer"], "oci-sdk-observe-native", "--pid", str(processes["native"]["pid"]),
        "--executable", tools["hub"], "--configuration-output", native_configuration,
        "--observation-output", native_observation,
    ]
    # The observer checks process ownership. Observe a system-service Hub as
    # its actual service user; the isolated pair otherwise runs as the VM owner.
    observer_user = tools.get("nativeObserverUser")
    if observer_user is not None:
        require_managed_pair(re.fullmatch(r"[a-z][a-z0-9-]{0,31}", observer_user),
                "OCI observer requires an explicit service user")
        # The minimal VM has no PAM login policy. Keep the actual service UID
        # and give only this inspection process the capability needed to read
        # a protected service's /proc environment and executable link.
        observer_arguments = [tools["setpriv"], "--reuid", observer_user,
            "--regid", observer_user, "--init-groups",
            "--inh-caps", "+sys_ptrace", "--ambient-caps", "+sys_ptrace",
            "--", *observer_arguments]
    private_guest_command(native, shlex.join(observer_arguments), timeout=30)
    for path in (native_observation, native_configuration):
        install_direct_guest_file(worker, tools["python"], root + "/" + path.rsplit("/", 1)[1],
            read_direct_guest_file(native, tools["python"], path, 256 * 1024))
    observations = json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, os, secrets, subprocess
        from pathlib import Path

        root = Path(selected['root'])
        env = dict(os.environ)
        env['NODE_EXTRA_CA_CERTS'] = '/etc/ssl/certs/ca-certificates.crt'
        def invoke(argv, label, timeout):
            result = subprocess.run(argv,env=env,stdin=subprocess.DEVNULL,
                capture_output=True,check=False,timeout=timeout)
            for name,body in ((label+'.stdout',result.stdout),(label+'.stderr',result.stderr)):
                fd = os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,'wb') as output:
                    output.write(body)
                    output.flush()
                    os.fsync(output.fileno())
            if result.returncode:
                raise ValueError('Managed prerequisite refused; no dispatch is replayed')
            return result.stdout
        clocks = []
        for number in range(2):
            output = root/('clock-'+str(number))
            invoke([selected['node'],selected['driver'],'--phase','clock',
                '--run-id',secrets.token_hex(32),'--origin',selected['origin'],
                '--control-key-file',str(root/'materials/HUB_DIRECT_UPLOAD_CONFORMANCE_KEY'),
                '--identity-file',selected['identity'],'--output-dir',str(output),
                '--clock-uncertainty-seconds','1'], 'clock-'+str(number), 40)
            clocks.append({name:str(output/('00001-clock-'+leaf+'.json')) for name,leaf in (
                ('request','request'),('reply','capture'),('authentication','authentication'))})
        namespace = root/'namespace.json'
        argv = [selected['python'],selected['namespaceObserver'],
            '--runner-pid',str(selected['process']['pid']),
            '--runner-start-ticks',selected['process']['startTicks'],
            '--socket-file',str(root/'control.sock'), '--node-file',selected['node'],
            '--runner-file',selected['runner'],'--workerd-file',selected['workerd'],
            '--configuration-file',selected['configuration'],'--source-store-path',selected['source'],
            '--miniflare-root',selected['miniflare'],'--identity-file',str(root/'clock-0/source-identity.json'),
            '--wasm-file',selected['wasm'],'--shim-file',selected['shim'],'--report-file',str(namespace)]
        invoke(argv,'namespace',30)
        anchor_root = root/'anchor-original'
        invoke([selected['python'],selected['anchor'],'prepare','--namespace-observation-file',
            str(namespace),'--output-directory',str(anchor_root)],'anchor-prepare',20)
        invoke([selected['python'],selected['anchor'],'dispatch','--original-directory',
            str(anchor_root),'--socket-file',str(root/'control.sock'),
            '--node-file',selected['node']], 'anchor-dispatch',35)
        def selected_file(path):
            with open(path,'rb') as stream:
                digest = hashlib.file_digest(stream,'sha256').hexdigest()
            return {'path':str(path),'sha256':digest}
        response = json.loads((anchor_root/'response.json').read_bytes())
        if response.get('status') != 'observed' or response.get('sdkInvocations') != {'put':1,'get':1}:
            raise ValueError('Managed one-shot original is not positively observed')
        print(json.dumps({'version':1,'namespaceObservation':selected_file(namespace),
            'nativeObservation':selected_file(root/'native-observation.json'),
            'nativeConfiguration':selected_file(root/'native-observed-configuration.json'),
            'anchorOriginal':selected_file(anchor_root/'original.json'),
            'anchorReceipt':selected_file(anchor_root/'response.json'),
            'clocks':[{name:selected_file(path) for name,path in clock.items()} for clock in clocks],
            'scope':'actual prerequisite observations; no acceptance or business permission'}))
    """, {"root": root, "origin": coordinates["workerOrigin"], "identity": identity_file,
        "process": processes["worker"], "configuration": prepared["configurationFile"],
        "driver": tools["qualificationDriver"], "namespaceObserver": tools["ociNamespaceObserver"],
        "anchor": tools["ociAnchor"], "source": tools["workerSourcePath"],
        **{name: tools[name] for name in ("node", "python", "runner", "workerd", "miniflare", "wasm", "shim")},
    }, timeout=190))
    return observations


def prepare_managed_oci_candidate(worker, tools, prepared, observed, artifacts):
    """Invoke the shared Rust preparation on exact actual retained file selections."""
    coordinates = prepared["coordinates"]
    module_root = tools["miniflare"] + "/lib/node_modules/wrangler/node_modules/miniflare/dist/src"
    installed = {"nativeExecutable": tools["hub"], "wasm": tools["wasm"], "shim": tools["shim"],
        "configuration": prepared["configurationFile"], "runner": tools["runner"],
        "miniflareModule": module_root + "/index.js",
        "miniflareEntryWorker": module_root + "/workers/shared/object-entry.worker.js",
        "miniflareBucketWorker": module_root + "/workers/r2/bucket.worker.js",
        "workerdExecutable": tools["workerd"], "nixExecutable": tools["nixBin"] + "/nix-store"}
    for name in ("sourceNar", "distributionNar"):
        require_managed_pair(re.fullmatch(r"[0-9a-f]{64}", artifacts["files"][name]["sha256"]),
                "Managed reviewer requires actual same-source NAR captures")
    return json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, os, subprocess, time
        from pathlib import Path

        root = Path(selected['root'])
        def file(path):
            with open(path,'rb') as stream:
                sha = hashlib.file_digest(stream,'sha256').hexdigest()
            return {'path':path,'sha256':sha}
        issued = int(time.time())
        document = {'version':1,'reviewerKeyId':selected['reviewerId'],
            'reviewerPublicKey':file(selected['reviewerPublicFile']),
            'deploymentId':selected['deployment'],'publicOrigin':selected['publicOrigin'],
            'nativeOrigin':selected['nativeOrigin'],'expectedSourceDigest':selected['sourceDigest'],
            'expectedScriptVersion':'emulated-'+selected['sourceDigest'],
            'sourceStorePath':selected['sourceStorePath'],'distributionStorePath':selected['distributionStorePath'],
            'sourceNarSha256':selected['sourceNarSha256'],'distributionNarSha256':selected['distributionNarSha256'],
            'issuedAt':issued,'expiresAt':issued+3600,'clockPolicy':selected['clockPolicy'],
            'maximumProviderRequests':2,'privateStagePolicyId':'managed-oci-'+selected['runId'],
            **{name:selected['observed'][name] for name in ('namespaceObservation','nativeObservation',
                'nativeConfiguration','anchorOriginal','anchorReceipt','clocks')},
            'conformanceKeyFile':str(root/'materials/HUB_DIRECT_UPLOAD_CONFORMANCE_KEY'),
            'installed':{name:file(path) for name,path in selected['installed'].items()}}
        selection = root/'review-selection.json'
        fd = os.open(selection,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as output:
            json.dump(document,output,sort_keys=True,separators=(',',':'))
            output.flush()
            os.fsync(output.fileno())
        candidate = root/'candidate.json'
        result = subprocess.run([selected['reviewer'],'oci-sdk-prepare','--selection-file',str(selection),
            '--output',str(candidate)],stdin=subprocess.DEVNULL,capture_output=True,check=False,timeout=180)
        for name,body in (('prepare.stdout',result.stdout),('prepare.stderr',result.stderr)):
            fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as output:
                output.write(body)
                output.flush()
                os.fsync(output.fileno())
        if result.returncode:
            raise ValueError('Actual OCI shared-codec preparation refused')
        actual = file(str(candidate))
        if result.stdout.decode().strip()!=actual['sha256']:
            raise ValueError('Actual Rust candidate output differs from retained bytes')
        print(json.dumps({'selection':file(str(selection)),'candidate':actual,
            'scope':'unsigned shared-codec candidate; independent review and Worker consumption pending'}))
    """, {"root": coordinates["workerRoot"], "runId": coordinates["runId"],
        "reviewerId": prepared["reviewerKeyId"], "reviewerPublicFile": prepared["reviewerPublicFile"],
        "deployment": coordinates["deploymentId"], "publicOrigin": coordinates["workerOrigin"],
        "nativeOrigin": coordinates["nativeOrigin"],
        "sourceDigest": hashlib.sha256(tools["workerSourcePath"].encode()).hexdigest(),
        "sourceStorePath": tools["workerSourcePath"], "distributionStorePath": tools["workerDistribution"],
        "sourceNarSha256": artifacts["files"]["sourceNar"]["sha256"],
        "distributionNarSha256": artifacts["files"]["distributionNar"]["sha256"],
        "clockPolicy": prepared["clockPolicy"]["policy"], "observed": observed,
        "installed": installed, "reviewer": tools["reviewer"]}, timeout=220))


def install_managed_oci_candidate(native, worker, tools, prepared, observed, candidate, processes,
                                  *, activate_native=None):
    """Sign independently reviewed bytes, stage exact KV, then activate Native."""
    coordinates = prepared["coordinates"]
    candidate_body = read_direct_guest_file(worker, tools["python"], candidate["candidate"]["path"], 65536)
    require_managed_pair(hashlib.sha256(candidate_body).hexdigest() == candidate["candidate"]["sha256"],
            "Managed candidate changed before independent review")
    label = "managed-oci-" + coordinates["runId"]
    retain_direct_flow(label + "-candidate.json", candidate_body)
    hashes = {name: observed[name]["sha256"] for name in (
        "namespaceObservation", "nativeObservation", "nativeConfiguration", "anchorOriginal", "anchorReceipt")}
    hashes.update(candidateSha256=candidate["candidate"]["sha256"], selectionSha256=candidate["selection"]["sha256"])
    for number, clock in enumerate(observed["clocks"]):
        hashes.update({"clock" + str(number) + name: value["sha256"] for name, value in clock.items()})
    reviewed = await_direct_review(label, hashes, {"candidateSha256"})
    require_managed_pair(reviewed["selection"]["candidateSha256"] == candidate["candidate"]["sha256"],
            "Independent OCI review selected different candidate bytes")
    staged = json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, os, subprocess
        from pathlib import Path

        root = Path(selected['root'])
        def invoke(argv,label,timeout):
            result = subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,check=False,timeout=timeout)
            for suffix,body in (('stdout',result.stdout),('stderr',result.stderr)):
                fd=os.open(root/(label+'.'+suffix),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,'wb') as output:
                    output.write(body)
                    output.flush()
                    os.fsync(output.fileno())
            if result.returncode:
                raise ValueError('Managed shared-codec sign or staging refused; retain originals')
            return result.stdout
        artifact=root/'signed-acceptance.json'
        signed=invoke([selected['reviewer'],'oci-sdk-sign','--selection-file',selected['selection']['path'],
            '--candidate-file',selected['candidate']['path'],'--candidate-sha256',selected['candidate']['sha256'],
            '--reviewer-key-file',selected['privateKey'],'--reviewer-public-key-file',selected['publicKey'],
            '--output',str(artifact)],'sign',180).decode().strip()
        with artifact.open('rb') as stream:
            actual=hashlib.file_digest(stream,'sha256').hexdigest()
        if signed!=actual:
            raise ValueError('Actual OCI signer output differs from retained artifact')
        with open(selected['reviewer'],'rb') as stream:
            verifier_sha=hashlib.file_digest(stream,'sha256').hexdigest()
        receipt=json.loads(invoke([selected['python'],selected['installer'],
            '--socket-file',str(root/'control.sock'),'--namespace-report',selected['namespace']['path'],
            '--runner-executable',selected['node'],'--artifact-file',str(artifact),
            '--reviewer-tool',selected['reviewer'],'--public-key-file',selected['publicKey'],
            '--output-directory',str(root/'acceptance-staging'),'--artifact-sha256',actual,
            '--reviewer-tool-sha256',verifier_sha,'--reviewer-key-id',selected['reviewerId'],
            '--deployment-id',selected['deployment'],'--public-origin',selected['origin'],
            '--source-digest',selected['source'],'--script-version','emulated-'+selected['source']],
            'staging',60))
        if receipt['artifactSha256']!=actual or receipt['readbackSha256']!=actual:
            raise ValueError('Actual KV readback differs from selected signed bytes')
        print(json.dumps({'version':1,'artifact':{'path':str(artifact),'sha256':actual},
            'stagingReceipt':receipt,'verifierSha256':verifier_sha,
            'scope':'shared-codec verified byte staging; Worker business consumption pending'}))
    """, {"root": coordinates["workerRoot"], "selection": candidate["selection"],
        "candidate": candidate["candidate"], "privateKey": prepared["reviewerPrivateFile"],
        "publicKey": prepared["reviewerPublicFile"], "namespace": observed["namespaceObservation"],
        "reviewerId": prepared["reviewerKeyId"], "deployment": coordinates["deploymentId"],
        "origin": coordinates["workerOrigin"],
        "source": hashlib.sha256(tools["workerSourcePath"].encode()).hexdigest(),
        **{name: tools[name] for name in ("reviewer", "python", "node")},
        "installer": tools["ociInstaller"]}, timeout=260))
    artifact_body = read_direct_guest_file(worker, tools["python"], staged["artifact"]["path"], 32768)
    require_managed_pair(hashlib.sha256(artifact_body).hexdigest() == staged["artifact"]["sha256"],
            "Managed artifact changed during transfer")
    install_direct_guest_file(native, tools["python"], prepared["nativeFiles"]["acceptance"], artifact_body)
    activation = (activate_native or activate_managed_oci_native)(native, tools, prepared, processes)
    return {"artifactFile": staged["artifact"]["path"], "artifactSha256": staged["artifact"]["sha256"],
        "publicKeyFile": prepared["reviewerPublicFile"], "reviewerKeyId": prepared["reviewerKeyId"],
        "staging": staged, **activation,
        "independentReview": reviewed, "scope": "actual installation; business Worker verification pending"}


def activate_managed_oci_native(native, tools, prepared, processes):
    """Replace the isolated Native process with its explicitly verified configuration."""
    coordinates = prepared["coordinates"]
    stopped = stop_managed_native(native, tools, prepared, processes["native"])
    replacement = launch_managed_process(native, tools, coordinates["nativeRoot"], "native-accepted",
        managed_native_arguments(tools["hub"], coordinates, prepared["nativeFiles"], acceptance=True), {
            "AOS_HUB_SECRET_KEY_FILE": prepared["nativeFiles"]["seal"],
            "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
            "HUB_DNS_JSON_ENDPOINT": tools["managedDnsJsonEndpoint"], "HUB_OCI_PULL_ENABLED": "true",
            "HUB_OCI_PUSH_ENABLED": "true", "HUB_OCI_GC_ENABLED": "true",
        })
    readiness = await_managed_tls(native, tools, coordinates["nativeOrigin"])
    return {"nativeStop": stopped, "native": replacement, "nativeTls": readiness}


def stop_managed_native(native, tools, prepared, process):
    """Stop only this exact owned Native lifetime and retain its terminal pin."""
    return json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, select, signal
        from pathlib import Path

        expected=selected['process']
        proc=Path('/proc')/str(expected['pid'])
        fd=os.pidfd_open(expected['pid'])
        try:
            fields=(proc/'stat').read_text().rpartition(') ')[2].split()
            argv=(proc/'cmdline').read_bytes().split(b'\\x00')[:-1]
            with (proc/'exe').open('rb') as stream:
                executable=hashlib.file_digest(stream,'sha256').hexdigest()
            environment=(proc/'environ').read_bytes()
            if (fields[19]!=expected['startTicks'] or proc.stat().st_uid!=expected['ownerUid']
                    or argv!=[os.fsencode(value) for value in expected['arguments']]
                    or executable!=expected['executableSha256']
                    or hashlib.sha256(environment).hexdigest()!=expected['environmentSha256']):
                raise ValueError('Managed Native lifetime changed; do not signal')
            signal.pidfd_send_signal(fd,signal.SIGTERM)
            poll=select.poll()
            poll.register(fd,select.POLLIN)
            if not poll.poll(40000):
                raise ValueError('Managed Native stop unresolved; do not replace')
            receipt={'version':1,'pid':expected['pid'],'startTicks':expected['startTicks'],
                'signal':'SIGTERM','pidfdReadable':True,'scope':'owned process stopped; no provider settlement claim'}
            path=Path(selected['root'])/'native-stop.json'
            output_fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(output_fd,'w') as output:
                json.dump(receipt,output,sort_keys=True,separators=(',',':'))
                output.flush()
                os.fsync(output.fileno())
            print(json.dumps(receipt))
        finally:
            os.close(fd)
    """, {"root": prepared["coordinates"]["nativeRoot"], "process": process}, timeout=50))


def create_managed_database(database, tools, coordinates, native_address):
    """Create a fresh database through PostgreSQL and allow only its Native peer."""
    require_managed_pair(coordinates == managed_pair_coordinates(coordinates["runId"]),
            "Managed database coordinates changed")
    address = ipaddress.IPv4Address(native_address)
    require_managed_pair(address.is_private and not address.is_loopback, "Managed database peer differs")
    document = {"database": coordinates["database"], "address": str(address),
                "postgres": tools["postgres"]}
    return json.loads(direct_guest_python(database, tools["python"], """
        import hashlib, os, subprocess
        from pathlib import Path

        name = selected['database']
        psql = selected['postgres'] + '/psql'
        def sql(command):
            result = subprocess.run([psql, '-h', '127.0.0.1', '-U', 'postgres',
                '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '-Atc', command],
                capture_output=True, check=False, timeout=30)
            if result.returncode:
                raise ValueError('Managed database command refused; no automatic retry')
            return result.stdout
        if sql("SELECT 1 FROM pg_database WHERE datname='" + name + "'").strip():
            raise ValueError('Managed database already exists; never replace an original')
        sql('CREATE DATABASE ' + name)
        hba = Path('/var/lib/hybrid-postgres/pg_hba.conf')
        before = hba.read_bytes()
        line = ('host ' + name + ' postgres ' + selected['address'] + '/32 trust\\n').encode()
        # The local fixture's existing postgres role stays confined to this
        # newly created database and independently selected Native VM.
        with hba.open('ab') as output:
            output.write(line)
            output.flush()
            os.fsync(output.fileno())
        sql('SELECT pg_reload_conf()')
        present = sql("SELECT datname FROM pg_database WHERE datname='" + name + "'").strip()
        if present.decode() != name:
            raise ValueError('Managed database creation lacks actual readback')
        print(json.dumps({'version':1,'database':name,
            'beforeHbaSha256':hashlib.sha256(before).hexdigest(),
            'afterHbaSha256':hashlib.sha256(hba.read_bytes()).hexdigest(),
            'scope':'fresh local database only; no serving schema or capability asserted'}))
    """, document, timeout=100))


def launch_managed_process(machine, tools, root, label, arguments, environment, *, nginx_observation=None):
    """Start one recorded fixture child and retain actual argv and environment."""
    require_managed_pair(re.fullmatch(r"[a-z][a-z0-9-]{0,31}", label)
            and root.startswith("/var/lib/hybrid-")
            and all(part not in {"", ".", ".."} for part in root.split("/")[1:]),
            "Managed process custody root differs")
    require_managed_pair(isinstance(arguments, list) and arguments and arguments[0].startswith("/nix/store/")
            and isinstance(environment, dict) and not {"HOME", "home", "CODEX_HOME"} & set(environment),
            "Managed process requires explicit source-built executable and inherited home")
    if nginx_observation is not None:
        require_managed_pair(set(nginx_observation) == {
                    "invocationObservationMode", "expectedMasterTitle", "configurationFile", "configurationSha256"}
                and arguments[0] == tools["nginx"]
                and nginx_observation["invocationObservationMode"] == "nginx_linux_master_title"
                and re.fullmatch(r"[0-9a-f]{64}", nginx_observation["configurationSha256"])
                and arguments.count("-c") == 1
                and arguments[arguments.index("-c") + 1] == nginx_observation["configurationFile"]
                and nginx_observation["expectedMasterTitle"] == "nginx: master process " + " ".join(arguments),
                "Managed proxy must use its exact prepared source-built Nginx invocation")
    return json.loads(direct_guest_python(machine, tools["python"], """
        import hashlib, os, subprocess, time
        from pathlib import Path

        root = Path(selected['root'])
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        environment = dict(os.environ)
        environment.update(selected['environment'])
        log_path = root / (selected['label'] + '.log')
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as log:
            # Binding state and process-created materials stay with this owner.
            child = subprocess.Popen(selected['arguments'], env=environment,
                stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True, umask=0o077)
        time.sleep(0.2)
        if child.poll() is not None:
            raise ValueError('Managed process exited before observation; retain its log')
        proc = Path('/proc') / str(child.pid)
        stat_before = (proc / 'stat').read_text().rpartition(') ')[2].split()
        argv = (proc / 'cmdline').read_bytes()
        if len(argv) > 65536:
            raise ValueError('Managed command line exceeds its custody bound')
        nginx = selected['nginxObservation']
        if nginx is None:
            matches = argv.split(b'\\x00')[:-1] == [os.fsencode(v) for v in selected['arguments']]
        else:
            # Linux Nginx sets its master title and pads the remaining argv area
            # with NUL bytes. Keep the original invocation distinct from readback.
            title = nginx['expectedMasterTitle'].encode()
            padding = argv[len(title):]
            matches = argv.startswith(title) and bool(padding) and not padding.strip(b'\\x00')
            config = Path(nginx['configurationFile']).read_bytes()
            if hashlib.sha256(config).hexdigest() != nginx['configurationSha256']:
                raise ValueError('Managed prepared proxy configuration changed')
        if (proc.stat().st_uid != os.getuid() or not matches
                or (proc / 'exe').resolve() != Path(selected['arguments'][0]).resolve()):
            raise ValueError('Managed actual process does not match selected executable')
        with (proc / 'exe').open('rb') as source:
            executable_sha = hashlib.file_digest(source, 'sha256').hexdigest()
        observed_environment = (proc / 'environ').read_bytes()
        if len(observed_environment) > 65536:
            raise ValueError('Managed environment exceeds custody bound')
        record = {'version':1,'pid':child.pid,'ownerUid':proc.stat().st_uid,
            'startTicks':stat_before[19],'arguments':selected['arguments'],
            'executableSha256':executable_sha,'logFile':str(log_path),
            'environmentSha256':hashlib.sha256(observed_environment).hexdigest(),
            'commandLineSha256':hashlib.sha256(argv).hexdigest(),
            'commandLineBytes':str(len(argv)),
            'invocationObservationMode':'original_argv' if nginx is None else nginx['invocationObservationMode']}
        if nginx is not None:
            record.update(nginx)
        after = (proc / 'stat').read_text().rpartition(') ')[2].split()
        if after[19] != record['startTicks'] or after[0] == 'Z':
            raise ValueError('Managed process changed during observation')
        for name, body in ((selected['label']+'.environment', observed_environment),
                (selected['label']+'.cmdline', argv),
                (selected['label']+'.process.json', json.dumps(record,sort_keys=True).encode())):
            fd = os.open(root/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd,'wb') as output:
                output.write(body); output.flush(); os.fsync(output.fileno())
        print(json.dumps(record))
    """, {"root": root, "label": label, "arguments": arguments,
            "environment": environment, "nginxObservation": nginx_observation}, timeout=30))
