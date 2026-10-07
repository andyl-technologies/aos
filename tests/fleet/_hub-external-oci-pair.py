"""Prepare the fresh ordinary bootstrap pair for controlled External OCI.

The same database, public origin and configured origins survive the later
explicit Native process switch. This preparation creates no accepted profile,
healthy placement or provider capability. Every key and persistence root belongs
to this fresh logical pair; the main workload's authority remains independent.
"""

import copy
import hashlib
import ipaddress
import json
import re
import shlex


EXTERNAL_OCI_PAIR_KEYS = (
    "HUB_STORAGE_WORK_KEY", "HUB_HYBRID_INGRESS_KEY",
    "HUB_DIRECT_UPLOAD_GUARD_KEY", "HUB_DIRECT_UPLOAD_CONFORMANCE_KEY",
    "HUB_DIRECT_UPLOAD_JOURNAL_KEY", "HUB_EXTERNAL_OBJECT_GUARD_KEY",
    "HUB_EXTERNAL_STAGE_KEY", "HUB_AUTHORITY_RENEWAL_KEY", "HUB_EXTERNAL_OCI_CANDIDATE_KEY",
)


def external_oci_pair_coordinates(run):
    """Name only the dedicated fixed listeners and new private resources."""
    if not isinstance(run, str) or re.fullmatch(r"[0-9a-f]{32}", run) is None:
        raise ValueError("External OCI pair run must be a fresh 32-hex identity")
    return {"version": 1, "runId": run, "publicOrigin": "https://localhost:4673",
        "controlOrigin": "https://localhost:4674", "listen": "127.0.0.1:4676",
        "nativeRoot": "/var/lib/hybrid-native/external-oci/" + run,
        "workerRoot": "/var/lib/hybrid-worker/external-oci/" + run,
        "clientRoot": "/var/lib/hybrid-client/external-oci/" + run,
        "databaseName": "fleet_external_" + run, "operatorRole": "fleet_external_operator_" + run,
        "placementPrefix": ".aos-direct-qualification/external-oci/" + run + "/registry"}


def external_oci_provider_prefix(bucket, binding_prefix, placement_prefix):
    """Compose the actual two key prefixes using the shared r2_key convention."""
    if (not isinstance(bucket, str) or re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,62}", bucket) is None
            or any(not isinstance(value, str) or not value or value.startswith("/")
                or any(part in {"", ".", ".."} for part in value.split("/"))
                for value in (binding_prefix, placement_prefix))):
        raise ValueError("External provider key coordinates differ")
    return "/" + bucket + "/" + binding_prefix.strip("/") + "/" + placement_prefix.lstrip("/") + "/"


def external_oci_initial_configuration(original, tools, coordinates, roles, clock_policy,
                                       reviewer_public_key):
    """Select one fresh Worker and fixed origins before physical observations."""
    if coordinates != external_oci_pair_coordinates(coordinates["runId"]):
        raise ValueError("External OCI initial coordinates changed")
    mirror = tools.get("mirrorFunctionalReviewer")
    role_names = EXTERNAL_OCI_PAIR_KEYS + (("HUB_MIRROR_GUARD_KEY",) if mirror is not None else ())
    if (set(roles) != set(role_names) or len(set(roles.values())) != len(roles)
            or any(not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
                for value in roles.values())):
        raise ValueError("External OCI roles are not independent fresh keys")
    if original["scriptPath"] != tools["shim"]:
        raise ValueError("External OCI pair changed the selected final Worker distribution")
    if not isinstance(reviewer_public_key, str) or re.fullmatch(r"[0-9a-f]{64}", reviewer_public_key) is None:
        raise ValueError("External Direct requires its actual selected independent reviewer")
    policy = clock_policy["policy"]
    if (policy != {"version": 1, "mode": "bounded_utc", "uncertaintySeconds": "1"}
            or re.fullmatch(r"[0-9a-f]{64}", clock_policy["commitment"]) is None):
        raise ValueError("External OCI clock differs from the selected shared policy encoder")
    root, run = coordinates["workerRoot"], coordinates["runId"]
    isolation_case = tools.get("copyIsolationCase", "same_worker")
    if isolation_case not in {"same_worker", "source_worker"}:
        raise ValueError("External Copy initial isolation case differs")
    source_worker = "fleet-external-oci-" + run
    if isolation_case == "source_worker":
        source_worker = "fleet-external-source-" + run
    copy_destination_prefix = coordinates["placementPrefix"]
    if isolation_case == "source_worker":
        copy_destination_prefix = coordinates["placementPrefix"].rsplit("/", 1)[0] + "/destination/registry"
    configuration = {name: copy.deepcopy(original[name]) for name in (
        "scriptPath", "compatibilityDate", "certificatePath", "privateKeyPath")}
    if "compatibilityFlags" in original:
        configuration["compatibilityFlags"] = copy.deepcopy(original["compatibilityFlags"])
    queue_names = {kind: "external-" + run + "-" + kind for kind in ("bulk", "metadata")}
    queue_options = {}
    for kind in queue_names:
        original_name = original["queueProducers"]["HUB_DIRECT_VERIFY_" + kind.upper()]
        queue_options[queue_names[kind]] = copy.deepcopy(original["queueConsumers"][original_name])
    queue_bindings = {name: value for name, value in original["bindings"].items()
        if name.startswith("HUB_DIRECT_VERIFY_") or name.startswith("HUB_DIRECT_QUALIFY_")}
    queue_bindings.update({"HUB_DIRECT_VERIFY_" + kind.upper() + "_NAME": name
        for kind, name in queue_names.items()})
    configuration.update({"name": "fleet-external-oci-" + run,
        "host": "127.0.0.1", "port": 4675, "resourcePersistencePath": root + "/state",
        "r2Buckets": {"REGISTRY_BUCKET": "external-oci-bootstrap-" + run},
        "durableObjects": {name: {"className": class_name, "useSQLite": True}
            for name, class_name in (
                ("HYBRID_OBJECT_GUARD", "HybridObjectGuard"),
                ("EXTERNAL_OBJECT_GUARD", "ExternalObjectGuard"),
                ("HYBRID_BINDING_STATE", "HybridBindingState"),
                ("HYBRID_DIRECT_UPLOAD", "HybridDirectUpload"))},
        "acceptanceSocketPath": root + "/control.sock",
        "queueObservationPath": root + "/queue-startup",
        "namespaceObservationPath": root + "/namespace-startup",
        "copyIsolationSelection": {"version": 1, "sourceWorkerName": source_worker},
        "copyIsolationModulePath": tools["externalCopyIsolation"],
        "kvNamespaces": {"HUB_DIRECT_UPLOAD_ACCEPTANCE": "external-direct-acceptance-" + run},
        "queueProducers": {"HUB_DIRECT_VERIFY_" + kind.upper(): name for kind, name in queue_names.items()},
        "queueConsumers": queue_options,
        "bindings": {**roles, **queue_bindings,
            "HUB_EXTERNAL_COPY_LIFETIME_OBSERVER": json.dumps({"version": 1, "capture_id": run,
                "source_prefix": coordinates["placementPrefix"], "destination_prefixes": [
                    (copy_destination_prefix if kind in {"replicate", "repair"}
                        else coordinates["placementPrefix"]) + "-" + kind + "-" + run
                    for kind in ("replicate", "repair", "cancel", "lost")]}, separators=(",", ":")),
            "HUB_TOPOLOGY": "hybrid",
            "HUB_DEPLOYMENT_ID": "fleet-external-oci-" + run,
            "HUB_EXTERNAL_URL": coordinates["publicOrigin"],
            "HUB_HYBRID_ORIGIN_URL": coordinates["controlOrigin"],
            "HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN": coordinates["publicOrigin"],
            "HUB_DIRECT_UPLOAD_MANAGED_R2": "false",
            "HUB_DIRECT_UPLOAD_QUALIFICATION_ENABLED": "true",
            "HUB_DIRECT_UPLOAD_QUALIFICATION_PUBLIC_KEY": reviewer_public_key,
            "HUB_DIRECT_UPLOAD_CLOCK_MODE": "bounded_utc",
            "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS": "1",
            "HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION": clock_policy["commitment"]}})
    if mirror is not None:
        if (set(mirror) != {"publicKey", "keyId"}
                or not isinstance(mirror["publicKey"], str)
                or re.fullmatch(r"[0-9a-f]{64}", mirror["publicKey"]) is None
                or mirror["publicKey"] == reviewer_public_key
                or not isinstance(mirror["keyId"], str)
                or re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}", mirror["keyId"]) is None
                or not tools.get("externalMirrorInstaller", "").startswith("/nix/store/")):
            raise ValueError("Mirror functional reviewer is not an independent initially selected role")
        configuration["externalMirrorInstallerPath"] = tools["externalMirrorInstaller"]
        configuration["kvNamespaces"]["HUB_EXTERNAL_MIRROR_FUNCTIONAL_ACCEPTANCE"] = "external-mirror-" + run
        configuration["bindings"].update({"HUB_EXTERNAL_MIRROR_FUNCTIONAL_PROBE": "1",
            "HUB_EXTERNAL_MIRROR_FUNCTIONAL_REVIEWER_PUBLIC_KEY": mirror["publicKey"],
            "HUB_EXTERNAL_MIRROR_FUNCTIONAL_REVIEWER_KEY_ID": mirror["keyId"]})
    return configuration


def external_oci_stock_arguments(hub, coordinates, files):
    """Serve ordinary Native at the helper's future address and stable inputs."""
    if coordinates != external_oci_pair_coordinates(coordinates["runId"]):
        raise ValueError("External OCI stock coordinates changed")
    return [hub, "--root", coordinates["nativeRoot"] + "/hub",
        "--database-url-file", files["database"], "serve", "--listen", coordinates["listen"],
        "--topology", "hybrid", "--external-url", coordinates["publicOrigin"],
        "--hybrid-worker-url", coordinates["publicOrigin"], "--hybrid-origin-url", coordinates["controlOrigin"],
        "--deployment-id", "fleet-external-oci-" + coordinates["runId"], "--reindex-interval", "0",
        "--release-receipt-key-id", "staging-publication-v1", "--release-receipt-key-file", files["release_seed"],
        "--channel-receipt-key-id", "staging-channel-v1", "--channel-receipt-key-file", files["channel_seed"],
        "--release-publication-keys-file", files["publication_keys"],
        "--qualification-keys-file", files["qualification_keys"],
        "--route-reservation-keys-file", files["route_keys"],
        "--hybrid-ingress-key-file", files["HUB_HYBRID_INGRESS_KEY"],
        "--storage-work-key-file", files["HUB_STORAGE_WORK_KEY"],
        "--jwt-secret-file", files["jwt"], "--secret-version-manifest-file", files["secrets"],
        "--domain-probe-signer-manifest-file", files["probeManifest"]]


def provision_external_oci_pair(native, worker, client, database, tools,
                               original_configuration, run, database_host, native_address,
                               worker_address, reviewer_public_key):
    """Initialize a fresh database and independent keys through ordinary init."""
    coordinates = external_oci_pair_coordinates(run)
    address = ipaddress.IPv4Address(native_address)
    worker_ip = ipaddress.IPv4Address(worker_address)
    if (not address.is_private or address.is_loopback or not worker_ip.is_private
            or worker_ip.is_loopback or worker_ip == address
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", database_host)):
        raise ValueError("External OCI database must use the actual separate peer VM")
    database_receipt = json.loads(direct_guest_python(database, tools["python"], """
        import hashlib, os, subprocess
        from pathlib import Path

        def sql(command):
            result=subprocess.run([selected['psql'],'-h','127.0.0.1','-U','postgres','-d','postgres',
                '-v','ON_ERROR_STOP=1','-Atc',command],capture_output=True,check=False,timeout=30)
            if result.returncode: raise ValueError('Fresh External database command refused')
            return result.stdout
        name=selected['database']
        if sql("SELECT 1 FROM pg_database WHERE datname='"+name+"'").strip():
            raise ValueError('External database already exists; preserve it')
        sql('CREATE DATABASE '+name)
        hba=Path('/var/lib/hybrid-postgres/pg_hba.conf'); before=hba.read_bytes()
        with hba.open('ab') as output:
            output.write(('host '+name+' postgres '+selected['address']+'/32 trust\\n').encode())
            output.write(('host '+name+' '+selected['operatorRole']+' '+selected['workerAddress']+
                '/32 scram-sha-256\\n').encode())
            output.flush(); os.fsync(output.fileno())
        sql('SELECT pg_reload_conf()')
        if sql("SELECT datname FROM pg_database WHERE datname='"+name+"'").strip().decode()!=name:
            raise ValueError('Fresh External database readback differs')
        print(json.dumps({'version':1,'database':name,'beforeHbaSha256':hashlib.sha256(before).hexdigest(),
            'afterHbaSha256':hashlib.sha256(hba.read_bytes()).hexdigest()}))
    """, {"database": coordinates["databaseName"], "address": str(address),
        "workerAddress": str(worker_ip), "operatorRole": coordinates["operatorRole"],
        "psql": tools["postgres"] + "/psql"}, timeout=100))
    material = json.loads(direct_guest_python(worker, tools["python"], """
        import base64, os, secrets, subprocess
        from pathlib import Path

        os.umask(0o077)
        root=Path(selected['root']); root.mkdir(mode=0o700,parents=True,exist_ok=False)
        materials=root/'materials'; materials.mkdir(mode=0o700)
        roles={name:secrets.token_hex(32) for name in selected['roles']}
        if len(set(roles.values()))!=len(roles): raise ValueError('External role entropy collided')
        for name,value in roles.items():
            descriptor=os.open(materials/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(descriptor,'w') as output:
                output.write(value); output.flush(); os.fsync(output.fileno())
        result=subprocess.run([selected['reviewer'],'oci-sdk-fixture-key',
            '--private-output',str(materials/'probe.seed'),'--public-output',str(materials/'probe.hex')],
            capture_output=True,check=False,timeout=30)
        if result.returncode: raise ValueError('External independent probe key derivation refused')
        seed=(materials/'probe.seed').read_bytes(); public=(materials/'probe.hex').read_text().strip()
        if len(seed)!=32 or len(bytes.fromhex(public))!=32: raise ValueError('Probe key shape differs')
        clock=subprocess.run([selected['reviewer'],'clock-policy','--uncertainty-seconds','1'],
            capture_output=True,check=False,timeout=30)
        if clock.returncode: raise ValueError('External shared clock policy encoder refused')
        print(json.dumps({'roles':roles,'probePublicKey':base64.urlsafe_b64encode(bytes.fromhex(public)).decode().rstrip('='),
            'clockPolicy':json.loads(clock.stdout),
            'probeManifest':[{'endpointId':'external-endpoint-'+selected['run'],'endpointGeneration':1,
                'signerSecretRef':'external-probe-'+selected['run'],
                'signingSeed':base64.urlsafe_b64encode(seed).decode().rstrip('=')}]}))
    """, {"root": coordinates["workerRoot"], "run": run,
        "roles": EXTERNAL_OCI_PAIR_KEYS + (("HUB_MIRROR_GUARD_KEY",)
            if tools.get("mirrorFunctionalReviewer") is not None else ()),
        "reviewer": tools["reviewer"]}, timeout=40))
    original = json.loads(read_direct_guest_file(worker, tools["python"], original_configuration, 1024 * 1024))
    configuration = external_oci_initial_configuration(original, tools, coordinates,
        material["roles"], material["clockPolicy"], reviewer_public_key)
    body = json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()
    configuration_file = coordinates["workerRoot"] + "/configuration-bootstrap.json"
    install_direct_guest_file(worker, tools["python"], configuration_file, body)
    files = {name: coordinates["nativeRoot"] + "/materials/" + name for name in material["roles"]}
    files.update({"database": coordinates["nativeRoot"] + "/materials/database.url",
        "jwt": coordinates["nativeRoot"] + "/materials/jwt.key", "seal": coordinates["nativeRoot"] + "/materials/seal.key",
        "secrets": coordinates["nativeRoot"] + "/materials/secrets.json",
        "probeManifest": coordinates["nativeRoot"] + "/materials/probe-manifest.json",
        "certificate": tools["issuerCertificate"], "privateKey": tools["issuerPrivateKey"]})
    for name, value in material["roles"].items():
        install_direct_guest_file(native, tools["python"], files[name], value.encode())
    for name in ("release_seed", "channel_seed", "publication_keys", "qualification_keys", "route_keys"):
        files[name] = coordinates["nativeRoot"] + "/materials/" + name
        install_direct_guest_file(native, tools["python"], files[name],
            read_direct_guest_file(native, tools["python"], tools["parityFixture"][name], 65536))
    install_direct_guest_file(native, tools["python"], files["database"],
        ("postgresql://postgres@" + database_host + ":5432/" + coordinates["databaseName"] + "\n").encode())
    install_direct_guest_file(native, tools["python"], files["probeManifest"],
        json.dumps(material["probeManifest"], separators=(",", ":")).encode())
    install_direct_guest_file(native, tools["python"], files["secrets"], b"{}\n")
    initialized = json.loads(direct_guest_python(native, tools["python"], """
        import os, secrets, subprocess
        from pathlib import Path

        os.umask(0o077)
        for name in ('jwt','seal'):
            descriptor=os.open(selected['files'][name],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(descriptor,'w') as output:
                output.write(secrets.token_hex(32)); output.flush(); os.fsync(output.fileno())
        environment=dict(os.environ)
        environment.update(HUB_DATABASE_URL_FILE=selected['files']['database'],AOS_HUB_SECRET_KEY_FILE=selected['files']['seal'])
        arguments=[selected['hub'],'--root',selected['root']+'/hub','init',
            '--root-email','fleet-root@example.test','--root-password','fleet-root-password']
        result=subprocess.run(arguments,env=environment,stdin=subprocess.DEVNULL,capture_output=True,check=False,timeout=180)
        for name,body in (('init.stdout',result.stdout),('init.stderr',result.stderr)):
            descriptor=os.open(Path(selected['root'])/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(descriptor,'wb') as output:
                output.write(body); output.flush(); os.fsync(output.fileno())
        if result.returncode: raise ValueError('Ordinary External pair init refused; preserve database and logs')
        print(json.dumps({'version':1,'exitCode':result.returncode}))
    """, {"files": files, "root": coordinates["nativeRoot"], "hub": tools["hub"]}, timeout=200))
    direct_guest_python(client, tools["python"], """
        import os
        from pathlib import Path
        os.umask(0o077)
        Path(selected['root']).mkdir(mode=0o700,parents=True,exist_ok=False)
    """, {"root": coordinates["clientRoot"]})
    return {"coordinates": coordinates, "configurationFile": configuration_file,
        "configurationSha256": hashlib.sha256(body).hexdigest(), "nativeFiles": files,
        "databaseReceipt": database_receipt, "initialization": initialized,
        "clockPolicy": material["clockPolicy"],
        "probePublicKey": material["probePublicKey"], "probeManifest": material["probeManifest"]}


def prepare_external_oci_boundaries(native, worker, tools, prepared,
                                   native_address, worker_address):
    """Prepare exact dedicated templates before either process is observed."""
    coordinates = prepared["coordinates"]
    if coordinates != external_oci_pair_coordinates(coordinates["runId"]):
        raise ValueError("External OCI boundary coordinates changed")
    addresses = {"native": ipaddress.IPv4Address(native_address),
        "worker": ipaddress.IPv4Address(worker_address)}
    if (addresses["native"] == addresses["worker"] or any(
            not address.is_private or address.is_loopback for address in addresses.values())):
        raise ValueError("External OCI proxies require separate actual private peers")
    roots = {"nativeInbound": coordinates["nativeRoot"] + "/inbound",
        "nativeOutbound": coordinates["nativeRoot"] + "/outbound",
        "workerBoundary": coordinates["workerRoot"] + "/boundary",
        "workerNativeOutbound": coordinates["workerRoot"] + "/native-outbound"}
    result = {"version": 1, "run": coordinates["runId"], "roots": roots,
        "nativeAddress": str(addresses["native"]), "workerAddress": str(addresses["worker"])}
    for role, machine, primary, additional in (
            ("native", native, "nativeInbound", "nativeOutbound"),
            ("worker", worker, "workerBoundary", "workerNativeOutbound")):
        reference = tools["externalOci" + role.title() + "ProxyTemplate"]
        body = managed_proxy_template_bytes(reference).decode()
        if "@EXTERNAL_RUN@" not in body:
            raise ValueError("External OCI template does not select independent roots")
        for token, value in (("@EXTERNAL_RUN@", coordinates["runId"]),
                ("@EXTERNAL_NATIVE_ADDRESS@", str(addresses["native"])),
                ("@EXTERNAL_WORKER_ADDRESS@", str(addresses["worker"]))):
            body = body.replace(token, value)
        if "@EXTERNAL_" in body:
            raise ValueError("External OCI template remains unresolved")
        path = coordinates[role + "Root"] + "/proxy-template.conf"
        install_direct_guest_file(machine, tools["python"], path, body.encode())
        result[role + "Proxy"] = start_direct_boundary_proxy(machine, tools,
            roots[primary], path, [roots[additional]], prepare_only=True)
    return result


def await_external_oci_tls(machine, tools, origin):
    """Require an actual fixed-origin TLS response, without claiming admission."""
    if origin not in {"https://localhost:4673", "https://localhost:4674"}:
        raise ValueError("External OCI readiness targets another origin")
    worker = origin.endswith(":4673")
    return json.loads(direct_guest_python(machine, tools["python"], """
        import subprocess, time

        observations=[]
        deadline=time.monotonic()+60
        while True:
            result=subprocess.run(selected['curl']+[
                '--silent','--show-error','--max-time','3','--output','/dev/null',
                '--write-out','%{http_code}','--request',selected['method'],selected['url']],
                stdin=subprocess.DEVNULL,capture_output=True,check=False,timeout=5)
            status=result.stdout.decode('ascii').strip()
            observations.append({'exitCode':result.returncode,'httpStatus':status})
            if result.returncode==0 and status==selected['status']:
                print(json.dumps({'version':1,'status':int(status),'observations':observations,
                    'scope':'actual TLS response; no business or provider qualification'}))
                break
            if len(observations)>=64 or time.monotonic()>=deadline:
                raise ValueError('Dedicated External TLS listener did not become ready')
            time.sleep(1)
    """, {"curl": shlex.split(tools["curl"]), "url": origin + (
        "/_internal/storage/v1/capabilities" if worker else "/-/health"),
        "method": "POST" if worker else "GET", "status": "401" if worker else "200"}, timeout=75))


def start_external_oci_pair(native, worker, client, tools, prepared, boundaries, *, ownership=None):
    """Launch the stock bootstrap processes at the later helper's fixed origins."""
    coordinates = prepared["coordinates"]
    if coordinates != external_oci_pair_coordinates(coordinates["runId"]):
        raise ValueError("External OCI startup coordinates changed")
    address = ipaddress.IPv4Address(boundaries["workerAddress"])
    if not address.is_private or address.is_loopback:
        raise ValueError("External OCI client forward targets another peer")
    forward = launch_managed_process(client, tools, coordinates["clientRoot"], "worker-forward", [
        tools["socat"], "TCP-LISTEN:4673,bind=127.0.0.1,reuseaddr,fork",
        "TCP:" + str(address) + ":4673"], {})
    if ownership is not None:
        ownership["forwards"] = [forward]
    closed_loss = install_external_copy_closed_loss(worker, tools, prepared, ownership=ownership)
    prepared["copyClosedLoss"] = closed_loss
    proxies = {}
    for role, machine in (("native", native), ("worker", worker)):
        selected = boundaries[role + "Proxy"]
        observation = {name: selected[name] for name in (
            "configurationFile", "configurationSha256", "invocationObservationMode", "expectedMasterTitle")}
        proxies[role] = launch_managed_process(machine, tools, coordinates[role + "Root"],
            "boundary", selected["invocationArguments"], {}, nginx_observation=observation)
        if ownership is not None:
            ownership.setdefault("processes", {})[role + "Proxy"] = proxies[role]
    trust = "/etc/ssl/certs/ca-certificates.crt"
    worker_process = launch_managed_process(worker, tools, coordinates["workerRoot"], "worker-bootstrap", [
        tools["node"], tools["runner"], tools["miniflare"], prepared["configurationFile"]], {
            "NODE_EXTRA_CA_CERTS": trust, "SSL_CERT_FILE": trust,
            "MINIFLARE_WORKERD_PATH": tools["workerd"]})
    worker_process = {**worker_process, "configurationFile": prepared["configurationFile"],
        "configurationSha256": prepared["configurationSha256"], "generation": "external-bootstrap"}
    if ownership is not None:
        ownership.setdefault("processes", {})["worker"] = worker_process
    worker_ready = await_external_oci_tls(native, tools, coordinates["publicOrigin"])
    native_process = launch_managed_process(native, tools, coordinates["nativeRoot"], "native-bootstrap",
        external_oci_stock_arguments(tools["hub"], coordinates, prepared["nativeFiles"]), {
            "AOS_HUB_SECRET_KEY_FILE": prepared["nativeFiles"]["seal"], "SSL_CERT_FILE": trust,
            "HUB_DNS_JSON_ENDPOINT": tools["managedDnsJsonEndpoint"],
            "HUB_OCI_PULL_ENABLED": "true", "HUB_OCI_PUSH_ENABLED": "true", "HUB_OCI_GC_ENABLED": "true"})
    if ownership is not None:
        ownership.setdefault("processes", {})["native"] = native_process
    native_ready = await_external_oci_tls(native, tools, coordinates["controlOrigin"])
    return {"native": native_process, "worker": worker_process,
        "nativeProxy": proxies["native"], "workerProxy": proxies["worker"],
        "forwards": [forward], "workerTls": worker_ready, "nativeTls": native_ready,
        "scope": "ordinary fresh bootstrap pair; External business admission pending"}


def observe_external_oci_pair(worker, tools, prepared, processes, label):
    """Retain real protected Clock replies and the selected live guard namespace."""
    if label not in {"bootstrap", "installed", "final", "mirror-functional"}:
        raise ValueError("External OCI observation phase differs")
    coordinates = prepared["coordinates"]
    root = coordinates["workerRoot"] + "/observations-" + label
    source = hashlib.sha256(tools["workerSourcePath"].encode()).hexdigest()
    identity_path = root + "/selected-source.json"
    install_direct_guest_file(worker, tools["python"], identity_path, json.dumps({
        "sourceDigest": source, "scriptVersion": "emulated-" + source,
        "publicOrigin": coordinates["publicOrigin"]}, separators=(",", ":")).encode())
    clocks = json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, os, secrets, subprocess
        from pathlib import Path

        root=Path(selected['root'])
        environment=dict(os.environ)
        environment['NODE_EXTRA_CA_CERTS']='/etc/ssl/certs/ca-certificates.crt'
        clocks=[]
        for ordinal in range(2):
            output=root/('clock-'+str(ordinal))
            arguments=[selected['node'],selected['driver'],'--phase','clock',
                '--run-id',secrets.token_hex(32),'--origin',selected['origin'],
                '--control-key-file',selected['conformanceKey'],'--identity-file',selected['identity'],
                '--output-dir',str(output),'--clock-uncertainty-seconds','1']
            result=subprocess.run(arguments,env=environment,stdin=subprocess.DEVNULL,
                capture_output=True,check=False,timeout=40)
            for suffix,body in (('stdout',result.stdout),('stderr',result.stderr)):
                descriptor=os.open(root/('clock-'+str(ordinal)+'.'+suffix),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(descriptor,'wb') as destination:
                    destination.write(body); destination.flush(); os.fsync(destination.fileno())
            if result.returncode:
                raise ValueError('Fresh External protected Clock refused; retain original attempt')
            refs={}
            for name,leaf in (('request','request'),('reply','capture'),('authentication','authentication')):
                path=output/('00001-clock-'+leaf+'.json')
                body=path.read_bytes()
                if not 0<len(body)<=65536: raise ValueError('Fresh External Clock exceeds bound')
                refs[name]={'file':str(path),'sha256':hashlib.sha256(body).hexdigest(),'byteSize':str(len(body))}
            clocks.append(refs)
        print(json.dumps(clocks))
    """, {"root": root, "node": tools["node"], "driver": tools["qualificationDriver"],
        "origin": coordinates["publicOrigin"], "identity": identity_path,
        "conformanceKey": coordinates["workerRoot"] + "/materials/HUB_DIRECT_UPLOAD_CONFORMANCE_KEY"}, timeout=100))
    namespace = direct_namespace_readback(worker, tools["python"], processes["worker"],
        socket_file=coordinates["workerRoot"] + "/control.sock", namespace_kind="external_copy")
    namespace_path = root + "/namespace.json"
    namespace_ref = install_direct_guest_file(worker, tools["python"], namespace_path,
        json.dumps(namespace, sort_keys=True, separators=(",", ":")).encode())
    return {"version": 1, "clocks": clocks, "namespace": namespace, "namespaceFile": namespace_ref,
        "worker": processes["worker"], "scope": "actual source/Clock/namespace observations; no qualification"}


def external_oci_controls(client, tools, prepared):
    """Authenticate the new authority through its unchanged ordinary public API."""
    coordinates = prepared["coordinates"]
    root = coordinates["clientRoot"] + "/browser-session"

    def refresh():
        return direct_root_browser_token(client, tools["curl"], tools["python"], private_guest_command,
            reuse_session=True, origin=coordinates["publicOrigin"], evidence_root=root)

    token = direct_root_browser_token(client, tools["curl"], tools["python"], private_guest_command,
        origin=coordinates["publicOrigin"], evidence_root=root)
    return DirectBootstrapControls(client, tools["curl"], tools["python"], token,
        private_guest_command, refresh_token=refresh, origin=coordinates["publicOrigin"],
        evidence_root=coordinates["clientRoot"] + "/controls"), refresh
