"""Configure the historical Worker proxy fleet for actual managed OCI writes.

The fixture keeps its production service, binding and API coordinates. Only its
local SDK provider configuration is added; the shared observation and signing
workflow still checks the installed binaries and live namespace before use.
"""

import copy
import hashlib
import json
import secrets
import shlex


def proxy_oci_configuration(original, tools, coordinates, materials):
    """Add the local OCI purpose without replacing existing transport roles."""
    configuration = copy.deepcopy(original)
    root = coordinates["workerRoot"]
    require_managed_pair(configuration["scriptPath"] == tools["shim"]
            and configuration["bindings"]["HUB_DEPLOYMENT_ID"] == coordinates["deploymentId"]
            and configuration["bindings"]["HUB_HYBRID_ORIGIN_URL"] == coordinates["nativeOrigin"],
            "Proxy OCI setup differs from the actual deployed fixture")
    configuration["r2Buckets"]["REGISTRY_BUCKET"] = coordinates["namespaceId"]
    configuration["durableObjects"]["HYBRID_DIRECT_UPLOAD"] = {
        "className": "HybridDirectUpload", "useSQLite": True,
    }
    configuration.setdefault("kvNamespaces", {})["HUB_OCI_SDK_EMULATOR_ACCEPTANCE"] = coordinates["namespaceId"] + "-oci"
    configuration.update({
        "acceptanceSocketPath": root + "/control.sock",
        "ociSdkNamespaceObservation": {
            "sourceStorePath": tools["workerSourcePath"], "wasmPath": tools["wasm"],
            "workerdPath": tools["workerd"],
        },
        "ociSdkAnchorEnabled": True,
        "ociSdkAcceptanceRegistryKey": materials["registryKey"],
    })
    bindings = configuration["bindings"]
    bindings.update({name: materials["roles"][name] for name in (
        "HUB_DIRECT_UPLOAD_GUARD_KEY", "HUB_DIRECT_UPLOAD_CONFORMANCE_KEY", "HUB_DIRECT_UPLOAD_JOURNAL_KEY")})
    bindings.update({
        "HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN": coordinates["workerOrigin"],
        "HUB_DIRECT_UPLOAD_MANAGED_R2": "false",
        "HUB_DIRECT_UPLOAD_QUALIFICATION_ENABLED": "true",
        "HUB_DIRECT_QUALIFY_MAX_PROVIDER_REQUESTS": "2",
        "HUB_DIRECT_QUALIFY_MAX_OBJECT_BYTES": "1024",
        "HUB_DIRECT_UPLOAD_CLOCK_MODE": "bounded_utc",
        "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS": materials["clockPolicy"]["policy"]["uncertaintySeconds"],
        "HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION": materials["clockPolicy"]["commitment"],
        "HUB_OCI_SDK_EMULATOR_ENABLED": "true",
        "HUB_OCI_SDK_EMULATOR_PUBLIC_ORIGIN": coordinates["workerOrigin"],
        "HUB_OCI_SDK_EMULATOR_REVIEWER_KEY_ID": "managed-oci-" + coordinates["runId"],
        "HUB_OCI_SDK_EMULATOR_REVIEWER_PUBLIC_KEY": materials["reviewerPublicKey"],
        "HUB_OCI_SDK_EMULATOR_MAX_PROVIDER_REQUESTS": "2",
    })
    return configuration


def prepare_proxy_oci(worker, native, tools, original_configuration):
    """Freeze fresh provider inputs before starting the selected Worker runner."""
    coordinates = managed_pair_coordinates(secrets.token_hex(16))
    original = json.loads(read_direct_guest_file(worker, tools["python"], original_configuration, 1024 * 1024))
    coordinates.update(deploymentId=original["bindings"]["HUB_DEPLOYMENT_ID"],
        workerOrigin="https://aos.fleet.test", nativeOrigin=original["bindings"]["HUB_HYBRID_ORIGIN_URL"],
        nativeRoot="/var/lib/aos-hub/proxy-oci-" + coordinates["runId"])
    materials = prepare_managed_oci_materials(worker, tools, coordinates)
    configuration = proxy_oci_configuration(original, tools, coordinates, materials)
    body = json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()
    configuration_file = coordinates["workerRoot"] + "/configuration.json"
    install_direct_guest_file(worker, tools["python"], configuration_file, body)
    root = coordinates["nativeRoot"]
    files = {"acceptance": root + "/acceptance.json", "reviewers": root + "/reviewers.json",
        "HUB_DIRECT_UPLOAD_GUARD_KEY": root + "/guard.key"}
    reviewer_id = "managed-oci-" + coordinates["runId"]
    install_direct_guest_file(native, tools["python"], files["reviewers"],
        json.dumps({reviewer_id: materials["reviewerPublicKey"]}).encode())
    install_direct_guest_file(native, tools["python"], files["HUB_DIRECT_UPLOAD_GUARD_KEY"],
        materials["roles"]["HUB_DIRECT_UPLOAD_GUARD_KEY"].encode())
    private_guest_command(native, shlex.join([tools["chown"], "-R", tools["nativeObserverUser"], root]))
    return {"coordinates": coordinates, "configurationFile": configuration_file,
        "configurationSha256": hashlib.sha256(body).hexdigest(), "nativeFiles": files,
        "reviewerKeyId": reviewer_id, "registryKey": materials["registryKey"],
        **{name: materials[name] for name in (
            "reviewerPublicKey", "reviewerPrivateFile", "reviewerPublicFile", "clockPolicy")}}


def activate_proxy_oci_native(native, tools, prepared, processes):
    """Activate the verified provider files on the existing production service."""
    files = prepared["nativeFiles"]
    result = json.loads(direct_guest_python(native, tools["python"], """
        import os, pwd, subprocess
        from pathlib import Path

        account = pwd.getpwnam(selected['user'])
        for path in selected['files'].values():
            os.chown(path, account.pw_uid, account.pw_gid)
        before = subprocess.run([selected['systemctl'], 'show', '-p', 'MainPID', '--value',
            'aos-hub.service'], capture_output=True, check=True, timeout=20).stdout.decode().strip()
        proc = Path('/proc')/before
        if (int(before) != selected['process']['pid']
                or (proc/'stat').read_text().rpartition(') ')[2].split()[19] != selected['process']['startTicks']
                or proc.stat().st_uid != selected['process']['ownerUid']
                or (proc/'exe').resolve(strict=True) != Path(selected['hub']).resolve(strict=True)):
            raise ValueError('Proxy Native lifetime changed before activation')
        directory = Path('/run/systemd/system/aos-hub.service.d')
        directory.mkdir(mode=0o755, parents=True, exist_ok=True)
        settings = {
            'HUB_OCI_SDK_EMULATOR_ACCEPTANCE_FILE': selected['files']['acceptance'],
            'HUB_OCI_SDK_EMULATOR_REVIEW_KEYS_FILE': selected['files']['reviewers'],
            'HUB_OCI_SDK_EMULATOR_GUARD_KEY_FILE': selected['files']['HUB_DIRECT_UPLOAD_GUARD_KEY'],
        }
        fd = os.open(directory/'oci-provider.conf', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as output:
            output.write('[Service]\\n')
            for name, value in settings.items():
                output.write('Environment="'+name+'='+value+'"\\n')
            output.flush()
            os.fsync(output.fileno())
        for arguments in (['daemon-reload'], ['restart', 'aos-hub.service']):
            subprocess.run([selected['systemctl'], *arguments], stdin=subprocess.DEVNULL,
                capture_output=True, check=True, timeout=60)
        print(json.dumps({'version': 1, 'previousPid': int(before), 'service': 'aos-hub.service'}))
    """, {"files": files, "user": tools["nativeObserverUser"], "systemctl": tools["systemctl"], "hub": tools["hub"],
        "process": processes["native"]}, timeout=150))
    readiness = wait_fixture_tls_response(native, tools["curl"], tools["python"],
        prepared["coordinates"]["nativeOrigin"] + "/-/health", "GET", {"401"},
        "proxy-oci-native-unsigned-refusal", 90)
    return {"nativeActivation": result, "nativeTls": readiness}


def qualify_proxy_oci(native, worker, tools, prepared, worker_process):
    """Review the actual namespace and binaries, then install the selected bytes."""
    # Native's startup queries the Worker. The boot-time attempt may have
    # stopped before the test started its Worker; observe a ready lifetime.
    private_guest_command(native, shlex.join([tools["systemctl"], "restart", "aos-hub.service"]), timeout=60)
    wait_fixture_tls_response(native, tools["curl"], tools["python"],
        prepared["coordinates"]["nativeOrigin"] + "/-/health", "GET", {"401"},
        "proxy-oci-native-startup", 90)
    native_process = json.loads(direct_guest_python(native, tools["python"], """
        import subprocess
        from pathlib import Path

        result = subprocess.run([selected['systemctl'], 'show', '-p', 'MainPID', '--value',
            'aos-hub.service'], capture_output=True, check=True, timeout=20)
        pid = int(result.stdout.decode().strip())
        if pid <= 0:
            raise ValueError('Proxy Native service has no running process')
        proc = Path('/proc')/str(pid)
        print(json.dumps({'pid': pid, 'startTicks': (proc/'stat').read_text().rpartition(') ')[2].split()[19],
            'ownerUid': proc.stat().st_uid}))
    """, {"systemctl": tools["systemctl"]}))
    processes = {"worker": worker_process, "native": native_process}
    observed = observe_managed_pair(native, worker, tools, prepared, processes)
    artifacts = json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, os, subprocess
        from pathlib import Path

        root = Path(selected['root'])
        files = {}
        for name, path in (('sourceNar', selected['source']), ('distributionNar', selected['distribution'])):
            target = root/(name+'.nar')
            fd = os.open(target, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as output:
                subprocess.run([selected['nixStore'], '--dump', path], stdin=subprocess.DEVNULL,
                    stdout=output, stderr=subprocess.PIPE, check=True, timeout=120)
                output.flush()
                os.fsync(output.fileno())
            with target.open('rb') as source:
                files[name] = {'path': str(target), 'sha256': hashlib.file_digest(source, 'sha256').hexdigest()}
        print(json.dumps({'files': files}))
    """, {"root": prepared["coordinates"]["workerRoot"], "source": tools["workerSourcePath"],
        "distribution": tools["workerDistribution"], "nixStore": tools["nixBin"] + "/nix-store"}, timeout=270))
    candidate = prepare_managed_oci_candidate(worker, tools, prepared, observed, artifacts)
    return install_managed_oci_candidate(native, worker, tools, prepared, observed, candidate, processes,
        activate_native=activate_proxy_oci_native)
