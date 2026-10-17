"""Join the installed audience refusal to real SQL and readonly observations.

The ordinary signed publication supplies the held original. These callbacks
read the selected database and live Worker; they issue no anchor or object
mutation and grant no permission. The profile fixture owns stop and restore.
"""

import hashlib
import json
import re


def managed_profile_original_sql(original, coordinates):
    """Select the actual held upload and its current physical placement pins."""
    admission = original.get("admission", {})
    upload_id = admission.get("upload_id")
    require_managed_pair(isinstance(upload_id, str)
        and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", upload_id)
        and admission.get("placement_prefix") == coordinates["gcPrefix"],
        "Held profile original escaped the actual selected upload scope")
    # SQL numeric IDs and revisions are read from these joined rows. A caller
    # cannot supply those facts through a parallel projection dictionary.
    projection = f"""
        SELECT json_build_object(
            'upload', row_to_json(upload),
            'chunk', row_to_json(chunk),
            'placement', row_to_json(placement),
            'binding', row_to_json(binding))::text
        FROM (
            SELECT id, registry_id, writer_id, token_id, idempotency_key,
                   expected_digest, expected_size, state, expires_at,
                   staging_placement_id, staging_placement_resource_version,
                   staging_binding_id, staging_binding_write_revision
            FROM oci_upload_sessions WHERE id = '{upload_id}'
        ) upload
        JOIN (
            SELECT upload_id, ordinal, byte_size, digest, staging_object_key
            FROM oci_upload_chunks WHERE ordinal = 0
        ) chunk ON chunk.upload_id = upload.id
        JOIN (
            SELECT id, registry_id, binding_id, prefix, resource_version
            FROM surface_placements
        ) placement ON placement.id = upload.staging_placement_id
            AND placement.registry_id = upload.registry_id
        JOIN (
            SELECT binding.id, binding.resource_version,
                   writer.current_write_revision AS write_revision
            FROM bindings binding
            JOIN binding_write_state writer ON writer.binding_id = binding.id
        ) binding ON binding.id = placement.binding_id
    """
    return projection


def capture_managed_profile_original(native, tools, prepared, original, held):
    """Retain one actual SELECT snapshot before the owner stops runner A."""
    nonce = original.get("nonce")
    require_managed_pair(isinstance(nonce, str) and re.fullmatch(r"[0-9a-f]{64}", nonce)
        and isinstance(held, dict) and re.fullmatch(r"[0-9a-f]{64}", held.get("requestSha256", "")),
        "Held profile original lacks its actual nonce and byte commitment")
    label = "profile-held-" + nonce[:16]
    sql = managed_fixture_module(tools["managedGcSql"], "managed_profile_sql_builder")
    query = sql.transaction(managed_profile_original_sql(original, prepared["coordinates"]),
        prepared["coordinates"]["database"])
    rows = capture_managed_gc_sql(native, tools, prepared, query, label)
    path = prepared["coordinates"]["nativeRoot"] + "/gc-observations/" + label + "/rows.private.json"
    raw = read_direct_guest_file(native, tools["python"], path, 512 * 1024)
    actual = json.loads(raw)
    require_managed_pair(actual == {"database": prepared["coordinates"]["database"], "value": rows},
        "Held profile SQL bytes differ from the consumed private projection")
    return {"file": path, "sha256": hashlib.sha256(raw).hexdigest(), "rows": rows}


def observe_managed_profile_worker(worker, tools, prepared, process, origin, configuration):
    """Retain actual TLS, signed Clock and namespace facts without SDK effects."""
    require_managed_pair(origin in {"https://localhost:4643", "https://localhost:4648"},
        "Profile observation origin differs from the two initial TLS listeners")
    root = prepared["coordinates"]["workerRoot"] + "/profile-observation-" + str(process["pid"])
    return json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, os, secrets, subprocess
        from pathlib import Path

        os.umask(0o077)
        root=Path(selected['root']); root.mkdir(mode=0o700,exist_ok=False)
        configuration=Path(selected['configuration']).read_bytes()
        config=json.loads(configuration)
        socket=config['acceptanceSocketPath']
        source=hashlib.sha256(selected['source'].encode()).hexdigest()
        identity=root/'identity.json'
        descriptor=os.open(identity,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(descriptor,'wb') as output:
            output.write(json.dumps({'sourceDigest':source,'scriptVersion':'emulated-'+source,
                'publicOrigin':selected['origin']}).encode())
            output.flush(); os.fsync(output.fileno())
        environment=dict(os.environ)
        environment['NODE_EXTRA_CA_CERTS']='/etc/ssl/certs/ca-certificates.crt'

        def invoke(arguments,label,timeout):
            result=subprocess.run(arguments,env=environment,stdin=subprocess.DEVNULL,
                capture_output=True,check=False,timeout=timeout)
            for suffix,body in (('stdout',result.stdout),('stderr',result.stderr)):
                if len(body)>262144: raise ValueError('Profile observation output exceeds bound')
                descriptor=os.open(root/(label+'.'+suffix),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(descriptor,'wb') as output:
                    output.write(body); output.flush(); os.fsync(output.fileno())
            if result.returncode:
                raise ValueError('Actual profile observation refused; do not replay')

        invoke([selected['curl'],'--silent','--show-error','--cacert',selected['ca'],
            '--noproxy','*','--request','POST','--output',str(root/'tls.body'),
            '--dump-header',str(root/'tls.headers'),selected['origin']+'/_internal/storage/v1/capabilities'],
            'tls',5)
        status=(root/'tls.headers').read_bytes().splitlines()[0].split()[1]
        if status!=b'401': raise ValueError('Profile actual TLS endpoint status differs')
        invoke([selected['node'],selected['driver'],'--phase','clock','--run-id',secrets.token_hex(32),
            '--origin',selected['origin'],'--control-key-file',selected['conformanceKey'],
            '--identity-file',str(identity),'--output-dir',str(root/'clock'),
            '--clock-uncertainty-seconds','1'],'clock',8)
        report=root/'namespace.json'
        invoke([selected['python'],selected['observer'],
            '--runner-pid',str(selected['process']['pid']),
            '--runner-start-ticks',selected['process']['startTicks'],
            '--socket-file',socket,'--node-file',selected['node'],
            '--runner-file',selected['runner'],'--workerd-file',selected['workerd'],
            '--configuration-file',selected['configuration'],'--source-store-path',selected['source'],
            '--miniflare-root',selected['miniflare'],'--identity-file',str(root/'clock/source-identity.json'),
            '--wasm-file',selected['wasm'],'--shim-file',selected['shim'],
            '--report-file',str(report)],'namespace',8)
        actual=json.loads(report.read_bytes())
        if actual['runnerPid']!=selected['process']['pid'] or actual['configurationSha256']!=hashlib.sha256(configuration).hexdigest():
            raise ValueError('Profile actual namespace/configuration join differs')
        print(json.dumps({'namespaceFile':str(report),'observation':{
            'sourceDigest':source,'scriptVersion':'emulated-'+source,
            'wasmSha256':actual['wasmSha256'],'runnerSha256':actual['runnerSha256'],
            'configurationSha256':actual['configurationSha256'],
            'pid':actual['runnerPid'],'origin':selected['origin']}}))
    """, {"root": root, "process": process, "configuration": configuration, "origin": origin,
        "ca": "/etc/ssl/certs/ca-certificates.crt", "curl": tools["curlBin"],
        "source": tools["workerSourcePath"], "driver": tools["qualificationDriver"],
        "observer": tools["ociNamespaceObserver"],
        "conformanceKey": prepared["coordinates"]["workerRoot"] + "/materials/HUB_DIRECT_UPLOAD_CONFORMANCE_KEY",
        **{name: tools[name] for name in ("python", "node", "runner", "workerd", "miniflare", "wasm", "shim")},
    }, timeout=30))
