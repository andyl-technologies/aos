"""Call the bounded pack window inside the genuine same-Worker Mirror pair.

The ordinary publication interval finishes before this supplemental caller.
Initial candidate material comes from the selected Core encoder, admissions
come from the current SQL-backed Native producer, and source controls travel
only over the driver's existing serialized guest channel. An unknown exact
whole-isolate allocation is reported separately from functional outcomes.
"""

import base64
import hashlib
import json
import re
import shlex
import time


PACK_MEMORY_CASES = ("semantic32", "live36", "replacement-overflow")
PACK_MEMORY_MATERIAL_SELECTOR = (
    "storage_work::external_oci::tests::fleet::pack_memory::actual_pack_memory_candidate_material")
PACK_MEMORY_CONSUMER_SELECTOR = (
    "storage_work::external_oci::tests::fleet::pack_memory::actual_pack_memory_native_consumer")

PACK_MEMORY_PUBLIC_BINDINGS = (
    "HUB_DEPLOYMENT_ID", "HUB_DIRECT_UPLOAD_MANAGED_R2", "HUB_MIRROR_CANDIDATE_SOURCE_SHA256",
    "HUB_MIRROR_CANDIDATE_SCRIPT_VERSION", "HUB_DIRECT_UPLOAD_CLOCK_MODE",
    "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS", "HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION",
    "HUB_DIRECT_UPLOAD_R2_ACCOUNT_ID", "HUB_DIRECT_UPLOAD_R2_BUCKET_NAME",
    "HUB_DIRECT_UPLOAD_R2_BUCKET_NAMESPACE", "HUB_DIRECT_UPLOAD_R2_CREDENTIAL_ID",
    "HUB_DIRECT_UPLOAD_R2_CREDENTIAL_GENERATION", "HUB_DIRECT_UPLOAD_R2_SECRET_VERSION_REF",
    "HUB_DIRECT_UPLOAD_R2_CHECKSUM", "HUB_DIRECT_UPLOAD_R2_PRIVATE_POLICY_ID",
    "HUB_DIRECT_UPLOAD_R2_PRIVATE_POLICY_DIGEST")


def pack_memory_public_projection(configuration):
    """Select public coordinates; never fingerprint full bindings or keys."""
    values = {name: configuration["bindings"][name] for name in PACK_MEMORY_PUBLIC_BINDINGS
        if name in configuration["bindings"]}
    if any(not isinstance(value, str) for value in values.values()):
        raise ValueError("candidate public projection has a nonstring binding")
    return {"version": 1, "bindings": values,
        "r2BucketNamespace": configuration["r2Buckets"]["REGISTRY_BUCKET"]}


def install_pack_memory_opaque_configuration(native, tools, path, configuration):
    """Move SDK input privately with file custody and no secret-content digest."""
    raw = json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > 256 * 1024:
        raise ValueError("candidate opaque configuration exceeds its fixed bound")
    return json.loads(direct_guest_python(native, tools["python"], """
        import os, stat
        from pathlib import Path
        os.umask(0o077)
        path=Path(selected['path']); path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        body=base64.b64decode(selected['body'],validate=True)
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(body); stream.flush(); os.fsync(stream.fileno())
            metadata=os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=os.getuid() \
                or stat.S_IMODE(metadata.st_mode)!=0o600 or metadata.st_nlink!=1:
            raise ValueError('opaque candidate configuration custody differs')
        print(json.dumps({'file':str(path),'custody':{'ownerUid':metadata.st_uid,
            'mode':'0600','nlink':str(metadata.st_nlink),'device':str(metadata.st_dev),
            'inode':str(metadata.st_ino),'bytes':str(metadata.st_size),
            'modifiedSeconds':str(metadata.st_mtime_ns//1000000000),
            'modifiedNanos':str(metadata.st_mtime_ns%1000000000),
            'changedSeconds':str(metadata.st_ctime_ns//1000000000),
            'changedNanos':str(metadata.st_ctime_ns%1000000000)}}))
    """, {"path": path, "body": base64.b64encode(raw).decode()}))


def pack_memory_reference(reference):
    """Normalize measured transport counts without changing their commitment."""
    return {"file": reference["file"], "sha256": reference["sha256"],
        "bytes": reference["byteSize"]}


def prepare_pack_memory_initial_material(native, tools, coordinates, configuration):
    """Encode the genuine initial candidate profile before its runner exists."""
    root = coordinates["nativeRoot"] + "/pack-memory/materials"
    source = install_pack_memory_opaque_configuration(native, tools,
        root + "/source-configuration.json", configuration)
    provenance = json.loads(read_direct_guest_file(native, tools["python"],
        tools["managedCleanupNativeHelperProvenance"], 65536))
    if (provenance["commonSourceStorePath"] != tools["commonSourceStorePath"]
            or provenance["workerFilteredSourceStorePath"] != tools["workerSourcePath"]):
        raise ValueError("candidate material encoder differs from the final common source")
    result = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, stat, subprocess, time
        from pathlib import Path

        os.umask(0o077)
        root=Path(selected['root'])
        cutoff=time.monotonic()+25
        output=root/'material.json'
        selection={
            'version':1,'configurationFile':selected['source']['file'],
            'configurationCustody':selected['source']['custody'],
            'expectedExecutableSha256':selected['executableSha256'],
            'expectedWorkerSourceDigest':selected['sourceDigest'],
            'expectedWorkerScriptVersion':'emulated-'+selected['sourceDigest'],
            'outputFile':str(output),'cutoffUnixSeconds':int(time.time())+25}
        selection_file=root/'material-selection.json'
        with selection_file.open('xb') as stream:
            stream.write(json.dumps(selection,separators=(',',':')).encode())
            stream.flush(); os.fsync(stream.fileno())
        environment=dict(os.environ,AOS_PACK_MEMORY_SELECTION=str(selection_file))
        process=None; primary=None; reaped=None; actual_exit=None
        stdout=(root/'material.stdout').open('xb')
        stderr=(root/'material.stderr').open('xb')
        try:
            os.fchmod(stdout.fileno(),0o600); os.fchmod(stderr.fileno(),0o600)
            process=subprocess.Popen([selected['executable'],selected['selector'],
                '--exact','--ignored','--nocapture'],env=environment,
                stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr)
            actual_exit=process.wait(timeout=max(0.001,cutoff-3-time.monotonic()))
            reaped=time.monotonic()<cutoff
            if actual_exit:
                raise ValueError('actual candidate material encoder refused; retain private output')
        except BaseException as error:
            primary=error
        finally:
            if process is not None and reaped is not True:
                remaining=max(0,cutoff-time.monotonic())
                if remaining>0:
                    try:
                        if process.poll() is None: process.terminate()
                        actual_exit=process.wait(timeout=remaining/2)
                        reaped=time.monotonic()<cutoff
                    except subprocess.TimeoutExpired:
                        try:
                            if process.poll() is None: process.kill()
                            actual_exit=process.wait(timeout=max(0,cutoff-time.monotonic()))
                            reaped=time.monotonic()<cutoff
                        except subprocess.TimeoutExpired:
                            reaped=None
                    except ProcessLookupError:
                        reaped=None
            for stream in (stdout,stderr):
                for action in (stream.flush,lambda:os.fsync(stream.fileno()),stream.close):
                    try: action()
                    except BaseException as error:
                        if primary is None: primary=error
                        else: primary.add_note('material output cleanup failed: '+type(error).__name__)
            disposition={'version':1,'pid':None if process is None else process.pid,
                'actualExitCode':actual_exit,'childReaped':reaped,
                'failureClass':None if primary is None else type(primary).__name__,
                'originalCutoffMonotonic':cutoff,'finishedMonotonic':time.monotonic()}
            try:
                fd=os.open(root/'material-process.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'w') as stream:
                    json.dump(disposition,stream); stream.flush(); os.fsync(stream.fileno())
            except BaseException as error:
                if primary is None: primary=error
                else: primary.add_note('material disposition retention failed: '+type(error).__name__)
        if primary is not None: raise primary
        if reaped is not True: raise RuntimeError('material child retirement unknown')
        fd=os.open(output,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1 \
                    or before.st_mode&0o077 or before.st_size>65536:
                raise ValueError('actual material output custody differs')
            raw=stream.read(65537); after=os.fstat(stream.fileno())
        if len(raw)!=before.st_size or any(getattr(before,k)!=getattr(after,k)
                for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')):
            raise ValueError('actual material output changed')
        material=json.loads(raw)
        # The selected Rust encoder returns no credential or candidate-key bytes.
        print(json.dumps({'result':material,'reference':{'file':str(output),
            'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},
            'actualExitCode':actual_exit,'childReaped':reaped}))
    """, {"root": root, "source": source,
        "executable": tools["managedCleanupNativeHelper"], "selector": PACK_MEMORY_MATERIAL_SELECTOR,
        "executableSha256": provenance["testExecutableSha256"],
        "sourceDigest": hashlib.sha256(tools["workerSourcePath"].encode()).hexdigest()}, timeout=30))
    encoded = result["result"]
    projection = encoded["bindingProjection"]
    allowed = {"HUB_DIRECT_UPLOAD_R2_PRIVATE_POLICY_DIGEST", "HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION"}
    if (set(projection) != allowed
            or encoded["nativeExecutableSha256"] != provenance["testExecutableSha256"]
            or encoded["configurationCustody"] != source["custody"]
            or result["childReaped"] is not True or result["actualExitCode"] != 0
            or encoded["runtimeAcceptance"] is not None or encoded["providerObservation"] is not None):
        raise ValueError("actual candidate material projection joins another source")
    updated = json.loads(json.dumps(configuration))
    for name, value in projection.items():
        if name in updated["bindings"] and updated["bindings"][name] != value:
            raise ValueError("candidate encoder changed an already selected commitment")
        updated["bindings"][name] = value
    public = pack_memory_public_projection(updated)
    if (set(public["bindings"]) != set(PACK_MEMORY_PUBLIC_BINDINGS)
            or encoded["publicConfiguration"] != public):
        raise ValueError("candidate public projection omits an installed coordinate")
    public_reference = pack_memory_reference(install_direct_guest_file(native, tools["python"],
        root + "/public-configuration.json", json.dumps(public, separators=(",", ":")).encode()))
    installed_configuration = install_pack_memory_opaque_configuration(native, tools,
        root + "/installed-configuration.json", updated)
    material = encoded["material"]
    references = {}
    for name in ("profile", "policy"):
        references[name] = pack_memory_reference(install_direct_guest_file(native, tools["python"],
            root + "/" + name + ".json", json.dumps(material[name], separators=(",", ":")).encode()))
    return updated, {"version": 1, "sourceConfigurationCustody": source,
        "installedConfigurationCustody": installed_configuration,
        "publicConfiguration": public_reference,
        "actualEncoder": result, "profile": references["profile"], "policy": references["policy"],
        "issuer": material["issuer"], "profileDigest": material["profileDigest"],
        "publicConfigurationDigest": encoded["publicConfigurationDigest"],
        "scope": "actual dedicated candidate material; Managed acceptance and provider qualification unknown"}


class PackMemorySerializedTransport:
    """Keep every guest operation inside one original controller cutoff."""

    def __init__(self, native, worker, tools, cutoff):
        self.native, self.worker, self.tools, self.cutoff = native, worker, tools, cutoff

    def action(self, machine, selection):
        remaining = self.cutoff - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("original pack bridge cutoff reached")
        # Every action is fixed by transport.py. No serial connection is shared
        # with a second host caller or injected into a running child shell.
        return json.loads(direct_guest_python(machine, self.tools["python"], """
            import importlib.util, sys
            from pathlib import Path
            path=Path(selected['module'])
            if not str(path).startswith('/nix/store/'):
                raise ValueError('memory transport is not from selected source')
            sys.path.insert(0,str(path.parent))
            specification=importlib.util.spec_from_file_location('pack_transport',path)
            module=importlib.util.module_from_spec(specification)
            specification.loader.exec_module(module)
            print(json.dumps(module.run_action(selected['action'])))
        """, {"module": self.tools["packMemoryModules"] + "/transport.py", "action": selection},
            timeout=min(15, remaining)))

    def pump(self, native_owner, source_owner, dispatch_base, run_id, case):
        """Forward exact mailbox requests until actual Native owner exit."""
        sequence = 0
        receipts = []
        operation_cutoff = self.cutoff - 3
        while time.monotonic() < operation_cutoff:
            polled = self.action(self.native, {"action": "poll", **native_owner})
            if polled["pidfdReadable"] is True or polled["recordedTerminalProcessAbsent"] is True:
                return {"owner": polled, "messages": receipts}
            message = self.action(self.native, {"action": "mailbox", "root": native_owner["root"],
                "sequence": sequence, "runId": run_id, "case": case})
            if message is None:
                time.sleep(min(0.05, max(0, operation_cutoff - time.monotonic())))
                continue
            request = message["request"]
            dispatch = {"version": 1, "request": request, **dispatch_base,
                "sourceOwnerReference": source_owner}
            reply = self.action(self.worker, {"action": "dispatch", "root": dispatch["root"],
                "moduleDirectory": self.tools["packMemoryModules"], "selection": dispatch})
            published = self.action(self.native, {"action": "respond", "root": native_owner["root"],
                "sequence": sequence, "requestSha256": message["reference"]["sha256"], "reply": reply})
            receipts.append({"request": message["reference"], "reply": published})
            sequence += 1
            if sequence > 512:
                raise ValueError("pack bridge message inventory exceeds its fixed bound")
        raise TimeoutError("Native owner did not exit before the original cleanup reserve")

    def until_terminal(self, machine, owner, leaf, operation_cutoff):
        while time.monotonic() < operation_cutoff:
            observed = self.action(machine, {"action": "poll", **owner})
            if observed["pidfdReadable"] is True or observed["recordedTerminalProcessAbsent"] is True:
                terminal = self.action(machine, {"action": "read_fixed", "root": owner["root"], "leaf": leaf})
                if terminal is None or terminal["value"]["ownerProcess"] != owner["process"]:
                    raise RuntimeError("actual memory owner exited without its joined terminal receipt")
                return {"owner": observed, "terminal": terminal}
            time.sleep(min(0.05, max(0, operation_cutoff - time.monotonic())))
        raise TimeoutError("actual memory owner remains live at its original operation cutoff")


def pack_memory_publish(transport, machine, root, leaf, value):
    return transport.action(machine, {"action": "publish", "root": root,
        "leaf": leaf, "value": value})


def pack_memory_phase(helper, root, output, phase):
    if not output.startswith(root + "/") or "/" in output[len(root) + 1:]:
        raise ValueError("memory phase output leaves its original private root")
    return {"version": 1, "helperInputFile": helper["input"]["file"],
        "helperInputSha256": helper["input"]["sha256"], "outputFile": output, "phase": phase}


def pack_memory_copy_source(client, worker, tools, transport, worker_root, source, leaf):
    """Copy one measured publisher file in fixed chunks; never through Native."""
    limits = {"pack.bin": 8 * 1024 * 1024, "index.bin": 4 * 1024 * 1024,
        "metadata-0.bin": 256 * 1024, "metadata-1.bin": 256 * 1024}
    if (leaf not in limits or type(source["bytes"]) is not int
            or not 0 < source["bytes"] <= limits[leaf]
            or not re.fullmatch(r"[0-9a-f]{64}", source["sha256"])):
        raise ValueError("memory publisher reference exceeds its exact role")
    reference = None
    for offset in range(0, source["bytes"], 128 * 1024):
        remaining = transport.cutoff - time.monotonic()
        if remaining <= 3:
            raise TimeoutError("original memory setup budget is exhausted")
        chunk = json.loads(direct_guest_python(client, tools["python"], """
            import hashlib, os, stat
            fd=os.open(selected['source']['file'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as stream:
                before=os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() \
                        or before.st_nlink!=1 or before.st_size!=selected['source']['bytes']:
                    raise ValueError('actual publisher source custody differs')
                if hashlib.file_digest(stream,'sha256').hexdigest()!=selected['source']['sha256']:
                    raise ValueError('actual publisher source commitment differs')
                stream.seek(selected['offset']); body=stream.read(128*1024)
                after=os.fstat(stream.fileno())
            if any(getattr(before,key)!=getattr(after,key) for key in
                    ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')):
                raise ValueError('actual publisher source changed')
            print(json.dumps({'body':base64.b64encode(body).decode(),'bytes':len(body)}))
        """, {"source": source, "offset": offset}, timeout=min(15, remaining - 3)))
        final = offset + chunk["bytes"] == source["bytes"]
        copied = transport.action(worker, {"action": "source_chunk", "root": worker_root,
            "chunk": {"leaf": leaf, "offset": offset, "body": chunk["body"],
                "bytes": source["bytes"], "sha256": source["sha256"], "final": final}})
        if final:
            reference = copied["reference"]
    if reference is None or any(reference[key] != source[key] for key in ("bytes", "sha256")):
        raise ValueError("actual complete source copy differs from its independent client inventory")
    return reference


def prepare_pack_memory_export(client, tools, coordinates):
    """Run the actual current parser emitter once, independently of Worker calls."""
    root = coordinates["clientRoot"] + "/pack-memory-export"
    remaining = tools["fleetCutoffMonotonic"] - time.monotonic()
    if remaining <= 120:
        raise TimeoutError("original fleet budget has no complete exporter subwindow")
    private_guest_command(client, shlex.join([tools["packMemoryExporter"], root]), timeout=120)
    raw = read_direct_guest_file(client, tools["python"], root + "/manifest.json", 65536)
    manifest = json.loads(raw)
    if (set(manifest) != {"version", "execution", "pairs", "wholeWorkerMemoryBytes", "providerEffects"}
            or type(manifest["version"]) is not int or manifest["version"] != 1
            or manifest["execution"] != "fixture_export_only" or manifest["providerEffects"] != "not_invoked"
            or manifest["wholeWorkerMemoryBytes"] is not None
            or [row["case"] for row in manifest["pairs"]] != list(PACK_MEMORY_CASES)):
        raise ValueError("actual current exporter manifest differs")
    return {"root": root, "manifest": manifest,
        "manifestReference": {"file": root + "/manifest.json", "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}}


def prepare_pack_memory_registry(controls, tools, source, run):
    """Use normal topology and public Mirror configuration for one Managed registry."""
    module = managed_fixture_module(tools["managedGcHelper"], "pack_memory_registry_" + run)
    registry = module.prepare_managed_registry(controls, {"slug": "external-" + run},
        "memory-" + run[:8], [source["signed"]["trustKey"]],
        ".aos-mirror-qualification/" + run + "/final", "pack-memory-" + run)
    selected = {"registrySlug": registry["registry"]["slug"],
        "upstream": source["upstream"], "mode": "pull_through"}
    configured = configure_external_mirror(controls, selected, "pack-memory-" + run)
    return {"managed": registry, "mirror": configured}


def pack_memory_case_inputs(pair, case, run, source, maximum_object_bytes):
    """Keep canonical pack views and exactly two real publisher metadata sources."""
    if (pair["case"] != case or not re.fullmatch(r"objects/pack/pack-[0-9a-f]{64}\.idx", pair["indexPath"])
            or type(maximum_object_bytes) is not int or maximum_object_bytes <= 0
            or not 0 < pair["packBytes"] <= min(8 * 1024 * 1024, maximum_object_bytes)
            or not 0 < pair["indexBytes"] <= min(4 * 1024 * 1024, maximum_object_bytes)):
        raise ValueError("actual pack pair does not fit the existing signed Mirror purpose")
    metadata = [row for row in source["inventory"]["objects"]
        if 0 < row["byteSize"] <= 256 * 1024
        and (row["path"].endswith(".narinfo") or row["path"] == "info/refs")][:2]
    if len(metadata) != 2 or metadata[0]["path"] == metadata[1]["path"]:
        raise ValueError("two distinct real publisher metadata objects are absent")
    prefix = "releases/memory/" + run + "/" + case + "/"
    return {"indexPath": prefix + pair["indexPath"],
        "packPath": prefix + pair["indexPath"][:-4] + ".pack",
        "metadata": [{"source": {"file": source["signed"]["surfaceRoot"] + "/" + row["path"],
            "bytes": row["byteSize"], "sha256": row["sha256"]},
            "path": prefix + "metadata-" + str(ordinal) + ".public"}
            for ordinal, row in enumerate(metadata)]}


def pack_memory_private_reference(native, tools, path):
    """Copy a selected immutable descriptor into SDK-required private custody."""
    raw = read_direct_guest_file(native, tools["python"], path, 65536)
    return raw


def pack_memory_owner_retired(terminal, kind):
    """Require actual owner and every owned child receipt before any next mutation."""
    value = terminal["value"]
    key = {"source": "reaped", "native": "ownedChildrenReaped", "admission": "reaped"}[kind]
    if (value.get(key) is not True
            or kind != "source" and value.get("retirementPoisoned") is not False):
        raise RuntimeError("pack memory child retirement remains unknown; stop later mutations")
    return value


def run_pack_memory_case(client, native, worker, tools, prepared, processes, helper,
                         mirror, registry, exported, pair):
    """Call one actual pack and two actual admitted candidate originals once."""
    case, run = pair["case"], prepared["coordinates"]["runId"]
    coordinates = prepared["coordinates"]
    cutoff = min(tools["fleetCutoffMonotonic"], time.monotonic() + 120)
    if cutoff - time.monotonic() <= 10:
        raise TimeoutError("no original pack case work and cleanup budget remains")
    transport = PackMemorySerializedTransport(native, worker, tools, cutoff)
    native_root = coordinates["nativeRoot"] + "/pack-memory/" + case
    worker_root = coordinates["workerRoot"] + "/pack-memory/" + case
    prepared_native = transport.action(native, {"action": "prepare", "root": native_root})
    native_cutoff = prepared_native["uptimeSeconds"] + max(0, cutoff - time.monotonic())
    prepared_worker = transport.action(worker, {"action": "prepare", "root": worker_root})
    worker_cutoff = prepared_worker["uptimeSeconds"] + max(0, cutoff - time.monotonic())
    tuple_reference = pack_memory_reference(install_direct_guest_file(native, tools["python"],
        native_root + "/current-tuple.json", pack_memory_private_reference(native, tools,
            tools["packMemoryCurrentTuple"])))
    descriptor_reference = pack_memory_reference(install_direct_guest_file(native, tools["python"],
        native_root + "/source-descriptor.json", pack_memory_private_reference(native, tools,
            tools["packMemorySourceDescriptor"])))
    purpose = mirror["evidence"]["purpose"]["producer"]["selection"]
    current = int(private_guest_command(native, shlex.join([tools["python"], "-c",
        "import time; print(int(time.time()))"])).strip())
    if (not purpose["issuedAt"] <= current < purpose["validUntil"]
            or purpose["upstreamBase"] != mirror["evidence"]["source"]["upstream"]):
        raise ValueError("actual signed Mirror purpose is expired or names another source")
    inputs = pack_memory_case_inputs(pair, case, run, mirror["evidence"]["source"],
        purpose["maximumObjectBytes"])
    files = {}
    for role, leaf, source in (
            ("pack", "pack.bin", {"file": exported["root"] + "/" + case + "/pair.pack",
                "bytes": pair["packBytes"], "sha256": pair["packSha256"]}),
            ("index", "index.bin", {"file": exported["root"] + "/" + case + "/pair.idx",
                "bytes": pair["indexBytes"], "sha256": pair["indexSha256"]}),
            ("metadata0", "metadata-0.bin", inputs["metadata"][0]["source"]),
            ("metadata1", "metadata-1.bin", inputs["metadata"][1]["source"])):
        reference = pack_memory_copy_source(client, worker, tools, transport, worker_root, source, leaf)
        path = inputs["packPath"] if role == "pack" else inputs["indexPath"] if role == "index" \
            else inputs["metadata"][int(role[-1])]["path"]
        files[role] = {**reference, "path": "/fleet-mirror/" + run + "/" + path}
    material = prepared["packMemoryMaterial"]
    candidate = {"configurationFile": material["installedConfigurationCustody"]["file"],
        "configurationCustody": material["installedConfigurationCustody"]["custody"],
        "publicConfigurationFile": material["publicConfiguration"]["file"],
        "publicConfigurationDigest": material["publicConfigurationDigest"],
        "managedProfileFile": material["profile"]["file"], "policyFile": material["policy"]["file"],
        "candidateKeyFile": prepared["nativeFiles"]["HUB_MIRROR_CANDIDATE_KEY"],
        "issuer": material["issuer"]}
    admission_template = pack_memory_publish(transport, native, native_root, "admission-template.json",
        pack_memory_phase(helper, native_root, native_root + "/admission-output.json",
            {"kind": "prepare_metadata", "material": candidate,
                "objects": [{"registryId": int(registry["mirror"]["registryId"]), "path": row["path"],
                    "verification": {"kind": "sha256", "sha256": row["source"]["sha256"],
                        "size": row["source"]["bytes"]}} for row in inputs["metadata"]]}))
    # Admission has its own <=30s original within the earlier case cutoff. No
    # response hold exists yet, so unknown admission cannot strand a held read.
    admission_clock = json.loads(direct_guest_python(native, tools["python"],
        "import time; print(json.dumps({'uptime':time.monotonic()}))", {},
        timeout=min(5, cutoff - time.monotonic())))
    admission_host_cutoff = min(cutoff - 3, time.monotonic() + 30)
    admission_cutoff = min(native_cutoff, admission_clock["uptime"]
        + max(0, admission_host_cutoff - time.monotonic()))
    admission_selection = pack_memory_publish(transport, native, native_root, "admission-selection.json", {
        "version": 1, "root": native_root, "currentTupleReference": tuple_reference,
        "sourceDescriptorReference": descriptor_reference, "templateReference": admission_template,
        "cutoffUptimeSeconds": admission_cutoff})
    report = {"version": 1, "runId": run, "case": case, "originalControllerCutoff": cutoff,
        "originalNativeCutoff": native_cutoff, "originalWorkerCutoff": worker_cutoff,
        "pureParser": pair["pureParser"], "sourceReferences": files,
        "sourceDescriptorReference": descriptor_reference, "currentTupleReference": tuple_reference,
        "wholeIsolateBytes": None, "linearWasmBytes": None, "memory128PredicateQualified": False,
        "strictCodecJoin": None, "intendedOverflowFence": None, "nativeBulkBytes": None, "cleanup": [],
        "scope": "supplemental actual callbacks; pure parser, process envelope and isolate allocation are distinct"}
    owned = []
    launch_unknown = False
    primary = None
    try:
        launch_unknown = True
        admission_owner = transport.action(native, {"action": "launch", "root": native_root,
            "python": tools["python"], "moduleDirectory": tools["packMemoryModules"],
            "kind": "admission", "selection": admission_selection})
        owned.append((native, admission_owner, admission_cutoff))
        launch_unknown = False
        admitted = transport.until_terminal(native, admission_owner, "admission-terminal.json",
            admission_host_cutoff - 2)
        actual = pack_memory_owner_retired(admitted["terminal"], "admission")
        report["admission"] = admitted
        if actual["failureClass"] is not None or actual["result"] is None:
            raise RuntimeError("actual metadata admission refused; preserve partial state without replay")
        value = actual["result"]["result"]["result"]
        if (value["kind"] != "prepare_metadata" or len(value["items"]) != 2
                or len(set(value["originalDigests"])) != 2
                or value["publicConfigurationDigest"] != material["publicConfigurationDigest"]
                or value["runtimeAcceptance"] is not None):
            raise ValueError("actual SQL admission selected another metadata cohort")
        metadata_templates = []
        for ordinal, item in enumerate(value["items"]):
            original = pack_memory_publish(transport, native, native_root,
                "metadata-original-" + str(ordinal) + ".json", item)
            header = native_root + "/capture/candidate-" + str(ordinal) + ".json"
            phase = {"kind": "metadata", "original_file": original["file"],
                "managed_profile_file": candidate["managedProfileFile"], "policy_file": candidate["policyFile"],
                "candidate_key_file": candidate["candidateKeyFile"], "issuer": candidate["issuer"],
                "configuration_file": candidate["configurationFile"],
                "configuration_custody": candidate["configurationCustody"],
                "public_configuration_file": candidate["publicConfigurationFile"],
                "public_configuration_digest": candidate["publicConfigurationDigest"],
                "candidate_buffers_output_file": header}
            reference = pack_memory_publish(transport, native, native_root,
                "metadata-template-" + str(ordinal) + ".json", pack_memory_phase(helper, native_root,
                    native_root + "/metadata-output-" + str(ordinal) + ".json", phase))
            metadata_templates.append({"selection": reference, "candidateBuffersHeaderFile": header})
        query = pack_memory_publish(transport, native, native_root, "pack-template.json",
            pack_memory_phase(helper, native_root, native_root + "/pack-output.json", {
                "kind": "pack", "registry_id": int(mirror["evidence"]["cases"]["full"]["configuration"]["registryId"]),
                "index_path": inputs["indexPath"], "oid": pair["selectedOid"]}))
        manifest = pack_memory_publish(transport, native, native_root, "fixture-manifest.json", pair)
        source_selection = pack_memory_publish(transport, worker, worker_root, "source-selection.json", {
            "version": 1, "host": "aos.fleet.test:4778", "port": 4778, "frontedBySelectedMirror": True,
            "runId": run, "bootId": prepared_worker["bootId"], "privateRoot": worker_root,
            "controlSocket": worker_root + "/source.sock", "cutoffUptimeMillis": worker_cutoff * 1000,
            "tlsKeyFile": tools["issuerPrivateKey"], "tlsCertificateFile": tools["issuerCertificate"],
            "files": files})
        owner_selection = pack_memory_publish(transport, worker, worker_root, "owner-selection.json", {
            "version": 1, "root": worker_root, "node": tools["node"],
            "launcher": tools["packMemoryModules"] + "/source-hold-launch.mjs",
            "configurationFile": source_selection["file"], "cutoffUptimeSeconds": worker_cutoff})
        launch_unknown = True
        source_owner = transport.action(worker, {"action": "launch", "root": worker_root,
            "python": tools["python"], "moduleDirectory": tools["packMemoryModules"],
            "kind": "source", "selection": owner_selection})
        owned.append((worker, source_owner, worker_cutoff))
        launch_unknown = False
        ready = None
        while time.monotonic() < cutoff - 3:
            ready = transport.action(worker, {"action": "read_fixed", "root": worker_root, "leaf": "ready.json"})
            if ready is not None:
                break
            state = transport.action(worker, {"action": "poll", **source_owner})
            if state["pidfdReadable"] is True:
                raise RuntimeError("actual source owner exited before its readiness receipt")
            time.sleep(min(0.05, max(0, cutoff - 3 - time.monotonic())))
        if ready is None:
            raise TimeoutError("actual source readiness absent at original cutoff")
        native_selection = pack_memory_publish(transport, native, native_root, "native-selection.json", {
            "version": 1, "runId": run, "case": case, "root": native_root,
            "bridgeRoot": native_root + "/bridge", "captureRoot": native_root + "/capture",
            "currentTupleReference": tuple_reference, "sourceDescriptorReference": descriptor_reference,
            "cutoffUptimeSeconds": native_cutoff, "prepared": {
                "queryReference": query, "metadataOriginalReferences": metadata_templates,
                "fixtureManifestReference": manifest, "currentTupleReference": tuple_reference}})
        launch_unknown = True
        native_owner = transport.action(native, {"action": "launch", "root": native_root,
            "python": tools["python"], "moduleDirectory": tools["packMemoryModules"],
            "kind": "native", "selection": native_selection})
        owned.append((native, native_owner, native_cutoff))
        launch_unknown = False
        runner = processes["worker"]
        pump = transport.pump(native_owner, ready["reference"], {
            "root": worker_root, "cutoffUptimeSeconds": worker_cutoff,
            "runnerProcess": {"pid": runner["pid"], "startTicks": int(runner["startTicks"]),
                "ownerUid": runner["ownerUid"]}, "workerd": tools["workerd"]}, run, case)
        report["pump"] = pump
        terminal = transport.action(native, {"action": "read_fixed", "root": native_root, "leaf": "terminal.json"})
        if terminal is None or terminal["value"]["ownerProcess"] != native_owner["process"]:
            raise RuntimeError("actual Native terminal receipt is missing or belongs to another owner")
        report["native"] = terminal
        actual = pack_memory_owner_retired(terminal, "native")
        if case != "replacement-overflow" and actual["terminal"] != "callbacks_completed":
            raise RuntimeError("actual positive pack and metadata callback window refused or remains unknown")
        report["functionalOutcome"] = actual["terminal"]
        # A generic nonzero Native receipt is not proof of the intended overflow
        # fence. Pure exporter refusal and actual runtime disposition stay apart.
        report["actualPackCodec"] = None
    except BaseException as error:
        primary = error
        report["failureClass"] = type(error).__name__
    finally:
        unknown = launch_unknown
        report["launchDispositionUnknown"] = launch_unknown
        for machine, owner, guest_cutoff in reversed(owned):
            disposition = {"owner": owner, "retired": None, "terminal": None}
            try:
                stopped = transport.action(machine, {"action": "terminate", **owner,
                    "cutoffUptimeSeconds": guest_cutoff})
                disposition["retired"] = stopped
                if stopped["pidfdReadable"] is not True and stopped.get("recordedTerminalProcessAbsent") is not True:
                    raise RuntimeError("actual owner exit is unknown")
                leaf = {"source": "owner-terminal.json", "native": "terminal.json",
                    "admission": "admission-terminal.json"}[owner["kind"]]
                terminal = transport.action(machine, {"action": "read_fixed", "root": owner["root"], "leaf": leaf})
                if terminal is None or terminal["value"]["ownerProcess"] != owner["process"]:
                    raise RuntimeError("actual child terminal is unknown")
                pack_memory_owner_retired(terminal, owner["kind"])
                disposition["terminal"] = terminal["reference"]
            except BaseException as error:
                unknown = True
                disposition["cleanupFailureClass"] = type(error).__name__
                if primary is None:
                    primary = error
                else:
                    primary.add_note("pack owner cleanup failed: " + type(error).__name__)
            report["cleanup"].append(disposition)
        report["ownedRetirementKnown"] = not unknown
        report["finishedControllerMonotonic"] = time.monotonic()
        try:
            retain_direct_flow("pack-memory-" + run + "-" + case + ".json", report)
        except BaseException as error:
            if primary is None:
                primary = error
            else:
                primary.add_note("pack report retention failed: " + type(error).__name__)
    if primary is not None:
        raise primary
    return report


def run_current_pack_memory_window(client, native, worker, tools, prepared, processes,
                                    helper, mirror, controls):
    """Run the three called cases after main publication, with no memory fiction."""
    if (tools["copyIsolationCase"] != "same_worker" or mirror is None
            or prepared.get("packMemoryMaterial") is None):
        raise ValueError("supplemental memory window lacks its genuine dedicated same-Worker prerequisites")
    coordinates = prepared["coordinates"]
    exported = prepare_pack_memory_export(client, tools, coordinates)
    registry = prepare_pack_memory_registry(controls, tools, mirror["evidence"]["source"], coordinates["runId"])
    results = []
    for pair in exported["manifest"]["pairs"]:
        results.append(run_pack_memory_case(client, native, worker, tools, prepared, processes,
            helper, mirror, registry, exported, pair))
    report = {"version": 1, "runId": coordinates["runId"], "export": exported,
        "registry": registry, "cases": results, "wholeIsolateBytes": None,
        "linearWasmBytes": None, "memory128PredicateQualified": False, "nativeBulkBytes": None,
        "scope": "main publication preceded these real supplemental calls; unavailable isolate telemetry is separate"}
    retain_direct_flow("pack-memory-" + coordinates["runId"] + "-window.json", report)
    return report
