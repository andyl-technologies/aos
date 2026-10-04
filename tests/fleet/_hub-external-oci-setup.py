"""Run normal setup for the dedicated controlled External OCI Fleet pair.

Fleet owns fresh database/process/custody provisioning and its initial proxies.
This adapter calls existing reviewed browser APIs and source-built operators.
It creates no SQL grants, issuer trust, accepted provider measurements or Hosted
artifact. The final Native serving helper is a separate selected process.
"""

import hashlib
import json
from pathlib import PurePosixPath
import re
import shlex


SETUP_SELECTOR = "storage_work::external_oci::tests::fleet_setup::actual_external_oci_fleet_setup"
PUBLIC_ORIGIN = "https://localhost:4673"
NATIVE_ORIGIN = "https://localhost:4674"
MAX_DOCUMENT_BYTES = 1024 * 1024


def _closed(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate setup metadata field")
        result[key] = value
    return result


def _hash(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("setup commitment is invalid")
    return value


def _absolute(path):
    if (not isinstance(path, str) or not path.startswith("/")
            or any(part in {"", ".", ".."} for part in path.split("/")[1:])):
        raise ValueError("setup file path is invalid")
    return path


def setup_coordinates(value):
    """Validate fixed origins and fresh run roots before issuing a control."""
    fields = {"version", "runId", "publicOrigin", "controlOrigin", "listen",
        "nativeRoot", "workerRoot", "clientRoot", "databaseName", "operatorRole",
        "placementPrefix"}
    if set(value) != fields or value["version"] != 1:
        raise ValueError("External OCI setup coordinates differ")
    run = value["runId"]
    if not isinstance(run, str) or not re.fullmatch(r"[0-9a-f]{32}", run):
        raise ValueError("External OCI setup run differs")
    expected = {"publicOrigin": PUBLIC_ORIGIN, "controlOrigin": NATIVE_ORIGIN,
        "listen": "127.0.0.1:4676",
        "nativeRoot": "/var/lib/hybrid-native/external-oci/" + run,
        "workerRoot": "/var/lib/hybrid-worker/external-oci/" + run,
        "clientRoot": "/var/lib/hybrid-client/external-oci/" + run,
        "databaseName": "fleet_external_" + run,
        "placementPrefix": ".aos-direct-qualification/external-oci/" + run + "/registry"}
    if any(value[field] != required for field, required in expected.items()):
        raise ValueError("External OCI setup leaves its dedicated pair")
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value["operatorRole"]):
        raise ValueError("External OCI SQL reader role is invalid")
    return dict(value)


def _control_pair(controls, coordinates):
    setup_coordinates(coordinates)
    expected = coordinates["clientRoot"] + "/controls"
    if controls.origin != PUBLIC_ORIGIN or controls.evidence_root != expected:
        raise ValueError("normal controls address another logical pair")


def _invoke(machine, private_command, arguments, timeout=120):
    _absolute(arguments[0])
    # The existing private transport suppresses command material on failure.
    # An ambiguous operator result is terminal; this adapter does not retry it.
    return private_command(machine, shlex.join(arguments), timeout=timeout)


def _read_json(machine, private_command, python, path, maximum=MAX_DOCUMENT_BYTES):
    _absolute(path)
    program = (
        f"{shlex.quote(_absolute(python))} - <<'EXTERNAL_OCI_SETUP_METADATA'\n"
        "import os,stat,sys\nfrom pathlib import Path\n"
        f"path=Path({path!r})\n"
        "before=path.lstat()\n"
        "if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or before.st_mode&0o077:\n"
        "    raise ValueError('setup metadata custody differs')\n"
        f"if before.st_size>{maximum}:raise ValueError('setup metadata exceeds bound')\n"
        "with path.open('rb') as stream:\n"
        "    opened=os.fstat(stream.fileno())\n"
        "    if (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino):raise ValueError('setup file replaced')\n"
        f"    body=stream.read({maximum + 1})\n"
        "    after=os.fstat(stream.fileno())\n"
        f"if len(body)>{maximum} or len(body)!=before.st_size or any(getattr(before,key)!=getattr(after,key) for key in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid')):\n"
        "    raise ValueError('setup metadata changed')\n"
        "sys.stdout.buffer.write(body)\nEXTERNAL_OCI_SETUP_METADATA\n"
    )
    raw = private_command(machine, program).encode()
    if len(raw) > maximum:
        raise ValueError("setup metadata response exceeds bound")
    return json.loads(raw, object_pairs_hook=_closed), {
        "path": path, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def bootstrap_external_oci_binding(controls, worker, tools, coordinates, selection,
                                   operator, database_host):
    """Create and probe a genuine binding using existing queued custody controls.

    The caller provides the already provisioned restricted reader's sql.url and
    sql-password under this run's operator root. `operator` is the existing
    _hub-direct-operator module. No grants or valid flags are created here.
    """
    _control_pair(controls, coordinates)
    fields = {"organizationSlug", "organizationName", "bindingStableId", "bindingName",
        "providerCoordinates", "versionReferences", "providerMaterial"}
    if set(selection) != fields:
        raise ValueError("binding setup selection differs")
    run = coordinates["runId"]
    if selection["organizationSlug"] != "external-" + run:
        raise ValueError("External OCI organization is not fresh for this run")
    provider = selection["providerCoordinates"]
    if (set(provider) != {"bucket", "prefix", "endpoint", "signingRegion", "accessMode"}
            or provider["prefix"] != coordinates["placementPrefix"].rsplit("/", 1)[0]
            or provider["accessMode"] != "private"):
        raise ValueError("binding coordinates escape the selected private run")
    if selection["versionReferences"] != {purpose: f"secret://fleet/external-oci/{run}/{purpose}/v1"
            for purpose in ("presign", "read", "list", "write")}:
        raise ValueError("setup requires real read/list/write/presign probes, without Delete inference")
    organization, binding = controls.create_external_binding(
        selection["organizationSlug"], selection["organizationName"],
        selection["bindingStableId"], selection["bindingName"], provider)
    root = coordinates["workerRoot"] + "/operator"
    versions = operator.install_operator_provider_versions(worker, tools["python"],
        selection["providerMaterial"], selection["versionReferences"], operator_root=root)

    def stage(operation_id, purpose):
        return operator.stage_queued_provider_credential(worker, tools["python"],
            tools["authorityBootstrap"], operation_id, purpose, tools["deploymentId"],
            PUBLIC_ORIGIN, tools["storageWorkKeyFile"], versions["manifestFile"], operator_root=root)

    operations = controls.validate_external_credentials(organization["slug"], binding["spec"]["name"],
        selection["versionReferences"], versions["materialSha256"], stage)
    binding = controls.get_external_binding(organization["slug"], binding["spec"]["name"])
    pins = operator.read_operator_binding_pins(worker, tools["postgres"], database_host, binding,
        operator_root=root, database_name=coordinates["databaseName"], operator_role=coordinates["operatorRole"])
    return {"organization": organization, "binding": binding, "currentSqlPins": pins,
        "operatorVersions": versions, "credentialOperations": operations, "qualification": None}


def bootstrap_external_oci_destination(controls, worker, tools, coordinates,
                                       source_credentials, provider_material, operator,
                                       database_host, private_command):
    """Create a second binding and independently validate its queued originals.

    Only the already provisioned read-only SQL login is copied to separate
    private operator custody. Provider values, version references and staging
    originals are retained independently for this destination binding.
    """
    _control_pair(controls, coordinates)
    run = coordinates["runId"]
    organization = source_credentials["organization"]
    source = source_credentials["binding"]
    if (organization["slug"] != "external-" + run
            or source["ownerScopeKey"] != organization["ownerScopeKey"]):
        raise ValueError("destination binding requires the selected original organization")
    prefix = coordinates["placementPrefix"].rsplit("/", 1)[0] + "/destination"
    provider = {**source["spec"]["s3"], "prefix": prefix}
    stable_id = "external-destination-" + run
    label = "external-destination-" + run
    binding = controls.reviewed("BindingService", "PlanCreateBinding", "CreateBinding", {
        "stableId": stable_id, "ownerScopeKey": organization["ownerScopeKey"],
        "expectedResourceVersion": "", "spec": {"name": "destination", "s3": provider},
    }, label + "-binding")["binding"]
    if (binding["stableId"] != stable_id or binding["stableId"] == source["stableId"]
            or binding["ownerScopeKey"] != organization["ownerScopeKey"]
            or binding["spec"]["name"] != "destination"
            or binding["spec"]["s3"] != provider):
        raise ValueError("actual destination binding differs from its independent selection")

    original_root = coordinates["workerRoot"] + "/operator"
    root = original_root + "/destination"
    # This private command emits no URL, password, provider value or digest.
    program = (
        "import os, stat\nfrom pathlib import Path\n"
        f"original=Path({original_root!r})\nroot=Path({root!r})\n"
        "root.mkdir(mode=0o700,exist_ok=False)\n"
        "for name in ('sql.url','sql-password'):\n"
        "    with os.fdopen(os.open(original/name,os.O_RDONLY|os.O_NOFOLLOW),'rb') as source:\n"
        "        metadata=os.fstat(source.fileno())\n"
        "        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=os.getuid()\n"
        "                or metadata.st_mode&0o077 or metadata.st_nlink!=1):\n"
        "            raise ValueError('destination reader custody differs')\n"
        "        body=source.read(8193)\n"
        "        if not 0<len(body)<=8192: raise ValueError('destination reader input exceeds bound')\n"
        "    with os.fdopen(os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as output:\n"
        "        output.write(body)\n        output.flush()\n        os.fsync(output.fileno())\n"
    )
    private_command(worker, shlex.join([tools["python"], "-c", program]))
    references = {purpose: f"secret://fleet/external-oci/{run}/destination/{purpose}/v1"
        for purpose in ("presign", "read", "list", "write")}
    versions = operator.install_operator_provider_versions(worker, tools["python"],
        provider_material, references, operator_root=root)

    def stage(operation_id, purpose):
        return operator.stage_queued_provider_credential(worker, tools["python"],
            tools["authorityBootstrap"], operation_id, purpose, tools["deploymentId"],
            PUBLIC_ORIGIN, tools["storageWorkKeyFile"], versions["manifestFile"], operator_root=root)

    operations = controls.validate_external_credentials(organization["slug"], "destination",
        references, versions["materialSha256"], stage, label_prefix=label)
    binding = controls.get_external_binding(organization["slug"], "destination")
    if (binding["stableId"] != stable_id or binding["ownerScopeKey"] != organization["ownerScopeKey"]
            or binding["spec"]["name"] != "destination" or binding["spec"]["s3"] != provider):
        raise ValueError("validated destination binding changed its independent scope")
    pins = operator.read_operator_binding_pins(worker, tools["postgres"], database_host, binding,
        operator_root=root, database_name=coordinates["databaseName"], operator_role=coordinates["operatorRole"])
    if pins["bindingId"] == source_credentials["currentSqlPins"]["bindingId"]:
        raise ValueError("destination SQL identity aliases the source binding")
    return {"organization": organization, "binding": binding, "currentSqlPins": pins,
        "operatorVersions": versions, "credentialOperations": operations, "qualification": None}


def export_external_oci_setup(native, worker, tools, coordinates, files, selected,
                              credential_report, controls, control_module, private_command,
                              observed_native_time, *, additional_associations=None):
    """Admit independently selected actual facts and invoke current SQL exporters.

    `selected` comes from independent review of this fresh namespace, provider,
    installation and clock. Existing authority Plan/Apply implements the full
    admission. Issuer files must already have separate genuine owner custody.
    """
    _control_pair(controls, coordinates)
    required_files = {"restrictedSqlUrlFile", "issuerConfigurationFile", "issuerPublicKeyFile",
        "storageWorkKeyFile", "secretVersionManifestFile", "nativeDatabaseUrlFile"}
    if set(files) != required_files:
        raise ValueError("authority setup files differ")
    for path in files.values():
        _absolute(path)
    arguments = (controls, credential_report["organization"]["slug"], credential_report["binding"],
        credential_report["currentSqlPins"], selected, observed_native_time)
    if additional_associations is None:
        authority = control_module.admit_external_fixture_authority(*arguments)
    else:
        authority = control_module.admit_external_fixture_authority(*arguments,
            additional_associations=additional_associations)
    return export_external_oci_cohorts(worker, tools, coordinates, files, selected,
        credential_report, authority, private_command)


def export_external_oci_cohorts(worker, tools, coordinates, files, selected,
                               credential_report, authority, private_command, *, operator_root=None):
    """Export one actual association after the complete authority admission.

    A paired caller invokes this for each independently admitted binding. Each
    exporter reopens current SQL; no cohort, profile or publication is copied.
    """
    setup_coordinates(coordinates)
    required_files = {"restrictedSqlUrlFile", "issuerConfigurationFile", "issuerPublicKeyFile",
        "storageWorkKeyFile", "secretVersionManifestFile", "nativeDatabaseUrlFile"}
    if set(files) != required_files:
        raise ValueError("authority cohort export files differ")
    for path in files.values():
        _absolute(path)
    root = operator_root or coordinates["workerRoot"] + "/operator"
    if root not in {coordinates["workerRoot"] + "/operator", coordinates["workerRoot"] + "/operator/destination"}:
        raise ValueError("authority cohort export leaves the selected binding roots")
    association = selected["associationId"]
    prefix = credential_report["binding"]["spec"]["s3"]["prefix"]
    output = root + "/authority-export"
    base = [tools["authorityBootstrap"], "--database-url-file", files["restrictedSqlUrlFile"]]
    _invoke(worker, private_command, base + ["export", "--authority-id", selected["authorityId"],
        "--association-id", association, "--deployment-id", tools["deploymentId"],
        "--issuer-configuration", files["issuerConfigurationFile"],
        "--issuer-public-key-file", files["issuerPublicKeyFile"],
        "--admitted-prefix", prefix, "--output", output])
    list_output = root + "/list-export"
    _invoke(worker, private_command, base + ["export-list-cohort", "--authority-id", selected["authorityId"],
        "--association-id", association, "--issuer-configuration", files["issuerConfigurationFile"],
        "--admitted-prefix", prefix, "--output", list_output])
    bootstrap, bootstrap_ref = _read_json(worker, private_command, tools["python"], output + "/bootstrap.json")
    listing, list_ref = _read_json(worker, private_command, tools["python"], list_output + "/list-cohort.json")
    if (bootstrap["publication"] != listing["publication"]
            or bootstrap["issuer_installation"] != listing["issuer_installation"]
            or bootstrap["issuer_installation"]["executor_identity"] != selected["executorIdentity"]
            or bootstrap["publication"]["authority"]["guard_namespace_id"] != selected["guardNamespaceId"]):
        raise ValueError("fresh export differs from the selected namespace or installation")
    # Fleet copies only these actual bounded public documents to Native's own
    # private issuer/setup files. The signer seed never travels to Worker.
    return {"authority": authority, "bootstrap": bootstrap, "listExport": listing,
        "bootstrapFile": bootstrap_ref, "listFile": list_ref,
        "initializeArguments": [tools["authority"], "initialize", "--configuration",
            coordinates["nativeRoot"] + "/issuer/configuration.json", "--publication",
            coordinates["nativeRoot"] + "/issuer/publication.json"],
        "serveArguments": [tools["authority"], "serve", "--configuration",
            coordinates["nativeRoot"] + "/issuer/configuration.json"], "qualification": None}


def project_external_oci_consumers(exports, profile, profile_receipt, selected_provider):
    """Project exact exports only after independent matching provider selection.

    Structural checks cannot establish actual conformance. The independently
    retained report and review must supply it; unknown/refused facts halt setup.
    No result here is an acceptance artifact or a readiness verdict.
    """
    required = {"providerReportSha256", "providerContract", "maximumListPageObjects",
        "maximumListPages", "providerConcurrency"}
    if set(selected_provider) != required:
        raise ValueError("independent Copy/List selection differs")
    report_sha = _hash(selected_provider["providerReportSha256"])
    if profile_receipt["providerReviewSha256"] != report_sha:
        raise ValueError("provider selection differs from the Rust setup input")
    bootstrap, listing = exports["bootstrap"], exports["listExport"]
    if (bootstrap["publication"] != listing["publication"]
            or bootstrap["issuer_installation"] != listing["issuer_installation"]
            or profile["issuer_installation"] != bootstrap["issuer_installation"]
            or profile["read_cohort"] != bootstrap["read_cohort"]
            or profile["write_cohort"] != bootstrap["write_cohort"]):
        raise ValueError("OCI profile or List export changed domains")
    contract = selected_provider["providerContract"]
    fields = {"contract_id", "evidence_digest", "versioned_conditional_range_read",
        "versioned_multipart_complete", "private_incomplete_upload", "completed_upload_rejects_late_parts",
        "abort_closes_upload_id", "upload_part_checksum_enforced", "versioned_empty_put"}
    optional = {"protected_versionless", "maximum_copy_read_range_bytes"}
    if not fields.issubset(contract) or set(contract) - fields - optional:
        raise ValueError("Copy/List provider contract differs")
    observed_range = contract.get("maximum_copy_read_range_bytes")
    if observed_range is not None and (not isinstance(observed_range, str)
            or not re.fullmatch(r"[1-9][0-9]*", observed_range)
            or not 1 <= int(observed_range) <= 64 * 1024 * 1024):
        raise ValueError("Copy conditional-read bound is not an explicit admitted integer")
    if contract["evidence_digest"] != report_sha or not isinstance(contract["contract_id"], str) or not contract["contract_id"]:
        raise ValueError("Copy/List provider report commitment differs")
    common = ("private_incomplete_upload", "completed_upload_rejects_late_parts",
        "abort_closes_upload_id", "upload_part_checksum_enforced")
    if any(contract[key] is not True for key in common):
        raise ValueError("Copy/List closure facts remain unknown or unsupported")
    if any(type(contract[key]) is not bool for key in fields - {"contract_id", "evidence_digest"}):
        raise ValueError("provider facts must be explicit booleans")
    guarded = contract.get("protected_versionless")
    if profile["versionless_conditional_reads"]:
        if (not isinstance(guarded, dict) or set(guarded) != {"strong_conditional_range_read", "positive_multipart_complete"}
                or any(value is not True for value in guarded.values())):
            raise ValueError("actual versionless conditional transport remains unqualified")
    elif (guarded is not None or contract["versioned_conditional_range_read"] is not True
            or contract["versioned_multipart_complete"] is not True):
        raise ValueError("actual versioned transport remains unqualified")
    bounds = (("providerConcurrency", 3, 32), ("maximumListPageObjects", 1, 256),
        ("maximumListPages", 1, 256))
    if any(type(selected_provider[key]) is not int or not low <= selected_provider[key] <= high
           for key, low, high in bounds):
        raise ValueError("Copy/List execution bounds differ")
    object_consumer = {"version": 1,
        "guard_namespace_id": bootstrap["publication"]["authority"]["guard_namespace_id"],
        "executor_identity": bootstrap["issuer_installation"]["executor_identity"],
        "issuer_key_id": bootstrap["issuer_key_id"], "issuer_public_key": bootstrap["issuer_public_key"],
        "timing_profile": bootstrap["timing_profile"], "clock_uncertainty": bootstrap["clock_uncertainty"],
        "aliases": bootstrap["publication"]["aliases"],
        "cohorts": [bootstrap["read_cohort"], listing["list_cohort"], bootstrap["write_cohort"]],
        "publications": [bootstrap["publication"]]}
    domain = {"issuer_installation": bootstrap["issuer_installation"],
        "producer_profile_digest": _hash(profile_receipt["profileDigest"]), "provider_contract": contract,
        "read_cohort": bootstrap["read_cohort"], "list_cohort": listing["list_cohort"],
        "write_cohort": bootstrap["write_cohort"], "part_bytes": "8388608",
        "provider_concurrency": selected_provider["providerConcurrency"],
        "maximum_list_page_objects": selected_provider["maximumListPageObjects"],
        "maximum_list_pages": selected_provider["maximumListPages"]}
    result = {"HUB_EXTERNAL_OBJECT_CONSUMER": object_consumer,
        "HUB_EXTERNAL_COPY_CONSUMER": {"version": 1, "domains": [domain]},
        "HUB_EXTERNAL_OCI_CONSUMER": {"version": 1, "profiles": [profile]}}
    if len(json.dumps(object_consumer, separators=(",", ":")).encode()) > 128 * 1024:
        raise ValueError("full object consumer exceeds its unchanged bound")
    return json.loads(json.dumps(result))


def combine_external_oci_consumers(source, destination):
    """Combine independently exported domains for the initial common-capacity epoch.

    This projection preserves each actual cohort, provider report and profile.
    The later signed capacity producer supplies the installed version-two
    ceilings; this initial version-one configuration keeps both bounds at three.
    """
    keys = {"HUB_EXTERNAL_OBJECT_CONSUMER", "HUB_EXTERNAL_COPY_CONSUMER",
        "HUB_EXTERNAL_OCI_CONSUMER", "HUB_EXTERNAL_STAGING_CONSUMER"}
    if set(source) != keys or set(destination) != keys:
        raise ValueError("paired initial consumers differ from their selected closed domains")
    left, right = (value["HUB_EXTERNAL_OBJECT_CONSUMER"] for value in (source, destination))
    common = set(left) - {"cohorts"}
    if (set(left) != set(right) or any(left[key] != right[key] for key in common)
            or len(left["cohorts"]) != 3 or len(right["cohorts"]) != 3):
        raise ValueError("paired consumer issuer, publication or timing differs")
    domains = [value["HUB_EXTERNAL_COPY_CONSUMER"] for value in (source, destination)]
    if any(value["version"] != 1 or len(value["domains"]) != 1
            or value["domains"][0]["provider_concurrency"] != 3 for value in domains):
        raise ValueError("paired initial Copy domains require the same actual capacity three")
    associations = [value["domains"][0]["read_cohort"]["association"] for value in domains]
    if (associations[0]["binding_id"] == associations[1]["binding_id"]
            or associations[0]["binding_stable_id"] == associations[1]["binding_stable_id"]):
        raise ValueError("paired consumers alias the same binding")
    result = json.loads(json.dumps(source))
    result["HUB_EXTERNAL_OBJECT_CONSUMER"]["cohorts"].extend(json.loads(json.dumps(right["cohorts"])))
    for key, member in (("HUB_EXTERNAL_COPY_CONSUMER", "domains"),
            ("HUB_EXTERNAL_OCI_CONSUMER", "profiles"), ("HUB_EXTERNAL_STAGING_CONSUMER", "domains")):
        if (set(source[key]) != {"version", member} or set(destination[key]) != {"version", member}
                or source[key]["version"] != 1 or destination[key]["version"] != 1
                or len(source[key][member]) != 1 or len(destination[key][member]) != 1):
            raise ValueError("paired consumer domain shape differs")
        result[key][member].extend(json.loads(json.dumps(destination[key][member])))
    for value in (source, destination):
        domain = value["HUB_EXTERNAL_COPY_CONSUMER"]["domains"][0]
        stage = value["HUB_EXTERNAL_STAGING_CONSUMER"]["domains"][0]
        profile = value["HUB_EXTERNAL_OCI_CONSUMER"]["profiles"][0]
        object_consumer = value["HUB_EXTERNAL_OBJECT_CONSUMER"]
        if (object_consumer["cohorts"] != [domain["read_cohort"], domain["list_cohort"], domain["write_cohort"]]
                or stage["publication"] != object_consumer["publications"][0]
                or any(domain[name] != stage[name] or domain[name] != profile[name]
                    for name in ("issuer_installation", "read_cohort", "write_cohort"))):
            raise ValueError("paired profile, staging and Copy select different actual exports")
    if len(json.dumps(result["HUB_EXTERNAL_OBJECT_CONSUMER"], separators=(",", ":")).encode()) > 128 * 1024:
        raise ValueError("paired full object consumer exceeds its unchanged bound")
    return result


def hydrate_external_oci_setup(native, worker, tools, coordinates, files, exports, private_command,
                               *, operator_root=None):
    """Deliver current protected metadata after real issuer/consumer installation."""
    setup_coordinates(coordinates)
    root = operator_root or coordinates["workerRoot"] + "/operator"
    if root not in {coordinates["workerRoot"] + "/operator",
            coordinates["workerRoot"] + "/operator/destination"}:
        raise ValueError("hydration leaves the selected binding roots")
    output = root + "/hydration"
    _invoke(worker, private_command, [tools["authorityBootstrap"], "--database-url-file",
        files["restrictedSqlUrlFile"], "hydrate", "--bootstrap", exports["bootstrapFile"]["path"],
        "--worker-url", PUBLIC_ORIGIN, "--storage-work-key-file", files["storageWorkKeyFile"],
        "--secret-version-manifest", files["secretVersionManifestFile"], "--output", output])
    body, reference = _read_json(worker, private_command, tools["python"], output + "/hydration.json")
    if (body["executor_public_origin"] != PUBLIC_ORIGIN or body["binding_hydrated"] is not True
            or body["provider_readiness_evaluated"] is not False
            or body["deployment_id"] != tools["deploymentId"]
            or body["publication_digest"] != exports["bootstrap"]["write_cohort"]["publication_digest"]):
        raise ValueError("actual hydration acknowledgement differs")
    publication = exports["bootstrap"]["publication"]
    control = _invoke(native, private_command, [tools["hub"], "--root", coordinates["nativeRoot"],
        "--database-url-file", files["nativeDatabaseUrlFile"], "authority-control-sync",
        "--authority-id", publication["authority"]["authority_id"],
        "--guard-namespace-id", publication["authority"]["guard_namespace_id"],
        "--executor-identity", exports["bootstrap"]["issuer_installation"]["executor_identity"],
        "--worker-url", PUBLIC_ORIGIN, "--deployment-id", tools["deploymentId"],
        "--storage-work-key-file", tools["nativeStorageWorkKeyFile"]])
    if len(control.encode()) > 262144:
        raise ValueError("authority acknowledgement exceeds bound")
    receipt = json.loads(control, object_pairs_hook=_closed)
    if (receipt["authority_id"] != publication["authority"]["authority_id"]
            or receipt["desired_generation"] != publication["generation"]
            or receipt["desired_digest"] != publication["digest"]
            or receipt["control_synchronized"] is not True or receipt["provider_readiness_evaluated"] is not False):
        raise ValueError("actual authority acknowledgement differs")
    return {"hydration": reference, "controlSynchronization": receipt, "providerQualification": None}


def invoke_external_oci_preparation(native, tools, coordinates, input_file, phase, private_command):
    """Run one exact ignored setup selector; no provider retry or acceptance."""
    setup_coordinates(coordinates)
    if phase not in {"profile", "candidate"} or PurePosixPath(input_file).parent != PurePosixPath(coordinates["nativeRoot"]):
        raise ValueError("setup invocation leaves the selected private run")
    offered, offered_ref = _read_json(native, private_command, tools["python"], input_file, maximum=65536)
    role = offered.get("profileRole")
    if role not in {None, "destination"} or (role is not None and phase != "profile"):
        raise ValueError("offered setup profile role differs from its phase")
    destination = role == "destination"
    output_name = "destination-profile" if destination else phase
    prefix = (coordinates["placementPrefix"].rsplit("/", 1)[0] + "/destination/registry"
        if destination else coordinates["placementPrefix"])
    if (offered.get("runId") != coordinates["runId"] or offered.get("phase") != phase
            or offered.get("placementPrefix") != prefix
            or offered.get("outputDirectory") != coordinates["nativeRoot"] + "/" + output_name):
        raise ValueError("offered setup input names another original or output")
    _invoke(native, private_command, [tools["env"], "AOS_EXTERNAL_OCI_SETUP_INPUT=" + _absolute(input_file),
        _absolute(tools["managedCleanupNativeHelper"]), SETUP_SELECTOR,
        "--exact", "--ignored", "--nocapture"], timeout=120)
    output = coordinates["nativeRoot"] + "/" + output_name
    receipt, reference = _read_json(native, private_command, tools["python"], output + "/setup-receipt.json")
    profile, profile_ref = _read_json(native, private_command, tools["python"], output + "/profile.json")
    _, after_ref = _read_json(native, private_command, tools["python"], input_file, maximum=65536)
    if (after_ref != offered_ref or receipt["inputSha256"] != offered_ref["sha256"]
            or receipt["bindingId"] != offered.get("bindingId")
            or receipt["placementId"] != offered.get("placementId")
            or receipt["profileSha256"] != profile_ref["sha256"] or receipt["qualification"] is not None
            or receipt["providerCalls"] is not None or receipt["sqlMutation"] is not False
            or (phase == "candidate") != (receipt["candidateSha256"] is not None)):
        raise ValueError("actual setup receipt differs from its completed phase")
    candidate_ref = None
    if phase == "candidate":
        candidate, candidate_ref = _read_json(native, private_command, tools["python"], output + "/candidate.json", maximum=4096)
        if (candidate_ref["sha256"] != receipt["candidateSha256"]
                or candidate["placement_prefix"] != coordinates["placementPrefix"]
                or candidate["source_digest"] != offered["sourceDigest"]
                or candidate["profile_digest"] != receipt["profileDigest"]):
            raise ValueError("produced candidate differs from the offered setup")
    return {"profile": profile, "profileFile": profile_ref, "receipt": receipt,
        "inputFile": offered_ref, "candidateReference": candidate_ref,
        "receiptFile": reference, "candidateFile": output + "/candidate.json" if phase == "candidate" else None,
        "candidateSignatureFile": output + "/candidate.signature" if phase == "candidate" else None,
        "qualification": None}


def scan_external_oci_registry(controls, coordinates, credential_report, source_trust_keys,
                               consumers, registry_name="containers"):
    """Require installed List projection, then use ordinary scan and promotion."""
    _control_pair(controls, coordinates)
    domain = consumers["HUB_EXTERNAL_COPY_CONSUMER"]["domains"][0]
    listing = domain["list_cohort"]
    if (listing["credential"]["purpose"] != "list" or listing["allowed_effects"] != ["list"]
            or listing not in consumers["HUB_EXTERNAL_OBJECT_CONSUMER"]["cohorts"]):
        raise ValueError("ordinary registry scan requires the independently installed List cohort")
    return controls.create_external_registry(credential_report["organization"], credential_report["binding"],
        registry_name, source_trust_keys, "external-oci", coordinates["placementPrefix"],
        credential_report["currentSqlPins"]["currentWriteRevision"], True)
