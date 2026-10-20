"""Create genuine binding originals and project actual exports for lease scale.

These helpers use the normal reviewed API/controller/operator interfaces. Their
JSON checks are measurement plumbing, not the Rust publication or signature
authority. The configured Worker and issuer independently validate the exports.
No helper result establishes clock, provider, namespace or scale qualification.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat


PURPOSES = ("presign", "read", "list", "delete", "write")


def _hex(value, length):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value):
        raise ValueError("selected scale commitment differs")
    return value


def _closed(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("duplicate export field")
        value[name] = item
    return value


def _encode(value):
    # Rust struct field order and wire integer strings arrive in its canonical
    # export. Preserve those bytes rather than sorting nested protocol fields.
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()


def bootstrap_scale_bindings(controls, run_id, organization, selections,
                             stage_original, read_current_sql_pins):
    """Create and genuinely validate sixteen independent binding originals.

    `stage_original` invokes the existing protected operator for the exact
    queued task. `read_current_sql_pins` uses the actual restricted SQL reader.
    Neither callback may install validated flags or fabricate readiness.
    """
    _hex(run_id, 32)
    if len(selections) != 16 or len({row["stableId"] for row in selections}) != 16:
        raise ValueError("scale requires sixteen distinct selected bindings")
    reports = []
    for index, selected in enumerate(selections):
        if set(selected) != {"stableId", "name", "coordinates", "versions", "fingerprint"}:
            raise ValueError("scale binding selection differs")
        if set(selected["versions"]) != set(PURPOSES):
            raise ValueError("scale binding requires all actual credential purposes")
        _hex(selected["fingerprint"], 64)
        coordinates = selected["coordinates"]
        if set(coordinates) != {"bucket", "prefix", "endpoint", "signingRegion", "accessMode"} or coordinates["accessMode"] != "private":
            raise ValueError("scale binding must use selected private coordinates")
        label = f"lease-scale-{run_id}-{index:02d}"
        binding = controls.reviewed("BindingService", "PlanCreateBinding", "CreateBinding", {
            "stableId": selected["stableId"], "ownerScopeKey": organization["ownerScopeKey"],
            "expectedResourceVersion": "", "spec": {"name": selected["name"], "s3": coordinates},
        }, label + "-binding")["binding"]
        if binding["stableId"] != selected["stableId"] or binding["ownerScopeKey"] != organization["ownerScopeKey"]:
            raise ValueError("actual binding creation returned another original")

        operations = {}
        for purpose in PURPOSES:
            current = controls.get_external_binding(organization["slug"], selected["name"])
            credential = controls.reviewed("BindingService", "PlanSetBindingCredential", "SetBindingCredential", {
                "bindingId": current["stableId"], "purpose": purpose,
                "secretVersionRef": selected["versions"][purpose],
                "credentialFingerprint": selected["fingerprint"],
                "expectedResourceVersion": current["resourceVersion"], "expectedCurrentGeneration": "0",
            }, label + "-set-" + purpose)["credential"]
            if (credential["bindingId"] != current["stableId"] or credential["purpose"] != purpose
                    or credential["secretVersionRef"] != selected["versions"][purpose]
                    or credential["credentialFingerprint"] != selected["fingerprint"]
                    or credential["validationState"] == "valid"):
                raise ValueError("credential was substituted or prematurely validated")
            queued = controls.reviewed("BindingService", "PlanValidateBindingCredential", "ValidateBindingCredential", {
                "bindingId": current["stableId"], "purpose": purpose,
                "generation": str(credential["generation"]),
                "expectedResourceVersion": credential["resourceVersion"],
            }, label + "-validate-" + purpose)["operation"]
            operation_id = queued["operationId"]
            failed = controls.wait_operation(operation_id, {"failed"})
            staged = stage_original(index, operation_id, purpose)
            if controls.operation(operation_id)["resourceVersion"] != failed["resourceVersion"]:
                raise ValueError("unstaged original changed before explicit retry")
            controls.retry_failed_operation(failed, label + "-retry-" + purpose)
            completed = controls.wait_operation(operation_id, {"succeeded"})
            operations[purpose] = {"operationId": operation_id, "initialUnstagedFailure": failed,
                "stageReceipt": staged, "completedOperation": completed}

        current = controls.get_external_binding(organization["slug"], selected["name"])
        pins = read_current_sql_pins(current)
        if pins["bindingStableId"] != current["stableId"] or pins["bindingResourceVersion"] != current["resourceVersion"]:
            raise ValueError("actual API and SQL binding pins differ")
        reports.append({"binding": current, "currentSqlPins": pins, "credentialOperations": operations})
    return reports


def admit_scale_authority(controls, run_id, org_slug, reports, reviewed,
                          association_ids, observed_native_time):
    """Apply one reviewed physical authority with sixteen actual associations.

    Namespace, resource, policy and qualification digests are independently
    selected inputs. Genuine credential controller results precede this step;
    root Plan/Apply and later current-SQL export remain the actual authority.
    """
    _hex(run_id, 32)
    if len(reports) != 16 or len(association_ids) != 16 or len(set(association_ids)) != 16:
        raise ValueError("scale admission requires sixteen exact originals")
    expected = {"authorityId", "aliasId", "attestationId", "guardNamespaceId",
        "physicalResourceEvidenceDigest", "qualificationDigest", "qualifiedManagedPrefix",
        "equivalenceEvidenceDigest", "providerPolicyEvidenceDigest", "executorIdentity",
        "attestationLifetimeSeconds"}
    if set(reviewed) != expected or type(observed_native_time) is not int or observed_native_time <= 0:
        raise ValueError("reviewed scale authority or actual Native clock differs")
    lifetime = reviewed["attestationLifetimeSeconds"]
    if type(lifetime) is not int or not 1 <= lifetime <= 3600:
        raise ValueError("scale attestation exceeds the declared fixture bound")
    members, selected = [], []
    for association_id, report in zip(association_ids, reports):
        old, pins = report["binding"], report["currentSqlPins"]
        current = controls.get_external_binding(org_slug, old["spec"]["name"])
        if (current != old or pins["bindingStableId"] != current["stableId"]
                or pins["bindingResourceVersion"] != current["resourceVersion"]
                or pins["bindingPrefix"] != current["spec"]["s3"]["prefix"]):
            raise ValueError("binding changed before physical admission")
        credentials = pins["credentials"]
        if set(row["purpose"] for row in credentials) != set(PURPOSES) or len(credentials) != 5:
            raise ValueError("scale membership lacks exact current credential purposes")
        if any(row["validationState"] != "valid" or not re.fullmatch(r"[1-9][0-9]*", row["validatedAt"] or "") for row in credentials):
            raise ValueError("scale credential has no genuine current validation")
        writer = controls.call("BindingService", "GetBindingWriteRevision", {
            "binding": {"organization": {"orgSlug": org_slug, "name": current["spec"]["name"]}},
            "revision": pins["currentWriteRevision"],
        })["revision"]
        write = next(row for row in credentials if row["purpose"] == "write")
        if (writer["bindingId"] != current["stableId"]
                or str(writer["revision"]) != pins["currentWriteRevision"]
                or str(writer["writeCredentialGeneration"]) != write["generation"]
                or writer["writeCredentialVersionRef"] != write["secretVersionRef"]
                or writer["validationState"] != "valid" or writer["writesSupported"] is not True):
            raise ValueError("scale writer has no matching current controller evidence")
        members.extend({"associationId": association_id, **{name: row[name]
            for name in ("purpose", "generation", "secretVersionRef", "credentialFingerprint")}}
            for row in credentials)
        selected.append((association_id, current, pins))
    providers = [row[1]["spec"]["s3"] for row in selected]
    coordinates = lambda row: (row["endpoint"], row["bucket"])
    if any(coordinates(row) != coordinates(providers[0]) for row in providers):
        raise ValueError("one scale authority cannot silently adopt another physical alias")

    label = "lease-scale-" + run_id
    creation = {name: reviewed[name] for name in ("authorityId", "guardNamespaceId",
        "physicalResourceEvidenceDigest", "qualificationDigest", "qualifiedManagedPrefix")}
    controls.authority_decision({"create": creation}, "", label + "-authority")
    head = controls.call("StorageAuthorityService", "GetAuthority", {"authorityId": reviewed["authorityId"]})
    controls.authority_decision({"approveAlias": {"aliasId": reviewed["aliasId"],
        "authorityId": reviewed["authorityId"], "address": {"dnsName": providers[0]["endpoint"]["dnsName"],
            "port": providers[0]["endpoint"]["port"], "bucket": providers[0]["bucket"]},
        "equivalenceEvidenceDigest": reviewed["equivalenceEvidenceDigest"]}}, head["resourceVersion"], label + "-alias")
    for index, (association_id, binding, pins) in enumerate(selected):
        controls.authority_decision({"associateBinding": {"associationId": association_id,
            "authorityId": reviewed["authorityId"], "aliasId": reviewed["aliasId"],
            "bindingId": pins["bindingId"], "bindingStableId": binding["stableId"],
            "bindingResourceVersion": binding["resourceVersion"],
            "bindingWriteRevision": pins["currentWriteRevision"], "bindingPrefix": pins["bindingPrefix"]}},
            binding["resourceVersion"], label + f"-association-{index:02d}")
    head = controls.call("StorageAuthorityService", "GetAuthority", {"authorityId": reviewed["authorityId"]})
    controls.authority_decision({"attest": {"attestationId": reviewed["attestationId"],
        "authorityId": reviewed["authorityId"], "managedPrefix": reviewed["qualifiedManagedPrefix"],
        "qualificationDigest": reviewed["qualificationDigest"],
        "providerPolicyEvidenceDigest": reviewed["providerPolicyEvidenceDigest"],
        "executorIdentity": reviewed["executorIdentity"],
        "credentials": sorted(members, key=lambda row: (row["associationId"], row["purpose"])),
        "validUntil": str(observed_native_time + lifetime)}}, head["resourceVersion"], label + "-attestation")
    controls.authority_decision({"setAdmission": {"authorityId": reviewed["authorityId"],
        "expectedGeneration": "0", "guardNamespaceId": reviewed["guardNamespaceId"],
        "state": "STORAGE_AUTHORITY_DESIRED_STATE_ADMITTED", "attestationId": reviewed["attestationId"],
        "associationIds": sorted(association_ids)}}, "0", label + "-admission")
    return controls.call("StorageAuthorityService", "GetAuthority", {"authorityId": reviewed["authorityId"]})


def export_scale_associations(worker, private_command, executable, database_url_file,
                              issuer_configuration, issuer_public_key_file,
                              deployment_id, authority_id, selections, output_root):
    """Run sixteen actual per-association exports into new private directories.

    The selected parent must already be private; the bootstrap CLI creates each
    child exclusively and rechecks current SQL. An ambiguous command is retained
    by the caller and is never automatically retried here.
    """
    if len(selections) != 16 or len({row["associationId"] for row in selections}) != 16:
        raise ValueError("scale export requires sixteen actual associations")
    paths = [executable, database_url_file, issuer_configuration, issuer_public_key_file, output_root]
    if any(not isinstance(path, str) or not path.startswith("/") for path in paths):
        raise ValueError("scale export requires explicit selected tool and custody paths")
    exported = []
    for index, selected in enumerate(selections):
        if set(selected) != {"associationId", "admittedPrefix"}:
            raise ValueError("scale association selection differs")
        destination = output_root + f"/association-{index:02d}"
        arguments = [executable, "--database-url-file", database_url_file, "export",
            "--authority-id", authority_id, "--association-id", selected["associationId"],
            "--deployment-id", deployment_id, "--issuer-configuration", issuer_configuration,
            "--issuer-public-key-file", issuer_public_key_file,
            "--admitted-prefix", selected["admittedPrefix"], "--output", destination]
        private_command(worker, shlex.join(arguments), timeout=120)
        exported.append({**selected, "directory": destination})
    return exported


def _private_export(path):
    path = Path(path)
    if not path.is_absolute() or path.parent.resolve() != path.parent:
        raise ValueError("export path differs from selected private custody")
    parent = path.parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
        raise ValueError("export parent is not owner-private")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or before.st_size > 1024 * 1024):
            raise ValueError("export file custody differs")
        data = source.read(1024 * 1024 + 1)
        after = os.fstat(source.fileno())
    identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns)
    if identity(before) != identity(after) or identity(before) != identity(path.stat(follow_symlinks=False)):
        raise ValueError("export changed during collection")
    return data, identity(before)


def project_scale_exports(directories, run_id, isolate_labels):
    """Copy actual export fields into bounded consumer/probe configurations.

    This projection does not authenticate SQL history or invent credentials.
    All canonical full publications must be byte-identical. The existing Rust
    consumer validator and issuer retain their independent authority checks.
    """
    _hex(run_id, 32)
    if len(directories) != 16 or len(set(directories)) != 16 or len(isolate_labels) != 4 or len(set(isolate_labels)) != 4:
        raise ValueError("scale projection requires sixteen exports and four process labels")
    for label in isolate_labels:
        _hex(label, 32)
    values, retained, publication_bytes = [], [], None
    for directory in directories:
        paths = [Path(directory) / name for name in ("bootstrap.json", "publication.json")]
        originals = [_private_export(path) for path in paths]
        bootstrap = json.loads(originals[0][0], object_pairs_hook=_closed)
        publication = json.loads(originals[1][0], object_pairs_hook=_closed)
        if bootstrap["version"] != 1 or bootstrap["publication"] != publication:
            raise ValueError("bootstrap and actual publication differ")
        if _encode(bootstrap) != originals[0][0] or _encode(publication) != originals[1][0]:
            raise ValueError("export is not canonical Rust JSON")
        if publication_bytes is not None and publication_bytes != originals[1][0]:
            raise ValueError("scale exports do not share the full current SQL publication")
        publication_bytes = originals[1][0]
        values.append(bootstrap)
        retained.extend((path, identity, hashlib.sha256(body).hexdigest())
            for path, (body, identity) in zip(paths, originals))
    first = values[0]
    common = ("issuer_installation", "issuer_key_id", "issuer_public_key", "timing_profile", "clock_uncertainty", "deployment_id")
    if any(any(value[field] != first[field] for field in common) for value in values):
        raise ValueError("scale exports have incompatible installation or profile")
    profile = first["timing_profile"]
    if (profile["maximum_lifetime"] not in {"8", "120"}
            or type(first["clock_uncertainty"]) is not int or first["clock_uncertainty"] != 2):
        raise ValueError("actual export does not select the prospective local policy")
    cohorts = [value[purpose + "_cohort"] for value in values for purpose in ("read", "write")]
    if len({_encode(value) for value in cohorts}) != 32 or len({value["association"]["association_id"] for value in cohorts}) != 16:
        raise ValueError("scale exports do not project thirty-two distinct genuine cohorts")
    publication = first["publication"]
    object_consumer = {"version": 1, "guard_namespace_id": publication["authority"]["guard_namespace_id"],
        "executor_identity": first["issuer_installation"]["executor_identity"],
        "issuer_key_id": first["issuer_key_id"], "issuer_public_key": first["issuer_public_key"],
        "timing_profile": profile, "clock_uncertainty": first["clock_uncertainty"],
        "aliases": publication["aliases"], "cohorts": cohorts, "publications": [publication]}
    if len(_encode(object_consumer)) > 128 * 1024:
        raise ValueError("genuine scale consumer exceeds the unchanged production bound")
    configurations = []
    for label in isolate_labels:
        fixture = {"version": 1, "run_id": run_id, "isolate_label": label,
            "installations": [first["issuer_installation"]]}
        configurations.append({"objectConsumer": object_consumer, "fixture": fixture,
            "configurationDigest": hashlib.sha256(_encode([object_consumer, fixture])).hexdigest()})
    for path, identity, digest in retained:
        body, observed = _private_export(path)
        if observed != identity or hashlib.sha256(body).hexdigest() != digest:
            raise ValueError("an earlier actual export changed during projection")
    return {"configurations": configurations,
        "cohortDigests": [hashlib.sha256(_encode(value)).hexdigest() for value in cohorts],
        "exports": [{"path": str(path), "sha256": digest} for path, _, digest in retained],
        "publicationSha256": hashlib.sha256(publication_bytes).hexdigest(),
        "qualification": None, "scope": "actual export projection; Rust authority and runtime joins required"}
