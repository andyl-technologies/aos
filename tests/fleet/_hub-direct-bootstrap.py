"""Bootstrap genuine External SQL metadata before physical authority review.

Every row originates in the authenticated browser API and the real credential
controller. The Worker operator has SELECT-only SQL access and keeps provider
material locally. This phase returns current metadata; it grants no physical
admission, runtime acceptance or provider qualification.
"""

import hashlib
import json
import os
from pathlib import Path


def bootstrap_external_direct(client, worker, database_machine, tools,
                              database_host, provider_material, coordinates):
    """Exercise actual API registration, unstaged refusal and provider probes."""
    token = direct_root_browser_token(
        client, tools["curl"], tools["python"], private_guest_command,
    )
    controls = DirectBootstrapControls(
        client, tools["curl"], tools["python"], token, private_guest_command,
        refresh_token=lambda: direct_root_browser_token(
            client, tools["curl"], tools["python"], private_guest_command,
            reuse_session=True,
        ),
    )
    organization, binding = controls.create_external_binding(
        "fleet-direct", "External Fleet Qualification", "fleet-direct-external-binding",
        "external-qualified", coordinates,
    )
    reader = provision_operator_reader(
        database_machine, worker, tools["python"], tools["postgres"], database_host,
        selected_tables=CREDENTIAL_CUSTODY_METADATA_TABLES,
    )
    version_references = {
        purpose: f"secret://fleet/direct/{purpose}/v1"
        for purpose in ("read", "presign", "list", "delete", "write")
    }
    versions = install_operator_provider_versions(
        worker, tools["python"], provider_material, version_references,
    )

    def stage_original(operation_id, purpose):
        return stage_queued_provider_credential(
            worker, tools["python"], tools["authorityBootstrap"], operation_id,
            purpose, tools["deploymentId"], tools["workerUrl"],
            tools["storageWorkKeyFile"], versions["manifestFile"],
        )

    validated = controls.validate_external_credentials(
        organization["slug"], binding["spec"]["name"], version_references,
        versions["materialSha256"], stage_original,
    )
    current_binding = controls.get_external_binding(
        organization["slug"], binding["spec"]["name"],
    )
    pins = read_operator_binding_pins(
        worker, tools["postgres"], database_host, current_binding,
    )
    report = {
        "version": 1, "organization": organization, "binding": current_binding,
        "operatorReader": reader, "operatorVersions": versions,
        "credentialOperations": validated, "currentSqlPins": pins,
        "controls": controls.observations,
        "scope": "actual API/controller/Worker custody prerequisite; no physical or runtime admission",
    }
    root = Path("external-direct-bootstrap")
    root.mkdir(mode=0o700)
    body = json.dumps(report, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    descriptor = os.open(root / "actual-bootstrap.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    print("Actual External credential bootstrap retained:", hashlib.sha256(body).hexdigest(), flush=True)
    return controls, report, hashlib.sha256(body).hexdigest()


def prepare_external_authority(controls, credential_report, worker, native, tools,
                               observation_hashes, provider_report_bytes, renewal_key):
    """Obtain independent physical review, then apply and export real authority."""
    provider_sha256 = hashlib.sha256(provider_report_bytes).hexdigest()
    if observation_hashes.get("providerObservations") != provider_sha256:
        raise ValueError("physical review must bind the actual retained provider report")
    required_observations = {
        "credentialBootstrap", "providerObservations", "providerInventory",
        "guardNamespace", "installation", "clockObservations",
    }
    if not required_observations.issubset(observation_hashes):
        raise ValueError("physical review omitted actual namespace, custody or clock observations")
    credential_bytes = Path("external-direct-bootstrap/actual-bootstrap.json").read_bytes()
    if (
        len(credential_bytes) > 1048576
        or hashlib.sha256(credential_bytes).hexdigest() != observation_hashes["credentialBootstrap"]
        or json.loads(credential_bytes) != credential_report
    ):
        raise ValueError("physical review differs from the retained actual credential bootstrap")
    reviewed = await_direct_review("external-physical-authority", observation_hashes, {
        "authority", "issuerInstallation", "timingProfile", "clockUncertaintySeconds",
        "clockCommitLatencySeconds", "issuerSigningKeyId", "providerContract",
        "privateStagePolicy", "checksumAlgorithm", "maximumGrantLifetimeSeconds",
    })
    selection = reviewed["selection"]
    authority = selection["authority"]
    installation = selection["issuerInstallation"]
    expected_authority = {
        "authority_id": authority["authorityId"],
        "guard_namespace_id": authority["guardNamespaceId"],
        "physical_resource_evidence_digest": authority["physicalResourceEvidenceDigest"],
        "qualification_digest": authority["qualificationDigest"],
        "qualified_managed_prefix": authority["qualifiedManagedPrefix"],
    }
    if (
        installation["authority"] != expected_authority
        or installation["executor_identity"] != authority["executorIdentity"]
    ):
        raise ValueError("selected issuer differs from the independently selected physical authority")

    # Observe Native's time immediately before the bounded attestation. Browser
    # controls refresh their bearer before each new request after review waits.
    actual_time = int(private_guest_command(native, (
        f"{tools['python']} -c 'import time; print(int(time.time()))'"
    )).strip())
    admission = admit_external_fixture_authority(
        controls, credential_report["organization"]["slug"], credential_report["binding"],
        credential_report["currentSqlPins"], authority, actual_time,
    )
    issuer = provision_external_issuer(
        native, worker, tools["python"], tools["openssl"], installation,
        selection["timingProfile"], selection["clockUncertaintySeconds"],
        selection["clockCommitLatencySeconds"], selection["issuerSigningKeyId"],
        renewal_key, tools["issuerCertificate"], tools["issuerPrivateKey"],
        tools["issuerCertificateHost"],
    )
    exported = export_external_authority(
        worker, native, tools["python"], tools["authorityBootstrap"], tools["authority"],
        authority["authorityId"], authority["associationId"], tools["deploymentId"],
        credential_report["binding"]["spec"]["s3"]["prefix"],
    )
    consumers = external_consumer_configuration(
        exported["bootstrap"], selection["providerContract"], provider_report_bytes,
        selection["privateStagePolicy"], selection["checksumAlgorithm"],
        selection["maximumGrantLifetimeSeconds"],
    )
    process = start_external_issuer(native, tools["python"], tools["authority"])
    return {
        "review": reviewed, "admission": admission, "issuer": issuer,
        "exported": exported, "consumerBindings": consumers, "issuerProcess": process,
        "scope": "actual reviewed SQL/issuer setup; consumer installation, fresh lease and runtime acceptance pending",
    }
