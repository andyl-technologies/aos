//! Verifies the versioned reproduction artifact format.

#![forbid(unsafe_code)]

use std::error::Error;

use crucible_harness::adversarial::{HostAdversaryProfile, canonical_host_adversary_matrix};
use crucible_harness::reproduction::{
    ComponentKind, ComponentPayload, ContentAddressedComponent,
    PRODUCER_BACKEND_BUILD_ID_COMPONENT_NAME, PRODUCER_CANONICAL_LOG_COMPONENT_NAME,
    PRODUCER_FINAL_FINGERPRINT_COMPONENT_NAME, PinnedBuildIdentity, REPRODUCTION_ARTIFACT_SCHEMA,
    RecordedDecision, ReproductionArtifact, ReproductionArtifactError, ReproductionSchedule,
    mock_e2e_reproduction_artifact, mock_reproduction_build_identity,
    verify_mock_machine_independent_reproduction,
    verify_mock_machine_independent_reproduction_bytes,
};

#[test]
fn reproduction_artifact_format_round_trips_seed_scenario_schedule_and_pinned_identities()
-> Result<(), Box<dyn Error>> {
    let artifact = mock_e2e_reproduction_artifact()?;
    let encoded = artifact.encode()?;
    let decoded = ReproductionArtifact::decode(&encoded)?;

    assert_eq!(decoded, artifact);
    assert_eq!(decoded.seed, 0xe2e0_0010);
    assert_eq!(decoded.scenario.kind, ComponentKind::ScenarioDef);
    assert!(decoded.scenario.digest.starts_with("crucible-hash:"));
    assert_eq!(
        decoded.scenario.store_uri,
        format!("cas:{}", decoded.scenario.digest)
    );
    assert!(decoded.components.iter().any(|component| {
        component.kind == ComponentKind::ScenarioDef
            && component.digest == decoded.scenario.digest
            && component.store_uri == decoded.scenario.store_uri
    }));
    assert!(decoded.schedule.decisions.len() > 8);
    assert!(
        decoded
            .schedule
            .decisions
            .iter()
            .enumerate()
            .all(|(sequence, decision)| decision.sequence == sequence as u64)
    );
    assert_eq!(decoded.build_identity.artifact_abi, decoded.schema_version);
    assert!(
        decoded
            .build_identity
            .qemu_build_id
            .starts_with("crucible-hash:")
    );
    assert!(!decoded.build_identity.qemu_patch_series_hash.is_empty());
    assert_eq!(decoded.build_identity.shmem_abi_version, "1");
    assert_eq!(decoded.build_identity.guest_host_protocol_version, "1");
    assert_eq!(decoded.build_identity.rpc_abi_version, "2.0.0");
    assert_eq!(decoded.build_identity.rpc_abi_build, "crucible-rpc-abi-v2");
    assert!(!decoded.fingerprint_tail.is_empty());
    assert!(!decoded.sampling_config.regions.is_empty());
    assert!(
        decoded
            .component_payloads
            .iter()
            .any(|payload| payload.digest == decoded.scenario.digest)
    );
    assert!(
        decoded
            .components
            .iter()
            .any(|component| component.name == PRODUCER_CANONICAL_LOG_COMPONENT_NAME)
    );
    assert!(
        decoded
            .components
            .iter()
            .any(|component| component.name == PRODUCER_FINAL_FINGERPRINT_COMPONENT_NAME)
    );

    Ok(())
}

#[test]
fn reproduction_artifact_format_rejects_mutated_schedule_digest() -> Result<(), Box<dyn Error>> {
    let mut artifact = mock_e2e_reproduction_artifact()?;
    artifact.schedule.digest = artifact.scenario.digest.clone();

    let error = match artifact.validate() {
        Ok(()) => panic!("mutated schedule digest must be rejected"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ReproductionArtifactError::ScheduleDigestMismatch { .. }
    ));

    Ok(())
}

#[test]
fn reproduction_artifact_format_rejects_unresolved_scenario_component() -> Result<(), Box<dyn Error>>
{
    let mut artifact = mock_e2e_reproduction_artifact()?;
    artifact.components.clear();

    let error = match artifact.validate() {
        Ok(()) => panic!("missing scenario component reference must be rejected"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ReproductionArtifactError::ScenarioComponentMissing { .. }
    ));

    Ok(())
}

#[test]
fn reproduction_artifact_format_rejects_unpinned_or_malformed_identities()
-> Result<(), Box<dyn Error>> {
    let mut artifact = mock_e2e_reproduction_artifact()?;
    artifact.build_identity.qemu_build_id = String::from("host-qemu");

    let error = match artifact.validate() {
        Ok(()) => panic!("unpinned QEMU build identity must be rejected"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ReproductionArtifactError::InvalidDigest {
            field: "build_identity.qemu_build_id",
            ..
        }
    ));

    Ok(())
}

#[test]
fn reproduction_artifact_format_enforces_total_schedule_order() -> Result<(), Box<dyn Error>> {
    let mut artifact = mock_e2e_reproduction_artifact()?;
    artifact.schedule.decisions.swap(1, 2);

    let error = match ReproductionSchedule::from_decisions(artifact.schedule.decisions) {
        Ok(_) => panic!("out-of-order schedule must be rejected"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ReproductionArtifactError::DecisionOutOfOrder {
            expected: 1,
            actual: 2
        }
    ));

    Ok(())
}

#[test]
fn reproduction_artifact_format_keeps_large_components_by_reference() -> Result<(), Box<dyn Error>>
{
    let scenario_bytes = b"large scenario body kept outside the artifact";
    let scenario = ContentAddressedComponent::from_bytes(
        ComponentKind::ScenarioDef,
        "external-scenario",
        "application/vnd.crucible.scenario+json",
        scenario_bytes,
    )?;
    let payload_digest = crucible_harness::reproduction::content_address_bytes(b"decision");
    let decision = RecordedDecision {
        sequence: 0,
        virtual_time_ticks: 1,
        node: String::from("node-a"),
        kind: String::from("deliver"),
        payload_digest,
    };
    let artifact = ReproductionArtifact::from_parts(
        7,
        PinnedBuildIdentity {
            engine_version: String::from("0.1.0"),
            engine_abi: String::from("engine-abi:v1"),
            artifact_abi: REPRODUCTION_ARTIFACT_SCHEMA.to_string(),
            qemu_build_id: crucible_harness::reproduction::content_address_bytes(b"qemu"),
            qemu_patch_series_hash: String::from(
                "crucible-hash:e1e3694e392946298e90eb185ad349906d47acc81ad934cb631fe9438b4bfc5d",
            ),
            shmem_abi_version: String::from("1"),
            guest_host_protocol_version: String::from("1"),
            rpc_abi_version: String::from("2.0.0"),
            rpc_abi_build: String::from("crucible-rpc-abi-v2"),
            plugin_abi: String::from("plugin-abi:v1"),
        },
        scenario.clone(),
        vec![decision],
        vec![scenario],
        Vec::new(),
        Vec::new(),
        crucible_harness::reproduction::FingerprintSamplingConfig {
            fine: String::from("every-decision"),
            coarse: String::from("final"),
            regions: vec![String::from("tail")],
        },
    )?;
    let encoded = String::from_utf8(artifact.encode()?)?;

    assert!(!encoded.contains("large scenario body kept outside the artifact"));
    assert!(encoded.contains("cas:crucible-hash:"));
    assert!(encoded.len() < 2048);

    Ok(())
}

#[test]
fn reproduction_artifact_format_rejects_duplicate_singleton_lines() -> Result<(), Box<dyn Error>> {
    let artifact = mock_e2e_reproduction_artifact()?;
    let mut encoded = String::from_utf8(artifact.encode()?)?;
    encoded.push_str("seed\t9\n");

    let error = match ReproductionArtifact::decode(encoded.as_bytes()) {
        Ok(_) => panic!("duplicate seed line must be rejected"),
        Err(error) => error,
    };

    assert!(matches!(error, ReproductionArtifactError::Decode { .. }));

    Ok(())
}

#[test]
fn reproduction_artifact_format_rejects_noncanonical_line_order() -> Result<(), Box<dyn Error>> {
    let artifact = mock_e2e_reproduction_artifact()?;
    let encoded = String::from_utf8(artifact.encode()?)?;
    let mut lines = encoded.lines().collect::<Vec<_>>();
    lines.swap(0, 1);
    let reordered = format!("{}\n", lines.join("\n"));

    let error = match ReproductionArtifact::decode(reordered.as_bytes()) {
        Ok(_) => panic!("noncanonical line order must be rejected"),
        Err(error) => error,
    };

    assert!(matches!(error, ReproductionArtifactError::Decode { .. }));

    Ok(())
}

#[test]
fn reproduction_artifact_format_rejects_payload_digest_mismatch() -> Result<(), Box<dyn Error>> {
    let scenario_bytes = b"inline scenario bytes";
    let scenario = ContentAddressedComponent::from_bytes(
        ComponentKind::ScenarioDef,
        "inline-scenario",
        "application/vnd.crucible.scenario+json",
        scenario_bytes,
    )?;
    let decision = RecordedDecision {
        sequence: 0,
        virtual_time_ticks: 1,
        node: String::from("node-a"),
        kind: String::from("deliver"),
        payload_digest: crucible_harness::reproduction::content_address_bytes(b"decision"),
    };
    let mut payload = ComponentPayload::from_bytes(scenario_bytes);
    payload.bytes.push(b'!');

    let error = match ReproductionArtifact::from_parts(
        7,
        PinnedBuildIdentity {
            engine_version: String::from("0.1.0"),
            engine_abi: String::from("engine-abi:v1"),
            artifact_abi: REPRODUCTION_ARTIFACT_SCHEMA.to_string(),
            qemu_build_id: crucible_harness::reproduction::content_address_bytes(b"qemu"),
            qemu_patch_series_hash: String::from(
                "crucible-hash:e1e3694e392946298e90eb185ad349906d47acc81ad934cb631fe9438b4bfc5d",
            ),
            shmem_abi_version: String::from("1"),
            guest_host_protocol_version: String::from("1"),
            rpc_abi_version: String::from("2.0.0"),
            rpc_abi_build: String::from("crucible-rpc-abi-v2"),
            plugin_abi: String::from("plugin-abi:v1"),
        },
        scenario.clone(),
        vec![decision],
        vec![scenario],
        vec![payload],
        Vec::new(),
        crucible_harness::reproduction::FingerprintSamplingConfig {
            fine: String::from("every-decision"),
            coarse: String::from("final"),
            regions: vec![String::from("tail")],
        },
    ) {
        Ok(_) => panic!("payload digest mismatch must be rejected"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ReproductionArtifactError::PayloadDigestMismatch { .. }
    ));

    Ok(())
}

#[test]
fn reproduction_artifact_machine_verification_replays_identically_across_host_profiles()
-> Result<(), Box<dyn Error>> {
    let artifact = mock_e2e_reproduction_artifact()?;
    let report = verify_mock_machine_independent_reproduction_bytes(
        &artifact.encode()?,
        canonical_host_adversary_matrix(),
        &mock_reproduction_build_identity(),
    )?;

    assert_eq!(report.artifact_digest, artifact.digest()?);
    assert_eq!(report.baseline.artifact_digest, report.artifact_digest);
    assert!(report.reproduced_on_different_machine_profiles.len() >= 2);
    for reproduced in &report.reproduced_on_different_machine_profiles {
        assert_ne!(reproduced.profile, report.baseline.profile);
        assert_eq!(reproduced.artifact_digest, report.artifact_digest);
        assert_eq!(reproduced.canonical_log, report.baseline.canonical_log);
        assert_eq!(
            reproduced.final_fingerprint,
            report.baseline.final_fingerprint
        );
    }

    Ok(())
}

#[test]
fn reproduction_artifact_machine_verification_rejects_build_identity_drift()
-> Result<(), Box<dyn Error>> {
    let artifact = mock_e2e_reproduction_artifact()?;
    let mut expected = mock_reproduction_build_identity();
    expected.qemu_build_id =
        crucible_harness::reproduction::content_address_bytes(b"different-qemu-build");

    let error = match verify_mock_machine_independent_reproduction(
        &artifact,
        canonical_host_adversary_matrix(),
        &expected,
    ) {
        Ok(_) => panic!("machine reproduction must reject QEMU identity drift"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ReproductionArtifactError::BuildIdentityMismatch { .. }
    ));

    Ok(())
}

#[test]
fn reproduction_artifact_machine_verification_rejects_plugin_abi_drift()
-> Result<(), Box<dyn Error>> {
    let artifact = mock_e2e_reproduction_artifact()?;
    let mut expected = mock_reproduction_build_identity();
    expected.plugin_abi = String::from("different-plugin-abi");

    let error = match verify_mock_machine_independent_reproduction(
        &artifact,
        canonical_host_adversary_matrix(),
        &expected,
    ) {
        Ok(_) => panic!("machine reproduction must reject plugin ABI drift"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ReproductionArtifactError::BuildIdentityMismatch { .. }
    ));

    Ok(())
}

#[test]
fn reproduction_artifact_machine_verification_requires_different_machine_profile()
-> Result<(), Box<dyn Error>> {
    let artifact = mock_e2e_reproduction_artifact()?;
    let profiles = [HostAdversaryProfile::quiet_single_core()];

    let error = match verify_mock_machine_independent_reproduction(
        &artifact,
        &profiles,
        &mock_reproduction_build_identity(),
    ) {
        Ok(_) => panic!("machine reproduction must require a different profile"),
        Err(error) => error,
    };

    assert_eq!(
        error,
        ReproductionArtifactError::MissingDifferentMachineProfile
    );

    Ok(())
}

#[test]
fn reproduction_artifact_machine_verification_rejects_producer_evidence_mismatch()
-> Result<(), Box<dyn Error>> {
    let mut artifact = mock_e2e_reproduction_artifact()?;
    let replacement = ComponentPayload::from_bytes(b"not-the-produced-canonical-log");
    let component = artifact
        .components
        .iter_mut()
        .find(|component| component.name == PRODUCER_CANONICAL_LOG_COMPONENT_NAME)
        .ok_or("producer log component missing")?;
    let old_digest = component.digest.clone();
    component.digest = replacement.digest.clone();
    component.store_uri = format!("cas:{}", component.digest);
    component.size_bytes = replacement.bytes.len() as u64;
    let payload = artifact
        .component_payloads
        .iter_mut()
        .find(|payload| payload.digest == old_digest)
        .ok_or("producer log payload missing")?;
    *payload = replacement;

    let error = match verify_mock_machine_independent_reproduction(
        &artifact,
        canonical_host_adversary_matrix(),
        &mock_reproduction_build_identity(),
    ) {
        Ok(_) => panic!("machine reproduction must compare against producer evidence"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ReproductionArtifactError::MachineReproductionMismatch { .. }
    ));

    Ok(())
}

#[test]
fn reproduction_artifact_machine_verification_rejects_scenario_payload_drift()
-> Result<(), Box<dyn Error>> {
    let mut artifact = mock_e2e_reproduction_artifact()?;
    let old_digest = artifact.scenario.digest.clone();
    let scenario_material = format!(
        "scenario\t{}\nnode\tmutated-node\tserver\n",
        artifact.scenario.name
    );
    let replacement = ComponentPayload::from_bytes(scenario_material.as_bytes());
    artifact.scenario.digest = replacement.digest.clone();
    artifact.scenario.store_uri = format!("cas:{}", artifact.scenario.digest);
    artifact.scenario.size_bytes = replacement.bytes.len() as u64;
    let component = artifact
        .components
        .iter_mut()
        .find(|component| {
            component.kind == ComponentKind::ScenarioDef && component.digest == old_digest
        })
        .ok_or("scenario component missing")?;
    component.digest = artifact.scenario.digest.clone();
    component.store_uri = artifact.scenario.store_uri.clone();
    component.size_bytes = artifact.scenario.size_bytes;
    let payload = artifact
        .component_payloads
        .iter_mut()
        .find(|payload| payload.digest == old_digest)
        .ok_or("scenario payload missing")?;
    *payload = replacement;

    let error = match verify_mock_machine_independent_reproduction(
        &artifact,
        canonical_host_adversary_matrix(),
        &mock_reproduction_build_identity(),
    ) {
        Ok(_) => panic!("machine reproduction must bind producer digest to ScenarioDef payload"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ReproductionArtifactError::ProducerArtifactDigestMismatch { .. }
    ));

    Ok(())
}

#[test]
fn reproduction_artifact_machine_verification_rejects_backend_build_id_drift()
-> Result<(), Box<dyn Error>> {
    let mut artifact = mock_e2e_reproduction_artifact()?;
    let replacement = ComponentPayload::from_bytes(b"different-backend-build-id");
    let component = artifact
        .components
        .iter_mut()
        .find(|component| component.name == PRODUCER_BACKEND_BUILD_ID_COMPONENT_NAME)
        .ok_or("producer backend build id component missing")?;
    let old_digest = component.digest.clone();
    component.digest = replacement.digest.clone();
    component.store_uri = format!("cas:{}", component.digest);
    component.size_bytes = replacement.bytes.len() as u64;
    let payload = artifact
        .component_payloads
        .iter_mut()
        .find(|payload| payload.digest == old_digest)
        .ok_or("producer backend build id payload missing")?;
    *payload = replacement;

    let error = match verify_mock_machine_independent_reproduction(
        &artifact,
        canonical_host_adversary_matrix(),
        &mock_reproduction_build_identity(),
    ) {
        Ok(_) => panic!("machine reproduction must bind backend build id to pinned QEMU identity"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ReproductionArtifactError::BuildIdentityMismatch { .. }
    ));

    Ok(())
}
