//! Verifies the versioned reproduction artifact format.

#![forbid(unsafe_code)]

use std::error::Error;

use crucible_harness::reproduction::{
    ComponentKind, ComponentPayload, ContentAddressedComponent, PinnedBuildIdentity,
    RecordedDecision, ReproductionArtifact, ReproductionArtifactError, ReproductionSchedule,
    mock_e2e_reproduction_artifact,
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
    assert!(!decoded.fingerprint_tail.is_empty());
    assert!(!decoded.sampling_config.regions.is_empty());
    assert!(
        decoded
            .component_payloads
            .iter()
            .any(|payload| payload.digest == decoded.scenario.digest)
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
            artifact_abi: String::from("crucible.reproduction-artifact.v1"),
            qemu_build_id: crucible_harness::reproduction::content_address_bytes(b"qemu"),
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
            artifact_abi: String::from("crucible.reproduction-artifact.v1"),
            qemu_build_id: crucible_harness::reproduction::content_address_bytes(b"qemu"),
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
