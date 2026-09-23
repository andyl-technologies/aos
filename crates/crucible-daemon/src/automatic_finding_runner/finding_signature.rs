//! Failure signatures and native replay-evidence binding.

use std::collections::BTreeSet;

use crucible::{
    ContentHash, EngineError, FailureClusterReportFailure, FailureKind, FailureTimeoutBudgetKind,
    FailureTriageReplayEvidence, FindingDiscoveryPath, FindingReproductionArtifact,
};
use crucible_campaign::{
    CampaignCodecError, CampaignExecutorStore, CampaignHash, ConfigurationArtifact, FindingKind,
    FindingSignature, FindingTarget, ObservationCandidate, ObservationStopSatisfaction,
    PolicyTimeoutKind, PropertyVerdict, PropertyVerdictSet, StopOutcome,
};

use super::{
    ASSERTION_FAILURE_CLASS, EXECUTION_QUANTA_TIMEOUT_CLASS, VIRTUAL_TIME_TIMEOUT_CLASS,
    divergence_fingerprint,
};
use crate::crucible_artifact::decode_crucible_configuration_artifact_with_owned_candidate;
use crate::{CrucibleArtifactError, CrucibleAttemptExecution, encode_crucible_scenario_artifact};

/// Selects the highest-priority authenticated failure represented by an observation.
///
/// Property failures take precedence over a modeled timeout reached
/// at the same boundary.
///
/// # Errors
///
/// Returns [`CampaignCodecError`] when the selected signature or one of its
/// content-addressed dependencies is invalid.
pub(crate) fn automatic_finding_signature(
    input: &CrucibleAttemptExecution,
    candidate: &ObservationCandidate,
) -> Result<Option<FindingSignature>, CampaignCodecError> {
    if let Some(signature) = property_violation_signature(input, candidate)? {
        return Ok(Some(signature));
    }
    let Some(timeout_kind) = observation_timeout_kind(candidate.observation().stop()) else {
        return Ok(None);
    };

    let failure_class = timeout_failure_class(timeout_kind);
    let fingerprint = timeout_fingerprint(input, failure_class)?;
    let coverage = candidate.coverage().id()?.content_id();
    FindingSignature::new(
        FindingKind::Timeout,
        fingerprint,
        None,
        String::from(failure_class),
        Some(FindingTarget::Configuration(candidate.child().id()?)),
        BTreeSet::from([coverage]),
    )
    .map(Some)
}

fn observation_timeout_kind(stop: &StopOutcome) -> Option<FailureTimeoutBudgetKind> {
    match stop {
        StopOutcome::Reached(crucible_campaign::StopCondition::ExecutionQuanta(_)) => {
            Some(FailureTimeoutBudgetKind::ExecutionQuanta)
        }
        StopOutcome::PolicyTimeout {
            kind: PolicyTimeoutKind::VirtualTime,
            ..
        } => Some(FailureTimeoutBudgetKind::VirtualTime),
        StopOutcome::PolicyTimeout {
            kind: PolicyTimeoutKind::ExecutionQuanta,
            ..
        } => Some(FailureTimeoutBudgetKind::ExecutionQuanta),
        StopOutcome::ObservationReached(proof)
            if proof.satisfaction() == ObservationStopSatisfaction::ExecutionQuanta =>
        {
            Some(FailureTimeoutBudgetKind::ExecutionQuanta)
        }
        StopOutcome::BoundedPrimaryReached { .. }
        | StopOutcome::BoundedPrimaryTimeout { .. }
        | StopOutcome::ObservationReached(_)
        | StopOutcome::Reached(_)
        | StopOutcome::TerminalSuccess
        | StopOutcome::ModeledTimeout(_)
        | StopOutcome::GuestCrash(_)
        | StopOutcome::AssertionFailure(_)
        | StopOutcome::ScenarioFailure(_) => None,
    }
}

fn timeout_failure_class(kind: FailureTimeoutBudgetKind) -> &'static str {
    match kind {
        FailureTimeoutBudgetKind::ExecutionQuanta => EXECUTION_QUANTA_TIMEOUT_CLASS,
        FailureTimeoutBudgetKind::VirtualTime => VIRTUAL_TIME_TIMEOUT_CLASS,
    }
}

fn timeout_fingerprint(
    input: &CrucibleAttemptExecution,
    failure_class: &str,
) -> Result<CampaignHash, CampaignCodecError> {
    let failure_class_bytes = u64::try_from(failure_class.len())
        .map_err(|_| CampaignCodecError::LimitExceeded {
            limit: "automatic-finding-failure-class-bytes",
        })?
        .to_be_bytes();
    let mut material = Vec::with_capacity(
        input.lineage().scenario().as_hash().as_bytes().len()
            + failure_class_bytes.len()
            + failure_class.len(),
    );
    material.extend_from_slice(&input.lineage().scenario().as_hash().as_bytes());
    material.extend_from_slice(&failure_class_bytes);
    material.extend_from_slice(failure_class.as_bytes());
    Ok(CampaignHash::derive(
        "crucible.daemon.qemu-execution-quanta-timeout-fingerprint.v1",
        &material,
    ))
}

pub(super) fn property_violation_signature(
    input: &CrucibleAttemptExecution,
    candidate: &ObservationCandidate,
) -> Result<Option<FindingSignature>, CampaignCodecError> {
    let property = match candidate.observation().stop() {
        StopOutcome::AssertionFailure(property) => property.as_str(),
        StopOutcome::ObservationReached(proof)
            if proof.satisfaction()
                == ObservationStopSatisfaction::AssertionViolationTransition =>
        {
            proof
                .assertion_witness()
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "assertion observation stop has no violation witness",
                })?
                .assertion()
        }
        _ => return Ok(None),
    };
    signature_for_failed_property(input, candidate.child(), candidate.properties(), property)
        .map(Some)
}

pub(super) fn replay_finding_signature(
    input: &CrucibleAttemptExecution,
    configuration: &ConfigurationArtifact,
    properties: &PropertyVerdictSet,
    coverage: &crucible_campaign::CoverageProjection,
    target_signature: &FindingSignature,
    triage: Option<&FailureTriageReplayEvidence>,
) -> Result<Option<FindingSignature>, CampaignCodecError> {
    if target_signature.kind() == FindingKind::PropertyViolation {
        let Some(preferred_property) = target_signature.property() else {
            return Ok(None);
        };
        let property = replayed_failed_property(input, properties, preferred_property);
        return property
            .as_deref()
            .map(|property| {
                signature_for_failed_property(input, configuration, properties, property)
            })
            .transpose();
    }

    let expected_native_kind = match target_signature.kind() {
        FindingKind::PropertyViolation => return Ok(None),
        FindingKind::Divergence => FailureKind::Divergence,
        FindingKind::Timeout => FailureKind::Timeout,
    };
    let Some(triage) = triage else {
        return Ok(None);
    };
    if triage.signature().failure_kind != expected_native_kind {
        return Ok(None);
    }
    let fingerprint = match (target_signature.kind(), triage.failure()) {
        (FindingKind::Divergence, FailureClusterReportFailure::Divergence(divergence)) => {
            divergence_fingerprint(input, divergence)
        }
        (FindingKind::Timeout, FailureClusterReportFailure::Timeout(timeout))
            if timeout_failure_class(timeout.budget_kind) == target_signature.failure_class() =>
        {
            timeout_fingerprint(input, target_signature.failure_class())?
        }
        _ => return Ok(None),
    };
    FindingSignature::new(
        target_signature.kind(),
        fingerprint,
        None,
        target_signature.failure_class().to_owned(),
        Some(FindingTarget::Configuration(configuration.id()?)),
        BTreeSet::from([coverage.id()?.content_id()]),
    )
    .map(Some)
}

fn replayed_failed_property(
    input: &CrucibleAttemptExecution,
    properties: &PropertyVerdictSet,
    preferred_property: &str,
) -> Option<String> {
    let preferred_failed = properties
        .properties()
        .get(preferred_property)
        .is_some_and(|evidence| evidence.verdict() == PropertyVerdict::Failed);
    if preferred_failed {
        return Some(preferred_property.to_owned());
    }

    input
        .scenario()
        .properties()
        .assertions()
        .iter()
        .map(|assertion| assertion.id.name.as_str())
        .find(|property| {
            properties
                .properties()
                .get(*property)
                .is_some_and(|evidence| evidence.verdict() == PropertyVerdict::Failed)
        })
        .map(ToOwned::to_owned)
}

/// Binds one selected actual QEMU failure source to its exact reproduction.
///
/// # Errors
///
/// Returns [`EngineError`] when multiple sources match the selected kind or
/// native replay evidence cannot be reconstructed from the retained inputs.
pub(crate) fn bind_qemu_triage_evidence(
    finding: &FindingReproductionArtifact,
    kind: FindingKind,
    property: Option<&str>,
    triage: crate::qemu_campaign_driver::QemuFindingCandidateTriageInputs,
) -> Result<Option<FailureTriageReplayEvidence>, EngineError> {
    let (
        failures,
        causal_entries,
        coverage_fingerprint,
        recorded_event_frames,
        paired_divergence_logs,
    ) = triage.into_parts();
    let mut matching = failures
        .into_iter()
        .filter(|failure| failure_matches_finding(failure, kind, property));
    let Some(mut failure) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some() {
        return Err(EngineError::UnifiedOperationEvidenceMismatch {
            operation: "automatic-finding-triage-evidence",
            reason: "multiple replay failure sources match the selected finding",
        });
    }
    match &mut failure {
        FailureClusterReportFailure::Property(record) => {
            record.violation.reproduction_artifact = finding.artifact.id();
        }
        FailureClusterReportFailure::Timeout(record) => {
            record.reproduction_artifact = finding.artifact.id();
        }
        FailureClusterReportFailure::Divergence(_) => {}
    }

    if let Some((expected, reproduced)) = paired_divergence_logs {
        return FailureTriageReplayEvidence::new_paired_divergence(
            finding.clone(),
            expected,
            reproduced,
            coverage_fingerprint,
            recorded_event_frames,
        )
        .map(Some);
    }

    FailureTriageReplayEvidence::new(
        finding.clone(),
        failure,
        causal_entries,
        coverage_fingerprint,
        recorded_event_frames,
    )
    .map(Some)
}

fn failure_matches_finding(
    failure: &FailureClusterReportFailure,
    kind: FindingKind,
    property: Option<&str>,
) -> bool {
    match (kind, failure) {
        (FindingKind::PropertyViolation, FailureClusterReportFailure::Property(record)) => {
            property.is_some_and(|property| record.violation.assertion.name == property)
        }
        (FindingKind::Divergence, FailureClusterReportFailure::Divergence(_))
        | (FindingKind::Timeout, FailureClusterReportFailure::Timeout(_)) => true,
        _ => false,
    }
}

fn signature_for_failed_property(
    input: &CrucibleAttemptExecution,
    configuration: &ConfigurationArtifact,
    properties: &PropertyVerdictSet,
    property: &str,
) -> Result<FindingSignature, CampaignCodecError> {
    if !input
        .scenario()
        .properties()
        .assertions()
        .iter()
        .any(|assertion| assertion.id.name == property)
    {
        return Err(CampaignCodecError::InvalidValue {
            reason: "assertion finding does not name a declared scenario property",
        });
    }
    if properties
        .properties()
        .get(property)
        .is_none_or(|evidence| evidence.verdict() != PropertyVerdict::Failed)
    {
        return Err(CampaignCodecError::InvalidValue {
            reason: "assertion finding does not name an actual failed property verdict",
        });
    }

    let fingerprint = assertion_failure_fingerprint(input, property)?;
    let properties = properties.id()?.content_id();
    FindingSignature::new(
        FindingKind::PropertyViolation,
        fingerprint,
        Some(property.to_owned()),
        String::from(ASSERTION_FAILURE_CLASS),
        Some(FindingTarget::Configuration(configuration.id()?)),
        BTreeSet::from([properties]),
    )
}

fn assertion_failure_fingerprint(
    input: &CrucibleAttemptExecution,
    property: &str,
) -> Result<CampaignHash, CampaignCodecError> {
    let property_bytes = u64::try_from(property.len())
        .map_err(|_| CampaignCodecError::LimitExceeded {
            limit: "automatic-finding-property-bytes",
        })?
        .to_be_bytes();
    let failure_class_bytes = u64::try_from(ASSERTION_FAILURE_CLASS.len())
        .map_err(|_| CampaignCodecError::LimitExceeded {
            limit: "automatic-finding-failure-class-bytes",
        })?
        .to_be_bytes();
    let mut material = Vec::with_capacity(
        32 + property_bytes.len()
            + property.len()
            + failure_class_bytes.len()
            + ASSERTION_FAILURE_CLASS.len(),
    );
    material.extend_from_slice(&input.lineage().scenario().as_hash().as_bytes());
    material.extend_from_slice(&property_bytes);
    material.extend_from_slice(property.as_bytes());
    material.extend_from_slice(&failure_class_bytes);
    material.extend_from_slice(ASSERTION_FAILURE_CLASS.as_bytes());
    Ok(CampaignHash::derive(
        "crucible.daemon.qemu-assertion-finding-fingerprint.v1",
        &material,
    ))
}

pub(super) fn minimization_seed(
    input: &CrucibleAttemptExecution,
    signature: &FindingSignature,
) -> Result<crucible::Seed, CampaignCodecError> {
    let mut material = Vec::with_capacity(64);
    material.extend_from_slice(&input.attempt().id()?.content_id().digest());
    material.extend_from_slice(&signature.cluster_key().as_bytes());
    Ok(crucible::Seed::from_bytes(
        CampaignHash::derive(
            "crucible.daemon.automatic-finding-minimization-seed.v1",
            &material,
        )
        .as_bytes(),
    ))
}

pub(super) fn original_finding(
    input: &CrucibleAttemptExecution,
    store: &CampaignExecutorStore,
    candidate: &ObservationCandidate,
    signature: &FindingSignature,
) -> Result<crucible::FindingReproductionArtifact, CrucibleArtifactError> {
    let scenario = encode_crucible_scenario_artifact(input.scenario())?;
    if scenario.id()? != input.lineage().scenario_content() {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "automatic finding scenario",
        });
    }
    let (configuration, _, _) = decode_crucible_configuration_artifact_with_owned_candidate(
        input.scenario(),
        &scenario,
        candidate.child(),
        store,
        candidate,
    )?;
    crucible::FindingReproductionArtifact::capture(
        FindingDiscoveryPath::StateSpaceSearch,
        ContentHash {
            bytes: signature.fingerprint().as_bytes(),
        },
        input.scenario(),
        &configuration,
    )
    .map_err(|source| CrucibleArtifactError::InvalidPayload {
        artifact: "automatic finding reproduction",
        source: Box::new(source),
    })
}

#[cfg(test)]
mod timeout_tests {
    use super::*;
    use crucible_campaign::{BoundedStopProof, StopCondition};

    #[test]
    fn policy_timeout_classes_keep_virtual_and_quantum_causes_distinct() {
        let stop = StopCondition::Bounded {
            primary: Box::new(StopCondition::Terminal),
            virtual_time_nanoseconds: Some(10),
            execution_quanta: Some(2),
        };
        let proof = BoundedStopProof::new(10, 2);
        let virtual_timeout = StopOutcome::PolicyTimeout {
            stop: stop.clone(),
            kind: PolicyTimeoutKind::VirtualTime,
            proof,
        };
        let quantum_timeout = StopOutcome::PolicyTimeout {
            stop,
            kind: PolicyTimeoutKind::ExecutionQuanta,
            proof,
        };

        assert_eq!(
            observation_timeout_kind(&virtual_timeout).map(timeout_failure_class),
            Some(VIRTUAL_TIME_TIMEOUT_CLASS),
        );
        assert_eq!(
            observation_timeout_kind(&quantum_timeout).map(timeout_failure_class),
            Some(EXECUTION_QUANTA_TIMEOUT_CLASS),
        );
    }
}
