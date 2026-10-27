//! Version-pairing regressions for authenticated post-quantum observation stops.

// crucible-lint: allow panic-shortcut -- canonical fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};

use crucible_store::content_store::{ContentId, ObjectKind};
use crucible_store::segment_store::MAX_MANIFEST_SEGMENTS;

use super::codec::{self, decode};
use super::*;

fn trace_manifest(label: &[u8]) -> ContentId {
    ContentId::for_bytes(ObjectKind::Trace, 4, label)
}

fn trace_segment(index: usize) -> ContentId {
    ContentId::for_bytes(ObjectKind::Trace, 1, format!("segment-{index}").as_bytes())
}

fn traced_observation() -> Observation {
    let (artifact, child, path, measurements, properties, coverage) = fixture_ids();
    let attempt = AttemptId::from_content_id(ContentId::for_bytes(
        ObjectKind::CampaignFact,
        9,
        b"trace-attempt",
    ))
    .expect("attempt identity");
    Observation::new(
        attempt,
        Observation::outcome(
            child,
            artifact,
            path,
            StopOutcome::TerminalSuccess,
            measurements,
            properties,
            coverage,
        ),
        BTreeSet::new(),
    )
    .expect("observation")
}

#[test]
fn observation_v16_binds_a_segmented_resolved_effect_trace_as_retained_children() {
    let manifest = trace_manifest(b"canonical-trace");
    let segments = vec![trace_segment(0), trace_segment(1)];
    let trace = ResolvedEffectTraceRef::new(manifest, segments.clone()).expect("trace reference");
    let observation = traced_observation()
        .with_resolved_effect_trace(trace.clone())
        .expect("trace attachment");

    assert_eq!(observation.resolved_effect_trace(), Some(&trace));
    assert_eq!(observation.schema_version(), 16);
    let children = observation.content_children();
    assert!(children.contains(&("resolved-effect-trace".to_owned(), manifest)));
    assert!(children.contains(&("resolved-effect-trace.segment.0000".to_owned(), segments[0])));
    assert!(children.contains(&("resolved-effect-trace.segment.0001".to_owned(), segments[1])));
    assert_eq!(
        Observation::from_canonical_bytes(&observation.canonical_bytes()).expect("round trip"),
        observation
    );

    let other = ResolvedEffectTraceRef::new(trace_manifest(b"other"), Vec::new())
        .expect("other trace reference");
    assert!(observation.with_resolved_effect_trace(other).is_err());
}

#[test]
fn resolved_effect_trace_references_require_exact_leaf_schemas() {
    let manifest = trace_manifest(b"manifest");

    assert!(ResolvedEffectTraceRef::new(manifest, Vec::new()).is_ok());
    assert!(
        ResolvedEffectTraceRef::new(
            ContentId::for_bytes(ObjectKind::Trace, 1, b"v3"),
            Vec::new()
        )
        .is_err()
    );
    assert!(
        ResolvedEffectTraceRef::new(
            manifest,
            vec![ContentId::for_bytes(ObjectKind::Trace, 4, b"not-a-segment")]
        )
        .is_err()
    );
    assert!(
        ResolvedEffectTraceRef::new(manifest, vec![trace_segment(0), trace_segment(0)]).is_err()
    );

    let at_limit = (0..MAX_MANIFEST_SEGMENTS)
        .map(trace_segment)
        .collect::<Vec<_>>();
    assert!(ResolvedEffectTraceRef::new(manifest, at_limit.clone()).is_ok());
    let mut beyond = at_limit;
    beyond.push(trace_segment(MAX_MANIFEST_SEGMENTS));
    assert!(matches!(
        ResolvedEffectTraceRef::new(manifest, beyond),
        Err(crate::CampaignCodecError::LimitExceeded {
            limit: "observation-resolved-effect-trace-segment-count"
        })
    ));
}

macro_rules! stored_id {
    ($type:ty, $kind:expr, $schema:expr, $label:expr) => {
        <$type>::from_content_id(ContentId::for_bytes($kind, $schema, $label.as_bytes()))
            .expect("typed content ID")
    };
}

fn fixture_ids() -> (
    ConfigurationArtifactId,
    ConfigurationId,
    BranchPathId,
    MeasurementSetId,
    PropertyVerdictSetId,
    CoverageProjectionId,
) {
    (
        stored_id!(
            ConfigurationArtifactId,
            ObjectKind::Configuration,
            1,
            "observation-stop-configuration"
        ),
        ConfigurationId::from_hash(CampaignHash::derive(
            "observation-stop-test",
            b"child configuration",
        )),
        stored_id!(
            BranchPathId,
            ObjectKind::CampaignFact,
            2,
            "observation-stop-path"
        ),
        stored_id!(
            MeasurementSetId,
            ObjectKind::Observation,
            2,
            "observation-stop-measurements"
        ),
        stored_id!(
            PropertyVerdictSetId,
            ObjectKind::Observation,
            1,
            "observation-stop-properties"
        ),
        stored_id!(
            CoverageProjectionId,
            ObjectKind::Projection,
            1,
            "observation-stop-coverage"
        ),
    )
}

fn assertion_proof(child: ConfigurationId) -> ObservationStopProof {
    ObservationStopProof::new(
        ObservationCondition::AssertionViolationTransition(String::from("safety")),
        ObservationStopSatisfaction::AssertionViolationTransition,
        child,
        ObservationQuantumBoundary::new(17, 3, 4, 1).expect("quantum boundary"),
        ObservationEventLogProof::new(
            CampaignHash::derive("observation-stop-test", b"event prefix"),
            Some(CampaignHash::derive(
                "observation-stop-test",
                b"appended segment",
            )),
            256,
            2,
            CampaignHash::derive("observation-stop-test", b"prefix digest"),
        ),
        Some(
            AssertionViolationWitness::new(
                "safety",
                1,
                CampaignHash::derive("observation-stop-test", b"assertion event"),
            )
            .expect("assertion witness"),
        ),
    )
    .expect("assertion observation proof")
}

#[test]
fn observation_stops_require_proofs_and_dedicated_enclosing_schemas() {
    let (configuration, child, path, measurements, properties, coverage) = fixture_ids();
    let condition = ObservationCondition::AssertionViolationTransition(String::from("safety"));
    let stop = StopCondition::Observation(condition.clone());

    let encoded_stop = codec::encode(&stop);
    assert_eq!(encoded_stop[0], 8);
    assert_eq!(
        decode::<StopCondition>(&encoded_stop).expect("stop round trip"),
        stop
    );

    let attempt = Attempt::new(AttemptStart::Discover { configuration }, path, stop.clone())
        .expect("observation-stop attempt");
    assert_eq!(attempt.schema_version(), 9);
    assert_eq!(
        Attempt::from_canonical_bytes(&attempt.canonical_bytes()).expect("attempt round trip"),
        attempt
    );
    let mut noncurrent_attempt = attempt.canonical_bytes();
    noncurrent_attempt[..4].copy_from_slice(&0_u32.to_be_bytes());
    assert!(Attempt::from_canonical_bytes(&noncurrent_attempt).is_err());

    let opportunity = stored_id!(
        ChoiceOpportunityId,
        ObjectKind::CampaignFact,
        1,
        "observation-stop-opportunity"
    );
    let domain = stored_id!(
        ChoiceDomainId,
        ObjectKind::CampaignFact,
        2,
        "observation-stop-domain"
    );
    let branch = BranchRequest::new(
        BranchRequest::identity(
            BranchPointId::from_hash(CampaignHash::derive(
                "observation-stop-test",
                b"branch point",
            )),
            configuration,
            opportunity,
            domain,
        ),
        CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(false)]))
            .expect("finite source"),
        BranchRequestCause::Operator(CampaignCommandId::from_hash(CampaignHash::derive(
            "observation-stop-test",
            b"branch command",
        ))),
        BranchBudget::new(1, 1).expect("branch budget"),
        stop.clone(),
    )
    .expect("observation-stop branch request");
    assert_eq!(branch.schema_version(), 10);
    assert_eq!(
        BranchRequest::from_canonical_bytes(&branch.canonical_bytes()).expect("branch round trip"),
        branch
    );
    let mut unsupported_branch_version = branch.canonical_bytes();
    unsupported_branch_version[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(BranchRequest::from_canonical_bytes(&unsupported_branch_version).is_err());

    let proof = assertion_proof(child);
    assert_eq!(
        ObservationStopProof::from_canonical_bytes(&proof.canonical_bytes())
            .expect("observation proof round trip"),
        proof
    );
    let outcome = StopOutcome::ObservationReached(Box::new(proof.clone()));
    assert!(outcome.reaches(&stop));
    assert!(!StopOutcome::Reached(stop.clone()).reaches(&stop));
    let discovered = stored_id!(
        ChoiceOpportunityId,
        ObjectKind::CampaignFact,
        1,
        "observation-stop-opportunity"
    );
    let observation = Observation::new(
        attempt.id().expect("attempt ID"),
        Observation::outcome(
            child,
            configuration,
            path,
            outcome,
            measurements,
            properties,
            coverage,
        ),
        BTreeSet::from([discovered]),
    )
    .expect("observation-stop observation");
    assert_eq!(observation.schema_version(), 16);
    assert_eq!(
        Observation::from_canonical_bytes(&observation.canonical_bytes())
            .expect("observation round trip"),
        observation
    );
    let mut noncurrent_observation = observation.canonical_bytes();
    noncurrent_observation[..4].copy_from_slice(&0_u32.to_be_bytes());
    assert!(Observation::from_canonical_bytes(&noncurrent_observation).is_err());
    assert!(
        Observation::new(
            attempt.id().expect("attempt ID"),
            Observation::outcome(
                child,
                configuration,
                path,
                StopOutcome::Reached(stop.clone()),
                measurements,
                properties,
                coverage,
            ),
            BTreeSet::new(),
        )
        .is_err()
    );

    let selection = stored_id!(
        SelectionId,
        ObjectKind::CampaignFact,
        1,
        "observation-stop-selection"
    );
    let selection_observation = observation
        .with_produced_selections(BTreeMap::from([(discovered, selection)]))
        .expect("selection observation");
    assert_eq!(selection_observation.schema_version(), 16);

    let discovery = DiscoveryRequest::new(
        CampaignCommandId::from_hash(CampaignHash::derive(
            "observation-stop-test",
            b"discovery command",
        )),
        stored_id!(
            CampaignSnapshotId,
            ObjectKind::CampaignSnapshot,
            3,
            "observation-stop-snapshot"
        ),
        configuration,
        stop,
    )
    .expect("observation-stop discovery");
    let fact = CampaignFact::DiscoveryRequested(discovery.clone());
    assert_eq!(&fact.canonical_bytes()[..4], &15_u32.to_be_bytes());
    assert_eq!(
        fact.id().expect("fact ID").content_id().schema_version(),
        15
    );
    assert_eq!(
        CampaignFact::from_canonical_bytes(&fact.canonical_bytes()).expect("fact round trip"),
        fact
    );
    let mut noncurrent_fact = fact.canonical_bytes();
    noncurrent_fact[..4].copy_from_slice(&0_u32.to_be_bytes());
    assert!(CampaignFact::from_canonical_bytes(&noncurrent_fact).is_err());

    let service = SubmitCampaignDiscoveryRequest::new(
        CampaignPrincipal::new("operator:observation-stop").expect("principal"),
        CampaignName::new("observation-stop").expect("campaign"),
        discovery,
    )
    .expect("observation-stop service request");
    assert_eq!(&service.canonical_bytes()[..4], &4_u32.to_be_bytes());
    assert_eq!(
        SubmitCampaignDiscoveryRequest::from_canonical_bytes(&service.canonical_bytes())
            .expect("service round trip"),
        service
    );
    let mut mismatched = service.canonical_bytes();
    mismatched[..4].copy_from_slice(&0_u32.to_be_bytes());
    assert!(SubmitCampaignDiscoveryRequest::from_canonical_bytes(&mismatched).is_err());
}

#[test]
fn observation_stop_proofs_reject_wrong_witness_shapes_and_child_bindings() {
    let (configuration, child, path, measurements, properties, coverage) = fixture_ids();
    let event_log = ObservationEventLogProof::new(
        CampaignHash::derive("observation-stop-test", b"event prefix"),
        None,
        0,
        1,
        CampaignHash::derive("observation-stop-test", b"prefix digest"),
    );
    assert!(ObservationQuantumBoundary::new(0, 4, 4, 0).is_err());
    assert!(ObservationQuantumBoundary::new(0, 4, 6, 0).is_err());
    assert!(
        ObservationStopProof::new(
            ObservationCondition::AssertionViolationTransition(String::from("safety")),
            ObservationStopSatisfaction::AssertionViolationTransition,
            child,
            ObservationQuantumBoundary::new(0, 3, 4, 1).expect("quantum boundary"),
            event_log,
            Some(
                AssertionViolationWitness::new(
                    "safety",
                    0,
                    CampaignHash::derive("observation-stop-test", b"old event"),
                )
                .expect("old assertion witness")
            ),
        )
        .is_err()
    );

    let stop = StopCondition::Observation(ObservationCondition::AssertionViolationTransition(
        String::from("safety"),
    ));
    let attempt = Attempt::new(AttemptStart::Discover { configuration }, path, stop)
        .expect("observation-stop attempt");
    let wrong_child = ConfigurationId::from_hash(CampaignHash::derive(
        "observation-stop-test",
        b"wrong child",
    ));
    assert!(
        Observation::new(
            attempt.id().expect("attempt ID"),
            Observation::outcome(
                wrong_child,
                configuration,
                path,
                StopOutcome::ObservationReached(Box::new(assertion_proof(child))),
                measurements,
                properties,
                coverage,
            ),
            BTreeSet::new(),
        )
        .is_err()
    );
}
