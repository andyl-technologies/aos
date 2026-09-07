//! Version-pairing regressions for absolute execution-quanta stop conditions.

// crucible-lint: allow panic-shortcut -- canonical fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::collections::BTreeSet;

use crucible_cas::content_store::{ContentId, ObjectKind};

use super::codec::decode;
use super::*;

macro_rules! stored_id {
    ($type:ty, $kind:expr, $schema:expr, $label:expr) => {
        <$type>::from_content_id(ContentId::for_bytes($kind, $schema, $label.as_bytes()))
            .expect("typed content ID")
    };
}

#[test]
fn extended_stops_require_their_exact_enclosing_schema_versions() {
    let configuration = stored_id!(
        ConfigurationArtifactId,
        ObjectKind::Configuration,
        1,
        "extended-stop-configuration"
    );
    let path = stored_id!(
        BranchPathId,
        ObjectKind::CampaignFact,
        2,
        "extended-stop-path"
    );
    let legacy_attempt = Attempt::new(
        AttemptStart::Discover { configuration },
        path,
        StopCondition::Terminal,
    )
    .expect("legacy attempt");
    let attempt = Attempt::new(
        AttemptStart::Discover { configuration },
        path,
        StopCondition::ExecutionQuanta(7),
    )
    .expect("execution-quanta attempt");
    assert_eq!(legacy_attempt.schema_version(), 1);
    assert_eq!(attempt.schema_version(), 2);
    assert_eq!(
        Attempt::from_canonical_bytes(&attempt.canonical_bytes()).expect("attempt round trip"),
        attempt
    );
    assert_eq!(
        attempt
            .id()
            .expect("attempt ID")
            .content_id()
            .schema_version(),
        2
    );
    let mut downgraded_attempt = attempt.canonical_bytes();
    downgraded_attempt[..4].copy_from_slice(&1_u32.to_be_bytes());
    assert!(Attempt::from_canonical_bytes(&downgraded_attempt).is_err());
    let mismatched_attempt_envelope = ObjectEnvelope::for_record_versioned(
        CampaignRecordKind::Attempt,
        1,
        super::object::content_children(attempt.content_children()).expect("attempt children"),
        attempt.canonical_bytes(),
    )
    .expect("structural attempt envelope");
    assert!(
        ObjectEnvelope::from_canonical_bytes(&mismatched_attempt_envelope.canonical_bytes())
            .is_err()
    );

    let branch_point =
        BranchPointId::from_hash(CampaignHash::derive("extended-stop-test", b"branch-point"));
    let opportunity = stored_id!(
        ChoiceOpportunityId,
        ObjectKind::CampaignFact,
        1,
        "extended-stop-opportunity"
    );
    let domain = stored_id!(
        ChoiceDomainId,
        ObjectKind::CampaignFact,
        1,
        "extended-stop-domain"
    );
    let cause = BranchRequestCause::Operator(CampaignCommandId::from_hash(CampaignHash::derive(
        "extended-stop-test",
        b"branch-command",
    )));
    let branch = BranchRequest::new(
        branch_point,
        configuration,
        opportunity,
        domain,
        CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(false)]))
            .expect("finite source"),
        cause,
        BranchBudget::new(1, 1).expect("branch budget"),
        StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_nanoseconds: 11,
            execution_quanta: 7,
        },
    )
    .expect("combined-stop branch request");
    assert_eq!(branch.schema_version(), 6);
    assert_eq!(
        BranchRequest::from_canonical_bytes(&branch.canonical_bytes()).expect("branch round trip"),
        branch
    );
    assert_eq!(
        branch
            .id()
            .expect("branch ID")
            .content_id()
            .schema_version(),
        6
    );
    let mut downgraded_branch = branch.canonical_bytes();
    downgraded_branch[..4].copy_from_slice(&5_u32.to_be_bytes());
    assert!(BranchRequest::from_canonical_bytes(&downgraded_branch).is_err());

    let measurements = stored_id!(
        MeasurementSetId,
        ObjectKind::Observation,
        1,
        "extended-stop-measurements"
    );
    let properties = stored_id!(
        PropertyVerdictSetId,
        ObjectKind::Observation,
        1,
        "extended-stop-properties"
    );
    let coverage = stored_id!(
        CoverageProjectionId,
        ObjectKind::Projection,
        1,
        "extended-stop-coverage"
    );
    let observation = Observation::new(
        attempt.id().expect("attempt ID"),
        ConfigurationId::from_hash(CampaignHash::derive("extended-stop-test", b"child")),
        configuration,
        path,
        StopOutcome::Reached(StopCondition::ExecutionQuanta(7)),
        measurements,
        properties,
        coverage,
        BTreeSet::new(),
    )
    .expect("execution-quanta observation");
    assert_eq!(observation.schema_version(), 5);
    assert_eq!(
        Observation::from_canonical_bytes(&observation.canonical_bytes())
            .expect("observation round trip"),
        observation
    );
    assert_eq!(
        observation
            .id()
            .expect("observation ID")
            .content_id()
            .schema_version(),
        5
    );
    for wrong_version in [1_u32, 6] {
        let mut mismatched = observation.canonical_bytes();
        mismatched[..4].copy_from_slice(&wrong_version.to_be_bytes());
        assert!(Observation::from_canonical_bytes(&mismatched).is_err());
    }

    let produced_selection = stored_id!(
        SelectionId,
        ObjectKind::CampaignFact,
        1,
        "extended-stop-produced-selection"
    );
    let selection_observation = observation
        .clone()
        .with_produced_selections(BTreeSet::from([produced_selection]))
        .expect("selection observation");
    assert_eq!(selection_observation.schema_version(), 7);
    assert_eq!(
        Observation::from_canonical_bytes(&selection_observation.canonical_bytes())
            .expect("selection observation round trip"),
        selection_observation
    );
    let mut impossible_scenario_failure_version = selection_observation.canonical_bytes();
    impossible_scenario_failure_version[..4].copy_from_slice(&8_u32.to_be_bytes());
    assert!(Observation::from_canonical_bytes(&impossible_scenario_failure_version).is_err());

    let discovery = DiscoveryRequest::new(
        CampaignCommandId::from_hash(CampaignHash::derive(
            "extended-stop-test",
            b"discovery-command",
        )),
        stored_id!(
            CampaignSnapshotId,
            ObjectKind::CampaignSnapshot,
            3,
            "extended-stop-snapshot"
        ),
        configuration,
        StopCondition::ExecutionQuanta(7),
    )
    .expect("execution-quanta discovery");
    let fact = CampaignFact::DiscoveryRequested(discovery.clone());
    assert_eq!(&fact.canonical_bytes()[..4], &9_u32.to_be_bytes());
    assert_eq!(fact.id().expect("fact ID").content_id().schema_version(), 9);
    assert_eq!(
        CampaignFact::from_canonical_bytes(&fact.canonical_bytes()).expect("fact round trip"),
        fact
    );
    let mut downgraded_fact = fact.canonical_bytes();
    downgraded_fact[..4].copy_from_slice(&8_u32.to_be_bytes());
    assert!(CampaignFact::from_canonical_bytes(&downgraded_fact).is_err());

    let service_request = SubmitCampaignDiscoveryRequest::new(
        CampaignPrincipal::new("operator:extended-stop").expect("principal"),
        CampaignName::new("extended-stop").expect("campaign name"),
        discovery,
    )
    .expect("service request");
    assert_eq!(
        &service_request.canonical_bytes()[..4],
        &2_u32.to_be_bytes()
    );
    assert_eq!(
        SubmitCampaignDiscoveryRequest::from_canonical_bytes(&service_request.canonical_bytes())
            .expect("service request round trip"),
        service_request
    );
    let mut downgraded_service_request = service_request.canonical_bytes();
    downgraded_service_request[..4].copy_from_slice(&1_u32.to_be_bytes());
    assert!(
        SubmitCampaignDiscoveryRequest::from_canonical_bytes(&downgraded_service_request).is_err()
    );

    let golden_digests = [
        blake3::hash(&legacy_attempt.canonical_bytes())
            .to_hex()
            .to_string(),
        blake3::hash(&attempt.canonical_bytes())
            .to_hex()
            .to_string(),
        blake3::hash(&branch.canonical_bytes()).to_hex().to_string(),
        blake3::hash(&observation.canonical_bytes())
            .to_hex()
            .to_string(),
        blake3::hash(&selection_observation.canonical_bytes())
            .to_hex()
            .to_string(),
        blake3::hash(&fact.canonical_bytes()).to_hex().to_string(),
        blake3::hash(&service_request.canonical_bytes())
            .to_hex()
            .to_string(),
    ];
    assert_eq!(
        golden_digests,
        [
            "16a43db59753647e81b424e087085d2dc4602cc1de21daad6cca851064461a54",
            "ca56047687eabd692abfa41dba49e9abbebdaa49e20e4fd4e143d4e13035f95f",
            "747d69bbba99888605848fd8d053f9bcbc47aaab957f37f5f3cadfd1a276ca02",
            "0c7770852530d0d7998409a6dac1f44c02cec7ef01785f51eb3d26c27fef45bc",
            "269a80641393f566e0f0bc846dbc8a0f4d4ef626503e0adc4f7c3b56204492f9",
            "2964e78ecc7b1fa408b1e5c16aaad83629f0a09738db28a4d1ed9d264bc06773",
            "62f72751a8db51bb3c033a9da6e454000bda19ab6c1793a92df75b31e86c2b9e",
        ]
    );
}

#[test]
fn extended_stop_tags_reject_zero_bounds_and_unknown_values() {
    let configuration = stored_id!(
        ConfigurationArtifactId,
        ObjectKind::Configuration,
        1,
        "extended-stop-invalid-configuration"
    );
    let path = stored_id!(
        BranchPathId,
        ObjectKind::CampaignFact,
        2,
        "extended-stop-invalid-path"
    );
    for stop in [
        StopCondition::ExecutionQuanta(0),
        StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_nanoseconds: 0,
            execution_quanta: 1,
        },
        StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_nanoseconds: 1,
            execution_quanta: 0,
        },
    ] {
        assert!(Attempt::new(AttemptStart::Discover { configuration }, path, stop).is_err());
    }

    assert!(matches!(
        decode::<StopCondition>(&[7]),
        Err(CampaignCodecError::UnknownTag {
            kind: "stop-condition",
            tag: 7,
        })
    ));
}
