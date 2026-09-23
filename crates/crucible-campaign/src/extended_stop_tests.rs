//! Version-pairing regressions for absolute execution-quanta stop conditions.

// crucible-lint: allow panic-shortcut -- canonical fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};

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
fn campaign_policy_deadlines_are_bounded_and_preserve_primary_precedence() {
    assert!(CampaignAttemptTimeoutPolicy::new(None, None, Some(240_000)).is_err());
    assert!(CampaignAttemptTimeoutPolicy::new(Some(0), None, None).is_err());
    assert!(CampaignAttemptTimeoutPolicy::new(Some(10), None, Some(3_600_001)).is_err());

    let policy = CampaignAttemptTimeoutPolicy::new(Some(10), Some(4), Some(240_000))
        .expect("bounded policy");
    let stop = StopCondition::bounded(
        StopCondition::NextChoice,
        policy.virtual_time_nanoseconds(),
        policy.execution_quanta(),
    )
    .expect("bounded stop");
    assert!(stop.accepts_next_choice());
    assert_eq!(
        decode::<StopCondition>(&codec::encode(&stop)).expect("round trip"),
        stop
    );
    assert!(StopCondition::bounded(stop.clone(), Some(20), None).is_err());

    let primary = StopOutcome::BoundedPrimaryReached {
        stop: stop.clone(),
        proof: BoundedStopProof::new(9, 3),
    };
    assert!(primary.reaches(&stop));
    assert!(primary.reached_next_choice());
    assert_eq!(
        decode::<StopOutcome>(&codec::encode(&primary)).expect("primary proof"),
        primary
    );

    let late_primary = StopOutcome::BoundedPrimaryReached {
        stop: stop.clone(),
        proof: BoundedStopProof::new(10, 3),
    };
    assert!(!late_primary.authenticates_requested_stop(&stop));
    assert!(decode::<StopOutcome>(&codec::encode(&late_primary)).is_err());

    let virtual_timeout = StopOutcome::PolicyTimeout {
        stop: stop.clone(),
        kind: PolicyTimeoutKind::VirtualTime,
        proof: BoundedStopProof::new(10, 4),
    };
    assert!(virtual_timeout.authenticates_requested_stop(&stop));
    assert!(!virtual_timeout.reaches(&stop));
    assert!(!virtual_timeout.reached_next_choice());
    assert_eq!(
        decode::<StopOutcome>(&codec::encode(&virtual_timeout)).expect("virtual-time tie"),
        virtual_timeout
    );

    let wrong_tie = StopOutcome::PolicyTimeout {
        stop: stop.clone(),
        kind: PolicyTimeoutKind::ExecutionQuanta,
        proof: BoundedStopProof::new(10, 4),
    };
    assert!(!wrong_tie.authenticates_requested_stop(&stop));
    assert!(decode::<StopOutcome>(&codec::encode(&wrong_tie)).is_err());

    let quanta_timeout = StopOutcome::PolicyTimeout {
        stop: stop.clone(),
        kind: PolicyTimeoutKind::ExecutionQuanta,
        proof: BoundedStopProof::new(9, 4),
    };
    assert!(quanta_timeout.authenticates_requested_stop(&stop));
    assert_eq!(
        decode::<StopOutcome>(&codec::encode(&quanta_timeout)).expect("quanta timeout"),
        quanta_timeout
    );
    assert!(decode::<StopOutcome>(&codec::encode(&StopOutcome::Reached(stop))).is_err());
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
    let terminal_attempt = Attempt::new(
        AttemptStart::Discover { configuration },
        path,
        StopCondition::Terminal,
    )
    .expect("terminal attempt");
    let attempt = Attempt::new(
        AttemptStart::Discover { configuration },
        path,
        StopCondition::ExecutionQuanta(7),
    )
    .expect("execution-quanta attempt");
    let next_choice_or_timeout_attempt = Attempt::new(
        AttemptStart::Discover { configuration },
        path,
        StopCondition::NextChoiceOrExecutionQuanta {
            execution_quanta: 7,
        },
    )
    .expect("next-choice-or-timeout attempt");
    assert_eq!(terminal_attempt.schema_version(), 9);
    assert_eq!(attempt.schema_version(), 9);
    assert_eq!(next_choice_or_timeout_attempt.schema_version(), 9);
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
        9
    );
    assert_eq!(
        Attempt::from_canonical_bytes(&next_choice_or_timeout_attempt.canonical_bytes())
            .expect("next-choice-or-timeout round trip"),
        next_choice_or_timeout_attempt
    );
    let mut noncurrent_attempt = attempt.canonical_bytes();
    noncurrent_attempt[..4].copy_from_slice(&0_u32.to_be_bytes());
    assert!(Attempt::from_canonical_bytes(&noncurrent_attempt).is_err());
    assert!(
        ObjectEnvelope::for_record_versioned(
            CampaignRecordKind::Attempt,
            0,
            super::object::content_children(attempt.content_children()).expect("attempt children"),
            attempt.canonical_bytes(),
        )
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
        BranchRequest::identity(branch_point, configuration, opportunity, domain),
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
    assert_eq!(branch.schema_version(), 10);
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
        10
    );
    let mut unsupported_branch_version = branch.canonical_bytes();
    unsupported_branch_version[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(BranchRequest::from_canonical_bytes(&unsupported_branch_version).is_err());

    let invocation = stored_id!(
        PlannerInvocationId,
        ObjectKind::Policy,
        2,
        "extended-stop-planner-invocation"
    );
    let value = ChoiceValue::Boolean(false);
    let smc_branch = BranchRequest::new(
        BranchRequest::identity(branch_point, configuration, opportunity, domain),
        CandidateSource::statistical_smc(
            StatisticalGenerationId::from_hash(CampaignHash::derive(
                "extended-stop-test",
                b"SMC generation",
            )),
            StatisticalParticleId::from_hash(CampaignHash::derive(
                "extended-stop-test",
                b"SMC particle",
            )),
            1,
            0,
            ProbabilityModelId::from_hash(CampaignHash::derive("extended-stop-test", b"SMC model")),
            BTreeMap::from([(value.clone(), 1)]),
            BTreeMap::from([(value, 1)]),
        )
        .expect("SMC source"),
        BranchRequestCause::Planner(invocation),
        BranchBudget::new(1, 1).expect("SMC branch budget"),
        StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_nanoseconds: 11,
            execution_quanta: 7,
        },
    )
    .expect("combined-stop SMC branch request");
    assert_eq!(smc_branch.schema_version(), 10);
    assert_eq!(
        BranchRequest::from_canonical_bytes(&smc_branch.canonical_bytes())
            .expect("SMC branch round trip"),
        smc_branch
    );
    assert_eq!(
        smc_branch
            .id()
            .expect("SMC branch ID")
            .content_id()
            .schema_version(),
        10
    );

    let measurements = stored_id!(
        MeasurementSetId,
        ObjectKind::Observation,
        2,
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
        Observation::outcome(
            ConfigurationId::from_hash(CampaignHash::derive("extended-stop-test", b"child")),
            configuration,
            path,
            StopOutcome::Reached(StopCondition::ExecutionQuanta(7)),
            measurements,
            properties,
            coverage,
        ),
        BTreeSet::new(),
    )
    .expect("execution-quanta observation");
    assert_eq!(observation.schema_version(), 13);
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
        13
    );
    let mut noncurrent_observation = observation.canonical_bytes();
    noncurrent_observation[..4].copy_from_slice(&0_u32.to_be_bytes());
    assert!(Observation::from_canonical_bytes(&noncurrent_observation).is_err());

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
    assert_eq!(selection_observation.schema_version(), 13);
    assert_eq!(
        Observation::from_canonical_bytes(&selection_observation.canonical_bytes())
            .expect("selection observation round trip"),
        selection_observation
    );
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

    let service_request = SubmitCampaignDiscoveryRequest::new(
        CampaignPrincipal::new("operator:extended-stop").expect("principal"),
        CampaignName::new("extended-stop").expect("campaign name"),
        discovery,
    )
    .expect("service request");
    assert_eq!(
        &service_request.canonical_bytes()[..4],
        &3_u32.to_be_bytes()
    );
    assert_eq!(
        SubmitCampaignDiscoveryRequest::from_canonical_bytes(&service_request.canonical_bytes())
            .expect("service request round trip"),
        service_request
    );
    let mut unsupported_service_version = service_request.canonical_bytes();
    unsupported_service_version[..4].copy_from_slice(&0_u32.to_be_bytes());
    assert!(
        SubmitCampaignDiscoveryRequest::from_canonical_bytes(&unsupported_service_version).is_err()
    );

    let golden_digests = [
        blake3::hash(&terminal_attempt.canonical_bytes())
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
            "b0ed027903ad6ee53ff16770cbea7221db343ce284a5e01b927ed46aff2cc3c0",
            "9f4b1ee50c0cd915fe9bf55fa9a2b765b0da73607fe794406ffd58cf9680fc6e",
            "2c33f5842cc9ed13e921d287b34c5776385503e3feac253c4c4993b0cee7f36c",
            "75500f41fc4855fd239cb03132231482eb085438511ef2b57a5e39631fbd31aa",
            "8e60273d4936917295147d076e5b068fc9f12b77082fd107c1d4cb12cec092de",
            "f3b1d09d16ab6aa112e584b8eda01f7abe8414bff8a97a3a15cf29efe6ddd03e",
            "dcb5d010f97bfbda6697408bcd9c456031be8eb7316d49202cb0b11a98b2cbeb",
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
        StopCondition::NextChoiceOrExecutionQuanta {
            execution_quanta: 0,
        },
    ] {
        assert!(Attempt::new(AttemptStart::Discover { configuration }, path, stop).is_err());
    }

    assert!(matches!(
        decode::<StopCondition>(&[10]),
        Err(CampaignCodecError::UnknownTag {
            kind: "stop-condition",
            tag: 10,
        })
    ));
}
