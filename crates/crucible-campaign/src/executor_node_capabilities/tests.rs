//! Regression tests for versioned realization identity and conservative guarantees.

// crucible-lint: allow panic-shortcut -- These executor node capabilities tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::Cell;

use crucible_cas::content_store::{ContentId, ObjectKind};

use super::*;

fn hash(label: &str) -> CampaignHash {
    CampaignHash::derive("crucible.test-node-roster.v1", label.as_bytes())
}

fn roster(guarantee: NodeExecutionGuarantee) -> ExecutorNodeRoster {
    let compute = OwnerImplementationBinding::new(
        "qemu-sim".to_owned(),
        hash("compute-complete-profile"),
        BTreeSet::from(["compute".to_owned()]),
        NodeExecutionGuarantee::Repeatable,
    )
    .unwrap();
    let external = OwnerImplementationBinding::new(
        "external-storage".to_owned(),
        hash("storage-complete-profile"),
        BTreeSet::from(["storage".to_owned()]),
        guarantee,
    )
    .unwrap();
    ExecutorNodeRoster::new(
        ScenarioArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Scenario,
            1,
            b"scenario",
        ))
        .unwrap(),
        ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Configuration,
            1,
            b"configuration",
        ))
        .unwrap(),
        hash("complete-realized-graph"),
        BTreeMap::from([
            ("compute-owner".to_owned(), compute),
            ("storage-owner".to_owned(), external),
        ]),
    )
    .unwrap()
}

struct VerifyTranscript {
    calls: Cell<usize>,
    admitted: bool,
}

impl TranscriptQualificationVerifier for VerifyTranscript {
    fn verify(
        &self,
        roster: &ExecutorNodeRoster,
        owner: &str,
        evidence: ConditionalTranscriptEvidence,
        operation: DeterministicExecutionOperation,
        context: &DeterministicExecutionContext,
    ) -> Result<(), CampaignCodecError> {
        self.calls.set(self.calls.get() + 1);
        assert!(roster.owners().contains_key(owner));
        assert_eq!(evidence.transcript, hash("transcript"));
        assert_eq!(evidence.qualification, hash("qualification"));
        assert_eq!(evidence.preconditions, hash("preconditions"));
        assert_eq!(context.inputs, hash("actual-input-context"));
        assert_eq!(context.request, hash("actual-request"));

        if self.admitted && operation != DeterministicExecutionOperation::Minimization {
            Ok(())
        } else {
            Err(CampaignCodecError::InvalidValue {
                reason: "transcript does not cover operation preconditions",
            })
        }
    }
}

#[test]
fn coupled_noncompute_owner_taints_all_deterministic_operations() {
    let world = roster(NodeExecutionGuarantee::Nondeterministic);
    let verifier = VerifyTranscript {
        calls: Cell::new(0),
        admitted: true,
    };

    assert!(!world.is_repeatable());
    let context = DeterministicExecutionContext {
        request: hash("actual-request"),
        inputs: hash("actual-input-context"),
    };
    for operation in [
        DeterministicExecutionOperation::CacheReuse,
        DeterministicExecutionOperation::ThinReplay,
        DeterministicExecutionOperation::Minimization,
        DeterministicExecutionOperation::Equivalence,
    ] {
        assert!(
            world
                .admit_deterministic_operation(operation, &context, &verifier)
                .is_err()
        );
    }
    assert_eq!(verifier.calls.get(), 0);

    let unqualified = roster(NodeExecutionGuarantee::Unqualified);
    assert!(
        unqualified
            .admit_deterministic_operation(
                DeterministicExecutionOperation::Equivalence,
                &context,
                &verifier,
            )
            .is_err()
    );
}

#[test]
fn capture_owner_identity_is_independent_from_execution_ownership() {
    let world = roster(NodeExecutionGuarantee::Repeatable);
    let mut owners = world.owners().clone();
    owners.insert(
        "capture-owner".to_owned(),
        OwnerImplementationBinding::new_with_roles(
            "durable-storage".to_owned(),
            hash("complete-capture-profile"),
            BTreeSet::from(["compute".to_owned(), "storage".to_owned()]),
            NodeExecutionGuarantee::Repeatable,
            BTreeSet::from([ExecutorOwnerRole::Capture]),
        )
        .unwrap(),
    );
    let captured = ExecutorNodeRoster::new(
        world.scenario(),
        world.configuration(),
        world.graph(),
        owners,
    )
    .unwrap();

    assert_eq!(captured.owners().len(), 3);
    assert_ne!(captured.digest(), world.digest());
    assert_eq!(
        ExecutorNodeRoster::from_canonical_bytes(&captured.canonical_bytes()).unwrap(),
        captured
    );
}

#[test]
fn conditional_replay_authenticates_evidence_and_refuses_unrecorded_counterfactuals() {
    let world = roster(NodeExecutionGuarantee::ConditionalTranscript {
        transcript: hash("transcript"),
        qualification: hash("qualification"),
        preconditions: hash("preconditions"),
    });
    let verifier = VerifyTranscript {
        calls: Cell::new(0),
        admitted: false,
    };
    let context = DeterministicExecutionContext {
        request: hash("actual-request"),
        inputs: hash("actual-input-context"),
    };

    assert!(
        world
            .admit_deterministic_operation(
                DeterministicExecutionOperation::ThinReplay,
                &context,
                &verifier
            )
            .is_err()
    );
    let verified = VerifyTranscript {
        calls: Cell::new(0),
        admitted: true,
    };
    assert!(
        world
            .admit_deterministic_operation(
                DeterministicExecutionOperation::ThinReplay,
                &context,
                &verified
            )
            .is_ok()
    );
    assert!(
        world
            .admit_deterministic_operation(
                DeterministicExecutionOperation::Minimization,
                &context,
                &verified
            )
            .is_err()
    );
    assert!(!world.is_repeatable());
    assert_eq!(verifier.calls.get(), 1);
    assert_eq!(verified.calls.get(), 2);
}

#[test]
fn roster_identity_binds_every_owner_and_rejects_duplicate_views() {
    let repeatable = roster(NodeExecutionGuarantee::Repeatable);
    let nonrepeatable = roster(NodeExecutionGuarantee::Nondeterministic);
    assert_ne!(repeatable.digest(), nonrepeatable.digest());

    let mut changed = repeatable.owners().clone();
    let binding = changed.get("storage-owner").unwrap();
    changed.insert(
        "storage-owner".to_owned(),
        OwnerImplementationBinding::new(
            binding.provider().to_owned(),
            hash("changed-storage-latency-and-implementation"),
            binding.nodes().clone(),
            binding.guarantee().clone(),
        )
        .unwrap(),
    );
    let changed = ExecutorNodeRoster::new(
        repeatable.scenario(),
        repeatable.configuration(),
        repeatable.graph(),
        changed,
    )
    .unwrap();
    assert_ne!(repeatable.digest(), changed.digest());

    let mut duplicate = repeatable.owners().clone();
    duplicate.insert(
        "duplicate-owner".to_owned(),
        duplicate.get("compute-owner").unwrap().clone(),
    );
    assert!(
        ExecutorNodeRoster::new(
            repeatable.scenario(),
            repeatable.configuration(),
            repeatable.graph(),
            duplicate,
        )
        .is_err()
    );
}

#[test]
fn new_capability_version_has_independent_fallback_policy() {
    let world = roster(NodeExecutionGuarantee::Nondeterministic);
    let capabilities = ExecutorNodeCapabilities::new(
        world.clone(),
        BTreeSet::from([NodeMaterializationStrategy::FreshExecution]),
    )
    .unwrap();
    assert_eq!(&capabilities.canonical_bytes()[..4], &2_u32.to_be_bytes());
    assert_eq!(
        ExecutorNodeCapabilities::from_canonical_bytes(&capabilities.canonical_bytes()).unwrap(),
        capabilities
    );
    assert!(
        ExecutorNodeCapabilities::new(
            world,
            BTreeSet::from([NodeMaterializationStrategy::ThinReplay]),
        )
        .is_err()
    );
}

#[test]
fn strict_decoding_rejects_unknown_versions_trailing_bytes_and_oversized_rosters() {
    let world = roster(NodeExecutionGuarantee::Repeatable);
    let bytes = world.canonical_bytes();
    assert_eq!(
        ExecutorNodeRoster::from_canonical_bytes(&bytes).unwrap(),
        world
    );

    let mut unknown = bytes.clone();
    unknown[..4].copy_from_slice(&2_u32.to_be_bytes());
    assert!(ExecutorNodeRoster::from_canonical_bytes(&unknown).is_err());

    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        ExecutorNodeRoster::from_canonical_bytes(&trailing),
        Err(CampaignCodecError::TrailingBytes)
    );
    assert!(ExecutorNodeRoster::from_canonical_bytes(&vec![0; MAX_ROSTER_BYTES + 1]).is_err());
}
