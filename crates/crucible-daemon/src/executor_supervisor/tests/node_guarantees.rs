//! Fail-closed guarantee checks before legacy replay and native worker admission.

// crucible-lint: allow rust-allow -- test setup and exact authority regressions deliberately panic on failure.
// crucible-lint: allow panic-shortcut -- These node guarantees tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};

use crucible_campaign::executor_node_capabilities::{
    ExecutorNodeRoster, NodeExecutionGuarantee, OwnerImplementationBinding,
};
use crucible_campaign::{CampaignHash, ScenarioArtifactId};

use super::*;

fn mixed_roster(guarantee: NodeExecutionGuarantee) -> ExecutorNodeRoster {
    let profile = CampaignHash::from_bytes([0x51; 32]);
    let modeled = OwnerImplementationBinding::new(
        "qemu-sim".to_owned(),
        profile,
        BTreeSet::from(["compute".to_owned()]),
        NodeExecutionGuarantee::Repeatable,
    )
    .unwrap();
    let physical = OwnerImplementationBinding::new(
        "external-device".to_owned(),
        profile,
        BTreeSet::from(["device".to_owned()]),
        guarantee,
    )
    .unwrap();
    ExecutorNodeRoster::new(
        ScenarioArtifactId::parse(&typed_content_id(
            "crucible.campaign.scenario-artifact",
            "scenario",
            1,
            0x52,
        ))
        .unwrap(),
        configuration(0x53),
        CampaignHash::from_bytes([0x54; 32]),
        BTreeMap::from([
            ("modeled-owner".to_owned(), modeled),
            ("physical-owner".to_owned(), physical),
        ]),
    )
    .unwrap()
}

#[test]
fn nonrepeatable_roster_refuses_cached_completion_before_legacy_assignment_lookup() {
    let epoch = daemon_epoch(0x21);
    let assignment = request(0x11, 0x31, epoch, resources(1, 2048, 4096));
    let cached = SubmitAttemptResponse::new(
        &assignment,
        SubmitAttemptDisposition::AlreadyCompleted {
            observation: observation(0x71),
        },
    )
    .unwrap();
    let mut ledger = MemoryAssignmentLedger::default();
    ledger
        .publish_assignment(&AssignmentRecord::new(assignment.clone(), cached.clone()).unwrap())
        .unwrap();

    let mut supervisor = LocalExecutorSupervisor::new_for_node_roster(
        ledger,
        |_request: &SubmitAttemptRequest| -> Result<(), ExecutorRejection> {
            panic!("nonrepeatable guarantee must refuse before semantic validation")
        },
        epoch,
        ExecutorCapacity::new(1, 2, 4096, 8192, 64).unwrap(),
        mixed_roster(NodeExecutionGuarantee::Nondeterministic),
    );

    let rejected = supervisor.submit_attempt(&assignment).unwrap();
    assert_eq!(
        rejected.disposition(),
        SubmitAttemptDisposition::Rejected {
            reason: ExecutorRejection::Incompatible,
        }
    );
    assert_ne!(rejected, cached);
    assert_eq!(supervisor.active_count(), 0);
    assert_eq!(supervisor.queued_count(), 0);

    let rejected_after_validation = supervisor
        .submit_after_validation(&assignment, Ok(ValidatedSubmitAdmission::default()))
        .unwrap();
    assert_eq!(rejected_after_validation, rejected);
}

#[test]
fn repeatable_claim_does_not_relabel_legacy_state_without_binding_authentication() {
    let epoch = daemon_epoch(0x21);
    let assignment = request(0x11, 0x31, epoch, resources(1, 2048, 4096));
    let mut supervisor = LocalExecutorSupervisor::new_for_node_roster(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        ExecutorCapacity::new(1, 2, 4096, 8192, 64).unwrap(),
        mixed_roster(NodeExecutionGuarantee::Repeatable),
    );

    assert_eq!(
        supervisor
            .submit_attempt(&assignment)
            .unwrap()
            .disposition(),
        SubmitAttemptDisposition::Rejected {
            reason: ExecutorRejection::Incompatible,
        }
    );
    assert_eq!(supervisor.active_count(), 0);
}
