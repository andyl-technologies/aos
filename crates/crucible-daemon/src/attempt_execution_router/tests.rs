//! Checks common routing with opaque data-only adapter proofs and legacy inputs.
//!
//! These fixtures perform no native preparation or backend qualification.
#![cfg(test)]
// crucible-lint: allow panic-shortcut -- fixtures identify exact proof and routing failures.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::*;
use crate::ExecutionCancellation;
use crucible::Configuration;
use crucible_campaign::{
    Attempt, AttemptResourceLimits, AttemptStart, BranchPath, CampaignLineage,
    ConfigurationArtifact, ConfigurationId, ExactCheckpointId, ExecutionRetentionIntent,
    ScenarioArtifact, ScenarioDefId,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

struct OriginalProof(AttemptReplayContract);
struct OriginalBoundary;

struct DataAdapter {
    contract: Option<AttemptReplayContract>,
    calls: Arc<Mutex<Vec<&'static str>>>,
    reject_start: bool,
    reconcile_retry: bool,
}

impl DataAdapter {
    fn record(&self, call: &'static str) {
        self.calls.lock().unwrap().push(call);
    }
}

impl CrucibleExecutionRunner for DataAdapter {
    type Error = &'static str;

    fn execute(
        &mut self,
        _: &CrucibleAttemptExecution,
        _: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        self.record("execute");
        Err(AttemptWorkerFailure::Canceled("data-only execution"))
    }

    fn reconcile_execution(
        &mut self,
        _: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        self.record("reconcile");
        if self.reconcile_retry {
            self.reconcile_retry = false;
            return Err(AttemptWorkerFailure::Retryable(
                "original publication pending",
            ));
        }
        Ok(AttemptExecutionReconciliationStep::Complete)
    }

    fn quarantine_pending_execution(&mut self) {
        self.record("quarantine");
    }
}

impl AttemptOriginVerifier for DataAdapter {
    type SelectedBoundary = OriginalBoundary;
    type SelectedProof = OriginalProof;
    type StartProof = OriginalProof;

    fn replay_contract(&self) -> Option<AttemptReplayContract> {
        self.contract
    }

    fn verify_selected_resume(
        &mut self,
        _: &CrucibleAttemptExecution,
        _: &AttemptExecutionContext,
        _: &OriginalBoundary,
    ) -> Result<OriginalProof, AttemptWorkerFailure<Self::Error>> {
        self.record("selected-proof");
        Ok(OriginalProof(self.contract.expect("declared contract")))
    }

    fn verify_start_prefix(
        &mut self,
        _: &CrucibleAttemptExecution,
        _: &AttemptExecutionContext,
    ) -> Result<OriginalProof, AttemptWorkerFailure<Self::Error>> {
        self.record("start-proof");
        if self.reject_start {
            return Err(AttemptWorkerFailure::Retryable(
                "original prefix unavailable",
            ));
        }
        Ok(OriginalProof(self.contract.expect("declared contract")))
    }
}

impl AttemptOriginResumeRunner for DataAdapter {
    type SelectedBoundary = OriginalBoundary;
    type SelectedProof = OriginalProof;
    type StartProof = OriginalProof;

    fn replay_contract(&self) -> Option<AttemptReplayContract> {
        self.contract
    }

    fn authenticate_resume_source(
        &mut self,
        _: &CrucibleAttemptExecution,
        _: &AttemptExecutionContext,
    ) -> Result<Option<OriginalBoundary>, AttemptWorkerFailure<Self::Error>> {
        self.record("source");
        Ok(Some(OriginalBoundary))
    }

    fn resume_verified_source(
        &mut self,
        _: &CrucibleAttemptExecution,
        _: &AttemptExecutionContext,
        proof: OriginalProof,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        assert_eq!(Some(proof.0), self.contract);
        self.record("selected-resume");
        Err(AttemptWorkerFailure::Canceled("data-only resume"))
    }

    fn resume_verified_start(
        &mut self,
        _: &CrucibleAttemptExecution,
        _: &AttemptExecutionContext,
        proof: OriginalProof,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        assert_eq!(Some(proof.0), self.contract);
        self.record("start-resume");
        Err(AttemptWorkerFailure::Canceled("data-only resume"))
    }
}

fn contract(byte: u8) -> AttemptReplayContract {
    AttemptReplayContract::new(CampaignHash::from_bytes([byte; 32]))
}

fn adapters(
    left: Option<AttemptReplayContract>,
    right: Option<AttemptReplayContract>,
) -> (DataAdapter, DataAdapter, Arc<Mutex<Vec<&'static str>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    (
        DataAdapter {
            contract: left,
            calls: calls.clone(),
            reject_start: false,
            reconcile_retry: false,
        },
        DataAdapter {
            contract: right,
            calls: calls.clone(),
            reject_start: false,
            reconcile_retry: false,
        },
        calls,
    )
}

#[test]
fn undeclared_or_foreign_contract_refuses_before_execution() {
    for (left, right, expected) in [
        (
            None,
            Some(contract(1)),
            AttemptExecutionRouterConstructionError::MissingReplayContract,
        ),
        (
            Some(contract(1)),
            None,
            AttemptExecutionRouterConstructionError::MissingReplayContract,
        ),
        (
            Some(contract(1)),
            Some(contract(2)),
            AttemptExecutionRouterConstructionError::IncompatibleReplayContract,
        ),
    ] {
        let (fresh, resume, calls) = adapters(left, right);
        assert!(
            matches!(AttemptExecutionRouter::new(fresh, resume), Err(error) if error.reason() == expected)
        );
        assert!(calls.lock().unwrap().is_empty());
    }
}

#[test]
fn opaque_non_qemu_start_proof_precedes_resume() {
    let (fresh, resume, calls) = adapters(Some(contract(1)), Some(contract(1)));
    let mut router = AttemptExecutionRouter::new(fresh, resume).expect("paired contracts");
    let input = routed_input_for_stop(StopCondition::EventCount(4));
    let context = routed_context(Some(exact_checkpoint_id(b"common-original")));

    assert!(matches!(
        router.execute(&input, &context),
        Err(AttemptWorkerFailure::Canceled(
            AttemptExecutionRouterError::Resume("data-only resume")
        ))
    ));
    assert_eq!(*calls.lock().unwrap(), ["start-proof", "start-resume"]);
}

#[test]
fn changed_original_contract_refuses_before_dispatch() {
    let (fresh, resume, calls) = adapters(Some(contract(1)), Some(contract(1)));
    let mut router = AttemptExecutionRouter::new(fresh, resume).expect("paired contracts");
    router.fresh_mut().contract = Some(contract(2));

    assert!(matches!(
        router.execute(
            &routed_input_for_stop(StopCondition::Terminal),
            &routed_context(None)
        ),
        Err(AttemptWorkerFailure::Terminal(
            AttemptExecutionRouterError::ReplayContractChanged
        ))
    ));
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn unavailable_original_prefix_retains_failure_class_without_resume() {
    let (mut fresh, resume, calls) = adapters(Some(contract(1)), Some(contract(1)));
    fresh.reject_start = true;
    let mut router = AttemptExecutionRouter::new(fresh, resume).expect("paired contracts");
    let input = routed_input_for_stop(StopCondition::EventCount(4));
    let context = routed_context(Some(exact_checkpoint_id(b"common-unavailable")));

    assert!(matches!(
        router.execute(&input, &context),
        Err(AttemptWorkerFailure::Retryable(
            AttemptExecutionRouterError::Fresh("original prefix unavailable")
        ))
    ));
    assert_eq!(*calls.lock().unwrap(), ["start-proof"]);
}

#[test]
fn selected_original_boundary_proof_precedes_native_resume_adapter() {
    let (fresh, resume, calls) = adapters(Some(contract(1)), Some(contract(1)));
    let mut router = AttemptExecutionRouter::new(fresh, resume).expect("paired contracts");
    let base = routed_input_for_stop(StopCondition::Terminal);
    let configuration = base.start().configuration().clone();
    let replay = crucible::SignalFaultCampaignReplayPlan::empty(configuration.clone());
    let origin = crate::crucible_execution::CrucibleAttemptOrigin::new(
        base.attempt().clone(),
        configuration,
        replay.clone(),
    );
    let input = base.for_origin_replay(
        base.attempt().clone(),
        CrucibleResolvedAttemptStart::AfterAttempt {
            base: Box::new(base.start().clone()),
            base_signal_fault_replay: replay.clone(),
            origins: Box::new(crate::crucible_execution::CrucibleAttemptOrigins::new(
                origin,
                Vec::new(),
            )),
        },
        replay,
    );
    let context = routed_context(Some(exact_checkpoint_id(b"selected-original")));

    assert!(matches!(
        router.execute(&input, &context),
        Err(AttemptWorkerFailure::Canceled(
            AttemptExecutionRouterError::Resume("data-only resume")
        ))
    ));
    assert_eq!(
        *calls.lock().unwrap(),
        ["source", "selected-proof", "selected-resume"]
    );
}

#[test]
fn pending_original_reconciliation_retains_route_until_complete() {
    let (mut fresh, resume, calls) = adapters(Some(contract(1)), Some(contract(1)));
    fresh.reconcile_retry = true;
    let mut router = AttemptExecutionRouter::new(fresh, resume).expect("paired contracts");
    // This data-only state fixture supplies no successful native outcome.
    router.pending = Some(PendingRoute::Fresh);
    let input = routed_input_for_stop(StopCondition::Terminal);

    assert!(matches!(
        router.execute(&input, &routed_context(None)),
        Err(AttemptWorkerFailure::Terminal(
            AttemptExecutionRouterError::PriorReconciliationPending
        ))
    ));
    assert!(matches!(
        router.reconcile_execution(AttemptExecutionDisposition::Failed),
        Err(AttemptWorkerFailure::Retryable(
            AttemptExecutionRouterError::Fresh("original publication pending")
        ))
    ));
    assert_eq!(router.pending, Some(PendingRoute::Fresh));
    assert_eq!(
        router
            .reconcile_execution(AttemptExecutionDisposition::Failed)
            .expect("original reconciled"),
        AttemptExecutionReconciliationStep::Complete
    );
    assert_eq!(router.pending, None);
    assert_eq!(*calls.lock().unwrap(), ["reconcile", "reconcile"]);
}

#[test]
fn quarantine_delegates_only_to_the_original_pending_route() {
    let (fresh, resume, calls) = adapters(Some(contract(1)), Some(contract(1)));
    let mut router = AttemptExecutionRouter::new(fresh, resume).expect("paired contracts");
    router.pending = Some(PendingRoute::Resume);

    router.quarantine_pending_execution();
    router.quarantine_pending_execution();
    assert_eq!(router.pending, None);
    assert_eq!(*calls.lock().unwrap(), ["quarantine"]);
}

#[test]
fn mixed_roster_contracts_refuse_a_changed_backend_or_missing_owner() {
    let mixed = AttemptReplayContract::new(CampaignHash::derive(
        "data-only-roster",
        b"host-clock:1;gem5-closed:2",
    ));
    for foreign in [
        b"host-clock:1;qemu:2".as_slice(),
        b"gem5-closed:2".as_slice(),
    ] {
        let changed = AttemptReplayContract::new(CampaignHash::derive("data-only-roster", foreign));
        let (fresh, resume, calls) = adapters(Some(mixed), Some(changed));

        assert!(matches!(
            AttemptExecutionRouter::new(fresh, resume),
            Err(failure) if failure.reason() == AttemptExecutionRouterConstructionError::IncompatibleReplayContract
        ));
        assert!(calls.lock().unwrap().is_empty());
    }
}

#[test]
fn refused_pair_retains_both_original_adapters_for_explicit_disposition() {
    let (fresh, resume, calls) = adapters(Some(contract(1)), Some(contract(2)));
    let failure = match AttemptExecutionRouter::new(fresh, resume) {
        Err(failure) => failure,
        Ok(_) => panic!("foreign original contract accepted"),
    };
    assert_eq!(failure.fresh().contract, Some(contract(1)));
    assert_eq!(failure.resume().contract, Some(contract(2)));
    assert!(calls.lock().unwrap().is_empty());

    let (reason, fresh, resume) = failure.into_parts();
    assert_eq!(
        reason,
        AttemptExecutionRouterConstructionError::IncompatibleReplayContract
    );
    assert!(Arc::ptr_eq(&fresh.calls, &calls));
    assert!(Arc::ptr_eq(&resume.calls, &calls));
    assert_eq!(fresh.contract, Some(contract(1)));
    assert_eq!(resume.contract, Some(contract(2)));
}

fn routed_input_for_stop(stop: StopCondition) -> CrucibleAttemptExecution {
    let scenario = crucible::crash_restart_scenario()
        .expect("built-in scenario")
        .scenario;
    let definition = scenario.scenario_def();
    let scenario_id = ScenarioDefId::from_hash(CampaignHash::from_bytes(definition.id().bytes));
    let scenario_artifact =
        ScenarioArtifact::new(scenario_id, 1, b"scenario".to_vec()).expect("scenario artifact");
    let scenario_content = scenario_artifact.id().expect("scenario artifact id");
    let configuration = Configuration::genesis(definition);
    let configuration_id =
        ConfigurationId::from_hash(CampaignHash::from_bytes(configuration.id().bytes));
    let configuration_artifact = ConfigurationArtifact::new(
        scenario_id,
        scenario_content,
        configuration_id,
        1,
        b"configuration".to_vec(),
    )
    .expect("configuration artifact");
    let configuration_content = configuration_artifact
        .id()
        .expect("configuration artifact id");
    let lineage = CampaignLineage::new(
        scenario_id,
        scenario_content,
        configuration_id,
        configuration_content,
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )
    .expect("campaign lineage");
    let path = BranchPath::new(Vec::new()).expect("genesis branch path");
    let attempt = Attempt::new(
        AttemptStart::Discover {
            configuration: configuration_content,
        },
        path.id().expect("branch path id"),
        stop,
    )
    .expect("discovery attempt");

    CrucibleAttemptExecution::from_test_parts(
        lineage,
        scenario,
        attempt,
        path,
        CrucibleResolvedAttemptStart::Discover { configuration },
    )
}

fn routed_context(checkpoint: Option<ExactCheckpointId>) -> AttemptExecutionContext {
    AttemptExecutionContext::new(
        AttemptResourceLimits::new(1, 1, 0, 1).expect("attempt limits"),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        crate::ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .with_resume_checkpoint(checkpoint)
}

fn exact_checkpoint_id(material: &[u8]) -> crucible_campaign::ExactCheckpointId {
    crucible_campaign::ExactCheckpointId::try_from(
        crucible_cas::content_store::ContentId::for_bytes(
            crucible_cas::content_store::ObjectKind::ExactManifest,
            5,
            material,
        ),
    )
    .expect("exact checkpoint root")
}
