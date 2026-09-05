//! Scripted regressions for exact hot-fork ownership and publication ordering.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};

use crucible_campaign::{AttemptId, CampaignLineageId, ExecutionId};

use super::*;
use crate::{AttemptExecutionDisposition, AttemptExecutionKey, AttemptExecutionReconciliationStep};

#[derive(Debug, Error)]
#[error("injected reconciliation failure")]
struct ScriptedError;

struct ScriptedBackend {
    basis: QemuHotForkReconciliationChildBasis,
    observations: VecDeque<QemuHotForkChildObservation>,
    calls: Arc<Mutex<Vec<&'static str>>>,
    fail_drain_once: bool,
    fail_release_resources_once: bool,
    resource_substeps_before_complete: u8,
}

impl QemuHotForkReconciliationBackend for ScriptedBackend {
    type Error = ScriptedError;

    fn child_basis(&self) -> QemuHotForkReconciliationChildBasis {
        self.basis
    }

    fn admit_child_channel(&mut self) -> Result<(), Self::Error> {
        self.calls.lock().expect("calls").push("admit");
        Ok(())
    }

    fn terminate_child(&mut self) -> Result<(), Self::Error> {
        self.calls.lock().expect("calls").push("terminate");
        Ok(())
    }

    fn drain_child_diagnostics(&mut self) -> Result<(), Self::Error> {
        self.calls.lock().expect("calls").push("drain");
        if self.fail_drain_once {
            self.fail_drain_once = false;
            return Err(ScriptedError);
        }
        Ok(())
    }

    fn observe_child(&mut self) -> Result<QemuHotForkChildObservation, Self::Error> {
        self.calls.lock().expect("calls").push("observe");
        self.observations.pop_front().ok_or(ScriptedError)
    }

    fn release_next_child_resource(&mut self) -> Result<bool, Self::Error> {
        self.calls.lock().expect("calls").push("resources");
        if self.fail_release_resources_once {
            self.fail_release_resources_once = false;
            return Err(ScriptedError);
        }
        if self.resource_substeps_before_complete != 0 {
            self.resource_substeps_before_complete -= 1;
            return Ok(false);
        }
        Ok(true)
    }

    fn release_target(&mut self) -> Result<(), Self::Error> {
        self.calls.lock().expect("calls").push("target");
        Ok(())
    }

    fn release_source_status(
        &mut self,
        _terminal: QemuHotForkChildObservation,
    ) -> Result<(), Self::Error> {
        self.calls.lock().expect("calls").push("status");
        Ok(())
    }

    fn release_process_contract(&mut self) -> Result<(), Self::Error> {
        self.calls.lock().expect("calls").push("contract");
        Ok(())
    }

    fn quarantine(&mut self) {
        self.calls.lock().expect("calls").push("quarantine");
    }
}

fn basis() -> QemuHotForkReconciliationChildBasis {
    QemuHotForkReconciliationChildBasis::new(41, 4242)
}

fn attempt_basis() -> QemuHotForkAttemptBasis {
    QemuHotForkAttemptBasis::new(
        AttemptExecutionKey::new(
            CampaignLineageId::parse(&typed_id(
                "crucible.campaign.lineage",
                "campaign-fact",
                0x31,
            ))
            .expect("lineage"),
            AttemptId::parse(&typed_id(
                "crucible.campaign.attempt",
                "campaign-fact",
                0x32,
            ))
            .expect("attempt"),
        ),
        ExecutionId::from_bytes([0x33; 16]).expect("execution"),
    )
}

fn typed_id(tag: &str, kind: &str, byte: u8) -> String {
    format!("{tag}@{kind}.1.{}", encode_hex(&[byte; 32]))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn observed(
    basis: QemuHotForkReconciliationChildBasis,
    disposition: QemuHotForkChildDisposition,
) -> QemuHotForkChildObservation {
    QemuHotForkChildObservation::new(basis.generation(), basis.process_id(), disposition)
        .expect("valid child observation")
}

fn service_and_observe(
    owner: &mut QemuHotForkAttemptReconciliation<ScriptedBackend>,
) -> QemuHotForkReconciliationStep {
    assert_eq!(
        owner.reconcile_step().expect("service child diagnostics"),
        QemuHotForkReconciliationStep::ChildDiagnosticsDrained
    );
    owner.reconcile_step().expect("observe child status")
}

fn scripted(
    dispositions: impl IntoIterator<Item = QemuHotForkChildDisposition>,
    fail_release_resources_once: bool,
) -> (
    QemuHotForkAttemptReconciliation<ScriptedBackend>,
    Arc<Mutex<Vec<&'static str>>>,
) {
    scripted_with_resource_substeps(dispositions, fail_release_resources_once, 0)
}

fn scripted_with_resource_substeps(
    dispositions: impl IntoIterator<Item = QemuHotForkChildDisposition>,
    fail_release_resources_once: bool,
    resource_substeps_before_complete: u8,
) -> (
    QemuHotForkAttemptReconciliation<ScriptedBackend>,
    Arc<Mutex<Vec<&'static str>>>,
) {
    let basis = basis();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let observations = dispositions
        .into_iter()
        .map(|disposition| observed(basis, disposition))
        .collect();
    (
        QemuHotForkAttemptReconciliation::new(
            attempt_basis(),
            ScriptedBackend {
                basis,
                observations,
                calls: Arc::clone(&calls),
                fail_drain_once: false,
                fail_release_resources_once,
                resource_substeps_before_complete,
            },
        ),
        calls,
    )
}

#[test]
fn exact_terminal_cleanup_waits_for_semantic_publication() {
    let (mut owner, calls) = scripted(
        [
            QemuHotForkChildDisposition::Running,
            QemuHotForkChildDisposition::Exited(0),
        ],
        false,
    );
    owner.admit_child().expect("admit child");
    assert_eq!(
        service_and_observe(&mut owner),
        QemuHotForkReconciliationStep::ChildRunning
    );
    assert_eq!(
        service_and_observe(&mut owner),
        QemuHotForkReconciliationStep::Advanced(QemuHotForkReconciliationPhase::ParentReaped)
    );
    assert_eq!(
        owner.reconcile_step().expect("release child resources"),
        QemuHotForkReconciliationStep::Advanced(
            QemuHotForkReconciliationPhase::ChildResourcesReleased
        )
    );
    assert_eq!(
        owner.reconcile_step().expect("release target"),
        QemuHotForkReconciliationStep::Advanced(QemuHotForkReconciliationPhase::TargetReleased)
    );
    assert_eq!(
        owner.reconcile_step().expect("await publication"),
        QemuHotForkReconciliationStep::AwaitingPublication
    );
    assert_eq!(
        calls.lock().expect("calls").as_slice(),
        [
            "drain",
            "admit",
            "drain",
            "observe",
            "drain",
            "observe",
            "resources",
            "target"
        ]
    );

    let observation = ObservationId::parse(&typed_id(
        "crucible.campaign.observation",
        "observation",
        0x44,
    ))
    .expect("observation");
    owner
        .reconcile_publication(QemuHotForkPublicationDisposition::Observation(observation))
        .expect("publication");
    assert_eq!(
        owner.reconcile_step().expect("release status"),
        QemuHotForkReconciliationStep::Advanced(
            QemuHotForkReconciliationPhase::SourceStatusReleased
        )
    );
    assert_eq!(
        owner.reconcile_step().expect("release contract"),
        QemuHotForkReconciliationStep::Complete
    );
    assert_eq!(
        calls.lock().expect("calls").as_slice(),
        [
            "drain",
            "admit",
            "drain",
            "observe",
            "drain",
            "observe",
            "resources",
            "target",
            "status",
            "contract",
        ]
    );
    let backend = match owner.into_reconciled_backend() {
        Ok(backend) => backend,
        Err(_owner) => panic!("expected a reconciled backend"),
    };
    drop(backend);
    assert!(!calls.lock().expect("calls").contains(&"quarantine"));
}

#[test]
fn retry_resumes_at_the_first_unreleased_phase_without_rerunning_guest() {
    let (mut owner, calls) = scripted([QemuHotForkChildDisposition::Signaled(9)], true);
    owner.request_termination().expect("terminate");
    service_and_observe(&mut owner);
    assert!(owner.reconcile_step().is_err());
    assert_eq!(owner.phase(), QemuHotForkReconciliationPhase::ParentReaped);
    owner.reconcile_step().expect("retry resources");
    assert_eq!(
        calls.lock().expect("calls").as_slice(),
        ["terminate", "drain", "observe", "resources", "resources"]
    );
    owner.quarantine();
}

#[test]
fn diagnostic_drain_failure_quarantines_before_status_observation() {
    let child_basis = basis();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut owner = QemuHotForkAttemptReconciliation::new(
        attempt_basis(),
        ScriptedBackend {
            basis: child_basis,
            observations: VecDeque::from([observed(
                child_basis,
                QemuHotForkChildDisposition::Running,
            )]),
            calls: Arc::clone(&calls),
            fail_drain_once: true,
            fail_release_resources_once: false,
            resource_substeps_before_complete: 0,
        },
    );

    assert!(matches!(
        owner.reconcile_step(),
        Err(QemuHotForkAttemptReconciliationError::Operation {
            operation: "drain branch-private child diagnostics",
            ..
        })
    ));
    assert_eq!(owner.phase(), QemuHotForkReconciliationPhase::Quarantined);
    assert_eq!(
        calls.lock().expect("calls").as_slice(),
        ["drain", "quarantine"]
    );
}

#[test]
fn diagnostic_drain_failure_quarantines_before_child_admission() {
    let child_basis = basis();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut owner = QemuHotForkAttemptReconciliation::new(
        attempt_basis(),
        ScriptedBackend {
            basis: child_basis,
            observations: VecDeque::new(),
            calls: Arc::clone(&calls),
            fail_drain_once: true,
            fail_release_resources_once: false,
            resource_substeps_before_complete: 0,
        },
    );

    assert!(matches!(
        owner.admit_child(),
        Err(QemuHotForkAttemptReconciliationError::Operation {
            operation: "drain child diagnostics before admission",
            ..
        })
    ));
    assert_eq!(owner.phase(), QemuHotForkReconciliationPhase::Quarantined);
    assert_eq!(
        calls.lock().expect("calls").as_slice(),
        ["drain", "quarantine"]
    );
}

#[test]
fn one_step_releases_at_most_one_backend_owned_child_resource() {
    let (mut owner, calls) =
        scripted_with_resource_substeps([QemuHotForkChildDisposition::Exited(0)], false, 2);
    service_and_observe(&mut owner);
    for _ in 0..2 {
        assert_eq!(
            owner.reconcile_step().expect("release one substep"),
            QemuHotForkReconciliationStep::Advanced(QemuHotForkReconciliationPhase::ParentReaped)
        );
    }
    assert_eq!(
        owner.reconcile_step().expect("finish child resources"),
        QemuHotForkReconciliationStep::Advanced(
            QemuHotForkReconciliationPhase::ChildResourcesReleased
        )
    );
    assert_eq!(
        calls.lock().expect("calls").as_slice(),
        ["drain", "observe", "resources", "resources", "resources"]
    );
    owner.quarantine();
}

#[test]
fn dropping_incomplete_owner_transfers_cleanup_to_quarantine() {
    let (owner, calls) = scripted([QemuHotForkChildDisposition::Running], false);
    drop(owner);
    assert_eq!(calls.lock().expect("calls").as_slice(), ["quarantine"]);
}

#[test]
fn explicitly_quarantined_owner_does_not_transfer_twice_on_drop() {
    let (mut owner, calls) = scripted([QemuHotForkChildDisposition::Running], false);
    owner.quarantine();
    drop(owner);
    assert_eq!(calls.lock().expect("calls").as_slice(), ["quarantine"]);
}

#[test]
fn unadmitted_child_cannot_publish_a_modeled_observation() {
    let (mut owner, _calls) = scripted([QemuHotForkChildDisposition::Signaled(9)], false);
    owner.request_termination().expect("terminate");
    service_and_observe(&mut owner);
    owner.reconcile_step().expect("release resources");
    owner.reconcile_step().expect("release target");
    owner.reconcile_step().expect("await publication");

    let observation = ObservationId::parse(&typed_id(
        "crucible.campaign.observation",
        "observation",
        0x45,
    ))
    .expect("observation");
    assert!(matches!(
        owner.reconcile_publication(QemuHotForkPublicationDisposition::Observation(observation)),
        Err(QemuHotForkAttemptReconciliationError::ModeledResultWithoutAdmission)
    ));
    owner
        .reconcile_publication(QemuHotForkPublicationDisposition::TerminalFailure)
        .expect("terminal failure disposition");
    owner.quarantine();
}

#[test]
fn worker_disposition_drives_the_retained_owner_to_completion() {
    let (mut owner, calls) = scripted([QemuHotForkChildDisposition::Exited(0)], false);
    owner.admit_child().expect("admit child");
    service_and_observe(&mut owner);
    owner.reconcile_step().expect("release child resources");
    owner.reconcile_step().expect("release target");
    owner.reconcile_step().expect("await publication");

    let observation = observation_id(0x46);
    assert_eq!(
        owner
            .reconcile_execution_disposition(AttemptExecutionDisposition::Observation(observation,))
            .expect("release source status"),
        AttemptExecutionReconciliationStep::Progressed
    );
    assert!(matches!(
        owner.reconcile_execution_disposition(AttemptExecutionDisposition::Canceled),
        Err(QemuHotForkAttemptReconciliationError::PublicationDispositionMismatch)
    ));
    assert_eq!(
        owner
            .reconcile_execution_disposition(AttemptExecutionDisposition::Observation(observation,))
            .expect("release process contract"),
        AttemptExecutionReconciliationStep::Complete
    );
    assert_eq!(
        calls.lock().expect("calls").as_slice(),
        [
            "drain",
            "admit",
            "drain",
            "observe",
            "resources",
            "target",
            "status",
            "contract"
        ]
    );
    let Ok(backend) = owner.into_reconciled_backend() else {
        panic!("owner should be fully reconciled")
    };
    drop(backend);
}

#[test]
fn a_foreign_parent_observation_fails_before_any_release() {
    let basis = basis();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut owner = QemuHotForkAttemptReconciliation::new(
        attempt_basis(),
        ScriptedBackend {
            basis,
            observations: VecDeque::from([QemuHotForkChildObservation::new(
                basis.generation(),
                basis.process_id() + 1,
                QemuHotForkChildDisposition::Exited(0),
            )
            .expect("foreign observation")]),
            calls: Arc::clone(&calls),
            fail_drain_once: false,
            fail_release_resources_once: false,
            resource_substeps_before_complete: 0,
        },
    );
    assert_eq!(
        owner.reconcile_step().expect("service child diagnostics"),
        QemuHotForkReconciliationStep::ChildDiagnosticsDrained
    );
    assert!(matches!(
        owner.reconcile_step(),
        Err(QemuHotForkAttemptReconciliationError::ChildBasisMismatch)
    ));
    assert_eq!(
        calls.lock().expect("calls").as_slice(),
        ["drain", "observe"]
    );
    owner.quarantine();
}

#[test]
fn io_error_type_remains_send_sync_for_worker_ownership() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<io::Error>();
    assert_send_sync::<LinuxQemuHotForkReconciliationError>();
}

fn observation_id(byte: u8) -> ObservationId {
    ObservationId::parse(&typed_id(
        "crucible.campaign.observation",
        "observation",
        byte,
    ))
    .expect("observation")
}
