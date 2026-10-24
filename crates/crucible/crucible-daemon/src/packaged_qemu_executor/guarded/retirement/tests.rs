//! Aggregation controls using actual worker retirement and borrowed file custody.
//!
//! These exercise returned reports only, without constructing Main or a native
//! factory. The production native stage ordering is checked separately.

use super::*;
use crate::campaign_process::{ExecutorWorkerRetirementError, retire_control_bodies};
use crucible_host_resources::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationGuard, HostOperationSupervisor,
};
use std::cell::{Cell, RefCell};
use std::error::Error;
use std::fs::File;
use std::time::Duration;

type TestResult = Result<(), Box<dyn Error>>;

struct FileWorker(File);

impl crate::LocalAttemptWorker for FileWorker {
    type Error = crucible_host_resources::host_supervision::HostSupervisionError;

    fn execute(&mut self, _: crate::QueuedAttempt) -> crate::AttemptWorkResult<Self::Error> {
        panic!("component cleanup owns no campaign execution");
    }

    fn try_retire_original(&mut self, original: &HostOperationGuard) -> Result<(), Self::Error> {
        original.wait_slice()?;
        assert!(self.0.metadata().is_ok());
        Ok(())
    }
}

struct FileCell {
    file: RefCell<Option<File>>,
    first: RefCell<Option<crucible_control_api::LifecycleApiError>>,
}

impl FileCell {
    fn new() -> std::io::Result<Self> {
        Ok(Self {
            file: RefCell::new(Some(tempfile::tempfile()?)),
            first: RefCell::new(Some(crucible_control_api::LifecycleApiError::LoopFactory {
                message: String::from("actual component file remains retained"),
            })),
        })
    }

    fn drain(&self) -> Result<(), crucible_control_api::LifecycleApiError> {
        if let Some(first) = self.first.borrow_mut().take() {
            return Err(first);
        }
        let mut file = self
            .file
            .try_borrow_mut()
            .map_err(|_| crucible_control_api::LifecycleApiError::ConstructionCustodyUnavailable)?;
        drop(file.take());
        Ok(())
    }

    fn observe(&self) -> Result<(), crucible_control_api::LifecycleApiError> {
        if self.file.borrow().is_none() {
            Ok(())
        } else {
            Err(crucible_control_api::LifecycleApiError::ConstructionCustodyUnavailable)
        }
    }
}

struct ControlFixture {
    workers: Arc<crate::executor_pool::ExecutorWorkerCustody>,
    file: FileCell,
}

impl ControlFixture {
    fn new() -> std::io::Result<Self> {
        Ok(Self {
            workers: crate::executor_pool::PreparedExecutorWorkers::unissued_component_custody(
                vec![FileWorker(tempfile::tempfile()?)],
            ),
            file: FileCell::new()?,
        })
    }

    fn report(
        &self,
        original: &HostOperationGuard,
    ) -> crate::campaign_process::ExecutorControlRetirementError {
        retire_control_bodies(
            original,
            || {
                self.workers
                    .try_retire_original(original)
                    .map_err(ExecutorWorkerRetirementError::Worker)
            },
            || self.file.drain(),
            || {
                self.workers
                    .verify_retired()
                    .map_err(ExecutorWorkerRetirementError::Worker)
            },
            || self.file.observe(),
        )
        .unwrap_err()
    }
}

fn cleanup() -> Result<HostOperationGuard, Box<dyn Error>> {
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )?;
    Ok(supervisor.begin(HostOperationClass::Cleanup)?)
}

fn lifecycle_payload(error: &crucible_control_api::LifecycleApiError) -> *const u8 {
    match error {
        crucible_control_api::LifecycleApiError::LoopFactory { message } => message.as_ptr(),
        other => panic!("unexpected component file cause: {other:?}"),
    }
}

fn control_payload(error: &crate::campaign_process::ExecutorControlRetirementError) -> *const u8 {
    lifecycle_payload(
        error
            .source()
            .unwrap()
            .downcast_ref::<crucible_control_api::LifecycleApiError>()
            .unwrap(),
    )
}

fn native_payload(cause: &GuardedCampaignOwnerRetirementCause) -> Option<*const u8> {
    match cause {
        GuardedCampaignOwnerRetirementCause::Actor(HostOperationalError::InvalidMessage {
            message,
        })
        | GuardedCampaignOwnerRetirementCause::Factory(
            QemuVmRealizationError::ExecutorUnavailable { message, .. },
        ) => Some(message.as_ptr()),
        _ => None,
    }
}

#[test]
fn occupied_file_controls_precede_independent_lifecycle_without_native_effects() -> TestResult {
    let original = cleanup()?;
    let fixture = ControlFixture::new()?;
    let borrowed_file = fixture.file.file.borrow();
    let controls = fixture.report(&original);
    assert!(!controls.physically_closed());
    assert!(fixture.workers.verify_retired().is_ok());
    let controls_payload = control_payload(&controls);
    let independent = FileCell::new()?;
    let lifecycle = independent.drain().unwrap_err();
    let lifecycle_address = lifecycle_payload(&lifecycle);

    let error = retire_after_controls(Some(controls), Some(lifecycle), || {
        panic!("unfinished actual file custody must exclude native retirement")
    })
    .unwrap_err();

    assert!(matches!(
        error.first_error(),
        GuardedCampaignOwnerRetirementCause::Controls(_)
    ));
    assert_eq!(
        control_payload(error.controls_error().unwrap()),
        controls_payload
    );
    assert_eq!(
        lifecycle_payload(error.lifecycle_error().unwrap()),
        lifecycle_address
    );
    assert!(!error.controls_error().unwrap().physically_closed());
    assert!(borrowed_file.as_ref().unwrap().metadata().is_ok());
    assert!(independent.file.borrow().is_some());
    Ok(())
}

#[test]
fn lifecycle_precedes_closed_controls_without_losing_either_payload() -> TestResult {
    let original = cleanup()?;
    let fixture = ControlFixture::new()?;
    let controls = fixture.report(&original);
    assert!(controls.physically_closed());
    assert!(fixture.file.file.borrow().is_none());
    assert!(fixture.workers.verify_retired().is_ok());
    let controls_payload = control_payload(&controls);
    let independent = FileCell::new()?;
    let lifecycle = independent.drain().unwrap_err();
    let lifecycle_address = lifecycle_payload(&lifecycle);

    let error = retire_after_controls(Some(controls), Some(lifecycle), || {
        panic!("independent lifecycle refusal precedes native retirement")
    })
    .unwrap_err();

    assert!(matches!(
        error.first_error(),
        GuardedCampaignOwnerRetirementCause::LifecycleCleanup(_)
    ));
    assert_eq!(
        control_payload(error.controls_error().unwrap()),
        controls_payload
    );
    assert_eq!(
        lifecycle_payload(error.lifecycle_error().unwrap()),
        lifecycle_address
    );
    assert!(error.controls_error().unwrap().physically_closed());
    Ok(())
}

#[test]
fn native_refusals_precede_closed_controls_and_preserve_their_history() -> TestResult {
    let original = cleanup()?;
    for first in [
        GuardedCampaignOwnerRetirementCause::SharedOwner,
        GuardedCampaignOwnerRetirementCause::BorrowedMain,
        GuardedCampaignOwnerRetirementCause::Actor(HostOperationalError::InvalidMessage {
            message: String::from("component actor refusal"),
        }),
        GuardedCampaignOwnerRetirementCause::Factory(QemuVmRealizationError::ExecutorUnavailable {
            operation: "component native refusal",
            message: String::from("component factory refusal"),
        }),
    ] {
        let fixture = ControlFixture::new()?;
        let controls = fixture.report(&original);
        assert!(controls.physically_closed());
        let payload = control_payload(&controls);
        let expected = std::mem::discriminant(&first);
        let first_payload = native_payload(&first);
        let calls = Cell::new(0);

        let error = retire_after_controls(Some(controls), None, || {
            calls.set(calls.get() + 1);
            Err(first)
        })
        .unwrap_err();

        assert_eq!(calls.get(), 1);
        assert_eq!(std::mem::discriminant(error.first_error()), expected);
        assert_eq!(native_payload(error.first_error()), first_payload);
        assert_eq!(control_payload(error.controls_error().unwrap()), payload);
        assert!(error.lifecycle_error().is_none());
    }
    Ok(())
}

#[test]
fn completed_or_pending_native_observation_preserves_closed_controls_priority() -> TestResult {
    let original = cleanup()?;
    for outcome in [
        Ok(()),
        Err(GuardedCampaignOwnerRetirementCause::DispatcherPending),
    ] {
        let fixture = ControlFixture::new()?;
        let controls = fixture.report(&original);
        assert!(controls.physically_closed());
        let payload = control_payload(&controls);

        let error = retire_after_controls(Some(controls), None, || outcome).unwrap_err();

        assert!(matches!(
            error.first_error(),
            GuardedCampaignOwnerRetirementCause::Controls(_)
        ));
        assert_eq!(control_payload(error.controls_error().unwrap()), payload);
        assert!(error.controls_error().unwrap().physically_closed());
    }
    Ok(())
}

#[test]
fn no_history_preserves_success_or_the_actual_native_refusal() {
    assert!(retire_after_controls(None, None, || Ok(())).is_ok());
    let error = retire_after_controls(None, None, || {
        Err(GuardedCampaignOwnerRetirementCause::DispatcherPending)
    })
    .unwrap_err();
    assert!(matches!(
        error.first_error(),
        GuardedCampaignOwnerRetirementCause::DispatcherPending
    ));
    assert!(error.controls_error().is_none());
    assert!(error.lifecycle_error().is_none());
}
