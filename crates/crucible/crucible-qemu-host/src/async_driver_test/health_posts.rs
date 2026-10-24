//! Checks same-operation posts after actual driver health returns.
//!
//! Scripted Source observations exercise the real driver and supervisor. They
//! do not issue Native entry, physical child return or selected execution.

use super::*;
use super::supervision::SupervisedRuntime;
use crate::ram_source::QemuRamSourceError;
use crucible_engine::{BackendError, BackendOperationalFailureKind, SchedulerError};
use crucible_host_resources::host_supervision::{HostOperationState, HostSupervisionError};
use std::error::Error;

#[test]
fn health_returns_observe_actual_original_at_every_quantum_cut() -> Result<(), Box<dyn Error>> {
    for cut in 1..=3 {
        for refuse_health in [false, true] {
            let mut runtime = SupervisedRuntime::new()?;
            let source = QemuAsyncDriverHealthError::ram_source(QemuRamSourceError::Canceled);
            let mut target = ScriptedTarget::completed();
            target.cancel_during_health = Some((
                runtime.supervisor.clone(),
                cut,
                refuse_health.then(|| source.clone()),
            ));

            let result = super::supervision::run(&mut target, &mut runtime);

            let expected = HostSupervisionError::Terminal {
                state: HostOperationState::Canceled,
            };
            match result.expect_err("health canceled the actual entered operation") {
                QemuAsyncDriverError::OperationalHealth(error) if refuse_health => {
                    assert!(std::ptr::eq(
                        error.source_failure(),
                        source.source_failure()
                    ));
                    assert_eq!(error.operational_supervision_post(), Some(expected));
                }
                QemuAsyncDriverError::Runtime(error) if !refuse_health => {
                    assert_eq!(error.operational_supervision_source(), Some(expected));
                }
                error => panic!("both actual observations must survive: {error}"),
            }
            assert_eq!(target.health_calls.get(), cut);
            assert_eq!(target.started.len(), usize::from(cut > 1));
            assert_eq!(target.finished, usize::from(cut > 2));
            assert_eq!(target.shutdowns, 0);
            assert_eq!(runtime.scripted.yields, usize::from(cut > 1));
            assert_eq!(runtime.scripted.awaits, usize::from(cut > 1));
        }
    }
    Ok(())
}

#[test]
fn health_original_post_survives_scheduler_conversion() -> Result<(), Box<dyn Error>> {
    let mut runtime = SupervisedRuntime::new()?;
    let source = QemuAsyncDriverHealthError::ram_source(QemuRamSourceError::Ownership);
    let mut target = ScriptedTarget::completed();
    target.cancel_during_health = Some((runtime.supervisor.clone(), 1, Some(source.clone())));

    let error = super::supervision::run(&mut target, &mut runtime).unwrap_err();
    let scheduler = SchedulerError::from(BackendError::from(
        crate::QemuNodeError::from_async_driver(error),
    ));

    assert!(matches!(&scheduler, SchedulerError::Backend(backend)
        if backend.operational_kind() == Some(BackendOperationalFailureKind::Terminal)));
    let retained = scheduler
        .source()
        .and_then(Error::source)
        .and_then(Error::source)
        .and_then(|source| source.downcast_ref::<QemuAsyncDriverHealthError>())
        .expect("complete health owner and post remain downcastable");
    assert!(std::ptr::eq(
        retained.source_failure(),
        source.source_failure()
    ));
    assert_eq!(
        retained.operational_supervision_post(),
        Some(HostSupervisionError::Terminal {
            state: HostOperationState::Canceled,
        })
    );
    Ok(())
}
