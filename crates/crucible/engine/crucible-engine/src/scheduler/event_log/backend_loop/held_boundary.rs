//! Closed unresolved physical stops retained for canonical peer arbitration.

use super::cap_boundary::validate_cap_boundary;
use super::dispatch_boundary::validate_dispatch_boundary;
use super::host_concurrent::{HeldHostRun, validate_host_run_outcome};
use super::input_boundary::validate_input_boundary;
use super::*;

#[derive(Clone, Debug)]
pub(super) enum HeldRunBoundary {
    Input(BackendRunInputBoundary),
    Cap(BackendRunCapBoundary),
    Dispatch(BackendRunDispatchBoundary),
}

impl HeldRunBoundary {
    pub(super) fn stopped(&self) -> NodeCounter {
        match self {
            Self::Input(boundary) => boundary.reached,
            Self::Cap(boundary) => boundary.stopped,
            Self::Dispatch(boundary) => boundary.reached,
        }
    }

    pub(super) fn validate(&self, run: &PreparedHostRun) -> Result<(), SchedulerError> {
        match self {
            Self::Input(boundary) => validate_input_boundary(run, boundary),
            Self::Cap(boundary) => validate_cap_boundary(run, boundary),
            Self::Dispatch(boundary) => validate_dispatch_boundary(run, boundary),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct HeldBoundaryRun {
    pub(super) generation: u64,
    pub(super) run: PreparedHostRun,
    pub(super) boundary: HeldRunBoundary,
}

pub(super) fn hold_run_result(
    run: PreparedHostRun,
    result: ConcurrentBackendRunResult,
    generation: u64,
    completed: &mut BTreeMap<NodeId, HeldHostRun>,
    boundaries: &mut BTreeMap<NodeId, HeldBoundaryRun>,
) -> Result<(), SchedulerError> {
    if run.dispatch_contract == crate::BackendDispatchContract::ControlV3
        && !matches!(&result, ConcurrentBackendRunResult::Completed(_))
    {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("control 3 cannot supply a native Source boundary receipt"),
        });
    }
    let node = run.plan.node.node.clone();
    if completed.contains_key(&node) || boundaries.contains_key(&node) {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("backend repeated a held RUN node"),
        });
    }
    match result {
        ConcurrentBackendRunResult::Completed(outcome) => {
            validate_host_run_outcome(&run, &outcome)?;
            completed.insert(
                node,
                HeldHostRun {
                    generation,
                    run,
                    completed: outcome,
                },
            );
        }
        ConcurrentBackendRunResult::InputBoundary(boundary) => {
            validate_input_boundary(&run, &boundary)?;
            boundaries.insert(
                node,
                HeldBoundaryRun {
                    generation,
                    run,
                    boundary: HeldRunBoundary::Input(boundary),
                },
            );
        }
        ConcurrentBackendRunResult::CapBoundary(boundary) => {
            validate_cap_boundary(&run, &boundary)?;
            boundaries.insert(
                node,
                HeldBoundaryRun {
                    generation,
                    run,
                    boundary: HeldRunBoundary::Cap(boundary),
                },
            );
        }
        ConcurrentBackendRunResult::DispatchBoundary(boundary) => {
            validate_dispatch_boundary(&run, &boundary)?;
            boundaries.insert(
                node,
                HeldBoundaryRun {
                    generation,
                    run,
                    boundary: HeldRunBoundary::Dispatch(boundary),
                },
            );
        }
    }
    Ok(())
}

pub(super) fn backend_run(run: &PreparedHostRun) -> ConcurrentBackendRun {
    ConcurrentBackendRun {
        admission: run.admission.clone(),
        preemptions: run
            .preemptions
            .iter()
            .map(|item| item.decision.clone())
            .collect(),
    }
}
