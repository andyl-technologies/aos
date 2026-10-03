//! No-motion physical cap negotiation under one retained semantic RUN.
//!
//! Scalar reports bind scheduler ownership only. The operational backend keeps
//! the genuine CANCEL/full-STOP ledger and current earlier-cap source, and must
//! authenticate them independently before any new PREP or execution effects.

use super::held_boundary::backend_run;
use super::host_concurrent::validate_host_run_outcome;
use super::*;

/// Retained RUN ownership after physical-cap negotiation fails.
///
/// This record is cleanup-only and preserves original staged history. It does
/// not manufacture a full STOP, execution permission or a semantic observation.
#[derive(Clone, Debug)]
pub struct FailedCapNegotiation {
    boundary: BackendRunCapBoundary,
    _run: PreparedHostRun,
    _source: Arc<SingleScheduler>,
}

impl FailedCapNegotiation {
    /// Returns the unchanged stop and earlier-cap observation retained on failure.
    #[must_use]
    pub const fn boundary(&self) -> &BackendRunCapBoundary {
        &self.boundary
    }

    /// Returns the latest exact admission retained before the fallible readmission.
    #[must_use]
    pub fn readmission(&self) -> &PreparedRunAdmission {
        &self._run.admission
    }
}

pub(super) fn validate_cap_boundary(
    run: &PreparedHostRun,
    boundary: &BackendRunCapBoundary,
) -> Result<(), SchedulerError> {
    if boundary.admission != run.admission
        || boundary.stopped != run.plan.before
        || boundary.tighter_cap <= boundary.stopped
        || boundary.tighter_cap.ticks >= run.plan.target_counter
    {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("cap negotiation is stale, moved or not strictly tighter"),
        });
    }
    Ok(())
}

pub(super) fn resolve_cap_boundary<B: ConcurrentSimulationBackend>(
    scheduler: &mut SingleScheduler,
    backend: &mut B,
    run: &mut PreparedHostRun,
    boundary: BackendRunCapBoundary,
    retained: &mut Option<FailedCapNegotiation>,
) -> Result<ConcurrentBackendRunResult, SchedulerError> {
    *retained = Some(FailedCapNegotiation {
        boundary: boundary.clone(),
        _run: run.clone(),
        _source: Arc::new(scheduler.clone()),
    });
    validate_cap_boundary(run, &boundary)?;

    // Publish a fresh complete inventory revision without changing the original
    // configuration, semantic command, context or horizon. No input is staged.
    let mut revised = scheduler.clone();
    revised.tighten_cap_boundary_admission(run, boundary.tighter_cap)?;
    *retained = Some(FailedCapNegotiation {
        boundary: boundary.clone(),
        _run: run.clone(),
        _source: Arc::new(revised.clone()),
    });
    *scheduler = revised;
    let result = backend.resume_cap_boundary(backend_run(run), &boundary)?;
    if let ConcurrentBackendRunResult::Completed(completed) = &result {
        validate_host_run_outcome(run, completed)?;
        *retained = None;
    }

    // An additional tighter cap or input stop returns to the same canonical
    // union before any peer is passed or another physical wave is readmitted.
    Ok(result)
}
