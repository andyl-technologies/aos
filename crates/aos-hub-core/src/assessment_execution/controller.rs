//! Bounded journal recovery and execution independent of scheduler transport.
//!
//! Native tasks and Worker queue consumers use this same controller pass. Queue
//! messages merely wake it; only SQL claims and private current job provenance
//! authorize work, so duplicate wakeups cannot create another logical refresh.

use anyhow::Result;
use aos_assessment_runtime::ports::{EvidenceStore, ProviderTransport};

use super::{run_scan, AssessmentAuthority, AssessmentSourceRoutes};
use crate::db::Database;

/// Reports a finite coordinator pass without exposing provider exception text.
#[derive(Clone, Debug, Default)]
pub struct AssessmentControllerPass {
    /// Number of claimable private jobs examined.
    pub examined: u32,
    /// Number of scans that committed an assessment, including partial coverage.
    pub committed: u32,
    /// Number of scans that remain fenced, failed or retryable after execution.
    pub deferred: u32,
    /// Exclusive scan cursor; an empty page restarts the next pass from the start.
    pub next_scan: Option<String>,
}

/// Supplies separately installed ports without conferring job admission authority.
pub struct AssessmentControllerPorts<'a, A, T, E, R> {
    /// Current principal and immutable job provenance checks.
    pub authority: &'a A,
    /// Exact installed local or paired remote physical executor.
    pub transport: &'a T,
    /// Authoritative compact evidence custody.
    pub evidence: &'a E,
    /// Independent current source routing authority.
    pub routes: &'a R,
}

/// Executes one bounded registry page from the authoritative durable journal.
///
/// Every job is independently reauthorized. Execution failures preserve its
/// existing leases, consumed quota and exact checkpoint; later passes reclaim
/// expired leases. Recovery settles superseded or exhausted work without
/// publishing a result. A failed job does not suppress another job in the page.
///
/// # Errors
/// Returns an error for invalid bounds or unavailable journal enumeration/recovery.
pub async fn run_assessment_controller_pass<A, T, E, R>(
    db: &Database,
    registry_id: i64,
    after_scan: &str,
    limit: u32,
    ports: AssessmentControllerPorts<'_, A, T, E, R>,
) -> Result<AssessmentControllerPass>
where
    A: AssessmentAuthority,
    T: ProviderTransport,
    E: EvidenceStore,
    R: AssessmentSourceRoutes,
{
    db.reconcile_assessment_scans(registry_id, after_scan, limit)
        .await?;
    db.admit_due_assessment_schedules(registry_id, 1).await?;
    db.reconcile_assessment_notifications(registry_id, 10).await?;
    let scans = db
        .assessment_controller_scan_page(registry_id, after_scan, limit)
        .await?;
    let mut pass = AssessmentControllerPass {
        examined: scans.len() as u32,
        next_scan: scans.last().cloned(),
        ..Default::default()
    };
    for scan_id in scans {
        match run_scan(
            db,
            registry_id,
            &scan_id,
            ports.authority,
            ports.transport,
            ports.evidence,
            ports.routes,
        )
        .await
        {
            Ok(_) => pass.committed += 1,
            Err(error) => {
                pass.deferred += 1;
                if error.is::<aos_assessment_runtime::acquisition::AcquisitionPaused>() {
                    // The yielded scan is immediately claimable. Preserve the
                    // incoming cursor so a queue continuation can revisit it.
                    pass.next_scan = Some(after_scan.into());
                    break;
                }
            }
        }
    }
    Ok(pass)
}
