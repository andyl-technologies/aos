//! Operator cancellation of unapplied reviewed GC plans.
//!
//! A planned run is review state only. It holds no registry GC lock, no
//! delete-credential hold, and no tombstone: apply acquires all of those in
//! one transaction. Its frozen placement actions stay `pending` but no worker
//! can claim them, because claims require an `applying` run.
//!
//! Cancellation therefore performs exactly the transition the expiry sweep
//! performs, `planned` to the terminal `aborted` state, and records a distinct
//! reason. Once aborted, apply rejects the run and registry-deletion blockers
//! no longer count it or its never-claimable actions.
//!
//! ```text
//! planned --apply------> applying --finalize--> complete
//!    |
//!    +--expiry sweep---> aborted   (last_error: review expired before apply)
//!    +--cancel---------> aborted   (last_error: cancelled by operator before apply)
//! ```
//!
//! An `applying` run owns tombstoned candidates and physical provider work, so
//! cancellation fails closed for it; the requeue and finalization paths own
//! its recovery.

use anyhow::{bail, Context, Result};

use super::OciGcGenerationRecord;
use crate::backend::Statement;
use crate::db::{validate_key_bytes, Database};

/// Durable failure detail recorded on a run an operator cancelled before apply.
pub const OCI_GC_CANCELLED_REASON: &str = "cancelled by operator before apply";

/// Exact identity of one reviewed GC run an operator wants to discard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelOciGc {
    /// Registry owning the run.
    pub registry_id: i64,
    /// Stable run id.
    pub generation_id: String,
    /// Resource version the operator reviewed. It is compared only while the
    /// run is still planned; a terminal run is returned unchanged.
    pub expected_resource_version: i64,
    /// Cancellation time in Unix seconds.
    pub now: i64,
}

impl Database {
    /// Moves one planned OCI GC run to the terminal `aborted` state.
    ///
    /// Cancellation is idempotent by state: a run that is already `aborted`,
    /// `complete`, or `failed` is returned unchanged, so a retried request
    /// whose first response was lost observes the same terminal run.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, an unknown run, an `applying` run,
    /// a stale resource version on a planned run, an unrecognized persisted
    /// state, or database failure.
    pub async fn cancel_oci_gc_plan(&self, input: &CancelOciGc) -> Result<OciGcGenerationRecord> {
        validate_key_bytes(&input.generation_id, "OCI GC generation id", 64)?;
        if input.registry_id <= 0 || input.expected_resource_version < 1 || input.now < 0 {
            bail!("OCI GC cancellation selector is invalid");
        }

        let run = self
            .oci_gc_generation(input.registry_id, &input.generation_id)
            .await?
            .context("OCI GC generation does not exist")?;
        if let Some(settled) = settled_cancellation(&run)? {
            return Ok(settled);
        }
        if run.resource_version != input.expected_resource_version {
            bail!("OCI GC generation resource version is stale");
        }

        // The CAS on state and version loses to a concurrent apply, expiry
        // sweep, or cancellation. Re-reading classifies that race exactly.
        let cancelled = self
            .backend
            .checked_batch(&[Statement::new(
                "UPDATE oci_gc_runs SET state = 'aborted', finished_at = ?4,
                     last_error = ?5, resource_version = resource_version + 1
                 WHERE id = ?1 AND registry_id = ?2 AND state = 'planned'
                   AND resource_version = ?3",
                vals![
                    input.generation_id,
                    input.registry_id,
                    input.expected_resource_version,
                    input.now,
                    OCI_GC_CANCELLED_REASON
                ],
            )
            .expecting(1)])
            .await;

        let current = self
            .oci_gc_generation(input.registry_id, &input.generation_id)
            .await?
            .context("OCI GC generation disappeared during cancellation")?;
        match cancelled {
            Ok(()) => Ok(current),
            Err(error) => match settled_cancellation(&current)? {
                Some(settled) => Ok(settled),
                None => Err(error.context("OCI GC generation changed during cancellation")),
            },
        }
    }
}

/// Classifies a run that cancellation must not transition.
///
/// Returns the run itself when it is already terminal, `None` when it is still
/// planned, and an error for an applying or unrecognized state.
fn settled_cancellation(run: &OciGcGenerationRecord) -> Result<Option<OciGcGenerationRecord>> {
    match run.state.as_str() {
        "planned" => Ok(None),
        "applying" => bail!(
            "OCI GC generation is applying and cannot be cancelled; physical recovery owns it"
        ),
        "aborted" | "complete" | "failed" => Ok(Some(run.clone())),
        _ => bail!("OCI GC generation has an unrecognized state"),
    }
}
