//! Resolves sealed ranges through genuine inspected and resumed manifest custody.
//!
//! Registry entries alone do not prove complete recovery: failures retain them
//! too. Each issued source therefore owns the actual acknowledged Running
//! context, which retains the complete original recovery, as well as the
//! independently verified manifest and its original metadata/body pair.

use super::*;
use crate::{
    host_cache::recovery_inspection::VerifiedRecoveryManifest,
    publisher_local::client::PublisherRunningContext,
};

/// Retains the original independently verified pair and acknowledged complete recovery.
pub(super) struct RecoveredSource {
    verified: Arc<VerifiedRecoveryManifest>,
    running: Arc<PublisherRunningContext>,
}

/// Selects only original verified backing after the physical owner acknowledges Resume.
///
/// # Errors
/// Refuses incomplete/failed recovery, missing original funding, foreign
/// sessions, stale metadata or a residence inconsistent with the verified claim.
pub(super) fn select(
    executor: &NativeOwnerExecutor,
    owner: &Custody,
    identity: &Identity,
    row: ResidenceRecord,
) -> io::Result<Source> {
    let running = executor.admission_context_locked(owner)?;
    for verified in executor.verified_manifests() {
        if state::hex(verified.claim().descriptor().digest()) != row.object {
            continue;
        }
        let body = verified.body().retained().body_arc();
        let span = claim_span(owner, verified.claim(), identity, &row)?;
        let source = Source {
            corruption: executor.sealed_corruption_signal(owner, &body)?,
            activity: executor.body_read_activity(owner, &body)?,
            origin: Origin::Recovery(RecoveredSource {
                verified: Arc::clone(verified),
                running,
            }),
            body,
            span,
            row,
            generation: owner.generation,
            project: owner.preparation.config.project_id,
            publisher_uid: owner.preparation.config.publisher.identities.publish_uid,
            allocation_limit: owner.preparation.config.reads.max_allocation_bytes,
        };
        check_origin(owner, &source, identity)?;
        return Ok(source);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "resident chunk lacks completed publication or verified manifest recovery",
    ))
}

impl RecoveredSource {
    /// Checks original durable custody under a later serialized producer's exclusion.
    ///
    /// This performs no publisher RPC and deliberately does not reuse Drain
    /// predicates after Resume or the original complete-state predicate after
    /// legitimate Running mutations. Actual reads never call this method.
    ///
    /// # Errors
    /// Refuses a changed recovery/session, bootstrap hold, metadata registration,
    /// actual body or independently derived residence.
    pub(super) fn check_registration(
        &self,
        owner: &Custody,
        source: &Source,
        identity: &Identity,
    ) -> io::Result<NativeChunkSpan> {
        check_snapshot(owner)?;
        let retained = self.verified.body().retained();
        let claim = self.verified.claim();
        if !Arc::ptr_eq(
            self.running.publisher_session(),
            &owner.preparation.publisher_session(),
        ) || !Arc::ptr_eq(&retained.body_arc(), &source.body)
            || !Arc::ptr_eq(source.body.layout(), owner.preparation.layout())
            || source.body.claim().descriptor() != claim.descriptor()
            || source.body.claim().domain() != claim.domain()
            || source.body.claim().canonical_manifest() != claim.canonical_manifest()
            || !owner.state.reservations.iter().any(|hold| {
                hold.id == state::hex(self.running.retained_bootstrap_id())
                    && hold.owner == owner.preparation.config.quota_owner
                    && hold.bytes == owner.preparation.config.metadata_sync_hold_bytes
            })
        {
            return Err(invalid("recovered source lost original completed custody"));
        }
        retained.backing().check_recovery_registration(owner)?;
        claim_span(owner, claim, identity, &source.row)
    }
}
