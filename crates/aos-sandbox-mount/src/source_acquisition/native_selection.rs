//! Borrowed dormant Mount continuation for original native catalog selection.
//!
//! This owner holds the real table, namespace-40 writer, authenticated session,
//! and original live admission together during pending control I/O. It reuses
//! the legacy table-derived common request and atomic reservation path. The
//! Mount service scheduler and Provider V3 effect/outcome acceptance remain
//! unimplemented activation prerequisites; this module registers no service.

use aos_sandbox::journal::ProtectedJournalAuthority;
use aos_sandbox_protocol::LiveValidatedAcquireMountSourceRequest;
use aos_sandbox_source_provider_security::{
    CurrentRootMountSourceProviderSessionV1, PendingNativeMountAcquireV3,
};

use super::SourceAcquisitionTableV2;
use super::format::state_error;
use super::reservation::ReservedProviderQueryV2;
use crate::Result;

mod original;
pub(super) use original::OriginalNativeAcquireFlightV5;

/// Distinguishes pending I/O, current reservation, and postcommit loss of currentness.
#[derive(Debug)]
pub(crate) enum NativeProviderAcquireProgressV3 {
    /// The same original query remains pending without a journal commit.
    Pending,
    /// The exact conditional send reservation passed postcommit readback.
    Reserved(ReservedProviderQueryV2),
    /// The journal is occupied, but the original session is now poisoned.
    CommittedCurrentnessLost {
        /// Original committed custody; no row-derived replacement is allowed.
        reservation: ReservedProviderQueryV2,
        /// Redacted failure from the genuine postcommit recheck.
        error: aos_sandbox_source_provider_security::SourceProviderSecurityError,
    },
    /// Commit was attempted, but exact protected readback is not established.
    CommitUnconfirmed {
        /// Original preparation and exact attempted records, never a send permit.
        custody: RetainedNativeAcquireCommitV3,
        /// Commit or confirmation failure; durable occupancy remains conservative.
        error: crate::MountError,
    },
}

/// Keeps original prepared custody on an ambiguous commit/confirmation boundary.
///
/// This has no reservation, signing, resend, cold-reconstruction, or retry
/// factory. The same original flight must be reconciled by a later owner path.
pub(crate) struct RetainedNativeAcquireCommitV3 {
    pub(super) prepared: aos_sandbox_source_provider_security::PreparedMountProviderRequestV2,
    pub(super) attempt: super::model::SourceProviderQueryAttemptV2,
    pub(super) head: super::model::SourceProviderHeadV2,
}

impl core::fmt::Debug for RetainedNativeAcquireCommitV3 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RetainedNativeAcquireCommitV3([original unconfirmed custody])")
    }
}

pub(super) struct NativeReservationCoordinatesV3 {
    attempt_key: Vec<u8>,
    attempt_record: Vec<u8>,
    head_key: Vec<u8>,
    head_record: Vec<u8>,
}

pub(super) enum NativeCommitAttemptV3<T> {
    Committed(T),
    Unconfirmed {
        custody: T,
        error: crate::MountError,
    },
}

// Private sequencing only: the production caller supplies an actual held
// currentness check, and custody is returned unchanged on commit ambiguity.
pub(super) fn commit_after_native_preflight<T>(
    custody: T,
    preflight: Result<()>,
    commit: impl FnOnce() -> Result<()>,
) -> Result<NativeCommitAttemptV3<T>> {
    preflight?;
    Ok(match commit() {
        Ok(()) => NativeCommitAttemptV3::Committed(custody),
        Err(error) => NativeCommitAttemptV3::Unconfirmed { custody, error },
    })
}

fn retain_postcommit_currentness<T, E>(
    custody: T,
    recheck: core::result::Result<(), E>,
) -> core::result::Result<T, (T, E)> {
    match recheck {
        Ok(()) => Ok(custody),
        Err(error) => Err((custody, error)),
    }
}

pub(super) fn reservation_coordinates(
    attempt: &super::model::SourceProviderQueryAttemptV2,
    head: &super::model::SourceProviderHeadV2,
) -> Result<NativeReservationCoordinatesV3> {
    use super::format::{provider_attempt_key, provider_head_key, put_record};
    use super::model::StoredRecordV2;

    let attempt_record = put_record(&StoredRecordV2::ProviderQueryAttempt {
        value: attempt.clone(),
    })?;
    let head_record = put_record(&StoredRecordV2::ProviderHead {
        value: head.clone(),
    })?;
    Ok(NativeReservationCoordinatesV3 {
        attempt_key: provider_attempt_key(attempt.attempt_id),
        attempt_record: attempt_record
            .value()
            .ok_or_else(|| state_error("native attempt coordinates are a delete"))?
            .to_vec(),
        head_key: provider_head_key(
            head.scope.holder_authority_id,
            head.scope.provider_authority_id,
        ),
        head_record: head_record
            .value()
            .ok_or_else(|| state_error("native head coordinates are a delete"))?
            .to_vec(),
    })
}

pub(super) fn confirm_native_reservation(
    journal: &ProtectedJournalAuthority<'_>,
    session: &mut CurrentRootMountSourceProviderSessionV1,
    prepared: aos_sandbox_source_provider_security::PreparedMountProviderRequestV2,
    attempt: super::model::SourceProviderQueryAttemptV2,
    head: super::model::SourceProviderHeadV2,
    coordinates: NativeReservationCoordinatesV3,
) -> Result<NativeProviderAcquireProgressV3> {
    let reservation = match session.confirm_native_acquire_reservation_v3(
        journal,
        prepared,
        coordinates.attempt_key,
        coordinates.attempt_record,
        coordinates.head_key,
        coordinates.head_record,
    ) {
        Ok(reservation) => reservation,
        Err((prepared, _error)) => {
            return Ok(NativeProviderAcquireProgressV3::CommitUnconfirmed {
                custody: RetainedNativeAcquireCommitV3 {
                    prepared,
                    attempt,
                    head,
                },
                error: state_error("native committed reservation readback is unconfirmed"),
            });
        }
    };
    let recheck = session.revalidate_native_acquire_reservation_v3(journal, &reservation);
    let reservation = ReservedProviderQueryV2::from_reserved(attempt.attempt_id, reservation);
    Ok(match retain_postcommit_currentness(reservation, recheck) {
        Ok(reservation) => NativeProviderAcquireProgressV3::Reserved(reservation),
        Err((reservation, error)) => {
            NativeProviderAcquireProgressV3::CommittedCurrentnessLost { reservation, error }
        }
    })
}

/// Holds every original owner borrow until native preparation is reserved.
#[must_use = "advance the original pending native flight or abandon it"]
pub(crate) struct PendingNativeProviderAcquireV3<'flight, 'journal> {
    table: &'flight mut SourceAcquisitionTableV2,
    journal: &'flight mut ProtectedJournalAuthority<'journal>,
    session: &'flight mut CurrentRootMountSourceProviderSessionV1,
    live_request: &'flight LiveValidatedAcquireMountSourceRequest,
    mount_request: Option<Vec<u8>>,
    mount_plan_digest: [u8; 32],
    ownership_lease_digest: [u8; 32],
    pending: PendingNativeMountAcquireV3,
}

impl core::fmt::Debug for PendingNativeProviderAcquireV3<'_, '_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PendingNativeProviderAcquireV3([borrowed original flight])")
    }
}

impl SourceAcquisitionTableV2 {
    /// Parks the original Security plan/query before fallible catalog I/O.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn begin_original_native_provider_acquire_retaining_v5(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        live_request: &LiveValidatedAcquireMountSourceRequest,
        mount_request: &[u8],
        mount_plan_digest: [u8; 32],
        ownership_lease_digest: [u8; 32],
        canonical_publication: &[u8],
        canonical_catalog: &[u8],
        selection_key: Option<Vec<u8>>,
        provider_deadline_seconds: i64,
        plan_slot: &mut Option<aos_sandbox_source_provider_security::CurrentMountProviderSessionPlanV2>,
        draft_slot: &mut Option<aos_sandbox_source_provider_protocol::AcquireSourceRequestV1>,
        retained: &mut Option<PendingNativeMountAcquireV3>,
    ) -> Result<()> {
        if live_request.request().kernel_coupled() {
            return Err(state_error(
                "native catalog planning cannot use KernelCoupled",
            ));
        }
        let (holder, provider, _) = session
            .current_authority_scope_v2()
            .map_err(|_| state_error("native provider authority cut is not current"))?;
        self.plan_acquire_draft_retaining_v5(
            journal,
            session,
            holder,
            provider,
            live_request,
            mount_request,
            mount_plan_digest,
            ownership_lease_digest,
            provider_deadline_seconds,
            plan_slot,
            draft_slot,
        )?;
        session
            .begin_original_native_acquire_from_parked_v5(
                journal,
                plan_slot,
                draft_slot,
                live_request,
                canonical_publication,
                canonical_catalog,
                selection_key,
                retained,
            )
            .map_err(|_| state_error("original native catalog challenge failed"))?;
        Ok(())
    }

    /// Begins native preparation under the original live Mount admission.
    ///
    /// The protected session supplies the fixed identities; artifacts are
    /// untrusted data and cannot select a signer, route, writer, or deadline.
    ///
    /// # Errors
    ///
    /// Rejects nonnative requests, noncurrent planning custody, invalid catalog
    /// artifacts, or failure to begin the exact original control exchange.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_native_provider_acquire_v3<'flight, 'journal>(
        &'flight mut self,
        journal: &'flight mut ProtectedJournalAuthority<'journal>,
        session: &'flight mut CurrentRootMountSourceProviderSessionV1,
        live_request: &'flight LiveValidatedAcquireMountSourceRequest,
        mount_request: Vec<u8>,
        mount_plan_digest: [u8; 32],
        ownership_lease_digest: [u8; 32],
        canonical_publication: &[u8],
        canonical_catalog: &[u8],
        selection_key: Option<Vec<u8>>,
        provider_deadline_seconds: i64,
    ) -> Result<PendingNativeProviderAcquireV3<'flight, 'journal>> {
        let mut pending = None;
        let mut plan = None;
        let mut draft = None;
        self.begin_original_native_provider_acquire_retaining_v5(
            journal,
            session,
            live_request,
            &mount_request,
            mount_plan_digest,
            ownership_lease_digest,
            canonical_publication,
            canonical_catalog,
            selection_key,
            provider_deadline_seconds,
            &mut plan,
            &mut draft,
            &mut pending,
        )?;
        let pending = pending.ok_or_else(|| state_error("original catalog owner absent"))?;
        Ok(PendingNativeProviderAcquireV3 {
            table: self,
            journal,
            session,
            live_request,
            mount_request: Some(mount_request),
            mount_plan_digest,
            ownership_lease_digest,
            pending,
        })
    }
}

impl PendingNativeProviderAcquireV3<'_, '_> {
    /// Advances once without replacing any original owner, nonce, or deadline.
    ///
    /// # Errors
    ///
    /// Returns an error if preparation was consumed, any original cut expired
    /// or changed, or exact signed-request admission/reservation fails.
    pub(crate) fn advance(&mut self) -> Result<NativeProviderAcquireProgressV3> {
        if self.mount_request.is_none() {
            return Err(state_error("native preparation was already consumed"));
        }
        let Some(prepared) = self
            .session
            .prepare_native_acquire_v3(self.journal, &mut self.pending)
            .map_err(|_| state_error("original native catalog preparation failed"))?
        else {
            return Ok(NativeProviderAcquireProgressV3::Pending);
        };
        let mount_request = self
            .mount_request
            .take()
            .ok_or_else(|| state_error("native preparation was already consumed"))?;
        self.table.admit_native_acquire_v3(
            self.journal,
            self.session,
            self.live_request,
            mount_request,
            self.mount_plan_digest,
            self.ownership_lease_digest,
            prepared,
        )
    }

    /// Uses the original borrowed owners for the existing guarded atomic send.
    ///
    /// # Errors
    ///
    /// Retains exact send recovery for any stale/poisoned original session,
    /// changed journal readback, expired deadline, or failed carrier send.
    pub(crate) fn send_reserved(
        &mut self,
        reservation: ReservedProviderQueryV2,
    ) -> core::result::Result<
        super::reservation::SentProviderQueryV2,
        super::reservation::ProviderQuerySendRecoveryV2,
    > {
        reservation.send(self.journal, self.session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    // A non-Clone DATA marker tests private sequencing, not a synthetic
    // session, prepared request, or reservation authority constructor.
    struct OriginalMarker(u8);

    #[test]
    fn failed_native_precommit_recheck_never_calls_commit() {
        let commits = Cell::new(0);
        let result = commit_after_native_preflight(
            OriginalMarker(7),
            Err(state_error("original paired deadline drifted")),
            || {
                commits.set(commits.get() + 1);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(commits.get(), 0);
    }

    #[test]
    fn postcommit_drift_retains_original_custody_and_durable_occupancy() {
        let occupied = Cell::new(false);
        let committed = commit_after_native_preflight(OriginalMarker(7), Ok(()), || {
            occupied.set(true);
            Ok(())
        })
        .unwrap();
        let NativeCommitAttemptV3::Committed(original) = committed else {
            panic!("successful commit lost its original DATA marker");
        };
        let (original, error) = retain_postcommit_currentness(
            original,
            Err::<(), _>("original paired deadline expired"),
        )
        .err()
        .unwrap();
        assert_eq!(original.0, 7);
        assert_eq!(error, "original paired deadline expired");
        assert!(occupied.get());
    }

    #[test]
    fn ambiguous_native_commit_keeps_unconfirmed_custody_not_send_authority() {
        let result = commit_after_native_preflight(OriginalMarker(7), Ok(()), || {
            Err(state_error("commit readback is indeterminate"))
        })
        .unwrap();
        match result {
            NativeCommitAttemptV3::Unconfirmed { custody, .. } => assert_eq!(custody.0, 7),
            NativeCommitAttemptV3::Committed(_) => {
                panic!("ambiguous commit became a confirmed marker")
            }
        }
    }
}
