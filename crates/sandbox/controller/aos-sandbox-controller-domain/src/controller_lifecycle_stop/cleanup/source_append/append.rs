//! Retains the real A8 planner, native append, publication and sole readback.

use super::authorization::AppendNativeOriginalV1;
use super::*;
use crate::journal::source_provisioning::SourceProvisioningIdentityV1;
use crate::lifecycle::{
    LifecycleHistoricalReadOriginalV1, LifecycleProtectedJournalOwnerV1,
    PreparedSourceLifecycleAdmissionV1, SourceLifecycleAdmissionCommitV1,
};
use crate::{JournalError, ResourceReservationErrorV1};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

#[derive(Clone, Copy)]
enum First {
    Geometry,
    Funding,
    Entry,
    Presence,
    Claim,
    Prepare,
    Commit,
    Publication,
    Readback,
    Post,
    Panic,
    Reentry,
}

/// Retains one independent Stop settlement without rewriting its old attempt.
///
/// Construction is inert. Only the actual Source22 loan can run this writer;
/// a completed value owns actual native publication and protected A8 readback,
/// independently of the unchanged historical Stop's failed SDK state.
#[doc(hidden)]
#[must_use = "retain all reached append/readback originals through native posts"]
pub struct StopCleanupSourceAppendOriginalV1 {
    entered: bool,
    geometry: Option<Result<ResourceVector>>,
    funding: Option<Result<()>>,
    entry: Option<CompletionResult<()>>,
    presence: Option<std::result::Result<bool, Box<dyn Error + Send + Sync>>>,
    claim: Option<std::result::Result<(), crate::lifecycle::LifecycleProtectedJournalErrorV1>>,
    prepared: Option<
        std::result::Result<
            PreparedSourceLifecycleAdmissionV1,
            crate::lifecycle::LifecycleProtectedJournalErrorV1,
        >,
    >,
    commit: Option<
        std::result::Result<
            SourceLifecycleAdmissionCommitV1,
            crate::protected_domain_journal::ResidentDomainCommitFailureV1,
        >,
    >,
    publication: Option<std::result::Result<(), JournalError>>,
    read: LifecycleHistoricalReadOriginalV1,
    readback: Option<std::result::Result<(), JournalError>>,
    native: Option<AppendNativeOriginalV1>,
    source: Option<std::result::Result<SourceProvisioningIdentityV1, JournalError>>,
    affinity: Option<Result<ControllerStopCleanupSourceAffinityV1>>,
    fresh: Option<LifecycleStopCompletionDataV1>,
    completed: Option<(
        LifecycleStopCompletionDataV1,
        crate::lifecycle::LifecycleRecordDigestV1,
        crate::lifecycle::LiveRuntimeFenceV1,
        i64,
    )>,
    first: Option<First>,
    later_panics: [Option<Box<dyn std::any::Any + Send>>; 2],
    closed: JournalError,
}

impl StopCleanupSourceAppendOriginalV1 {
    /// Constructs empty, once-only destinations without allocation or authority.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entered: false,
            geometry: None,
            funding: None,
            entry: None,
            presence: None,
            claim: None,
            prepared: None,
            commit: None,
            publication: None,
            read: LifecycleHistoricalReadOriginalV1::new(),
            readback: None,
            native: Some(AppendNativeOriginalV1::new()),
            source: None,
            affinity: None,
            fresh: None,
            completed: None,
            first: None,
            later_panics: [None, None],
            closed: JournalError::ProtectedBoundary,
        }
    }

    fn receiving_demand(
        source: &Journal,
        data: &LifecycleStopCompletionDataV1,
    ) -> Result<ResourceVector> {
        use crate::policy_compiler::RetainedKernelPairedClockAttemptV1 as Pair;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|n| {
                n.checked_add(
                    std::mem::size_of::<StopCleanupSourceAppendAuthorizationV1<'_>>()
                        .checked_mul(3)?,
                )
            })
            .and_then(|n| n.checked_add(Pair::dominant_requested_bytes_v1()?.checked_mul(2)?))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(CLOSED)?;
        let header = ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(
            D::OpenFiles,
            u64::try_from(
                Pair::MAXIMUM_RETAINED_FILES_V1
                    .checked_mul(2)
                    .ok_or(CLOSED)?,
            )
            .map_err(|_| CLOSED)?,
        );
        let pair = crate::lifecycle::stop_cleanup_completion_receiving_demand_v1(source, data)?;
        // Separate full planes retain the actual plan/commit, its literal
        // prechecked copy/payload and the final graph plus A8 selection. No
        // failed native prefix or prior financial debit is subtracted.
        header
            .checked_add(pair)?
            .checked_add(pair)?
            .checked_add(pair)?
            .checked_add(ControllerStopCleanupSourceAffinityV1::receiving_demand_v1()?)
            .map_err(Into::into)
    }

    pub(crate) fn run_once_v1(
        &mut self,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        native: &mut aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1,
        auth: &StopCleanupSourceAppendAuthorizationV1<'_>,
    ) -> std::result::Result<(), JournalError> {
        self.first = Some(First::Presence);
        self.presence = Some(auth.read_v1().stop_completion_is_present_data_v1());
        let existing = self
            .presence
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        if existing {
            self.first = Some(First::Commit);
            auth.begin_existing_read_once_v1(source.journal_ref_v1(), native)?;
        } else {
            self.first = Some(First::Claim);
            let mut owner =
                match LifecycleProtectedJournalOwnerV1::claim_original_stop_cleanup_source_v1(
                    source, auth,
                ) {
                    Ok(owner) => {
                        self.claim = Some(Ok(()));
                        owner
                    }
                    Err(cause) => {
                        self.claim = Some(Err(cause));
                        return Err(JournalError::ProtectedBoundary);
                    }
                };
            self.first = Some(First::Prepare);
            self.prepared = Some(owner.prepare_original_stop_cleanup_source_v1(auth));
            let prepared = self
                .prepared
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            self.first = Some(First::Commit);
            self.commit =
                Some(owner.commit_original_stop_cleanup_source_v1(prepared, native, auth));
            if !matches!(
                self.commit,
                Some(Ok(SourceLifecycleAdmissionCommitV1::Applied(_)))
            ) {
                return Err(JournalError::ProtectedBoundary);
            }
            self.first = Some(First::Publication);
            self.publication =
                Some(owner.require_original_stop_cleanup_published_v1(prepared, native, auth));
            if !matches!(self.publication, Some(Ok(()))) {
                return Err(JournalError::ProtectedBoundary);
            }
            drop(owner);
        }

        self.first = Some(First::Readback);
        self.readback = Some((|| {
            self.read.observe_once_v1(
                source.journal_ref_v1().historical_read_view_v1().rows_data_v2(),
                auth.completion_data_v1().operation(),
            )?;
            self.read.select_stop_completion_once_v1()?;
            let actual = self.read.stop_completion_data_v1()?;
            let fresh = auth.completion_data_v1();
            if self.read.operation_v1()?.1.digest() != fresh.binding_v1().operation_record
                || actual.binding_v1().operation_record != fresh.binding_v1().operation_record
                || actual.binding_v1().dispatch_record != fresh.binding_v1().dispatch_record
                || actual.operation() != fresh.operation()
                || actual.evidence_v1().historical_scope_v1()
                    != fresh.evidence_v1().historical_scope_v1()
                || (!existing && actual != fresh)
            {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        if !matches!(self.readback, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.source = Some(source.journal_ref_v1().source_provisioning_identity_v1());
        if !matches!(self.source, Some(Ok(_))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.first = None;
        Ok(())
    }

    fn require_completed(
        &self,
    ) -> std::result::Result<
        &(
            LifecycleStopCompletionDataV1,
            crate::lifecycle::LifecycleRecordDigestV1,
            crate::lifecycle::LiveRuntimeFenceV1,
            i64,
        ),
        JournalError,
    > {
        if self.first.is_some()
            || !self
                .native
                .as_ref()
                .is_some_and(AppendNativeOriginalV1::completed)
            || self.failure().is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.completed
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)
    }

    /// Rejoins the same real Source22 payer and actual published A8 Source cut.
    ///
    /// # Errors
    /// Refuses missing native completion, another payer, Source or current cut.
    pub fn require_completed_source_v1(
        &self,
        loan: &ControllerHostStopCleanupSourceLoanV1<'_, '_>,
        controller: &Journal,
    ) -> std::result::Result<(), JournalError> {
        self.require_completed_source_prefix_v1(loan.source.journal_ref_v1())?;
        let fresh = self
            .fresh
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?
            .binding_v1();
        let subject = loan
            .subject_data_v1(controller)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        if fresh.recovery.as_bytes() != subject.recovery_operation_v1()
            || fresh.recovery_request.as_bytes() != subject.recovery_request_digest_v1()
            || fresh.cleanup_request != *subject.cleanup_request_v1()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        loan.require_same_inventory_financial_original_v1(
            self.affinity
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?,
            controller,
        )
        .map_err(|_| JournalError::ProtectedBoundary)
    }

    /// Checks the actual native Source successor retained after A8 readback.
    ///
    /// # Errors
    /// Refuses an incomplete, foreign, advanced or failed native Source cut.
    pub fn require_completed_source_prefix_v1(
        &self,
        source: &Journal,
    ) -> std::result::Result<(), JournalError> {
        self.require_completed()?;
        source.require_current_source_provisioning_identity_v1(
            self.source
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?,
        )
    }

    /// Returns the actual complete protected A8 auxiliary-record commitment.
    ///
    /// # Errors
    /// Refuses incomplete native publication or protected readback.
    pub fn completed_record_digest_data_v1(
        &self,
    ) -> std::result::Result<ObjectDigest, JournalError> {
        self.require_completed()?;
        self.read.stop_completion_record_digest_data_v1()
    }

    /// Returns the unchanged historical Stop operation-record commitment.
    ///
    /// # Errors
    /// Refuses incomplete native publication or protected readback.
    pub fn historical_record_digest_data_v1(
        &self,
    ) -> std::result::Result<crate::lifecycle::LifecycleRecordDigestV1, JournalError> {
        Ok(self.require_completed()?.1)
    }

    /// Returns the unchanged actual old Stop resource fence.
    ///
    /// # Errors
    /// Refuses incomplete native publication or protected readback.
    pub fn actual_stop_fence_data_v1(
        &self,
    ) -> std::result::Result<crate::lifecycle::LiveRuntimeFenceV1, JournalError> {
        Ok(self.require_completed()?.2)
    }

    /// Returns the genuine Root48 exchange's verified authority expiry.
    ///
    /// # Errors
    /// Refuses incomplete native publication or protected readback.
    pub fn verified_authority_expiry_data_v1(&self) -> std::result::Result<i64, JournalError> {
        Ok(self.require_completed()?.3)
    }

    /// Borrows the selected original cause without another native observation.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let selected = match self.first? {
            First::Geometry => error(&self.geometry),
            First::Funding => error(&self.funding),
            First::Entry => self
                .entry
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as _)
                .or_else(|| {
                    self.affinity
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            First::Presence => self
                .presence
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause.as_ref() as _),
            First::Claim => self
                .native
                .as_ref()
                .and_then(AppendNativeOriginalV1::body_failure)
                .or_else(|| self
                .claim
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as _)),
            First::Prepare => self
                .native
                .as_ref()
                .and_then(AppendNativeOriginalV1::body_failure)
                .or_else(|| self
                .prepared
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as _)),
            First::Commit => self
                .native
                .as_ref()
                .and_then(AppendNativeOriginalV1::body_failure)
                .or_else(|| self.commit.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Publication => self
                .native
                .as_ref()
                .and_then(AppendNativeOriginalV1::body_failure)
                .or_else(|| {
                    self.publication
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            First::Readback => self
                .read
                .failure()
                .or_else(|| {
                    self.readback
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                })
                .or_else(|| self.source.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Post => self
                .native
                .as_ref()
                .and_then(AppendNativeOriginalV1::failure),
            First::Panic | First::Reentry => None,
        };
        selected.or(Some(&self.closed as _))
    }
}

impl Default for StopCleanupSourceAppendOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl ControllerHostStopCleanupSourceLoanV1<'_, '_> {
    /// Appends only the genuine completed cleanup on this same funded Source22.
    ///
    /// Every reached result stays in `original`. Binding enters an independently
    /// owed clock post which runs even after an error or unwind; the original
    /// panic resumes only after that post and its complete owner are retained.
    ///
    /// # Errors
    /// Refuses reuse, unavailable finance, foreign proof, changed Source,
    /// preparation, native append/publication or readback/post failure.
    ///
    /// # Panics
    /// Resumes the earliest reached native or decoder panic only after every
    /// independently owed post and its original custody have been retained.
    #[doc(hidden)]
    pub fn run_stop_completion_append_once_v1(
        &mut self,
        controller: &Journal,
        proof: &StopCleanupCompletionOriginalV1<'_>,
        original: &mut StopCleanupSourceAppendOriginalV1,
    ) -> Result<()> {
        if original.entered {
            original.first.get_or_insert(First::Reentry);
            return Err(CLOSED);
        }
        original.entered = true;
        original.first = Some(First::Geometry);
        original.geometry = Some(StopCleanupSourceAppendOriginalV1::receiving_demand(
            self.source.journal_ref_v1(),
            &proof.data,
        ));
        let demand = *positive(&original.geometry)?;
        original.first = Some(First::Funding);
        original.funding = Some(self.reserve_additional_v1(controller, demand));
        positive(&original.funding)?;
        original.first = Some(First::Entry);
        original.entry = Some(proof.require_same_source22_v1(self, controller));
        if !matches!(original.entry, Some(Ok(()))) {
            return Err(CLOSED);
        }
        original.affinity = Some(self.capture_inventory_financial_original_v1(controller));
        positive(&original.affinity)?;
        original.fresh = Some(proof.data);
        let owner = held_owner_mut(self.owner);
        let cleanup = owner.cleanup.as_deref().ok_or(CLOSED)?;
        let native = owner
            .native
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(CLOSED)?;
        let parts = match owner.host_turn.cleanup_native_parts_v1() {
            Ok(parts) => parts,
            Err(cause) => {
                original.entry = Some(Err(cause.into()));
                return Err(CLOSED);
            }
        };
        let state = std::cell::RefCell::new(original.native.take().ok_or(CLOSED)?);
        let auth = StopCleanupSourceAppendAuthorizationV1::new(
            parts.read,
            parts.identity,
            &state,
            &owner.bank,
            owner.profile.as_ref(),
            native,
            controller,
            cleanup,
            proof,
        );
        let body = catch_unwind(AssertUnwindSafe(|| {
            original.run_once_v1(self.source, parts.native, &auth)
        }));
        let native_post = catch_unwind(AssertUnwindSafe(|| {
            auth.observe_existing_source_owed_after_v1(self.source.journal_ref_v1(), parts.native)
        }));
        let post = catch_unwind(AssertUnwindSafe(|| {
            auth.observe_source_append_owed_after_v1()
        }));
        drop(auth);
        let mut state = state.into_inner();
        if let Some(successor) = state.successor.take() {
            *parts.identity = successor;
        }
        original.native = Some(state);
        if original.first.is_none()
            && (!matches!(post, Ok(Ok(())))
                || !matches!(native_post, Ok(Ok(())))
                || !original
                    .native
                    .as_ref()
                    .is_some_and(AppendNativeOriginalV1::completed))
        {
            original.first = Some(First::Post);
        }
        match (body, native_post, post) {
            (Err(payload), native_post, post) => {
                if let Err(later) = native_post {
                    original.later_panics[0] = Some(later);
                }
                if let Err(later) = post {
                    original.later_panics[1] = Some(later);
                }
                original.first.get_or_insert(First::Panic);
                resume_unwind(payload)
            }
            (_, Err(payload), post) => {
                if let Err(later) = post {
                    original.later_panics[1] = Some(later);
                }
                original.first.get_or_insert(First::Panic);
                resume_unwind(payload)
            }
            (_, _, Err(payload)) => {
                original.first.get_or_insert(First::Panic);
                resume_unwind(payload)
            }
            (Ok(Ok(())), Ok(Ok(())), Ok(Ok(())))
                if original
                    .native
                    .as_ref()
                    .is_some_and(AppendNativeOriginalV1::completed) =>
            {
                let data = *original
                    .read
                    .stop_completion_data_v1()
                    .map_err(|_| CLOSED)?;
                original.completed = Some((data, proof.historical, proof.fence, proof.expiry));
                Ok(())
            }
            _ => Err(CLOSED),
        }
    }
}
