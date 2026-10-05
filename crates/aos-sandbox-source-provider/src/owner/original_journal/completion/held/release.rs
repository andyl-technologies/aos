//! Independently authorized Release admission on the same original Held owner.
//!
//! The request, current verification, lease clock, projected rows and whole
//! append stay resident. Admission keeps physical custody and cleanup debt; it
//! does not run a backend, sign a cleanup receipt or acknowledge retirement.

use super::*;
use aos_sandbox_source_provider_protocol::{
    SignedSourceProviderRequestV1, SourceProviderSignatureError,
    VerifiedProviderRequestV1,
};
use aos_sandbox_source_provider_security::SelectedSourceProviderFailureRefV1;
use aos_sandbox_source_provider_security::{OriginalNativeSigningErrorV5, ProviderOutcomeAuthorizationV1};
use aos_sandbox_source_provider_protocol::{
    PreparedNativeExportFenceDataV1, PreparedSourceProviderStatusDataV5,
    SourceProviderSignature, SignedSourceProviderNativeExportFenceV1,
    SignedSourceProviderStatusV1, ReleaseSourceResponseV2,
};
use crate::FixedSelectedProviderFailureRefV1;
use crate::native_completion::clock::{
    OriginalReleaseClockGuardV1, original_release_receive_cut_v1,
    require_original_release_receive_cut_v1,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReleaseStageV1 {
    Receive,
    Prepare,
    Preflight,
    Commit,
    Admitted,
    Closed,
}

#[derive(Clone, Copy)]
enum ReleaseFailureV1 {
    ReceiveCut,
    Boundary,
    Receive,
    Signed,
    Current,
    Clock,
    Recovered,
    Native,
    Rows,
    Mutation,
    Transaction,
    Action(usize),
    OwnerPost,
    ClockPost,
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum PendingStatusStageV1 {
    #[default]
    Authorize,
    PrepareFence,
    SignFence,
    PrepareStatus,
    SignStatus,
    Finalize,
    PrepareAppend,
    Preflight,
    Commit,
    Send,
    Sent,
}

impl PendingStatusStageV1 {
    fn action_index(self) -> Option<usize> {
        match self {
            Self::Authorize => Some(0),
            Self::PrepareFence => Some(1),
            Self::SignFence => Some(2),
            Self::PrepareStatus => Some(3),
            Self::SignStatus => Some(4),
            Self::Finalize => Some(5),
            Self::PrepareAppend => Some(6),
            Self::Preflight => Some(7),
            Self::Commit => Some(8),
            Self::Send => Some(9),
            Self::Sent => None,
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Authorize => Self::PrepareFence,
            Self::PrepareFence => Self::SignFence,
            Self::SignFence => Self::PrepareStatus,
            Self::PrepareStatus => Self::SignStatus,
            Self::SignStatus => Self::Finalize,
            Self::Finalize => Self::PrepareAppend,
            Self::PrepareAppend => Self::Preflight,
            Self::Preflight => Self::Commit,
            Self::Commit => Self::Send,
            Self::Send | Self::Sent => Self::Sent,
        }
    }
}

#[derive(Clone, Copy)]
enum PendingStatusFailureV1 {
    Boundary,
    Records,
    Authorization,
    Fence,
    Loan(usize),
    Status,
    Response,
    Finalized,
    Transaction,
    Send,
    Action(usize),
    OwnerPost,
    ClockPost,
}

// Only the genuine admitted R1 child creates this empty reservoir. It never
// replaces the R1 request, append, clock or an earlier result to permit retry.
#[derive(Default)]
pub(super) struct OriginalPendingReleaseStatusV1 {
    stage: PendingStatusStageV1,
    first: Option<PendingStatusFailureV1>,
    boundary: Option<OriginalProducerErrorV5>,
    records: Option<Result<Vec<(Vec<u8>, Vec<u8>)>, ProviderLedgerError>>,
    authorization: Option<Result<ProviderOutcomeAuthorizationV1, OriginalNativeSigningErrorV5>>,
    fence_prepared: Option<Result<PreparedNativeExportFenceDataV1, OriginalNativeSigningErrorV5>>,
    signatures: [Option<SourceProviderSignature>; 2],
    signing_attempted: [bool; 2],
    loan_failures: [Option<OriginalNativeSigningErrorV5>; 2],
    fence: Option<SignedSourceProviderNativeExportFenceV1>,
    status_prepared: Option<Result<PreparedSourceProviderStatusDataV5, OriginalNativeSigningErrorV5>>,
    signed_status: Option<SignedSourceProviderStatusV1>,
    response: Option<Result<ReleaseSourceResponseV2, SourceProviderSignatureError>>,
    encoded: Option<Vec<u8>>,
    finalized: Option<Result<aos_sandbox_source_provider_ledger::FinalizedCompletionV1, ProviderLedgerError>>,
    transaction: Option<Result<aos_sandbox::JournalTransaction, OriginalNativeSigningErrorV5>>,
    input: Option<aos_sandbox::JournalTransaction>,
    pub(super) append: Option<super::super::super::PreparedSourceOriginalV5>,
    actions: [Option<Result<bool, OriginalProducerErrorV5>>; 10],
    send_attempted: bool,
    send: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    owner_post: Option<Result<(), OriginalProducerErrorV5>>,
    clock_post: Option<Result<(), ProviderLedgerError>>,
}

impl OriginalPendingReleaseStatusV1 {
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            PendingStatusFailureV1::Boundary => self.boundary.as_ref().map(|cause| cause as _),
            PendingStatusFailureV1::Records => self.records.as_ref()?.as_ref().err().map(|cause| cause as _),
            PendingStatusFailureV1::Authorization => self.authorization.as_ref()?.as_ref().err().map(|cause| cause as _),
            PendingStatusFailureV1::Fence => self.fence_prepared.as_ref()?.as_ref().err().map(|cause| cause as _),
            PendingStatusFailureV1::Loan(index) => self.loan_failures[index].as_ref().map(|cause| cause as _),
            PendingStatusFailureV1::Status => self.status_prepared.as_ref()?.as_ref().err().map(|cause| cause as _),
            PendingStatusFailureV1::Response => self.response.as_ref()?.as_ref().err().map(|cause| cause as _),
            PendingStatusFailureV1::Finalized => self.finalized.as_ref()?.as_ref().err().map(|cause| cause as _),
            PendingStatusFailureV1::Transaction => self.transaction.as_ref()?.as_ref().err().map(|cause| cause as _),
            PendingStatusFailureV1::Send => self.send.as_ref()?.as_ref().err().map(|cause| cause as _),
            PendingStatusFailureV1::Action(index) => self.actions[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            PendingStatusFailureV1::OwnerPost => self.owner_post.as_ref()?.as_ref().err().map(|cause| cause as _),
            PendingStatusFailureV1::ClockPost => self.clock_post.as_ref()?.as_ref().err().map(|cause| cause as _),
        }
    }
}

pub(super) struct OriginalSourceReleaseV1 {
    stage: ReleaseStageV1,
    receive_cut: Result<u64, ProviderLedgerError>,
    packet: Option<Result<Option<Vec<u8>>, SourceProviderSecurityError>>,
    pub(super) signed: Option<Result<SignedSourceProviderRequestV1, SourceProviderSignatureError>>,
    pub(super) current: Option<Result<CurrentProviderRequestV1, SourceProviderSecurityError>>,
    pub(super) clock: Option<Result<OriginalReleaseClockGuardV1, ProviderLedgerError>>,
    recovered: Option<Result<crate::model::RecoveredProviderLedgerV1, ProviderLedgerError>>,
    native: Option<Result<SourceNativeHeldCompletionRecordV1, ProviderLedgerError>>,
    rows: Option<Result<crate::release::FreshReleaseRowsV1, ProviderLedgerError>>,
    mutation: Option<Result<crate::transaction::PreparedLedgerMutationV1, ProviderLedgerError>>,
    transaction: Option<Result<aos_sandbox::JournalTransaction, aos_sandbox::JournalError>>,
    input: Option<aos_sandbox::JournalTransaction>,
    pub(super) append: Option<super::super::super::PreparedSourceOriginalV5>,
    actions: [Option<Result<bool, OriginalProducerErrorV5>>; 4],
    boundary: Option<OriginalProducerErrorV5>,
    first: Option<ReleaseFailureV1>,
    owner_post: Option<Result<(), OriginalProducerErrorV5>>,
    clock_post: Option<Result<(), ProviderLedgerError>>,
    pub(super) status: Option<OriginalPendingReleaseStatusV1>,
}

impl OriginalSourceReleaseV1 {
    fn pending(receive_cut: Result<u64, ProviderLedgerError>) -> Self {
        let first = receive_cut.is_err().then_some(ReleaseFailureV1::ReceiveCut);
        Self {
            stage: ReleaseStageV1::Receive,
            receive_cut,
            packet: None,
            signed: None,
            current: None,
            clock: None,
            recovered: None,
            native: None,
            rows: None,
            mutation: None,
            transaction: None,
            input: None,
            append: None,
            actions: std::array::from_fn(|_| None),
            boundary: None,
            first,
            owner_post: None,
            clock_post: None,
            status: None,
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            ReleaseFailureV1::ReceiveCut => self.receive_cut.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::Boundary => self.boundary.as_ref().map(|cause| cause as _),
            ReleaseFailureV1::Receive => self.packet.as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::Signed => self.signed.as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::Current => self.current.as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::Clock => self.clock.as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::Recovered => self.recovered.as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::Native => self.native.as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::Rows => self.rows.as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::Mutation => self.mutation.as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::Transaction => self.transaction.as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::Action(index) => self.actions[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::OwnerPost => self.owner_post.as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::ClockPost => self.clock_post.as_ref()?.as_ref().err().map(|cause| cause as _),
        }
    }

    fn require_clock(&self) -> Result<(), ProviderLedgerError> {
        if let Some(clock) = &self.clock {
            clock.as_ref().map_err(|_| ProviderLedgerError::RuntimePoisoned)?.require_current(
                self.current.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or(ProviderLedgerError::Unavailable)?,
                self.signed.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or(ProviderLedgerError::Unavailable)?,
            )
        } else {
            let cutoff = *self.receive_cut.as_ref().map_err(|_| ProviderLedgerError::RuntimePoisoned)?;
            require_original_release_receive_cut_v1(cutoff)
        }
    }
}

impl FixedProviderOwnerV1 {
    /// Advances the admitted original Release to stored and once-sent Pending.
    ///
    /// The same native/Source cleanup debt and original physical owners remain
    /// resident. This path cannot acknowledge retirement or population Drain.
    #[doc(hidden)]
    pub fn advance_original_native_release_status_v1(
        &mut self,
        publication: &[u8],
        rows: &[u8],
    ) -> Progress {
        if self.original_ingress.producer_closed_v5() {
            return Progress::Closed;
        }
        if self.original_release_v1().is_err()
            || self.original_release_v1().is_ok_and(|child| child.stage != ReleaseStageV1::Admitted)
        {
            match self.advance_original_native_release_v1(publication, rows) {
                Progress::ReleaseAdmitted => {}
                progress => return progress,
            }
        }
        let mut guard = OriginalHeldClosureV5 {
            original: OriginalProducerClosureGuardV5 { owner: self, completed: false },
        };
        let progress = guard.original.owner.advance_original_release_status_inner_v1(publication, rows);
        guard.original.completed = progress != Progress::Closed;
        progress
    }

    fn advance_original_release_status_inner_v1(&mut self, publication: &[u8], rows: &[u8]) -> Progress {
        let Ok(release) = self.original_release_mut_v1() else {
            return Progress::Closed;
        };
        if release.first.is_some() || release.stage != ReleaseStageV1::Admitted {
            return Progress::Closed;
        }
        if release.status.is_none() {
            release.status = Some(OriginalPendingReleaseStatusV1::default());
        }
        let Some(status) = release.status.as_ref() else {
            return Progress::Closed;
        };
        if status.first.is_some() {
            return Progress::Closed;
        }
        let stage = status.stage;

        let boundary = (|| {
            self.require_original_publication_inputs_v5(publication, rows)?;
            self.require_original_release_owner_v1()?;
            self.original_release_v1()?.require_clock()?;
            Ok(())
        })();
        if let Err(cause) = boundary {
            if let Ok(release) = self.original_release_mut_v1()
                && let Some(status) = &mut release.status
                && status.first.is_none()
            {
                status.boundary = Some(cause);
                status.first = Some(PendingStatusFailureV1::Boundary);
            }
            self.observe_original_release_status_posts_v1();
            return Progress::Closed;
        }
        if stage == PendingStatusStageV1::Sent {
            return Progress::ReleaseStatusSent;
        }
        let Some(index) = stage.action_index() else {
            return Progress::Closed;
        };
        if self.original_release_v1().ok().and_then(|release| release.status.as_ref())
            .is_none_or(|status| status.actions[index].is_some())
        {
            return Progress::Closed;
        }
        let action = self.advance_original_release_status_action_v1(stage);
        let progressed = action.as_ref().is_ok_and(|progressed| *progressed);
        let Ok(release) = self.original_release_mut_v1() else {
            return Progress::Closed;
        };
        let Some(status) = &mut release.status else {
            return Progress::Closed;
        };
        if action.is_err() && status.first.is_none() {
            status.first = Some(PendingStatusFailureV1::Action(index));
        }
        status.actions[index] = Some(action);
        self.observe_original_release_status_posts_v1();
        let Ok(release) = self.original_release_mut_v1() else {
            return Progress::Closed;
        };
        let Some(status) = &mut release.status else {
            return Progress::Closed;
        };
        if status.first.is_some() {
            return Progress::Closed;
        }
        if progressed {
            status.stage = stage.next();
        }
        match status.stage {
            PendingStatusStageV1::Send => Progress::ReleaseStatusStored,
            PendingStatusStageV1::Sent => Progress::ReleaseStatusSent,
            _ => Progress::Pending,
        }
    }

    fn observe_original_release_status_posts_v1(&mut self) {
        let owner = self.require_original_release_owner_v1();
        if let Ok(release) = self.original_release_mut_v1()
            && let Some(status) = &mut release.status
            && status.owner_post.as_ref().is_none_or(|result| result.is_ok())
        {
            if owner.is_err() && status.first.is_none() {
                status.first = Some(PendingStatusFailureV1::OwnerPost);
            }
            status.owner_post = Some(owner);
        }
        let clock = self.original_release_v1().and_then(OriginalSourceReleaseV1::require_clock);
        if let Ok(release) = self.original_release_mut_v1()
            && let Some(status) = &mut release.status
            && status.clock_post.as_ref().is_none_or(|result| result.is_ok())
        {
            if clock.is_err() && status.first.is_none() {
                status.first = Some(PendingStatusFailureV1::ClockPost);
            }
            status.clock_post = Some(clock);
        }
    }

    fn advance_original_release_status_action_v1(
        &mut self,
        stage: PendingStatusStageV1,
    ) -> Result<bool, OriginalProducerErrorV5> {
        use super::super::super::OriginalJournalPurposeV1 as Purpose;
        match stage {
            PendingStatusStageV1::Preflight => {
                self.preflight_original_journal_for_v1(Purpose::ReleaseStatus)?;
                return Ok(true);
            }
            PendingStatusStageV1::Commit => {
                self.commit_original_journal_for_v1(Purpose::ReleaseStatus)?;
                return Ok(true);
            }
            PendingStatusStageV1::PrepareAppend => {
                let release = self.original_release_mut_v1()?;
                let status = release.status.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
                if status.append.is_some() || status.input.is_some() {
                    return Err(ProviderLedgerError::RuntimePoisoned.into());
                }
                status.input = Some(status.transaction.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or(ProviderLedgerError::Unavailable)?.clone());
                super::super::super::PreparedSourceOriginalV5::park(&mut status.input, &mut None, &mut status.append)?;
                self.prepare_original_journal_for_v1(Purpose::ReleaseStatus)?;
                return Ok(true);
            }
            _ => {}
        }

        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let original = held.original.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let history = self.hold_challenges.original_history_v5()?;
        let writer = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?
            .claim_source_original_native_v5(&history)?;
        let completion = original.producer.as_mut()
            .and_then(|producer| producer.original_completion.as_mut())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let physical = completion.handoff.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let release = completion.held.as_mut()
            .and_then(|held| held.release.as_mut()).ok_or(ProviderLedgerError::Unavailable)?;
        let current = release.current.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let signed = release.signed.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let clock = release.clock.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let status = release.status.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let readback = if stage == PendingStatusStageV1::Send {
            status.append.as_ref().and_then(|append| append.readback.as_ref())
        } else {
            release.append.as_ref().and_then(|append| append.readback.as_ref())
        }.ok_or(ProviderLedgerError::Unavailable)?;

        if stage == PendingStatusStageV1::Authorize {
            if status.records.is_some() || status.authorization.is_some() {
                return Err(ProviderLedgerError::RuntimePoisoned.into());
            }
            status.records = Some(crate::transaction::original_release_status_records_v1(
                &writer, readback,
                original.history.current.as_ref().ok_or(ProviderLedgerError::Unavailable)?,
                original.history.durable.as_ref().ok_or(ProviderLedgerError::Unavailable)?,
            ));
            if matches!(status.records, Some(Err(_))) {
                status.first = Some(PendingStatusFailureV1::Records);
                return Err(ProviderLedgerError::RuntimePoisoned.into());
            }
            let result = held.session.authorize_original_native_release_status_v1(
                &writer, readback, current, &mut status.authorization,
            );
            if result.is_err() {
                status.first = Some(PendingStatusFailureV1::Authorization);
            }
            result?;
            return Ok(true);
        }

        let authorization = status.authorization.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let records = status.records.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProviderLedgerError::Unavailable)?;
        match stage {
            PendingStatusStageV1::PrepareFence => {
                if status.fence_prepared.is_some() {
                    return Err(ProviderLedgerError::RuntimePoisoned.into());
                }
                status.fence_prepared = Some(held.session.prepare_original_native_release_fence_v1(
                    &writer, readback, authorization, records,
                ));
                if matches!(status.fence_prepared, Some(Err(_))) {
                    status.first = Some(PendingStatusFailureV1::Fence);
                    return Err(ProviderLedgerError::RuntimePoisoned.into());
                }
            }
            PendingStatusStageV1::SignFence | PendingStatusStageV1::SignStatus => {
                let index = usize::from(stage == PendingStatusStageV1::SignStatus);
                if status.signing_attempted[index] || status.signatures[index].is_some()
                    || status.loan_failures[index].is_some()
                {
                    return Err(ProviderLedgerError::RuntimePoisoned.into());
                }
                status.signing_attempted[index] = true;
                if index == 0 {
                    if status.fence.is_some() {
                        return Err(ProviderLedgerError::RuntimePoisoned.into());
                    }
                    let prepared = status.fence_prepared.as_ref().and_then(|result| result.as_ref().ok())
                        .ok_or(ProviderLedgerError::Unavailable)?;
                    let loan = match held.session.borrow_original_native_release_fence_v1(
                        &writer, readback, authorization, records, physical, prepared,
                    ) {
                        Ok(loan) => loan,
                        Err(cause) => {
                            status.loan_failures[index] = Some(cause);
                            status.first = Some(PendingStatusFailureV1::Loan(index));
                            return Err(ProviderLedgerError::RuntimePoisoned.into());
                        }
                    };
                    clock.require_current(current, signed)?;
                    status.signatures[index] = Some(loan.sign());
                    // All fallible work is over before the infallible move.
                    if let (Some(Ok(prepared)), Some(signature)) =
                        (status.fence_prepared.take(), status.signatures[index].as_ref())
                    {
                        status.fence = Some(prepared.attach_signature(signature.clone()));
                    }
                } else {
                    if status.signed_status.is_some() {
                        return Err(ProviderLedgerError::RuntimePoisoned.into());
                    }
                    let prepared = status.status_prepared.as_ref().and_then(|result| result.as_ref().ok())
                        .ok_or(ProviderLedgerError::Unavailable)?;
                    let fence = status.fence.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
                    let loan = match held.session.borrow_original_pending_release_status_v1(
                        &writer, readback, authorization, records, physical, fence, prepared,
                    ) {
                        Ok(loan) => loan,
                        Err(cause) => {
                            status.loan_failures[index] = Some(cause);
                            status.first = Some(PendingStatusFailureV1::Loan(index));
                            return Err(ProviderLedgerError::RuntimePoisoned.into());
                        }
                    };
                    clock.require_current(current, signed)?;
                    status.signatures[index] = Some(loan.sign());
                    if let (Some(Ok(prepared)), Some(signature)) =
                        (status.status_prepared.take(), status.signatures[index].as_ref())
                    {
                        status.signed_status = Some(prepared.attach_signature(*signature.as_bytes()));
                    }
                }
            }
            PendingStatusStageV1::PrepareStatus => {
                if status.status_prepared.is_some() {
                    return Err(ProviderLedgerError::RuntimePoisoned.into());
                }
                status.status_prepared = Some(held.session.prepare_original_pending_release_status_v1(
                    &writer, readback, authorization, records,
                    status.fence.as_ref().ok_or(ProviderLedgerError::Unavailable)?,
                ));
                if matches!(status.status_prepared, Some(Err(_))) {
                    status.first = Some(PendingStatusFailureV1::Status);
                    return Err(ProviderLedgerError::RuntimePoisoned.into());
                }
            }
            PendingStatusStageV1::Finalize => {
                if status.response.is_some() || status.encoded.is_some()
                    || status.finalized.is_some() || status.transaction.is_some()
                {
                    return Err(ProviderLedgerError::RuntimePoisoned.into());
                }
                status.response = Some(ReleaseSourceResponseV2::new(
                    status.signed_status.as_ref().ok_or(ProviderLedgerError::Unavailable)?.clone(),
                    status.fence.as_ref().ok_or(ProviderLedgerError::Unavailable)?.clone(),
                ));
                let Some(Ok(response)) = &status.response else {
                    status.first = Some(PendingStatusFailureV1::Response);
                    return Err(ProviderLedgerError::RuntimePoisoned.into());
                };
                status.encoded = Some(response.to_canonical_bytes());
                let encoded = status.encoded.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
                if encoded.len() != aos_sandbox_source_provider_protocol::MAXIMUM_NATIVE_RELEASE_RESPONSE_BYTES_V2 {
                    return Err(ProviderLedgerError::Equivocation.into());
                }

                let seconds = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
                status.finalized = Some(crate::release::finalize_original_pending_release_v1(records, current, encoded, seconds));
                let Some(Ok(finalized)) = &status.finalized else {
                    status.first = Some(PendingStatusFailureV1::Finalized);
                    return Err(ProviderLedgerError::RuntimePoisoned.into());
                };

                status.transaction = Some(held.session.prepare_original_release_status_transaction_v1(
                    &writer, readback, authorization, finalized,
                ));
                if matches!(status.transaction, Some(Err(_))) {
                    status.first = Some(PendingStatusFailureV1::Transaction);
                    return Err(ProviderLedgerError::RuntimePoisoned.into());
                }
            }
            PendingStatusStageV1::Send => {
                let encoded = status.encoded.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
                let loan = match held.session.borrow_original_release_status_send_v1(
                    &writer, readback, authorization, encoded,
                    &mut status.send_attempted, &mut status.send,
                ) {
                    Ok(loan) => loan,
                    Err(cause) => {
                        status.loan_failures[0] = Some(cause);
                        status.first = Some(PendingStatusFailureV1::Loan(0));
                        return Err(ProviderLedgerError::RuntimePoisoned.into());
                    }
                };
                clock.require_current(current, signed)?;
                loan.send();
                if !matches!(status.send, Some(Ok(()))) {
                    status.first = Some(PendingStatusFailureV1::Send);
                    return Err(ProviderLedgerError::RuntimePoisoned.into());
                }
            }
            _ => return Err(ProviderLedgerError::RuntimePoisoned.into()),
        }
        Ok(true)
    }

    fn original_release_v1(&self) -> Result<&OriginalSourceReleaseV1, ProviderLedgerError> {
        self.original_held_v5()?.release.as_ref().ok_or(ProviderLedgerError::Unavailable)
    }

    fn original_release_mut_v1(&mut self) -> Result<&mut OriginalSourceReleaseV1, ProviderLedgerError> {
        self.original_held_mut_v5()?.release.as_mut().ok_or(ProviderLedgerError::Unavailable)
    }

    /// Borrows the actual new purpose's first cause without another observation.
    #[doc(hidden)]
    #[must_use]
    pub fn original_release_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Ok(child) = self.original_release_v1() {
            if let Some(cause) = child.status.as_ref().and_then(OriginalPendingReleaseStatusV1::failure) {
                return Some(cause);
            }
            let receiving = matches!(child.first, Some(ReleaseFailureV1::Receive))
                || (child.first.is_none() && child.stage == ReleaseStageV1::Receive);
            if receiving {
                // The lower receiver parks its native cause before its own
                // posts. That cause remains reachable if a post unwinds before
                // this child receives the deliberately nonspecific refusal.
                match self.selected_original_failure() {
                    Some(FixedSelectedProviderFailureRefV1::Security(
                        SelectedSourceProviderFailureRefV1::Socket(cause),
                    )) => return Some(cause),
                    Some(FixedSelectedProviderFailureRefV1::Security(
                        SelectedSourceProviderFailureRefV1::Binding(cause),
                    )) => return Some(cause),
                    _ => {}
                }
            }
            if let Some(cause) = child.failure() {
                return Some(cause);
            }
        }
        self.original_terminal_receipt_failure_v5()
    }

    /// Borrows later Release observations separately from the first action cause.
    #[doc(hidden)]
    #[must_use]
    pub fn original_release_postcheck_debt_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let child = self.original_release_v1().ok()?;
        if let Some(status) = &child.status {
            if let Some(cause) = status.owner_post.as_ref().and_then(|result| result.as_ref().err()) {
                return Some(cause);
            }
            if let Some(cause) = status.clock_post.as_ref().and_then(|result| result.as_ref().err()) {
                return Some(cause);
            }
        }
        child.owner_post.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| child.clock_post.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as _))
    }

    /// Lends the fixed selected receive/Release cutoff, never authorization.
    #[doc(hidden)]
    #[must_use]
    pub fn original_release_deadline_v1(&self) -> Option<u64> {
        let child = self.original_release_v1().ok()?;
        if let Some(Ok(clock)) = &child.clock { Some(clock.deadline()) }
        else { child.receive_cut.as_ref().ok().copied() }
    }

    /// Continues only the actual phase10 owner to independent Release admission.
    ///
    /// Physical custody, cleanup, retirement and population Drain remain closed.
    #[doc(hidden)]
    pub fn advance_original_native_release_v1(
        &mut self,
        publication: &[u8],
        rows: &[u8],
    ) -> Progress {
        if self.original_ingress.producer_closed_v5() {
            return Progress::Closed;
        }
        let installed = self.original_release_v1().is_ok();
        if !installed {
            match self.advance_original_native_terminal_receipt_v5(publication, rows) {
                Progress::RootTerminalRecorded => {}
                progress => return progress,
            }
            let receive_cut = original_release_receive_cut_v1();
            let Ok(held) = self.original_held_mut_v5() else { return Progress::Closed; };
            held.release = Some(OriginalSourceReleaseV1::pending(receive_cut));
        }

        let mut guard = OriginalHeldClosureV5 {
            original: OriginalProducerClosureGuardV5 { owner: self, completed: false },
        };
        let progress = guard.original.owner.advance_original_release_inner_v1(publication, rows);
        guard.original.completed = progress != Progress::Closed;
        progress
    }

    fn advance_original_release_inner_v1(&mut self, publication: &[u8], rows: &[u8]) -> Progress {
        let stage = match self.original_release_v1() {
            Ok(child) if child.first.is_none() => child.stage,
            _ => return Progress::Closed,
        };
        if stage == ReleaseStageV1::Closed {
            return Progress::Closed;
        }
        let before = (|| {
            self.require_original_publication_inputs_v5(publication, rows)?;
            self.require_original_release_owner_v1()?;
            self.original_release_v1()?.require_clock()?;
            Ok(())
        })();
        if let Err(cause) = before {
            if let Ok(child) = self.original_release_mut_v1() {
                if child.first.is_none() {
                    child.boundary = Some(cause);
                    child.first = Some(ReleaseFailureV1::Boundary);
                }
            }
            self.observe_original_release_posts_v1();
            return Progress::Closed;
        }
        if stage == ReleaseStageV1::Admitted {
            return Progress::ReleaseAdmitted;
        }

        let (index, action) = match stage {
            ReleaseStageV1::Receive => (0, self.receive_original_release_v1()),
            ReleaseStageV1::Prepare => (1, self.prepare_original_release_append_v1().map(|()| true)),
            ReleaseStageV1::Preflight => (2, self.preflight_original_journal_for_v1(
                super::super::super::OriginalJournalPurposeV1::Release).map(|()| true).map_err(Into::into)),
            ReleaseStageV1::Commit => (3, self.commit_original_journal_for_v1(
                super::super::super::OriginalJournalPurposeV1::Release).map(|()| true).map_err(Into::into)),
            _ => return Progress::Closed,
        };
        let progressed = action.as_ref().is_ok_and(|progressed| *progressed);
        if let Ok(child) = self.original_release_mut_v1() {
            if action.is_err() && child.first.is_none() {
                child.first = Some(ReleaseFailureV1::Action(index));
            }
            child.actions[index] = Some(action);
        } else {
            return Progress::Closed;
        }
        self.observe_original_release_posts_v1();
        let Ok(child) = self.original_release_mut_v1() else { return Progress::Closed; };
        if child.first.is_some() {
            child.stage = ReleaseStageV1::Closed;
            return Progress::Closed;
        }
        if progressed {
            child.stage = match stage {
                ReleaseStageV1::Receive => ReleaseStageV1::Prepare,
                ReleaseStageV1::Prepare => ReleaseStageV1::Preflight,
                ReleaseStageV1::Preflight => ReleaseStageV1::Commit,
                ReleaseStageV1::Commit => ReleaseStageV1::Admitted,
                other => other,
            };
        }
        if child.stage == ReleaseStageV1::Admitted {
            Progress::ReleaseAdmitted
        } else {
            Progress::Pending
        }
    }

    fn require_original_release_owner_v1(&mut self) -> Result<(), OriginalProducerErrorV5> {
        self.observe_original_journal_v5()?;
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let completion = held.original.as_mut().and_then(|original| original.producer.as_mut())
            .and_then(|producer| producer.original_completion.as_mut()).ok_or(ProviderLedgerError::Unavailable)?;
        let physical = completion.handoff.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProviderLedgerError::Unavailable)?;
        held.session.revalidate_original_held_mount_v5(physical)?;
        Ok(())
    }

    fn observe_original_release_posts_v1(&mut self) {
        let owner = self.require_original_release_owner_v1();
        if let Ok(child) = self.original_release_mut_v1() {
            if child.owner_post.as_ref().is_none_or(|result| result.is_ok()) {
                if owner.is_err() && child.first.is_none() {
                    child.first = Some(ReleaseFailureV1::OwnerPost);
                }
                child.owner_post = Some(owner);
            }
        }
        // Clock observation is independent even when owner observation ended.
        let clock = self.original_release_v1().and_then(OriginalSourceReleaseV1::require_clock);
        if let Ok(child) = self.original_release_mut_v1() {
            if child.clock_post.as_ref().is_none_or(|result| result.is_ok()) {
                if clock.is_err() && child.first.is_none() {
                    child.first = Some(ReleaseFailureV1::ClockPost);
                }
                child.clock_post = Some(clock);
            }
        }
    }

    fn receive_original_release_v1(&mut self) -> Result<bool, OriginalProducerErrorV5> {
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let original = held.original.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let producer = original.producer.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let acquisition = producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?
            .request().claims().provider_acquisition().1;
        let readback = producer.readback(Append::RootTerminalRecorded)?;
        let history = self.hold_challenges.original_history_v5()?;
        let writer = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?
            .claim_source_original_native_v5(&history)?;
        writer.validate_readback(readback)?;
        let readback = producer.readback(Append::RootTerminalRecorded)?;
        let replay = writer.replayed_origins()?;
        if replay.current_rows() != readback.rows() { return Err(ProviderLedgerError::Equivocation.into()); }
        let completion = producer.original_completion.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let lease = completion.signatures.as_ref().and_then(|signatures| signatures.signed_lease())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let child = completion.held.as_mut().and_then(|held| held.release.as_mut())
            .ok_or(ProviderLedgerError::Unavailable)?;
        if child.signed.is_some() || child.current.is_some() { return Err(ProviderLedgerError::RuntimePoisoned.into()); }
        child.packet = Some(held.session.receive_current_request_packet());
        if child.packet.as_ref().is_some_and(|result| result.is_err()) {
            child.first = Some(ReleaseFailureV1::Receive);
            return Err(ProviderLedgerError::RuntimePoisoned.into());
        }
        let Some(bytes) = child.packet.as_ref().and_then(|result| result.as_ref().ok()).and_then(Option::as_ref) else {
            return Ok(false);
        };
        child.signed = Some(SignedSourceProviderRequestV1::from_canonical_bytes(bytes));
        if child.signed.as_ref().is_some_and(|result| result.is_err()) {
            child.first = Some(ReleaseFailureV1::Signed);
            return Err(ProviderLedgerError::RuntimePoisoned.into());
        }
        let signed = child.signed.as_ref().and_then(|result| result.as_ref().ok()).ok_or(ProviderLedgerError::Unavailable)?;
        if signed.method() != aos_sandbox_source_provider_protocol::SourceProviderMethod::Release {
            return Err(ProviderLedgerError::Equivocation.into());
        }
        let configuration = original.history.current.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let archived = original.history.durable.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        child.recovered = Some(crate::recovery::original_source_capacity::authenticate_archived_complete_cut_v5(
            replay.current_rows(), archived, configuration,
        ));
        if child.recovered.as_ref().is_some_and(|result| result.is_err()) {
            child.first = Some(ReleaseFailureV1::Recovered);
            return Err(ProviderLedgerError::RuntimePoisoned.into());
        }
        let recovered = child.recovered.as_ref().and_then(|result| result.as_ref().ok()).ok_or(ProviderLedgerError::Unavailable)?;
        let expectation = crate::transaction::request_sequence_expectation_from_recovered_v5(recovered, signed)?;
        child.current = Some(held.session.verify_current_request(signed, expectation, &[]));
        if child.current.as_ref().is_some_and(|result| result.is_err()) {
            child.first = Some(ReleaseFailureV1::Current);
            return Err(ProviderLedgerError::RuntimePoisoned.into());
        }
        let current = child.current.as_ref().and_then(|result| result.as_ref().ok()).ok_or(ProviderLedgerError::Unavailable)?;
        let VerifiedProviderRequestV1::Release(verified) = current.verified() else {
            return Err(ProviderLedgerError::Equivocation.into());
        };
        if verified.request().acquisition_id() != acquisition { return Err(ProviderLedgerError::Equivocation.into()); }
        let existing = recovered.acquisitions.values().find(|row| row.acquisition_id == acquisition)
            .ok_or(ProviderLedgerError::Unavailable)?;
        child.clock = Some(OriginalReleaseClockGuardV1::capture(current, signed, existing, lease,
            *child.receive_cut.as_ref().map_err(|_| ProviderLedgerError::RuntimePoisoned)?));
        if child.clock.as_ref().is_some_and(|result| result.is_err()) {
            child.first = Some(ReleaseFailureV1::Clock);
            return Err(ProviderLedgerError::RuntimePoisoned.into());
        }
        Ok(true)
    }

    fn prepare_original_release_append_v1(&mut self) -> Result<(), OriginalProducerErrorV5> {
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let original = held.original.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let producer = original.producer.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let readback = producer.readback(Append::RootTerminalRecorded)?;
        let history = self.hold_challenges.original_history_v5()?;
        let writer = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?
            .claim_source_original_native_v5(&history)?;
        writer.validate_readback(readback)?;
        let replay = writer.replayed_origins()?;
        let key = native_completion_key_v2(producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?
            .request().claims().provider_acquisition().1);
        let (readback, completion, _, _) = producer.settlement_parts_v5(Append::RootTerminalRecorded)?;
        let child = completion.held.as_mut().and_then(|held| held.release.as_mut()).ok_or(ProviderLedgerError::Unavailable)?;
        if child.append.is_some() || child.transaction.is_some() { return Err(ProviderLedgerError::RuntimePoisoned.into()); }
        child.native = Some(SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key,
            replay.current_rows().get(&(RecordNamespace::SourceProviderAuthority, key.clone()))
                .ok_or(ProviderLedgerError::Unavailable)?).map_err(Into::into));
        if child.native.as_ref().is_some_and(|result| result.is_err()) {
            child.first = Some(ReleaseFailureV1::Native); return Err(ProviderLedgerError::RuntimePoisoned.into());
        }
        let native = child.native.as_ref().and_then(|result| result.as_ref().ok()).ok_or(ProviderLedgerError::Unavailable)?;
        let current = child.current.as_ref().and_then(|result| result.as_ref().ok()).ok_or(ProviderLedgerError::Unavailable)?;
        let recovered = child.recovered.as_ref().and_then(|result| result.as_ref().ok()).ok_or(ProviderLedgerError::Unavailable)?;
        let configuration = original.history.current.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let archived = original.history.durable.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        child.rows = Some(crate::release::prepare_original_release_rows_v1(configuration, recovered, current, native));
        if child.rows.as_ref().is_some_and(|result| result.is_err()) {
            child.first = Some(ReleaseFailureV1::Rows); return Err(ProviderLedgerError::RuntimePoisoned.into());
        }
        let rows = child.rows.as_ref().and_then(|result| result.as_ref().ok()).ok_or(ProviderLedgerError::Unavailable)?;
        child.mutation = Some(crate::transaction::prepare_original_release_admission(&writer, readback,
            configuration, archived, native.original().acquisition_id,
            rows.records.iter().map(|(key, value)| (key.clone(), Some(value.clone()))).collect()));
        if child.mutation.as_ref().is_some_and(|result| result.is_err()) {
            child.first = Some(ReleaseFailureV1::Mutation); return Err(ProviderLedgerError::RuntimePoisoned.into());
        }
        let mutation = child.mutation.as_ref().and_then(|result| result.as_ref().ok()).ok_or(ProviderLedgerError::Unavailable)?;
        child.transaction = Some(writer.derive_original_release_admission_v1(readback, &mutation.transaction,
            native.original().acquisition_id));
        if child.transaction.as_ref().is_some_and(|result| result.is_err()) {
            child.first = Some(ReleaseFailureV1::Transaction); return Err(ProviderLedgerError::RuntimePoisoned.into());
        }
        child.input = child.transaction.as_ref().and_then(|result| result.as_ref().ok()).cloned();
        super::super::super::PreparedSourceOriginalV5::park(&mut child.input, &mut None, &mut child.append)?;
        self.prepare_original_journal_for_v1(super::super::super::OriginalJournalPurposeV1::Release)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_cut_error_remains_first_when_negative_boundary_debt_arrives() {
        let mut child = OriginalSourceReleaseV1::pending(Err(ProviderLedgerError::Unavailable));
        child.boundary = Some(ProviderLedgerError::RuntimePoisoned.into());

        let Some(cause) = child.failure()
            .and_then(|cause| cause.downcast_ref::<ProviderLedgerError>())
        else {
            panic!("the original receive-cut cause was hidden");
        };

        assert!(matches!(child.first, Some(ReleaseFailureV1::ReceiveCut)));
        assert!(matches!(cause, ProviderLedgerError::Unavailable));
        assert!(child.packet.is_none());
        assert!(child.signed.is_none());
        assert!(child.append.is_none());
    }

    #[test]
    fn an_empty_pending_cut_has_neither_authority_nor_positive_progress() {
        let child = OriginalSourceReleaseV1::pending(Ok(1));

        assert!(child.first.is_none());
        assert!(child.failure().is_none());
        assert!(child.current.is_none());
        assert!(child.clock.is_none());
        assert!(child.transaction.is_none());
        assert!(matches!(child.stage, ReleaseStageV1::Receive));
    }
}
