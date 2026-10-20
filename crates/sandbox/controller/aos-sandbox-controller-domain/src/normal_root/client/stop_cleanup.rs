//! Retains the same fresh Stop22 payer and physical Root exchange to completion.
//!
//! Opening, ordinary Controller signing, Host child execution and final Host3
//! remain separate finite phases on one continuously retained Root socket.
//! Effect and observation decisions never reconstruct an old native Stop owner.

use std::{error::Error, mem::size_of, sync::Arc};

use aos_sandbox_broker::controller_receiving::bank_launch::ControllerStopCleanupSourceAffinityV1;
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::unix_stream::{RetainedSubjectStreamReadV1, SubjectStreamReadErrorV1};
use aos_sandbox_protocol::{
    domain_ledger::{
        create_storage_history::HistoryErrorV1,
        provisioning_root::{stop_cleanup::*, storage_apply::ApplyRootDataErrorV1},
    },
    host_stop_cleanup::HostStopCleanupSubjectDataV1,
};

use super::{
    ProductionControllerNormalRootProfileV1,
    bookend::RootClientBookendV1,
    peer_receiving::CreateStorageRootPeerReceivingOriginalsV1,
    resource_stream::{
        self, RootClientFundingV1, RootClientLoanV1, RootReplyPurposeV1, RootReplyReceiveV1,
        RootSubjectDataV1,
    },
    root_connection::ControllerRootConnectionOriginalV1,
    strict_chunk::RootStrictChunkOriginalV1,
};
use crate::{
    Journal,
    controller_lifecycle_stop::ControllerHostStopCleanupSourceLoanV1,
    controller_resource_reservation::ResourceReservationErrorV1,
    policy_compiler::{
        RetainedKernelPairedClockAttemptV1,
        bounded_stream_io::{DeadlineStreamDirectionV1, FixedDeadlineStreamIoV1},
    },
};

mod completion;
mod io;
mod opening;
mod signing;
pub use completion::{RootStopCleanupChildLoanV1, RootStopCleanupClientCompletedBorrowV1};
pub use signing::RootStopCleanupSigningLoanV1;

type Cause = Box<dyn Error + Send + Sync>;
type Source<'owner, 'source> = ControllerHostStopCleanupSourceLoanV1<'owner, 'source>;
type HostReference = ([u8; 16], [u8; 32], [u8; 32], [u8; 32], [u8; 32]);
const BOOKENDS: usize = 8;

/// Reports an incomplete or refused continuously retained Stop Root exchange.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the retained Stop cleanup Root exchange is incomplete or refused")]
pub struct RootStopCleanupClientClosedV1;

/// Owns the actual socket, frames and negative originals through all outer posts.
#[must_use = "retain the actual Root original through Source disposition"]
pub struct RootStopCleanupClientOriginalV1 {
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    native: Option<Box<Native>>,
    complete: ResourceVector,
    observations: usize,
    wire: u64,
    output: u64,
    received_bound: usize,
    admission: Option<Result<(), ResourceReservationErrorV1>>,
    funding_original: bool,
    phase: usize,
    pending: Option<usize>,
    body: [Option<Result<(), Cause>>; 3],
    validation: Option<Cause>,
    first: Option<First>,
    repeated: Option<RootStopCleanupClientClosedV1>,
}

#[derive(Clone, Copy)]
enum First {
    Entry,
    Funding,
    Bookend(usize),
    Body(usize),
    Signing,
    Validation,
    External,
    Reentry,
}

struct Native {
    profile: Arc<ProductionControllerNormalRootProfileV1>,
    affinity: ControllerStopCleanupSourceAffinityV1,
    controller: crate::journal::ExecutionObservationJournalIdentityV4,
    origin: RawPairedClockSample,
    source_cutoff: u64,
    cutoff: u64,
    expiry: i64,
    source_parent: [u8; 32],
    source_subject: HostStopCleanupSubjectDataV1,
    opening: opening::Opening,
    query_digest: [u8; 32],
    decision_digest: [u8; 32],
    observed: bool,
    connection: ControllerRootConnectionOriginalV1,
    connect: Option<Result<(), HistoryErrorV1>>,
    reporting: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    query_sender: FixedDeadlineStreamIoV1<QUERY_BYTES_V1>,
    query_sent: Option<Result<(), HistoryErrorV1>>,
    sender: [FixedDeadlineStreamIoV1<4096>; 3],
    sent: [Option<Result<(), HistoryErrorV1>>; 3],
    scratch: [u8; 4096],
    data_failure: Option<ApplyRootDataErrorV1>,
    replies: [Reply; 4],
    eof: FixedDeadlineStreamIoV1<1>,
    eof_byte: [u8; 1],
    ended: Option<Result<(), HistoryErrorV1>>,
    confirmation: Option<Result<(), HistoryErrorV1>>,
    comparison: Option<Result<(), HistoryErrorV1>>,
    bookends: [RootClientBookendV1; BOOKENDS],
    signing: Option<Box<signing::Signing>>,
    final_host: Option<HostReference>,
}

struct Reply {
    received: RetainedSubjectStreamReadV1,
    preparation: Option<Result<(), SubjectStreamReadErrorV1>>,
    extension: Option<Result<(), SubjectStreamReadErrorV1>>,
    chunk: Option<Box<RootStrictChunkOriginalV1>>,
}

impl Default for RootStopCleanupClientOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl RootStopCleanupClientOriginalV1 {
    /// Constructs inert destinations without admission, allocation or IO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entry: None,
            native: None,
            complete: ResourceVector::ZERO,
            observations: 0,
            wire: 0,
            output: 0,
            received_bound: REPLY_HEADER_BYTES_V1,
            admission: None,
            funding_original: false,
            phase: 0,
            pending: None,
            body: std::array::from_fn(|_| None),
            validation: None,
            first: None,
            repeated: None,
        }
    }

    fn require_phase(&self, phase: usize) -> Result<(), RootStopCleanupClientClosedV1> {
        if self.first.is_some() || self.phase != phase || self.pending.is_some() {
            return Err(RootStopCleanupClientClosedV1);
        }
        Ok(())
    }

    fn require_source(&self, source: &Source<'_, '_>, controller: &Journal) -> Result<(), Cause> {
        let native = self
            .native
            .as_deref()
            .ok_or(RootStopCleanupClientClosedV1)?;
        source.require_same_inventory_financial_original_v1(&native.affinity, controller)?;
        if !Arc::ptr_eq(&source.root_profile_arc_v1(), &native.profile)
            || !native
                .controller
                .is_same_original_v4(&controller.execution_observation_identity_v4())
            || source.original_clock_data_v1(controller)? != native.origin
            || source.original_cutoff_v1(controller)? != native.source_cutoff
            || source.subject_data_v1(controller)? != native.source_subject
            || source.source_parent_data_v1(controller)? != native.source_parent
        {
            return Err(RootStopCleanupClientClosedV1.into());
        }
        Ok(())
    }

    fn record_body(&mut self, index: usize, result: Result<(), Cause>) {
        if result.is_err() {
            self.first.get_or_insert(First::Body(index));
        }
        self.body[index] = Some(result);
    }

    fn validate_source(
        &mut self,
        source: &Source<'_, '_>,
        controller: &Journal,
    ) -> Result<(), RootStopCleanupClientClosedV1> {
        if let Err(cause) = self.require_source(source, controller) {
            return Err(self.retain_validation(cause));
        }
        Ok(())
    }

    fn retain_validation(&mut self, cause: Cause) -> RootStopCleanupClientClosedV1 {
        if self.validation.is_none() {
            self.validation = Some(cause);
        }
        self.first.get_or_insert(First::Validation);
        RootStopCleanupClientClosedV1
    }

    fn refuse_reentry(&mut self) -> RootStopCleanupClientClosedV1 {
        self.repeated.get_or_insert(RootStopCleanupClientClosedV1);
        self.first.get_or_insert(First::Reentry);
        RootStopCleanupClientClosedV1
    }

    /// Borrows the original retained native, framing or financial refusal.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Entry => error(&self.entry),
            First::Funding => error(&self.admission),
            First::Bookend(index) => self.native.as_ref()?.bookends[index].failure(),
            First::Body(index) => {
                let native = self.native.as_deref()?;
                native
                    .connection
                    .failure()
                    .or_else(|| error(&native.reporting))
                    .or_else(|| native.query_sender.failure())
                    .or_else(|| error(&native.query_sent))
                    .or_else(|| native.sender[index].failure())
                    .or_else(|| error(&native.sent[index]))
                    .or_else(|| {
                        native.replies.iter().find_map(|reply| {
                            reply
                                .chunk
                                .as_ref()
                                .and_then(|chunk| chunk.failure(&reply.received))
                        })
                    })
                    .or_else(|| native.data_failure.as_ref().map(|cause| cause as _))
                    .or_else(|| error(&native.comparison))
                    .or_else(|| native.eof.failure())
                    .or_else(|| error(&native.ended))
                    .or_else(|| {
                        self.body[index]
                            .as_ref()?
                            .as_ref()
                            .err()
                            .map(|cause| cause.as_ref() as _)
                    })
            }
            First::Signing => {
                let native = self.native.as_deref()?;
                let local = native.signing.as_deref()?;
                local
                    .failure_before_send()
                    .or_else(|| native.sender[1].failure())
                    .or_else(|| error(&native.sent[1]))
                    .or_else(|| {
                        native.replies[3]
                            .chunk
                            .as_ref()
                            .and_then(|chunk| chunk.failure(&native.replies[3].received))
                    })
                    .or_else(|| error(&native.replies[3].preparation))
                    .or_else(|| error(&native.replies[3].extension))
                    .or_else(|| native.data_failure.as_ref().map(|cause| cause as _))
                    .or_else(|| error(&native.comparison))
                    .or_else(|| local.failure())
            }
            First::Validation => self.validation.as_ref().map(|cause| cause.as_ref() as _),
            First::External | First::Reentry => self.repeated.as_ref().map(|cause| cause as _),
        }
    }

    /// Reports that the retained same-Source native cause owns financial refusal.
    #[must_use]
    pub fn source_failure_selected_v1(&self) -> bool {
        self.funding_original
    }

    /// Selects the effect branch only from the actual healthy held Root reply.
    ///
    /// # Errors
    /// Refuses an unfinished opening, failed payer or changed native Source/C.
    pub fn requires_signing_v1(
        &self,
        source: &Source<'_, '_>,
        controller: &Journal,
    ) -> Result<bool, RootStopCleanupClientClosedV1> {
        self.require_phase(1)?;
        self.require_source(source, controller)
            .map_err(|_| RootStopCleanupClientClosedV1)?;
        Ok(!self
            .native
            .as_ref()
            .ok_or(RootStopCleanupClientClosedV1)?
            .observed)
    }
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, RootStopCleanupClientClosedV1> {
    slot.as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(RootStopCleanupClientClosedV1)
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

struct OwedAfter<'root> {
    owner: &'root mut RootStopCleanupClientOriginalV1,
    profile: Arc<ProductionControllerNormalRootProfileV1>,
}

impl OwedAfter<'_> {
    fn finish(&mut self) {
        let _ = self.owner.drain_owed(&self.profile);
    }
}

impl Drop for OwedAfter<'_> {
    fn drop(&mut self) {
        if self.owner.pending.is_some() {
            self.owner
                .repeated
                .get_or_insert(RootStopCleanupClientClosedV1);
            self.owner.first.get_or_insert(First::External);
            let _ = self.owner.drain_owed(&self.profile);
        }
    }
}
