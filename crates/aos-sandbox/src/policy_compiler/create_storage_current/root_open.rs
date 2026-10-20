//! Produces one actual RootOpen record through the sole Native append engine.
//!
//! The private producer borrows its real accepted Root flight and both actual
//! fixed writers. RootOpen correlation is untrusted; it grants no U, signing,
//! dispatch or Prepare authority. Native final crossing rejoins these same
//! owners after ordinary semantic validation and before the original append.

use std::error::Error as StdError;
use std::io;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HEAD_BYTES, RECORD_OVERHEAD_BYTES, HistoryErrorV1, KeyV1, LatestHeadV1,
    OwnerV1, PhaseV1, RecordCoordinatesV1, RecordEnvelopeV1,
    root_open::{ROOT_OPEN_BODY_BYTES_V1, RootOpenBodyDataV1}, transport::OpenQueryV1,
};
use crate::journal::create_storage_history::{
    HistoryPairReadbackV1, prepare_history_pair_v1, readback_history_pair_v1,
};

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::{
    CommitResult, Journal, JournalError, JournalTransaction,
    ProtectedJournalNamesV1, ProtectedJournalCurrentnessOriginalsV1, RecordNamespace,
};
use crate::normal_root::{
    NormalRootStartupErrorV1, RootCurrentOpenIdentityDataV1, RootPolicyAcceptedFlightV1,
};

use super::RootCreateStorageCurrentErrorV1 as Error;
use super::super::{fresh_root_nonce, root_current_writers::RootCreateStorageCurrentWritersV1};
use super::super::protected_owner::{
    POLICY_AUTHORITY_JOURNAL, POLICY_STATE_JOURNAL, PROTECTED_POLICY_ROOT,
    policy_authority_journal_limits, policy_state_journal_limits,
};
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;

type WitnessOriginal = aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1<JournalError>;

const ROOT_RECORD_BYTES: usize = RECORD_OVERHEAD_BYTES + ROOT_OPEN_BODY_BYTES_V1;
const MAXIMUM_ROOT_FLIGHT: Duration = Duration::from_secs(65);

pub(crate) struct RootCurrentOpenStateV1 {
    provision: Option<Result<(), NormalRootStartupErrorV1>>,
    identity: Option<Result<RootCurrentOpenIdentityDataV1, NormalRootStartupErrorV1>>,
    clock_original: RetainedKernelPairedClockAttemptV1,
    clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    started: Option<Instant>,
    nonce: Option<io::Result<[u8; 16]>>,
    authority_name_original: ProtectedJournalCurrentnessOriginalsV1,
    authority_witness_original: WitnessOriginal,
    policy_name_original: ProtectedJournalCurrentnessOriginalsV1,
    policy_witness_original: WitnessOriginal,
    authority_names: Option<Result<ProtectedJournalNamesV1, JournalError>>,
    policy_names: Option<Result<ProtectedJournalNamesV1, JournalError>>,
    body: Option<Result<RootOpenBodyDataV1, JournalError>>,
    body_encoding: Option<Result<[u8; ROOT_OPEN_BODY_BYTES_V1], HistoryErrorV1>>,
    encoded_body: [u8; ROOT_OPEN_BODY_BYTES_V1],
    record: [u8; ROOT_RECORD_BYTES],
    head: [u8; HEAD_BYTES],
    head_encoding: Option<Result<[u8; HEAD_BYTES], HistoryErrorV1>>,
    checksum: Option<Result<[u8; 32], HistoryErrorV1>>,
    transaction: Option<Result<JournalTransaction, JournalError>>,
    crossing: RootCurrentOpenCrossingV1,
    append: Option<Result<CommitResult, JournalError>>,
    readback: Option<Result<RootCurrentOpenReadbackV1, JournalError>>,
    posts: RootCurrentHistoryPostsV1,
    production: Option<Result<(), Error>>,
    complete: bool,
    closed: bool,
}

impl RootCurrentOpenStateV1 {
    pub(super) fn new() -> Self {
        Self {
            provision: None,
            identity: None,
            clock_original: Default::default(),
            clock: None,
            started: None,
            nonce: None,
            authority_name_original: Default::default(), authority_witness_original: Default::default(),
            policy_name_original: Default::default(), policy_witness_original: Default::default(),
            authority_names: None,
            policy_names: None,
            body: None,
            body_encoding: None,
            encoded_body: [0; ROOT_OPEN_BODY_BYTES_V1],
            record: [0; ROOT_RECORD_BYTES],
            head: [0; HEAD_BYTES],
            head_encoding: None,
            checksum: None,
            transaction: None,
            crossing: RootCurrentOpenCrossingV1::default(),
            append: None,
            readback: None,
            posts: RootCurrentHistoryPostsV1::default(),
            production: None,
            complete: false,
            closed: false,
        }
    }

    pub(super) fn produce_once(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
        original: &UnixStream,
        open: OpenQueryV1,
    ) -> Result<(), Error> {
        if self.production.is_some() || self.closed {
            self.closed = true;
            return Err(Error::Original);
        }
        self.production = Some(self.produce_inner(flight, writers, original, open));
        // Actual held writers and independent peer/Root/clock posts run before
        // the earlier returned append/preparation result is classified.
        self.finish_posts_once(flight, writers);
        self.complete = matches!(self.production, Some(Ok(())))
            && matches!(self.readback, Some(Ok(_)))
            && matches!(self.posts.authority_post, Some(Ok(())))
            && matches!(self.posts.policy_post, Some(Ok(())))
            && matches!(self.posts.names_binding, Some(Ok(())))
            && matches!(self.posts.peer_post, Some(Ok(())))
            && matches!(self.posts.final_clock, Some(Ok(())))
            && self.failure().is_none();
        if self.complete { Ok(()) } else { Err(Error::History) }
    }

    fn produce_inner(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
        original: &UnixStream,
        open: OpenQueryV1,
    ) -> Result<(), Error> {
        let startup = flight.current_cut_startup().map_err(|_| Error::Original)?;
        self.provision = Some(startup.prepay_create_storage_root_open_once());
        positive(&self.provision).map_err(|_| Error::History)?;
        self.posts.arm_once(flight)?;
        self.identity = Some(flight.current_root_open_identity());
        positive(&self.identity).map_err(|_| Error::Original)?;
        self.started = Some(Instant::now());
        self.clock = Some(self.clock_original.observe_once(None));
        positive(&self.clock).map_err(|_| Error::Original)?;
        self.nonce = Some(fresh_root_nonce());
        positive(&self.nonce).map_err(|_| Error::Original)?;

        let (authority, policy) = writers.authority_and_policy().map_err(|_| Error::Writers)?;
        self.authority_names = Some(authority.observe_held_physical_names_retaining_v1(&mut self.authority_name_original, &mut self.authority_witness_original));
        self.policy_names = Some(policy.observe_held_physical_names_retaining_v1(&mut self.policy_name_original, &mut self.policy_witness_original));
        self.body = Some((|| {
            let identity = positive(&self.identity)?;
            let clock = positive(&self.clock)?;
            Ok(RootOpenBodyDataV1 {
                open,
                root_nonce: *positive(&self.nonce)?,
                boot: clock.host_boot_id(),
                started: clock.boottime_nanoseconds(),
                cutoff: clock.boottime_nanoseconds().checked_add(65_000_000_000)
                    .ok_or(JournalError::SequenceExhausted)?,
                authority_names: *positive(&self.authority_names)?,
                policy_names: *positive(&self.policy_names)?,
                authority_next: authority.snapshot_sequence(),
                policy_next: policy.snapshot_sequence(),
                root_profile: identity.profile,
                root_recipient: identity.recipient,
                root_producer: identity.producer,
                root_pid: identity.root_pid,
                controller_pid: identity.controller_pid,
                controller_uid: identity.controller_uid,
                controller_gid: identity.controller_gid,
            })
        })());
        let body = *positive(&self.body).map_err(|_| Error::History)?;
        self.body_encoding = Some(body.encode());
        self.encoded_body = *positive(&self.body_encoding).map_err(|_| Error::History)?;
        let key = KeyV1::new(open.lane, OwnerV1::Root, 1).map_err(|_| Error::History)?;
        let phase = PhaseV1::new(OwnerV1::Root, 1).map_err(|_| Error::History)?;
        self.checksum = Some(RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key,
            phase,
            predecessor: [0; 32],
            correlation: open.seed,
        }, &self.encoded_body, &mut self.record));
        let checksum = *positive(&self.checksum).map_err(|_| Error::History)?;
        self.head_encoding = Some(LatestHeadV1::new(1, checksum).map(|head| head.encode()));
        self.head = *positive(&self.head_encoding).map_err(|_| Error::History)?;
        self.transaction = Some(make_transaction(open.lane, checksum, &self.record, &self.head));
        let transaction = positive(&self.transaction).map_err(|_| Error::History)?;

        // Only this private actual producer constructs the closed append loan.
        // Mutable authority and independently held immutable policy are split
        // from the same two writer owners; no raw Journal/plan/vector factory
        // reaches this constructor from a decoded RootOpen record.
        self.crossing.peer_original = Some(flight.arm_history_peer_post_v1());
        positive(&self.crossing.peer_original).map_err(|_| Error::Original)?
            .require_armed_v1().map_err(|_| Error::Original)?;
        let mut loan = RootCurrentOpenAppendLoanV1 {
            flight,
            original,
            policy,
            body,
            transaction,
            clock: *positive(&self.clock).map_err(|_| Error::Original)?,
            started: self.started.ok_or(Error::Original)?,
            crossing: &mut self.crossing,
            purpose: RootCurrentHistoryPurposeV1::Open,
        };
        self.append = Some(authority.commit_create_storage_root_history_v1(transaction, &mut loan));
        // The complete CommitResult/Err is parked before any readback or post.
        if matches!(self.append, Some(Ok(_))) {
            self.readback = Some(readback(authority, policy, body, transaction,
                &self.record, &self.head, positive(&self.append).map_err(|_| Error::History)?));
        }
        positive(&self.append).map_err(|_| Error::History)?;
        positive(&self.readback).map_err(|_| Error::History).map(|_| ())
    }

    fn finish_posts_once(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
    ) {
        self.posts.observe_once(flight, writers,
            self.body.as_ref().and_then(|result| result.as_ref().ok()),
            self.clock.as_ref().and_then(|result| result.as_ref().ok()).copied(),
            self.started);
    }

    pub(crate) fn committed_record(&self) -> Result<&[u8; ROOT_RECORD_BYTES], Error> {
        if !self.complete || self.closed || self.failure().is_some() {
            return Err(Error::History);
        }
        let readback = positive(&self.readback).map_err(|_| Error::History)?;
        let body = positive(&self.body).map_err(|_| Error::History)?;
        if readback.record != self.record || readback.head != self.head
            || body.authority_next.checked_add(4) != Some(readback.next)
        {
            return Err(Error::History);
        }
        Ok(&self.record)
    }

    pub(crate) fn completed_body(&self) -> Result<RootOpenBodyDataV1, Error> {
        self.committed_record()?;
        positive(&self.body).copied().map_err(|_| Error::History)
    }

    pub(crate) fn completed_receiver(&self) -> Result<([u8; 16], [u8; 16]), Error> {
        let body = self.completed_body()?;
        Ok((body.root_recipient, body.root_producer))
    }

    pub(super) fn readback_current(
        &self,
        authority: &Journal,
        policy: &Journal,
    ) -> Result<RootCurrentOpenReadbackV1, JournalError> {
        let body = self.completed_body().map_err(|_| JournalError::ProtectedBoundary)?;
        readback(authority, policy, body, positive(&self.transaction)?,
            &self.record, &self.head, positive(&self.append)?)
    }

    pub(super) fn original_clock_origin_v1(&self) -> Result<(RawPairedClockSample, Instant), Error> {
        self.completed_body()?;
        Ok((*positive(&self.clock).map_err(|_| Error::Original)?, self.started.ok_or(Error::Original)?))
    }

    pub(in crate::policy_compiler) fn require_clock(&self, current: RawPairedClockSample) -> Result<(), JournalError> {
        let body = self.completed_body().map_err(|_| JournalError::ProtectedBoundary)?;
        require_original_clock(*positive(&self.clock)?, current, body.cutoff,
            self.started.ok_or(JournalError::ProtectedBoundary)?)
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        macro_rules! cause {
            ($slot:expr) => { $slot.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn StdError + 'static)) };
        }
        cause!(self.provision)
            .or_else(|| cause!(self.identity))
            .or_else(|| self.clock_original.failure()).or_else(|| cause!(self.clock))
            .or_else(|| cause!(self.nonce))
            .or_else(|| self.authority_name_original.failure().or_else(|| self.authority_witness_original.failure()).or_else(|| cause!(self.authority_names)))
            .or_else(|| self.policy_name_original.failure().or_else(|| self.policy_witness_original.failure()).or_else(|| cause!(self.policy_names)))
            .or_else(|| cause!(self.body))
            .or_else(|| cause!(self.body_encoding))
            .or_else(|| cause!(self.checksum))
            .or_else(|| cause!(self.head_encoding))
            .or_else(|| cause!(self.transaction))
            .or_else(|| self.crossing.failure())
            .or_else(|| cause!(self.append))
            .or_else(|| cause!(self.readback))
            .or_else(|| cause!(self.production))
            .or_else(|| self.posts.failure())
    }
}

pub(super) type RootCurrentOpenReadbackV1 = HistoryPairReadbackV1<ROOT_RECORD_BYTES>;

#[derive(Default)]
pub(super) struct RootCurrentOpenCrossingV1 {
    purpose_current: Option<Result<(), JournalError>>,
    root_history: crate::policy_compiler::create_q04::RootInertHistoryScanV1,
    root_history_result: Option<Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1>>,
    transition: Option<Result<(), JournalError>>,
    authority_location_original: ProtectedJournalCurrentnessOriginalsV1,
    policy_location_original: ProtectedJournalCurrentnessOriginalsV1,
    authority: Option<Result<(), JournalError>>,
    policy: Option<Result<(), JournalError>>,
    authority_name_original: ProtectedJournalCurrentnessOriginalsV1,
    authority_witness_original: WitnessOriginal,
    policy_name_original: ProtectedJournalCurrentnessOriginalsV1,
    policy_witness_original: WitnessOriginal,
    authority_names: Option<Result<ProtectedJournalNamesV1, JournalError>>,
    policy_names: Option<Result<ProtectedJournalNamesV1, JournalError>>,
    cut_binding: Option<Result<(), JournalError>>,
    endpoint: Option<Result<(), aos_sandbox_linux::Error>>,
    endpoint_binding: Option<Result<(), NormalRootStartupErrorV1>>,
    peer_original: Option<Result<crate::normal_root::RootHistoryPeerPostV1, NormalRootStartupErrorV1>>,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    clock_original: RetainedKernelPairedClockAttemptV1,
    clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    completion: Option<Result<(), JournalError>>,
}

impl RootCurrentOpenCrossingV1 {
    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        macro_rules! cause {
            ($slot:expr) => { $slot.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn StdError + 'static)) };
        }
        cause!(self.transition)
            .or_else(|| cause!(self.purpose_current))
            .or_else(|| self.root_history.failure())
            .or_else(|| cause!(self.root_history_result))
            .or_else(|| self.authority_location_original.failure().or_else(|| cause!(self.authority)))
            .or_else(|| self.policy_location_original.failure().or_else(|| cause!(self.policy)))
            .or_else(|| self.authority_name_original.failure().or_else(|| self.authority_witness_original.failure()).or_else(|| cause!(self.authority_names)))
            .or_else(|| self.policy_name_original.failure().or_else(|| self.policy_witness_original.failure()).or_else(|| cause!(self.policy_names)))
            .or_else(|| cause!(self.cut_binding))
            .or_else(|| cause!(self.endpoint_binding))
            .or_else(|| cause!(self.endpoint))
            .or_else(|| self.peer_original.as_ref().and_then(|result| match result {
                Ok(original) => original.failure(), Err(cause) => Some(cause as _),
            }))
            .or_else(|| cause!(self.peer))
            .or_else(|| self.clock_original.failure()).or_else(|| cause!(self.clock))
            .or_else(|| cause!(self.completion))
    }
}

/// Borrows one live Root cut for its purpose-fixed history append.
///
/// Only the actual retained producer constructs this loan. Decoded history and
/// public journal access cannot create it or select a different transaction.
pub(crate) struct RootCurrentOpenAppendLoanV1<'cut, 'listener, 'startup> {
    flight: &'cut mut RootPolicyAcceptedFlightV1<'listener, 'startup>,
    original: &'cut UnixStream,
    policy: &'cut Journal,
    body: RootOpenBodyDataV1,
    transaction: &'cut JournalTransaction,
    clock: RawPairedClockSample,
    started: Instant,
    crossing: &'cut mut RootCurrentOpenCrossingV1,
    purpose: RootCurrentHistoryPurposeV1<'cut>,
}

#[derive(Clone, Copy)]
pub(super) enum RootCurrentHistoryPurposeV1<'cut> {
    Open,
    UseAuthorized {
        root: &'cut RootCurrentOpenStateV1,
        readonly: &'cut super::controller_readonly::RootCurrentControllerReadonlyStateV1,
        source: &'cut super::source_current::RootCurrentSourceExchangeStateV1,
        cache: &'cut super::cache_current::RootCurrentCacheProofStateV1,
    },
    UseAdmitted {
        root: &'cut RootCurrentOpenStateV1,
        authorization: &'cut super::use_authorized::RootCurrentUseAuthorizedStateV1,
        reserved: &'cut super::use_reserved::RootCurrentUseReservedStateV1,
        source: &'cut super::source_current::RootCurrentSourceExchangeStateV1,
        cache: &'cut super::cache_current::RootCurrentCacheProofStateV1,
    },
    Closed {
        root: &'cut RootCurrentOpenStateV1,
        outcome: &'cut super::outcome::RootCurrentOutcomeStateV1,
        reserved: &'cut super::use_reserved::RootCurrentUseReservedStateV1,
        source: &'cut super::source_current::RootCurrentSourceExchangeStateV1,
        read: &'cut super::closed::read::RootCurrentClosedReadV1,
    },
    Outcome {
        root: &'cut RootCurrentOpenStateV1,
        signed: &'cut super::signed_bound::RootCurrentSignedBoundStateV1,
        reserved: &'cut super::use_reserved::RootCurrentUseReservedStateV1,
        source: &'cut super::source_current::RootCurrentSourceExchangeStateV1,
        read: &'cut super::outcome::read::RootCurrentOutcomeReadV1,
    },
    SignedBound {
        admitted: &'cut super::use_admitted::RootCurrentUseAdmittedStateV1,
        reserved: &'cut super::use_reserved::RootCurrentUseReservedStateV1,
        source: &'cut super::source_current::RootCurrentSourceExchangeStateV1,
        signed: &'cut super::signed_bound::input::RootSignedInputV1,
    },
}

impl RootCurrentHistoryPurposeV1<'_> {
    fn require_prepared(&self) -> Result<(), Error> {
        match self {
            Self::Open => Ok(()),
            Self::Closed { outcome, reserved, read, .. } => {
                outcome.require_complete_v1()?; reserved.require_complete_v1()?; read.require_complete_v1()
            },
            Self::Outcome { signed, reserved, read, .. } => {
                signed.require_complete_v1()?;
                reserved.require_complete_v1()?;
                read.require_complete_v1()
            }
            Self::SignedBound { admitted, reserved, signed, .. } => {
                admitted.require_complete_v1()?;
                reserved.require_complete_v1()?;
                signed.require_complete_v1()
            }
            Self::UseAdmitted { root, authorization, reserved, source, cache } => {
                reserved.require_complete_v1()?;
                source.require_use_complete_for_v1(root, authorization, reserved)?;
                cache.require_use_complete_for_v1(root, authorization, reserved)
            }
            Self::UseAuthorized { readonly, source, cache, .. } => {
                readonly.require_complete_v1()?;
                source.require_complete_v1()?;
                cache.require_complete_v1()
            }
        }
    }

    fn require_current(&self, authority: &Journal, policy: &Journal) -> Result<(), JournalError> {
        match self {
            Self::Open => Ok(()),
            Self::Closed { outcome, read, .. } => {
                read.require_complete_v1().map_err(|_| JournalError::ProtectedBoundary)?;
                outcome.readback_current_v1(authority, policy).map(|_| ())
            },
            Self::Outcome { signed, read, .. } => {
                read.require_complete_v1().map_err(|_| JournalError::ProtectedBoundary)?;
                signed.readback_current_v1(authority, policy).map(|_| ())
            }
            Self::SignedBound { admitted, signed, .. } => {
                signed.require_complete_v1().map_err(|_| JournalError::ProtectedBoundary)?;
                admitted.readback_current_v1(authority, policy).map(|_| ())
            }
            Self::UseAdmitted { root, authorization, reserved, source, cache } => {
                reserved.require_complete_v1().map_err(|_| JournalError::ProtectedBoundary)?;
                source.require_use_complete_for_v1(root, authorization, reserved).map_err(|_| JournalError::ProtectedBoundary)?;
                cache.require_use_complete_for_v1(root, authorization, reserved).map_err(|_| JournalError::ProtectedBoundary)?;
                authorization.readback_current_v1(authority, policy).map(|_| ())
            }
            Self::UseAuthorized { root, readonly, source, cache } => {
                readonly.require_complete_v1().map_err(|_| JournalError::ProtectedBoundary)?;
                source.require_complete_v1().map_err(|_| JournalError::ProtectedBoundary)?;
                cache.require_complete_v1().map_err(|_| JournalError::ProtectedBoundary)?;
                root.readback_current(authority, policy).map(|_| ())
            }
        }
    }

    fn require_live_at(&self, current: RawPairedClockSample) -> Result<(), JournalError> {
        match self {
            Self::Open => Ok(()),
            Self::Closed { root, outcome, reserved, source, read } => read.require_live_at_v1(root, reserved, source, outcome, current),
            Self::Outcome { root, reserved, source, read, .. } => read.require_live_at_v1(root, reserved, source, current),
            Self::UseAdmitted { reserved, source, .. } | Self::SignedBound { reserved, source, .. } => {
                reserved.completed_readonly_v1().map_err(|_| JournalError::ProtectedBoundary)?.require_live_at_v1(current)?;
                if current.boottime_nanoseconds() >= source.original_cutoff_v1().map_err(|_| JournalError::ProtectedBoundary)? {
                    return Err(JournalError::ProtectedBoundary);
                }
                Ok(())
            }
            Self::UseAuthorized { readonly, source, .. } => {
                readonly.require_live_at_v1(current)?;
                if current.boottime_nanoseconds() >= source.original_cutoff_v1()
                    .map_err(|_| JournalError::ProtectedBoundary)?
                { return Err(JournalError::ProtectedBoundary); }
                Ok(())
            }
        }
    }

    pub(super) fn expected_authority_next(&self, body: RootOpenBodyDataV1) -> Result<u64, JournalError> {
        match self {
            Self::Open => Ok(body.authority_next),
            Self::Closed { .. } => body.authority_next.checked_add(20)
                .ok_or(JournalError::SequenceExhausted),
            Self::Outcome { .. } => body.authority_next.checked_add(16)
                .ok_or(JournalError::SequenceExhausted),
            Self::SignedBound { .. } => body.authority_next.checked_add(12)
                .ok_or(JournalError::SequenceExhausted),
            Self::UseAdmitted { .. } => body.authority_next.checked_add(8)
                .ok_or(JournalError::SequenceExhausted),
            Self::UseAuthorized { .. } => body.authority_next.checked_add(4)
                .ok_or(JournalError::SequenceExhausted),
        }
    }
}

impl<'cut, 'listener, 'startup> RootCurrentOpenAppendLoanV1<'cut, 'listener, 'startup> {
    pub(super) fn for_history_purpose_v1(
        flight: &'cut mut RootPolicyAcceptedFlightV1<'listener, 'startup>,
        original: &'cut UnixStream, policy: &'cut Journal,
        root: &'cut RootCurrentOpenStateV1, purpose: RootCurrentHistoryPurposeV1<'cut>,
        transaction: &'cut JournalTransaction, crossing: &'cut mut RootCurrentOpenCrossingV1,
    ) -> Result<Self, Error> {
        purpose.require_prepared()?;
        crossing.peer_original = Some(flight.arm_history_peer_post_v1());
        positive(&crossing.peer_original).map_err(|_| Error::Original)?
            .require_armed_v1().map_err(|_| Error::Original)?;
        let body = root.completed_body()?;
        let clock = *positive(&root.clock).map_err(|_| Error::Original)?;
        let started = root.started.ok_or(Error::Original)?;
        Ok(Self { flight, original, policy, body, transaction, clock, started, crossing, purpose })
    }

}

impl RootCurrentOpenAppendLoanV1<'_, '_, '_> {
    /// Joins the exact prepared members to the same preappend writer cut.
    ///
    /// # Errors
    /// Rejects reentry, substituted members or changed original history/NEXT.
    pub(crate) fn require_transition(
        &mut self,
        journal: &Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        if self.crossing.transition.is_some() { return Err(JournalError::ProtectedBoundary); }
        self.crossing.transition = Some((|| {
            if transaction != self.transaction
                || matches!(self.purpose, RootCurrentHistoryPurposeV1::Open)
                    && journal.records(RecordNamespace::CreateStorageHistory).next().is_some()
                || journal.snapshot_sequence() != self.purpose.expected_authority_next(self.body)?
                || self.policy.snapshot_sequence() != self.body.policy_next
            { return Err(JournalError::ProtectedBoundary); }
            self.purpose.require_current(journal, self.policy)
        })());
        positive(&self.crossing.transition)?;
        self.crossing.root_history_result = Some(journal.observe_inert_root_q04_predecessor_v1(
            &mut self.crossing.root_history,
        ));
        self.crossing.root_history.require_complete()
    }

    /// Compares the exact earlier typed history check at the ordinary boundary.
    ///
    /// The same native commit engine invokes this only after `require_transition`
    /// checked its actual writer state. It cannot select a transaction or grant
    /// Use; final crossing still rejoins the actual Root/peer/cutoff.
    pub(crate) fn require_prechecked_root_history_successor_v1(&self,
        transaction: &JournalTransaction) -> Result<(), JournalError>
    {
        positive(&self.crossing.transition)?;
        if transaction != self.transaction { return Err(JournalError::ProtectedBoundary); }
        self.crossing.root_history.require_complete()
    }

    /// Rechecks the held writers, accepted peer and immutable original cutoff.
    ///
    /// # Errors
    /// Retains each independent native result and rejects a changed live cut.
    pub(crate) fn final_crossing(
        &mut self,
        journal: &Journal,
    ) -> Result<(), JournalError> {
        if self.crossing.completion.is_some() { return Err(JournalError::ProtectedBoundary); }
        self.crossing.purpose_current = Some(self.purpose.require_current(journal, self.policy));
        self.crossing.authority = Some(require_authority_retaining(journal, &mut self.crossing.authority_location_original));
        self.crossing.policy = Some(require_policy_retaining(self.policy, &mut self.crossing.policy_location_original));
        self.crossing.authority_names = Some(journal.observe_held_physical_names_retaining_v1(&mut self.crossing.authority_name_original, &mut self.crossing.authority_witness_original));
        self.crossing.policy_names = Some(self.policy.observe_held_physical_names_retaining_v1(&mut self.crossing.policy_name_original, &mut self.crossing.policy_witness_original));
        // Park the exact writer-cut comparison before later independent peer
        // and clock samples; their errors cannot replace an earlier mismatch.
        self.crossing.cut_binding = Some((|| {
            if *positive(&self.crossing.authority_names)? != self.body.authority_names
                || *positive(&self.crossing.policy_names)? != self.body.policy_names
                || journal.snapshot_sequence() != self.purpose.expected_authority_next(self.body)?
                || self.policy.snapshot_sequence() != self.body.policy_next
            {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        self.crossing.endpoint_binding = Some(match self.flight.current_cut_native() {
            Ok(native) => {
                self.crossing.endpoint = Some(native.require_same_endpoint_v1(self.original.as_fd()));
                Ok(())
            }
            Err(error) => Err(error),
        });
        self.crossing.peer = Some(match self.crossing.peer_original.as_mut() {
            Some(Ok(original)) => self.flight.observe_history_peer_post_once_v1(original),
            _ => Err(NormalRootStartupErrorV1::Service),
        });
        // Sample after all slow original/native/PID1 checks; neither origin
        // nor cutoff is renewed. Ordinary Storage None path executes no IO here.
        self.crossing.clock = Some(self.crossing.clock_original.observe_once(None));
        self.crossing.completion = Some((|| {
            positive(&self.crossing.transition)?;
            positive(&self.crossing.purpose_current)?;
            self.crossing.root_history.require_complete()?;
            positive(&self.crossing.authority)?;
            positive(&self.crossing.policy)?;
            positive(&self.crossing.cut_binding)?;
            positive(&self.crossing.endpoint_binding)?;
            positive(&self.crossing.endpoint)?;
            positive(&self.crossing.peer)?;
            let current = *positive(&self.crossing.clock)?;
            require_original_clock(self.clock, current, self.body.cutoff, self.started)?;
            self.purpose.require_live_at(current)
        })());
        positive(&self.crossing.completion).map(|_| ())
    }
}

fn make_transaction(
    lane: [u8; 16],
    checksum: [u8; 32],
    record: &[u8; ROOT_RECORD_BYTES],
    head: &[u8; HEAD_BYTES],
) -> Result<JournalTransaction, JournalError> {
    let key = KeyV1::new(lane, OwnerV1::Root, 1).map_err(|_| JournalError::ProtectedBoundary)?;
    let phase = PhaseV1::new(OwnerV1::Root, 1).map_err(|_| JournalError::ProtectedBoundary)?;
    let envelope = RecordEnvelopeV1::decode(record, key, phase)
        .map_err(|_| JournalError::ProtectedBoundary)?;
    if envelope.checksum() != checksum { return Err(JournalError::ProtectedBoundary); }
    prepare_history_pair_v1(key, phase, record, head)
}

fn readback(
    authority: &Journal,
    policy: &Journal,
    body: RootOpenBodyDataV1,
    transaction: &JournalTransaction,
    record: &[u8; ROOT_RECORD_BYTES],
    head: &[u8; HEAD_BYTES],
    committed: &CommitResult,
) -> Result<RootCurrentOpenReadbackV1, JournalError> {
    let observed = readback_history_pair_v1(
        authority, transaction, record, head, body.authority_next, committed,
    )?;
    if policy.snapshot_sequence() != body.policy_next {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(observed)
}

pub(super) fn require_authority(journal: &Journal) -> Result<(), JournalError> {
    journal.require_protected_location(Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL, 0, policy_authority_journal_limits())
}

pub(super) fn require_policy(journal: &Journal) -> Result<(), JournalError> {
    journal.require_protected_location(Path::new(PROTECTED_POLICY_ROOT),
        POLICY_STATE_JOURNAL, 0, policy_state_journal_limits())
}

fn require_authority_retaining(journal: &Journal, original: &mut ProtectedJournalCurrentnessOriginalsV1)
    -> Result<(), JournalError> {
    journal.require_protected_location_retaining(Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL, 0, policy_authority_journal_limits(), original)
}

fn require_policy_retaining(journal: &Journal, original: &mut ProtectedJournalCurrentnessOriginalsV1)
    -> Result<(), JournalError> {
    journal.require_protected_location_retaining(Path::new(PROTECTED_POLICY_ROOT),
        POLICY_STATE_JOURNAL, 0, policy_state_journal_limits(), original)
}

/// Pays all actual fresh native destinations of one complete fixed pair stage.
/// Initial RootOpen reaches ten; later pair producers reach twelve across the
/// crossing and two independently owed posts. Witnesses add no descriptors.
pub(super) fn history_native_receiving_demand_v1() -> Result<aos_sandbox_core::ResourceVector, JournalError> {
    let one = one_history_names_demand_v1()?;
    one.checked_add(one).and_then(|value| value.checked_add(one)).map_err(|_| JournalError::JournalTooLarge)
}

fn one_history_names_demand_v1() -> Result<aos_sandbox_core::ResourceVector, JournalError> {
    use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
    let invalid = || JournalError::JournalTooLarge;
    let mut demand = ResourceVector::ZERO;
    for name in [POLICY_AUTHORITY_JOURNAL, POLICY_STATE_JOURNAL] {
        let one = ProtectedJournalCurrentnessOriginalsV1::fixed_demand_v1(Path::new(PROTECTED_POLICY_ROOT), name)?;
        for _ in 0..2 { demand = demand.checked_add(one).map_err(|_| invalid())?; }
    }
    let witness = WitnessOriginal::receiving_footprint_v1().ok_or_else(invalid)?;
    let bytes = witness.memory_bytes.checked_mul(2).ok_or_else(invalid)?;
    demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
        u64::try_from(bytes).map_err(|_| invalid())?)).map_err(|_| invalid())
}

fn require_original_clock(
    original: RawPairedClockSample,
    current: RawPairedClockSample,
    cutoff: u64,
    started: Instant,
) -> Result<(), JournalError> {
    original.validate_later_sample(current).map_err(|_| JournalError::ProtectedBoundary)?;
    if current.boottime_nanoseconds() >= cutoff || started.elapsed() >= MAXIMUM_ROOT_FLIGHT {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn positive<T, E>(result: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    result.as_ref().and_then(|result| result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}


/// Keeps the same independent Root/writer/peer/clock posts for fixed history.
#[derive(Default)]
pub(super) struct RootCurrentHistoryPostsV1 {
    reentered: bool,
    peer_original: Option<Result<crate::normal_root::RootHistoryPeerPostV1, NormalRootStartupErrorV1>>,
    authority_name_original: ProtectedJournalCurrentnessOriginalsV1,
    authority_witness_original: WitnessOriginal,
    policy_name_original: ProtectedJournalCurrentnessOriginalsV1,
    policy_witness_original: WitnessOriginal,
    authority_location_original: ProtectedJournalCurrentnessOriginalsV1,
    policy_location_original: ProtectedJournalCurrentnessOriginalsV1,
    authority_names_post: Option<Result<ProtectedJournalNamesV1, JournalError>>,
    policy_names_post: Option<Result<ProtectedJournalNamesV1, JournalError>>,
    names_binding: Option<Result<(), JournalError>>,
    authority_post: Option<Result<(), JournalError>>,
    policy_post: Option<Result<(), JournalError>>,
    peer_post: Option<Result<(), NormalRootStartupErrorV1>>,
    clock_original: RetainedKernelPairedClockAttemptV1,
    clock_post: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    final_clock: Option<Result<(), JournalError>>,
}

impl RootCurrentHistoryPostsV1 {
    pub(super) fn arm_once(&mut self, flight: &RootPolicyAcceptedFlightV1<'_, '_>) -> Result<(), Error> {
        if self.peer_original.is_some() || self.peer_post.is_some() {
            self.reentered = true;
            return Err(Error::Original);
        }
        self.peer_original = Some(flight.arm_history_peer_post_v1());
        positive(&self.peer_original).map_err(|_| Error::Original)?
            .require_armed_v1().map_err(|_| Error::Original)
    }

    pub(super) fn additional_owed_demand_v1() -> Result<aos_sandbox_core::ResourceVector, JournalError> {
        crate::normal_root::RootHistoryPeerPostV1::additional_resident_demand_v1().map_err(|_| JournalError::JournalTooLarge)
    }

    pub(super) fn additional_receiving_demand_v1() -> Result<aos_sandbox_core::ResourceVector, JournalError> {
        let owed = Self::additional_owed_demand_v1()?;
        let names = one_history_names_demand_v1()?;
        let clock = history_clock_receiving_demand_v1()?;
        owed.checked_add(names).and_then(|value| value.checked_add(clock))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(super) fn observe_once(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
        body: Option<&RootOpenBodyDataV1>,
        origin_clock: Option<RawPairedClockSample>,
        started: Option<Instant>,
    ) {
        if !matches!(self.peer_original, Some(Ok(_))) || self.peer_post.is_some() {
            self.reentered = true;
            self.peer_post.get_or_insert(Err(NormalRootStartupErrorV1::Service));
            return;
        }
        match writers.authority_and_policy() {
            Ok((authority, policy)) => {
                self.authority_names_post = Some(authority.observe_held_physical_names_retaining_v1(&mut self.authority_name_original, &mut self.authority_witness_original));
                self.policy_names_post = Some(policy.observe_held_physical_names_retaining_v1(&mut self.policy_name_original, &mut self.policy_witness_original));
                self.authority_post = Some(require_authority_retaining(authority, &mut self.authority_location_original));
                self.policy_post = Some(require_policy_retaining(policy, &mut self.policy_location_original));
            }
            Err(error) => {
                self.authority_post = Some(Err(error));
                self.policy_post = Some(Err(JournalError::ProtectedBoundary));
            }
        }
        self.names_binding = Some((|| {
            let body = body.ok_or(JournalError::ProtectedBoundary)?;
            if *positive(&self.authority_names_post)? != body.authority_names
                || *positive(&self.policy_names_post)? != body.policy_names
            {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        self.peer_post = Some(match self.peer_original.as_mut() {
            Some(Ok(original)) => flight.observe_history_peer_post_once_v1(original),
            _ => Err(NormalRootStartupErrorV1::Service),
        });
        self.clock_post = Some(self.clock_original.observe_once(None));
        self.final_clock = Some((|| {
            let original = origin_clock.ok_or(JournalError::ProtectedBoundary)?;
            let current = *positive(&self.clock_post)?;
            let body = body.ok_or(JournalError::ProtectedBoundary)?;
            require_original_clock(original, current, body.cutoff,
                started.ok_or(JournalError::ProtectedBoundary)?)
        })());
    }

    pub(super) fn require_complete(&self) -> Result<(), JournalError> {
        if self.reentered { return Err(JournalError::ProtectedBoundary); }
        positive(&self.authority_names_post)?;
        positive(&self.policy_names_post)?;
        positive(&self.names_binding)?;
        positive(&self.authority_post)?;
        positive(&self.policy_post)?;
        positive(&self.peer_post)?;
        positive(&self.final_clock).map(|_| ())
    }

    pub(super) fn authority_names_v1(&self) -> Result<ProtectedJournalNamesV1, JournalError> {
        self.require_complete()?;
        positive(&self.authority_names_post).copied()
    }

    pub(super) fn sample(&self) -> Result<RawPairedClockSample, JournalError> {
        positive(&self.clock_post).copied()
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        macro_rules! cause {
            ($slot:expr) => { $slot.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn StdError + 'static)) };
        }
        self.peer_original.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &(dyn StdError + 'static))
            .or_else(|| self.authority_name_original.failure()).or_else(|| self.authority_witness_original.failure()).or_else(|| cause!(self.authority_names_post)).or_else(|| self.policy_name_original.failure().or_else(|| self.policy_witness_original.failure()).or_else(|| cause!(self.policy_names_post)))
            .or_else(|| self.authority_location_original.failure().or_else(|| cause!(self.authority_post))).or_else(|| self.policy_location_original.failure().or_else(|| cause!(self.policy_post)))
            .or_else(|| cause!(self.names_binding))
            .or_else(|| self.peer_original.as_ref().and_then(|result| result.as_ref().ok()).and_then(|original| original.failure()))
            .or_else(|| cause!(self.peer_post))
            .or_else(|| self.clock_original.failure()).or_else(|| cause!(self.clock_post)).or_else(|| cause!(self.final_clock))
            .or_else(|| self.reentered.then_some(&ROOT_HISTORY_POST_REENTRY as &(dyn StdError + 'static)))
    }
}

const ROOT_HISTORY_POST_REENTRY: Error = Error::Original;

// The same existing retained paired-clock engine owns every reached boot-id
// file/error. A positive primitive closes before its next step; a failed pair
// stays resident beside the separately paid independent post.
pub(super) fn history_clock_receiving_demand_v1() -> Result<aos_sandbox_core::ResourceVector, JournalError> {
    super::ready::subject::RootCurrentChunkReceivingV1::additional_clock_demand_v1()
}
