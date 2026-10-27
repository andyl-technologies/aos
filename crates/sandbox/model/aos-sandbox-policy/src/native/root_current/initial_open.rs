//! Produces the initial RootOpen from its genuine current pair and first clock.
//!
//! The fixed initial purpose has no caller-selectable phase. The actual writer
//! producer remains borrowed through Open and Ready; issuer credentials are
//! captured only afterward. The append context borrows the same first clock,
//! held writer pair and accepted native peer after slow native preparation.

use std::error::Error;
use std::io;
use std::os::fd::BorrowedFd;

use aos_sandbox_broker::canonical_journal::CommitResult;
use aos_sandbox_broker::receiving::{
    RootAcceptedHistoryBorrowerV1, RootObservationErrorV1, RootOpenClockClosedV1,
    RootOpenClockOriginalV1, RootOpenPhysicalBorrowerV1,
};
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HEAD_BYTES, RECORD_OVERHEAD_BYTES, HistoryErrorV1, KeyV1, LatestHeadV1,
    OwnerV1, PhaseV1, RecordCoordinatesV1, RecordEnvelopeV1,
    HistoryPairPreparationErrorV1, prepare_history_pair_v1,
    readback::{HistoryPairReadbackBytesDataV1, HistoryPairReadbackDataV1},
    root_open::{ROOT_OPEN_BODY_BYTES_V1, RootCurrentOpenIdentityDataV1, RootOpenBodyDataV1},
    transport::OpenQueryV1,
};
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use crate::native::journal::{RootPolicyJournalV1, names::{
    RootFixedNameRecipeV1, RootFixedNameRoleV1, RootPolicyNameObservationOriginalV1,
}};
use crate::native::target::RootPolicyTargetOriginalV1;
use crate::native::PolicyNativeJournalErrorV1;

use super::writers::RootCurrentWritersOriginalV1;
use super::history_post::RootCurrentHistoryPostOriginalV1;
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use aos_sandbox_broker::kernel_clock::{KernelPairedClockErrorV1, RetainedKernelPairedClockAttemptV1};
use crate::q04_data::{RootInertHistoryScanV1, PolicyQ04DataErrorV1};

pub(super) const ROOT_RECORD_BYTES: usize = RECORD_OVERHEAD_BYTES + ROOT_OPEN_BODY_BYTES_V1;

type Readback = HistoryPairReadbackDataV1<ROOT_RECORD_BYTES>;

/// Retains one concrete initial Open preparation or native crossing refusal.
///
/// Its actual underlying native, clock and observation originals remain owned
/// beside this diagnostic. An error value supplies no successful role receipt.
#[derive(Debug, thiserror::Error)]
pub enum RootInitialOpenErrorV1 {
    /// Reports an incomplete, substituted or changed protected boundary.
    #[error("protected journal storage boundary is invalid")]
    Boundary,
    /// Reports checked exhaustion of the original history sequence or cutoff.
    #[error("journal sequence is exhausted")]
    SequenceExhausted,
    /// Retains the actual native journal or receiving refusal.
    #[error(transparent)]
    Native(#[from] PolicyNativeJournalErrorV1),
    /// Retains a same-original Root service or peer refusal.
    #[error(transparent)]
    Root(#[from] RootObservationErrorV1),
    /// Reports refusal while the saved clock retains its concrete cause.
    #[error(transparent)]
    Clock(#[from] RootOpenClockClosedV1),
    /// Retains the original kernel nonce failure.
    #[error(transparent)]
    Nonce(#[from] io::Error),
    /// Retains the actual native metadata refusal at a later history readback.
    #[error(transparent)]
    Metadata(io::Error),
    /// Retains canonical history body, record or head format refusal.
    #[error(transparent)]
    Format(#[from] HistoryErrorV1),
    /// Retains canonical record/head transaction preparation refusal.
    #[error(transparent)]
    Pair(#[from] HistoryPairPreparationErrorV1),
    /// Retains the actual accepted endpoint comparison failure.
    #[error(transparent)]
    Endpoint(#[from] aos_linux_descriptors::Error),
    /// Retains the original nonissuing predecessor history refusal.
    #[error(transparent)]
    History(#[from] PolicyQ04DataErrorV1),
}

type E = RootInitialOpenErrorV1;

/// Retains the initial producer's real first-clock and prepared record custody.
///
/// Constructors and transitions remain private to the native Current programme.
/// Neither decoded RootOpen DATA nor an ordinary journal can construct it.
pub(super) struct RootInitialOpenPreparedOriginalV1 {
    identity: Option<Result<RootCurrentOpenIdentityDataV1, RootObservationErrorV1>>,
    identity_service: Option<Result<(), RootObservationErrorV1>>,
    clock: RootOpenClockOriginalV1,
    clock_returned: Option<Result<aos_sandbox_model::RawPairedClockSample, RootOpenClockClosedV1>>,
    nonce: Option<io::Result<[u8; 16]>>,
    authority_original: RootPolicyNameObservationOriginalV1,
    policy_original: RootPolicyNameObservationOriginalV1,
    authority_names: Option<Result<ProtectedJournalNamesV1, E>>,
    policy_names: Option<Result<ProtectedJournalNamesV1, E>>,
    body: Option<Result<RootOpenBodyDataV1, E>>,
    body_encoding: Option<Result<[u8; ROOT_OPEN_BODY_BYTES_V1], HistoryErrorV1>>,
    encoded_body: [u8; ROOT_OPEN_BODY_BYTES_V1],
    record: [u8; ROOT_RECORD_BYTES],
    head: [u8; HEAD_BYTES],
    head_encoding: Option<Result<[u8; HEAD_BYTES], HistoryErrorV1>>,
    checksum: Option<Result<[u8; 32], HistoryErrorV1>>,
    transaction: Option<Result<JournalTransaction, E>>,
    preparation: Option<Result<(), E>>,
    committed: Option<Result<CommitResult, PolicyNativeJournalErrorV1>>,
    readback: Option<Result<Readback, E>>,
}

impl RootInitialOpenPreparedOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            identity: None,
            identity_service: None,
            clock: RootOpenClockOriginalV1::new(),
            clock_returned: None,
            nonce: None,
            authority_original: RootPolicyNameObservationOriginalV1::new(),
            policy_original: RootPolicyNameObservationOriginalV1::new(),
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
            preparation: None,
            committed: None,
            readback: None,
        }
    }

    // The enclosing actual native Open programme must first finish its real
    // RootOpen provision/service-before and arm its independently owed post.
    // This method is not exported as a receiving or append authority factory.
    pub(super) fn prepare_once_v1(
        &mut self,
        writers: &mut RootCurrentWritersOriginalV1,
        accepted: &RootAcceptedHistoryBorrowerV1<'_, '_>,
        open: OpenQueryV1,
    ) -> Result<(), E> {
        if self.preparation.is_some() {
            return Err(E::Boundary);
        }
        self.preparation = Some(self.prepare_inner_v1(writers, accepted, open));
        positive(&self.preparation).map(|_| ())
    }

    fn prepare_inner_v1(
        &mut self,
        writers: &mut RootCurrentWritersOriginalV1,
        accepted: &RootAcceptedHistoryBorrowerV1<'_, '_>,
        open: OpenQueryV1,
    ) -> Result<(), E> {
        // This is the old SECOND service recheck. The first belongs to the
        // real RootOpen provision before the independent post was armed.
        let startup = accepted.borrow_selected_startup_v1()?;
        self.identity_service = Some(startup.recheck_v1());
        positive(&self.identity_service)?;
        self.identity = Some(accepted.root_open_identity_data_v1());
        positive(&self.identity)?;

        self.clock_returned = Some(self.clock.start_once_v1());
        positive(&self.clock_returned)?;
        self.nonce = Some(aos_sandbox_broker::root_nonce::fresh_root_nonce());
        positive(&self.nonce)?;

        let pair = writers.opened_pair_v1()?;
        let (authority, policy) = pair.authority_and_policy_v1()?;
        self.authority_names = Some(observe_authority_names_v1(
            authority,
            &mut self.authority_original,
        ));
        self.policy_names = Some(policy.observe_held_physical_names_once_v1(
            &mut self.policy_original,
        ).map_err(|()| E::Boundary));

        self.body = Some(self.make_body_v1(authority, policy, open));
        let body = *positive(&self.body)?;
        self.body_encoding = Some(body.encode());
        self.encoded_body = *positive(&self.body_encoding)?;
        let key = KeyV1::new(open.lane, OwnerV1::Root, 1)?;
        let phase = PhaseV1::new(OwnerV1::Root, 1)?;
        self.checksum = Some(RecordEnvelopeV1::encode_into(
            RecordCoordinatesV1 {
                key,
                phase,
                predecessor: [0; 32],
                correlation: open.seed,
            },
            &self.encoded_body,
            &mut self.record,
        ));
        let checksum = *positive(&self.checksum)?;
        self.head_encoding = Some(LatestHeadV1::new(1, checksum).map(|head| head.encode()));
        self.head = *positive(&self.head_encoding)?;
        self.transaction = Some(make_transaction_v1(
            open.lane,
            checksum,
            &self.record,
            &self.head,
        ));
        positive(&self.transaction).map(|_| ())
    }

    fn make_body_v1(
        &self,
        authority: &RootPolicyJournalV1,
        policy: &RootPolicyTargetOriginalV1,
        open: OpenQueryV1,
    ) -> Result<RootOpenBodyDataV1, E> {
        let identity = positive(&self.identity)?;
        let clock = positive(&self.clock_returned)?;
        Ok(RootOpenBodyDataV1 {
            open,
            root_nonce: *positive(&self.nonce)?,
            boot: clock.host_boot_id(),
            started: clock.boottime_nanoseconds(),
            cutoff: clock.boottime_nanoseconds().checked_add(65_000_000_000)
                .ok_or(E::SequenceExhausted)?,
            authority_names: *positive(&self.authority_names)?,
            policy_names: *positive(&self.policy_names)?,
            authority_next: authority.snapshot_sequence(),
            policy_next: policy.current_snapshot_sequence_data_v1(),
            root_profile: identity.profile,
            root_recipient: identity.recipient,
            root_producer: identity.producer,
            root_pid: identity.root_pid,
            controller_pid: identity.controller_pid,
            controller_uid: identity.controller_uid,
            controller_gid: identity.controller_gid,
        })
    }

    pub(super) fn clock_original_v1(&self) -> &RootOpenClockOriginalV1 {
        &self.clock
    }

    pub(super) fn body_v1(&self) -> Result<RootOpenBodyDataV1, E> {
        positive(&self.preparation)?;
        positive(&self.body).copied()
    }

    pub(super) fn committed_record_v1(&self) -> Result<&[u8; ROOT_RECORD_BYTES], E> {
        let observed = positive(&self.readback)?;
        positive(&self.committed)?;
        let body = self.body_v1()?;
        if observed.record != self.record || observed.head != self.head
            || body.authority_next.checked_add(4) != Some(observed.next)
        {
            return Err(E::Boundary);
        }
        Ok(&self.record)
    }

    pub(super) fn readback_current_v1(
        &self,
        authority: &RootPolicyJournalV1,
        policy: &RootPolicyTargetOriginalV1,
    ) -> Result<Readback, E> {
        self.committed_record_v1()?;
        self.readback_v1(authority, policy, positive(&self.committed)?)
    }

    pub(super) fn transaction_v1(&self) -> Result<&JournalTransaction, E> {
        positive(&self.preparation)?;
        positive(&self.transaction)
    }

    pub(super) fn readback_v1(
        &self,
        authority: &RootPolicyJournalV1,
        policy: &RootPolicyTargetOriginalV1,
        committed: &CommitResult,
    ) -> Result<Readback, E> {
        let body = self.body_v1()?;
        let transaction = self.transaction_v1()?;
        let record = self.record.as_slice();
        let head = &self.head;
        let before_next = body.authority_next;
        let journal = authority;
        let readback: Result<HistoryPairReadbackBytesDataV1<'_>, E> =
            aos_sandbox_protocol::readback_create_storage_history_pair_bytes_data_v1! {
                journal: journal,
                transaction: transaction,
                record: record,
                head: head,
                before_next: before_next,
                committed: committed,
                namespace: RecordNamespace::CreateStorageHistory,
                boundary: E::Boundary,
                result: HistoryPairReadbackBytesDataV1,
            };
        let bytes = readback?;
        let record = bytes.record.try_into().map_err(|_| E::Boundary)?;
        let observed = Readback { record, head: bytes.head, next: bytes.next };
        if policy.current_snapshot_sequence_data_v1() != body.policy_next {
            return Err(E::Boundary);
        }
        Ok(observed)
    }

    // Only the enclosing initial programme reaches this after its own real
    // Open provision and both independently armed history owners. The private
    // crossing arm rejoins its original peer and stream before the pair splits.
    pub(super) fn append_once_v1(
        &mut self,
        writers: &mut RootCurrentWritersOriginalV1,
        crossing: &mut RootInitialOpenCrossingOriginalV1,
        history: &mut RootCurrentHistoryPostOriginalV1,
        producer: &crate::native::startup::RootStartupControllerPeerOriginalV1<'_>,
        stream: &RetainedUnixStream,
        endpoint: BorrowedFd<'_>,
    ) -> Result<(), E> {
        if self.committed.is_some() {
            return Err(E::Boundary);
        }

        let committed = {
            let accepted = history.borrow_accepted_v1(producer, stream)?;
            let physical = accepted.with_root_open_clock_v1(&self.clock)?;
            physical.require_same_controller_peer_original_v1(producer.native_peer_original_v1()?)?;
            let body = self.body_v1()?;
            let transaction = self.transaction_v1()?;
            let pair = writers.opened_pair_v1()?;
            let (authority, policy) = pair.authority_and_policy_v1()?;
            let mut gate = RootInitialOpenAppendGateV1 {
                physical,
                purpose: RootHistoryAppendPurposeV1::Initial,
                clock: &self.clock,
                policy,
                body,
                transaction,
                endpoint,
                crossing,
            };
            authority.commit_with_role_gate_v1(
                transaction,
                crate::native::append::PolicyMutationGateV1::RootOpen(&mut gate),
            )
        };
        self.committed = Some(committed);

        // A successful durable result is retained before any readback. A later
        // failure cannot turn a committed native transaction into an unattempted
        // append, and the independent outer post remains separately owed.
        if let Some(Ok(committed)) = &self.committed {
            let pair = writers.opened_pair_v1()?;
            let (authority, policy) = pair.authority_and_policy_v1()?;
            self.readback = Some(self.readback_v1(authority, policy, committed));
        }
        positive(&self.committed)?;
        positive(&self.readback).map(|_| ())
    }

    pub(super) fn preappend_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.identity_service)
            .or_else(|| cause(&self.identity))
            .or_else(|| self.clock.failure_v1())
            .or_else(|| cause(&self.clock_returned))
            .or_else(|| cause(&self.nonce))
            .or_else(|| self.authority_original.failure())
            .or_else(|| cause(&self.authority_names))
            .or_else(|| self.policy_original.failure())
            .or_else(|| cause(&self.policy_names))
            .or_else(|| cause(&self.body))
            .or_else(|| cause(&self.body_encoding))
            .or_else(|| cause(&self.checksum))
            .or_else(|| cause(&self.head_encoding))
            .or_else(|| cause(&self.transaction))
            .or_else(|| cause(&self.preparation))
    }

    pub(super) fn append_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.committed).or_else(|| cause(&self.readback))
    }

}

fn observe_authority_names_v1(
    authority: &RootPolicyJournalV1,
    original: &mut RootPolicyNameObservationOriginalV1,
) -> Result<ProtectedJournalNamesV1, E> {
    original.observe_once(authority, RootFixedNameRoleV1::Authority, RootFixedNameRecipeV1::Physical)
        .map_err(|()| E::Boundary)?;
    original.names().ok_or(E::Boundary)
}

fn make_transaction_v1(
    lane: [u8; 16],
    checksum: [u8; 32],
    record: &[u8; ROOT_RECORD_BYTES],
    head: &[u8; HEAD_BYTES],
) -> Result<JournalTransaction, E> {
    let key = KeyV1::new(lane, OwnerV1::Root, 1).map_err(|_| E::Boundary)?;
    let phase = PhaseV1::new(OwnerV1::Root, 1).map_err(|_| E::Boundary)?;
    let envelope = RecordEnvelopeV1::decode(record, key, phase).map_err(|_| E::Boundary)?;
    if envelope.checksum() != checksum {
        return Err(E::Boundary);
    }
    prepare_history_pair_v1(key, phase, record, head).map_err(E::Pair)
}

fn positive<T, F>(slot: &Option<Result<T, F>>) -> Result<&T, E> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::Boundary)
}

fn cause<T, F: Error + 'static>(slot: &Option<Result<T, F>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}

#[derive(Debug, thiserror::Error)]
pub(super) enum RootInitialClockErrorV1 {
    #[error("Source genesis owner or credential is not current")]
    Stale,
    #[error(transparent)]
    Kernel(aos_linux_descriptors::Error),
}

impl KernelPairedClockErrorV1 for RootInitialClockErrorV1 {
    fn stale() -> Self {
        Self::Stale
    }

    fn kernel(error: aos_linux_descriptors::Error) -> Self {
        Self::Kernel(error)
    }
}

/// Retains every reached native final-crossing observation independently.
///
/// The first clock remains on the prepared Open owner. This separate native
/// attempt samples only after the final names, endpoint and peer observations.
pub(super) struct RootInitialOpenCrossingOriginalV1 {
    transition: Option<Result<(), E>>,
    purpose_current: Option<Result<(), E>>,
    history: RootInertHistoryScanV1,
    history_returned: Option<Result<(), PolicyQ04DataErrorV1>>,
    authority_location: RootPolicyNameObservationOriginalV1,
    policy_location: RootPolicyNameObservationOriginalV1,
    authority_location_returned: Option<Result<(), E>>,
    policy_location_returned: Option<Result<(), E>>,
    authority_physical: RootPolicyNameObservationOriginalV1,
    policy_physical: RootPolicyNameObservationOriginalV1,
    authority_names: Option<Result<ProtectedJournalNamesV1, E>>,
    policy_names: Option<Result<ProtectedJournalNamesV1, E>>,
    cut_binding: Option<Result<(), E>>,
    endpoint: Option<Result<(), aos_linux_descriptors::Error>>,
    peer: Option<Result<(), RootObservationErrorV1>>,
    clock_original: RetainedKernelPairedClockAttemptV1<RootInitialClockErrorV1>,
    clock: Option<Result<aos_sandbox_model::RawPairedClockSample, RootInitialClockErrorV1>>,
    completion: Option<Result<(), E>>,
}

impl RootInitialOpenCrossingOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            transition: None,
            purpose_current: None,
            history: RootInertHistoryScanV1::default(),
            history_returned: None,
            authority_location: RootPolicyNameObservationOriginalV1::new(),
            policy_location: RootPolicyNameObservationOriginalV1::new(),
            authority_location_returned: None,
            policy_location_returned: None,
            authority_physical: RootPolicyNameObservationOriginalV1::new(),
            policy_physical: RootPolicyNameObservationOriginalV1::new(),
            authority_names: None,
            policy_names: None,
            cut_binding: None,
            endpoint: None,
            peer: None,
            clock_original: RetainedKernelPairedClockAttemptV1::default(),
            clock: None,
            completion: None,
        }
    }

    pub(super) fn failure_v1<'cause>(
        &'cause self,
        history: Option<&'cause RootCurrentHistoryPostOriginalV1>,
    ) -> Option<&'cause (dyn Error + 'static)> {
        cause(&self.transition)
            .or_else(|| cause(&self.purpose_current))
            .or_else(|| self.history.failure())
            .or_else(|| cause(&self.history_returned))
            .or_else(|| self.authority_location.failure())
            .or_else(|| cause(&self.authority_location_returned))
            .or_else(|| self.policy_location.failure())
            .or_else(|| cause(&self.policy_location_returned))
            .or_else(|| self.authority_physical.failure())
            .or_else(|| cause(&self.authority_names))
            .or_else(|| self.policy_physical.failure())
            .or_else(|| cause(&self.policy_names))
            .or_else(|| cause(&self.cut_binding))
            .or_else(|| cause(&self.endpoint))
            .or_else(|| history.and_then(RootCurrentHistoryPostOriginalV1::failure_v1))
            .or_else(|| cause(&self.peer))
            .or_else(|| self.clock_original.failure())
            .or_else(|| cause(&self.clock))
            .or_else(|| cause(&self.completion))
    }
}

/// Borrows the actual fixed initial Open at the sole native append boundary.
///
/// There is no public constructor, phase selector, journal getter or DATA
/// adopter. The only constructor above rejoins a genuinely paid history arm,
/// the same native peer producer, the prepared transaction and its own clock.
pub(in crate::native) struct RootInitialOpenAppendGateV1<'cut, 'startup> {
    physical: RootOpenPhysicalBorrowerV1<'cut, 'startup>,
    purpose: RootHistoryAppendPurposeV1<'cut>,
    clock: &'cut RootOpenClockOriginalV1,
    policy: &'cut RootPolicyTargetOriginalV1,
    body: RootOpenBodyDataV1,
    transaction: &'cut JournalTransaction,
    endpoint: BorrowedFd<'cut>,
    crossing: &'cut mut RootInitialOpenCrossingOriginalV1,
}

impl<'cut, 'startup> RootInitialOpenAppendGateV1<'cut, 'startup> {
    pub(super) fn for_purpose_v1(
        open: &'cut RootInitialOpenPreparedOriginalV1,
        purpose: RootHistoryAppendPurposeV1<'cut>,
        policy: &'cut RootPolicyTargetOriginalV1,
        transaction: &'cut JournalTransaction,
        crossing: &'cut mut RootInitialOpenCrossingOriginalV1,
        history: &'cut mut RootCurrentHistoryPostOriginalV1,
        producer: &'cut crate::native::startup::RootStartupControllerPeerOriginalV1<'startup>,
        stream: &'cut RetainedUnixStream,
        endpoint: BorrowedFd<'cut>,
    ) -> Result<Self, E> {
        purpose.require_complete_v1()?;
        history.require_armed_v1()?;
        let body = open.body_v1()?;
        let physical = history.borrow_accepted_v1(producer, stream)?
            .with_root_open_clock_v1(open.clock_original_v1())?;
        physical.require_same_controller_peer_original_v1(producer.native_peer_original_v1()?)?;
        Ok(Self {
            physical,
            purpose,
            clock: open.clock_original_v1(),
            policy,
            body,
            transaction,
            endpoint,
            crossing,
        })
    }
}

// This closed loan borrows the actual completed native purposes. Neither a
// decoded record nor a public phase value can select a successful append.
pub(super) enum RootHistoryAppendPurposeV1<'cut> {
    Initial,
    UseAdmitted {
        open: &'cut RootInitialOpenPreparedOriginalV1,
        authorization: &'cut super::initial_use_authorized::RootInitialUseAuthorizedOriginalV1,
        reserved: &'cut super::use_tail::reserved::RootUseReservedOriginalV1,
        source: &'cut super::initial_source_exchange::RootInitialSourceExchangeOriginalV1,
        cache: &'cut super::initial_cache::RootInitialCacheProofOriginalV1,
    },
    SignedBound {
        admitted: &'cut super::use_tail::admitted::RootUseAdmittedOriginalV1,
        reserved: &'cut super::use_tail::reserved::RootUseReservedOriginalV1,
        source: &'cut super::initial_source_exchange::RootInitialSourceExchangeOriginalV1,
        signed: &'cut super::use_tail::signed::received::RootSignedReceivedOriginalV1,
    },
    UseAuthorized {
        open: &'cut RootInitialOpenPreparedOriginalV1,
        readonly: &'cut super::initial_controller::RootInitialControllerReadonlyOriginalV1,
        source: &'cut super::initial_source_exchange::RootInitialSourceExchangeOriginalV1,
        cache: &'cut super::initial_cache::RootInitialCacheProofOriginalV1,
    },
}

impl RootHistoryAppendPurposeV1<'_> {
    fn require_complete_v1(&self) -> Result<(), E> {
        match self {
            // Initial owns a separate fixed factory above. A continuation
            // factory cannot use this variant to evade its real predecessor.
            Self::Initial => Err(E::Boundary),
            Self::SignedBound {
                admitted,
                reserved,
                signed,
                ..
            } => {
                admitted.require_complete_v1().map_err(|_| E::Boundary)?;
                reserved.require_complete_v1().map_err(|_| E::Boundary)?;
                signed.require_complete_v1().map_err(|_| E::Boundary)
            }
            Self::UseAuthorized { readonly, source, cache, .. } => {
                readonly.require_complete_v1().map_err(|_| E::Boundary)?;
                source.require_complete_v1().map_err(|_| E::Boundary)?;
                cache.require_complete_v1().map_err(|_| E::Boundary)
            },
            Self::UseAdmitted { open, authorization, reserved, source, cache } => {
                reserved.require_complete_v1().map_err(|_| E::Boundary)?;
                source.require_use_complete_for_v1(open, authorization, reserved).map_err(|_| E::Boundary)?;
                cache.require_use_complete_for_v1(open, authorization, reserved).map_err(|_| E::Boundary)
            },
        }
    }

    fn expected_authority_next_v1(&self, body: RootOpenBodyDataV1) -> Result<u64, E> {
        match self {
            Self::Initial => Ok(body.authority_next),
            Self::SignedBound { .. } => body
                .authority_next
                .checked_add(12)
                .ok_or(E::SequenceExhausted),
            Self::UseAdmitted { .. } => body.authority_next.checked_add(8)
                .ok_or(E::SequenceExhausted),
            Self::UseAuthorized { .. } => body.authority_next.checked_add(4)
                .ok_or(E::SequenceExhausted),
        }
    }

    fn require_current_v1(
        &self,
        authority: &RootPolicyJournalV1,
        policy: &RootPolicyTargetOriginalV1,
    ) -> Result<(), E> {
        match self {
            Self::Initial => Ok(()),
            Self::SignedBound {
                admitted, signed, ..
            } => {
                signed.require_complete_v1().map_err(|_| E::Boundary)?;
                admitted.readback_current_v1(authority, policy).map(|_| ())
            }
            Self::UseAdmitted { open, authorization, reserved, source, cache } => {
                reserved.require_complete_v1().map_err(|_| E::Boundary)?;
                source.require_use_complete_for_v1(open, authorization, reserved).map_err(|_| E::Boundary)?;
                cache.require_use_complete_for_v1(open, authorization, reserved).map_err(|_| E::Boundary)?;
                authorization.readback_current_v1(authority, policy).map(|_| ())
            },
            Self::UseAuthorized { open, readonly, source, cache } => {
                readonly.require_complete_v1().map_err(|_| E::Boundary)?;
                source.require_complete_v1().map_err(|_| E::Boundary)?;
                cache.require_complete_v1().map_err(|_| E::Boundary)?;
                open.readback_current_v1(authority, policy).map(|_| ())
            }
        }
    }

    fn require_live_at_v1(&self, current: aos_sandbox_model::RawPairedClockSample) -> Result<(), E> {
        match self {
            Self::Initial => Ok(()),
            Self::SignedBound {
                reserved, source, ..
            } => {
                reserved
                    .completed_controller_v1()
                    .map_err(|_| E::Boundary)?
                    .require_live_at_v1(current)
                    .map_err(|_| E::Boundary)?;
                if current.boottime_nanoseconds()
                    >= source.original_cutoff_v1().map_err(|_| E::Boundary)?
                {
                    return Err(E::Boundary);
                }
                Ok(())
            }
            Self::UseAdmitted { reserved, source, .. } => {
                reserved.completed_controller_v1().map_err(|_| E::Boundary)?
                    .require_live_at_v1(current).map_err(|_| E::Boundary)?;
                if current.boottime_nanoseconds() >= source.original_cutoff_v1().map_err(|_| E::Boundary)? {
                    return Err(E::Boundary);
                }
                Ok(())
            },
            Self::UseAuthorized { readonly, source, .. } => {
                readonly.require_live_at_v1(current).map_err(|_| E::Boundary)?;
                if current.boottime_nanoseconds() >= source.original_cutoff_v1().map_err(|_| E::Boundary)? {
                    return Err(E::Boundary);
                }
                Ok(())
            }
        }
    }
}

impl RootInitialOpenAppendGateV1<'_, '_> {
    pub(in crate::native) fn require_transition(
        &mut self,
        authority: &RootPolicyJournalV1,
        transaction: &JournalTransaction,
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        if self.crossing.transition.is_some() {
            return Err(PolicyNativeJournalErrorV1::boundary());
        }
        self.crossing.transition = Some(self.require_transition_inner_v1(authority, transaction));
        positive(&self.crossing.transition).map_err(|_| PolicyNativeJournalErrorV1::boundary())?;

        self.crossing.history_returned = Some(self.crossing.history.observe_once(
            authority.historical_read_view_v1().materialized_state_v1(),
        ));
        self.crossing.history.require_complete()
            .map_err(|_| PolicyNativeJournalErrorV1::boundary())
    }

    fn require_transition_inner_v1(
        &self,
        authority: &RootPolicyJournalV1,
        transaction: &JournalTransaction,
    ) -> Result<(), E> {
        if transaction != self.transaction
            || matches!(self.purpose, RootHistoryAppendPurposeV1::Initial)
                && authority.records(RecordNamespace::CreateStorageHistory).next().is_some()
            || authority.snapshot_sequence() != self.purpose.expected_authority_next_v1(self.body)?
            || self.policy.current_snapshot_sequence_data_v1() != self.body.policy_next
        {
            return Err(E::Boundary);
        }
        self.purpose.require_current_v1(authority, self.policy)
    }

    pub(in crate::native) fn require_prechecked_root_history_successor_v1(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        positive(&self.crossing.transition).map_err(|_| PolicyNativeJournalErrorV1::boundary())?;
        if transaction != self.transaction {
            return Err(PolicyNativeJournalErrorV1::boundary());
        }
        self.crossing.history.require_complete()
            .map_err(|_| PolicyNativeJournalErrorV1::boundary())
    }

    pub(in crate::native) fn final_crossing(
        &mut self,
        authority: &RootPolicyJournalV1,
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        if self.crossing.completion.is_some() {
            return Err(PolicyNativeJournalErrorV1::boundary());
        }

        self.crossing.purpose_current = Some(self.purpose.require_current_v1(authority, self.policy));
        self.crossing.authority_location_returned = Some(self.crossing.authority_location
            .observe_once(authority, RootFixedNameRoleV1::Authority, RootFixedNameRecipeV1::Location)
            .map_err(|()| E::Boundary));
        self.crossing.policy_location_returned = Some(self.policy
            .observe_fixed_location_once_v1(&mut self.crossing.policy_location)
            .map_err(|()| E::Boundary));
        self.crossing.authority_names = Some(observe_names_v1(
            authority,
            RootFixedNameRoleV1::Authority,
            RootFixedNameRecipeV1::Physical,
            &mut self.crossing.authority_physical,
        ));
        self.crossing.policy_names = Some(self.policy
            .observe_held_physical_names_once_v1(&mut self.crossing.policy_physical)
            .map_err(|()| E::Boundary));

        // Retain the exact cut mismatch before the independently owed endpoint,
        // peer and late clock work. Those observations cannot replace it.
        self.crossing.cut_binding = Some(self.require_cut_binding_v1(authority));
        self.crossing.endpoint = Some(self.physical.require_same_endpoint_v1(self.endpoint));
        self.crossing.peer = Some(self.physical.observe_shared_once_v1());
        self.crossing.clock = Some(self.crossing.clock_original.observe_once(None));
        self.crossing.completion = Some(self.require_crossing_complete_v1());
        positive(&self.crossing.completion)
            .map(|_| ())
            .map_err(|_| PolicyNativeJournalErrorV1::boundary())
    }

    fn require_cut_binding_v1(&self, authority: &RootPolicyJournalV1) -> Result<(), E> {
        if *positive(&self.crossing.authority_names)? != self.body.authority_names
            || *positive(&self.crossing.policy_names)? != self.body.policy_names
            || authority.snapshot_sequence() != self.purpose.expected_authority_next_v1(self.body)?
            || self.policy.current_snapshot_sequence_data_v1() != self.body.policy_next
        {
            return Err(E::Boundary);
        }
        Ok(())
    }

    fn require_crossing_complete_v1(&self) -> Result<(), E> {
        positive(&self.crossing.transition)?;
        positive(&self.crossing.purpose_current)?;
        self.crossing.history.require_complete()?;
        positive(&self.crossing.authority_location_returned)?;
        positive(&self.crossing.policy_location_returned)?;
        positive(&self.crossing.cut_binding)?;
        positive(&self.crossing.endpoint)?;
        positive(&self.crossing.peer)?;
        let current = *positive(&self.crossing.clock)?;

        // Only this actual immutable owner may validate the final observation.
        // A separately started clock cannot renew the prepared body's interval.
        if !std::ptr::eq(self.physical.clock_original_v1(), self.clock) {
            return Err(E::Boundary);
        }
        self.clock.require_current_v1(current, self.body.cutoff)?;
        self.purpose.require_live_at_v1(current)
    }
}

pub(super) fn observe_names_v1(
    journal: &RootPolicyJournalV1,
    role: RootFixedNameRoleV1,
    recipe: RootFixedNameRecipeV1,
    original: &mut RootPolicyNameObservationOriginalV1,
) -> Result<ProtectedJournalNamesV1, E> {
    original.observe_once(journal, role, recipe).map_err(|()| E::Boundary)?;
    original.names().ok_or(E::Boundary)
}


pub(super) struct RootInitialOpenProgrammeOriginalV1 {
    pub(super) prepared: RootInitialOpenPreparedOriginalV1,
    pub(super) crossing: RootInitialOpenCrossingOriginalV1,
    pub(super) crossing_history: Option<RootCurrentHistoryPostOriginalV1>,
    pub(super) outer: super::initial_post::RootInitialOpenPostsOriginalV1,
    pub(super) outer_arm_returned: Option<Result<(), RootObservationErrorV1>>,
    pub(super) crossing_arm_returned: Option<Result<(), RootObservationErrorV1>>,
    pub(super) preparation_returned: Option<Result<(), E>>,
    pub(super) append_returned: Option<Result<(), E>>,
    pub(super) completion: Option<Result<(), E>>,
    pub(super) finished: bool,
    pub(super) closed: Option<E>,
}

impl RootInitialOpenProgrammeOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            prepared: RootInitialOpenPreparedOriginalV1::new(),
            crossing: RootInitialOpenCrossingOriginalV1::new(),
            crossing_history: None,
            outer: super::initial_post::RootInitialOpenPostsOriginalV1::new(),
            outer_arm_returned: None,
            crossing_arm_returned: None,
            preparation_returned: None,
            append_returned: None,
            completion: None,
            finished: false,
            closed: None,
        }
    }

    pub(super) fn complete_after_posts_v1(&self) -> Result<(), E> {
        if self.closed.is_some() { return Err(E::Boundary); }
        positive(&self.outer_arm_returned)?;
        positive(&self.preparation_returned)?;
        positive(&self.crossing_arm_returned)?;
        positive(&self.append_returned)?;
        positive(&self.prepared.committed)?;
        positive(&self.prepared.readback)?;
        positive(&self.crossing.completion)?;
        self.outer.require_complete_v1()
    }

    pub(super) fn require_complete_v1(&self) -> Result<(), E> {
        if self.closed.is_some() { return Err(E::Boundary); }
        positive(&self.completion).map(|_| ())
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.outer.arm_failure_v1()
            .or_else(|| cause(&self.outer_arm_returned))
            .or_else(|| self.prepared.preappend_failure_v1())
            .or_else(|| self.crossing.failure_v1(self.crossing_history.as_ref()))
            .or_else(|| cause(&self.crossing_arm_returned))
            .or_else(|| self.prepared.append_failure_v1())
            .or_else(|| cause(&self.preparation_returned))
            .or_else(|| cause(&self.append_returned))
            .or_else(|| self.outer.failure_v1())
            .or_else(|| cause(&self.completion))
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}


pub(super) fn continuation_control_bytes_v1() -> Option<usize> {
    use std::mem::size_of;
    let purpose = size_of::<RootHistoryAppendPurposeV1<'_>>().checked_mul(6)?;
    let current_slot = size_of::<Option<Result<(), E>>>().checked_mul(3)?;
    let constructor = size_of::<(
        &RootInitialOpenPreparedOriginalV1, RootHistoryAppendPurposeV1<'_>,
        &RootPolicyTargetOriginalV1, &JournalTransaction,
        &mut RootInitialOpenCrossingOriginalV1, &mut RootCurrentHistoryPostOriginalV1,
        &crate::native::startup::RootStartupControllerPeerOriginalV1<'_>,
        &RetainedUnixStream, BorrowedFd<'_>,
    )>().checked_mul(3)?;
    let queries = size_of::<&RootHistoryAppendPurposeV1<'_>>().checked_mul(3)?
        .checked_add(size_of::<(&RootHistoryAppendPurposeV1<'_>, &RootPolicyJournalV1,
        &RootPolicyTargetOriginalV1)>().checked_mul(6)?)?
        .checked_add(size_of::<(&RootHistoryAppendPurposeV1<'_>, aos_sandbox_model::RawPairedClockSample)>().checked_mul(3)?)?
        .checked_add(size_of::<(&RootHistoryAppendPurposeV1<'_>, RootOpenBodyDataV1)>().checked_mul(6)?)?;
    let results = size_of::<Result<RootInitialOpenAppendGateV1<'_, '_>, E>>().checked_mul(3)?
        .checked_add(size_of::<Result<(), E>>().checked_mul(21)?)?
        .checked_add(size_of::<Result<u64, E>>().checked_mul(6)?)?
        .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(3)?)?
        .checked_add(size_of::<&&RootInitialOpenCrossingOriginalV1>().checked_mul(3)?)?;
    purpose.checked_add(current_slot)?.checked_add(constructor)?.checked_add(queries)?.checked_add(results)
}
