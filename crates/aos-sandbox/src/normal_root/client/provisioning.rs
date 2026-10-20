//! Keeps the actual C23 Root Apply opening and its unfinished continuation.
//!
//! The same original baseline pays this closed purpose. Query DATA never
//! creates an account, claim, signer or semantic completion. The socket and
//! native Root anchors remain resident across signing, Apply and publication;
//! only the later independently validated final acknowledgement may close it.

mod shape;
mod receive;
mod current_turn;
mod final_exchange;
pub use final_exchange::RootStorageApplyCompletionOriginalV1;
mod diagnostics;
pub use current_turn::{RootStorageApplyCurrentTurnV1, RootStorageApplyConstructionTurnV1};

use std::error::Error;
use std::sync::Arc;
use rand::{TryRngCore as _, rngs::OsRng};
use aos_sandbox_core::{RawPairedClockSample, ResourceVector, OperationId};
use aos_sandbox_linux::unix_stream::RetainedSubjectStreamReadV1;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1;
use aos_sandbox_protocol::domain_ledger::provisioning_root::storage_apply::{
    StorageApplyQueryDataV1, StorageApplySubjectDataV1, StorageApplyReplyDataV1,
    StorageApplyAdmissionDataV1, ApplyRootDataErrorV1, QUERY_BYTES_V1,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::ContinuationKindV1;
use aos_sandbox_protocol::domain_ledger::resource_bank::ACCOUNT_HEAD_BYTES_V1;
use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::OriginalCreateProvisioningRootLoanV1;
use crate::Journal;
use crate::policy_compiler::{RetainedKernelPairedClockAttemptV1,
    bounded_stream_io::{FixedDeadlineStreamIoV1, DeadlineStreamDirectionV1}};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use super::root_connection::ControllerRootConnectionOriginalV1;
use super::strict_chunk::RootStrictChunkOriginalV1;
use super::peer_receiving::sample::PeerSampleV1;
use super::peer_receiving::{CreateStorageRootPeerReceivingOriginalsV1, StableRootPeerV1};
use super::{NormalRootStartupErrorV1, ProductionControllerNormalRootProfileV1};

/// Reports an unfinished or refused original Root Apply client.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the original Root Apply client is incomplete or retains a refusal")]
#[doc(hidden)]
pub struct RootStorageApplyClientClosedV1;
type Closed = RootStorageApplyClientClosedV1;

#[derive(Clone, Copy)]
enum First { Nonce, Metadata, Query, Connect, BeforeClock, Before,
    Reporting, Send, Admission, Receive, Reply, After, AfterClock, Temporal, Settlement }

/// Retains the actual socket, native samples, unsigned output and original time.
///
/// No public constructor or raw reply adopter exists. This owner must remain
/// resident until the real signed Apply/publication continuation and final ack.
#[doc(hidden)]
#[must_use = "retain this unfinished native Root connection through its final acknowledgement"]
pub struct RootStorageApplyClientOriginalV1 {
    parent: OperationId,
    profile: Arc<ProductionControllerNormalRootProfileV1>,
    origin: RawPairedClockSample,
    original_cutoff: u64,
    preparation_cutoff: u64,
    cutoff: u64,
    complete: ResourceVector,
    observations: usize,
    native_turn: u64,
    received_bound: usize,
    wire: u64,
    output: u64,
    admission: Option<Result<(), ResourceReservationErrorV1>>,
    funding_original: bool,
    state: Box<OpeningV1>,
    first: Option<First>,
    admitted: bool,
    terminal_complete: bool,
    stable: Option<StableRootPeerV1>,
    next_refusal: Option<Box<current_turn::RefusalOriginalV1>>,
    publication: current_turn::PublicationTurnStateV1,
    construction_entered: bool,
    final_exchange: final_exchange::FinalExchangeStateV1,
    closed: Closed,
}

struct OpeningV1 {
    connection: ControllerRootConnectionOriginalV1,
    nonce: [u8; 16],
    entropy: Option<Result<(), rand::rand_core::OsError>>,
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    query: Option<Result<StorageApplyQueryDataV1, ApplyRootDataErrorV1>>,
    query_bytes: [u8; QUERY_BYTES_V1],
    controller_head: [u8; ACCOUNT_HEAD_BYTES_V1],
    root_closed: [u8; aos_sandbox_protocol::domain_ledger::create_storage_history::outcome::ROOT_CLOSED_RECEIPT_BYTES_V1],
    query_encoding: Option<Result<(), ApplyRootDataErrorV1>>,
    data_failure: Option<ApplyRootDataErrorV1>,
    native_inputs: Option<Result<(),ResourceReservationErrorV1>>,
    connect: Option<Result<(), HistoryErrorV1>>,
    before_clock: RetainedKernelPairedClockAttemptV1,
    before_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    peer_before: Option<Box<PeerSampleV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    reporting: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    sender: FixedDeadlineStreamIoV1<4096>,
    sent: Option<Result<(), HistoryErrorV1>>,
    send_scratch: [u8; 4096],
    query_sender: FixedDeadlineStreamIoV1<QUERY_BYTES_V1>,
    query_sent: Option<Result<(), HistoryErrorV1>>,
    received: RetainedSubjectStreamReadV1,
    preparation: Option<Result<(), aos_sandbox_linux::unix_stream::SubjectStreamReadErrorV1>>,
    extension: Option<Result<(), aos_sandbox_linux::unix_stream::SubjectStreamReadErrorV1>>,
    chunk: Option<Box<RootStrictChunkOriginalV1>>,
    reply: Option<Result<StorageApplyAdmissionDataV1, ApplyRootDataErrorV1>>,
    peer_after: Option<Box<PeerSampleV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    after_clock: RetainedKernelPairedClockAttemptV1,
    after_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    temporal: Option<Result<u64, ApplyRootDataErrorV1>>,
    settlement: Option<Result<(), NormalRootStartupErrorV1>>,
}

impl OpeningV1 {
    fn new() -> Self {
        Self {
            connection: Default::default(),
            nonce: [0; 16],
            entropy: None,
            metadata: None,
            query: None,
            query_bytes: [0; QUERY_BYTES_V1],
            controller_head: [0; ACCOUNT_HEAD_BYTES_V1],
            root_closed: [0; aos_sandbox_protocol::domain_ledger::create_storage_history::outcome::ROOT_CLOSED_RECEIPT_BYTES_V1],
            query_encoding: None,
            data_failure: None,
            native_inputs: None,
            connect: None,
            before_clock: Default::default(),
            before_sample: None,
            peer_before: Some(Box::new(PeerSampleV1::new())),
            before: None,
            reporting: None,
            sender: Default::default(),
            sent: None,
            send_scratch: [0; 4096],
            query_sender: Default::default(),
            query_sent: None,
            received: Default::default(),
            preparation: None,
            extension: None,
            chunk: None,
            reply: None,
            peer_after: Some(Box::new(PeerSampleV1::new())),
            after: None,
            after_clock: Default::default(),
            after_sample: None,
            temporal: None,
            settlement: None,
        }
    }
}

impl RootStorageApplyClientOriginalV1 {
    pub(crate) fn begin_original_once_v1(loan:&mut OriginalCreateProvisioningRootLoanV1<'_, '_>,
        controller:&Journal, ready:&[u8], outcome:&AuthenticatedBrokerMethodOutcomeV1,
        co_resident:ResourceVector,
    )->Result<Self,ResourceReservationErrorV1> {
        loan.require_storage_apply_inputs_v1(controller,ready,outcome)?;
        let (origin,original_cutoff)=loan.original_horizon_v1()?;
        let preparation_cutoff=loan.storage_preparation_cutoff_v1()?;
        let fixed=Self::fixed_demand_v1(loan.profile_v1())?;
        let complete=co_resident.checked_add(fixed)?;
        let complete=complete.checked_add(Self::peer_traffic_v1(3)?)?;
        // Both native samples and the full next-refusal traffic are paid before
        // the first allocation/socket/clock. Refused entry stays on real C23.
        loan.require_complete_v1(controller,complete)?;
        let mut owner = Self {
            parent: loan.parent_operation_v1(),
            profile: loan.retained_profile_v1(),
            origin,
            original_cutoff,
            preparation_cutoff,
            cutoff: original_cutoff.min(preparation_cutoff),
            complete: co_resident.checked_add(fixed)?,
            observations: 3,
            native_turn: loan.native_turn_v1(),
            received_bound: 20,
            wire: 0,
            output: 0,
            admission: None,
            funding_original: false,
            state: Box::new(OpeningV1::new()),
            first: None,
            admitted: false,
            terminal_complete: false,
            stable: None,
            next_refusal: Some(Box::new(current_turn::RefusalOriginalV1::new())),
            publication: Default::default(),
            construction_entered: false,
            final_exchange: Default::default(),
            closed: RootStorageApplyClientClosedV1,
        };
        let primary=owner.open_inner(loan,controller,ready,outcome);
        if let Err(first)=primary { owner.first=Some(first); }
        // The independently paid peer after is never gated on the body/debit.
        // A failed connect has no socket/peer association to observe; its whole
        // native error stays retained and the outer C23 original still owes its
        // own separately prearmed name/profile/launch post.
        owner.finish_opening_posts(loan);
        Ok(owner)
    }

    fn open_inner(&mut self,loan:&mut OriginalCreateProvisioningRootLoanV1<'_, '_>,
        controller:&Journal,ready:&[u8],outcome:&AuthenticatedBrokerMethodOutcomeV1,
    )->Result<(),First> {
        self.state.entropy=Some(OsRng.try_fill_bytes(&mut self.state.nonce));
        if !matches!(self.state.entropy,Some(Ok(()))) || self.state.nonce==[0;16] { return Err(First::Nonce); }
        let (metadata,_)=controller.held_native_receiving_metadata_v1();
        self.state.metadata=Some(metadata);
        let end=self.state.metadata.as_ref().and_then(|r|r.as_ref().ok()).ok_or(First::Metadata)?.len();
        self.state.native_inputs=Some((|| {
            let head=loan.controller_account_head_v1(controller)?;
            let head: &[u8;ACCOUNT_HEAD_BYTES_V1]=head.try_into()
                .map_err(|_|ResourceReservationErrorV1::Conflict)?;
            self.state.controller_head.copy_from_slice(head);
            let lane=aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ReadyBundleDataV1::borrow_field_framing_data_v1(ready)
                .map_err(|_|ResourceReservationErrorV1::Conflict)?.lane;
            loan.root_closed_receipt_v1()?.encode_into(lane,ContinuationKindV1::Closed,&mut self.state.root_closed)
                .map_err(|_|ResourceReservationErrorV1::Conflict)?;
            Ok(())
        })());
        if !matches!(self.state.native_inputs,Some(Ok(()))) {return Err(First::Query);}
        let subject=StorageApplySubjectDataV1 {ready,prepare_request:outcome.request().canonical_packet(),
            prepare_outcome:outcome.canonical_packet(),root_closed:&self.state.root_closed,
            controller_account:&self.state.controller_head};
        self.state.query=Some((||Ok(StorageApplyQueryDataV1 { controller_nonce:self.state.nonce,
            original_boot:self.origin.host_boot_id(),original_boottime_ns:self.origin.boottime_nanoseconds(),
            original_cutoff_ns:self.original_cutoff,subject_bytes:u64::try_from(subject.encoded_bytes_v1()?)
                .map_err(|_|ApplyRootDataErrorV1::Extent)?,subject_digest:subject.digest_v1()?,
            controller_next:controller.snapshot_sequence(),controller_end:end }))());
        let query=*positive(&self.state.query).map_err(|_|First::Query)?;
        self.state.query_encoding=Some(query.encode_v1().map(|bytes|self.state.query_bytes=bytes));
        if !matches!(self.state.query_encoding,Some(Ok(()))) {return Err(First::Query);}
        let subject_bytes=usize::try_from(query.subject_bytes).map_err(|_|First::Admission)?;
        let output=subject_bytes.checked_add(QUERY_BYTES_V1).ok_or(First::Admission)?;
        self.charge(loan,controller,0,output.checked_add(20).ok_or(First::Admission)?,output)?;
        self.state.before_sample=Some(self.state.before_clock.observe_once(Some(self.origin)));
        let before=*self.state.before_sample.as_ref().and_then(|r|r.as_ref().ok()).ok_or(First::BeforeClock)?;
        let lease=loan.ownership_lease_v1().map_err(|_|First::BeforeClock)?;
        self.state.temporal=Some((|| {
            if before.wall_seconds()<lease.authority_issued_seconds() {
                return Err(ApplyRootDataErrorV1::Malformed);
            }
            let deadline=before.conservative_expiry_deadline_data_v1(lease.authority_expires_seconds())
                .ok_or(ApplyRootDataErrorV1::Malformed)?;
            let cutoff=self.cutoff.min(deadline);
            if before.boottime_nanoseconds()>=cutoff {return Err(ApplyRootDataErrorV1::Malformed);}
            Ok(cutoff)
        })());
        self.cutoff=*positive(&self.state.temporal).map_err(|_|First::Temporal)?;
        self.state.connect=Some(self.state.connection.connect_once());
        if !matches!(self.state.connect,Some(Ok(()))) {return Err(First::Connect);}
        self.state.before = Some({
            let state = &mut *self.state;
            state.peer_before.as_mut().ok_or(First::Before)?.observe_with_cutoff_once_v1(&self.profile,
                state.connection.stream().map_err(|_| First::Before)?, None, None, false, self.cutoff)
        });
        if !matches!(self.state.before,Some(Ok(()))) {return Err(First::Before);}
        self.state.reporting=Some(self.state.connection.stream_mut().map_err(|_|First::Reporting)?.enable_subject_reporting());
        if !matches!(self.state.reporting,Some(Ok(()))) {return Err(First::Reporting);}
        self.state.query_sent = Some({
            let state = &mut *self.state;
            state.query_sender.run_once(state.connection.stream_mut().map_err(|_| First::Send)?,
                &mut state.query_bytes, self.cutoff, DeadlineStreamDirectionV1::Write)
        });
        if !matches!(self.state.query_sent,Some(Ok(()))) {return Err(First::Send);}
        self.send_subject(loan,controller,ready,outcome)?;
        self.receive_reply(loan,controller)?;
        let state = &mut *self.state;
        match StorageApplyReplyDataV1::decode_v1(state.received.bytes()) {
            Ok(reply) => state.reply = Some(StorageApplyAdmissionDataV1::decode_v1(reply.admission)),
            Err(cause) => {
                state.data_failure = Some(cause);
                return Err(First::Reply);
            }
        }
        let admission=*positive(&self.state.reply).map_err(|_|First::Reply)?;
        // Untrusted Root DATA may only tighten the already-paid native horizon.
        // The full original/query/lease/paired relation is checked after the
        // independent Root post and actual trailing paired sample.
        self.cutoff=self.cutoff.min(admission.cutoff_ns);
        Ok(())
    }

    fn finish_opening_posts(&mut self,loan:&OriginalCreateProvisioningRootLoanV1<'_, '_>) {
        let state = &mut *self.state;
        if let Ok(stream) = state.connection.stream() {
            let result = match state.peer_after.as_mut() {
                Some(after) if matches!(state.before, Some(Ok(()))) => {
                    match state.peer_before.as_deref() {
                        Some(before) => after.observe_against_sample_with_cutoff_once_v1(
                            &self.profile, stream, before, None, true, self.cutoff),
                        None => Err(NormalRootStartupErrorV1::Service),
                    }
                }
                Some(after) => after.observe_with_cutoff_once_v1(
                    &self.profile, stream, None, None, true, self.cutoff),
                None => Err(NormalRootStartupErrorV1::Service),
            };
            state.after = Some(result);
            if !matches!(state.after, Some(Ok(()))) && self.first.is_none() {
                self.first = Some(First::After);
            }
        }
        self.state.after_sample=Some(self.state.after_clock.observe_once(Some(self.origin)));
        if !matches!(self.state.after_sample,Some(Ok(_))) && self.first.is_none() {self.first=Some(First::AfterClock);}
        if self.first.is_some() {return;}
        self.state.temporal=Some((|| {
            let query=*positive(&self.state.query)?;
            let admission=*positive(&self.state.reply)?;
            let before=*self.state.before_sample.as_ref().and_then(|r|r.as_ref().ok()).ok_or(ApplyRootDataErrorV1::Malformed)?;
            let after=*self.state.after_sample.as_ref().and_then(|r|r.as_ref().ok()).ok_or(ApplyRootDataErrorV1::Malformed)?;
            let lease=loan.ownership_lease_v1().map_err(|_|ApplyRootDataErrorV1::Malformed)?;
            require_temporal_v1(self.origin,self.original_cutoff,query,admission,before,after,
                lease.authority_issued_seconds(),lease.authority_expires_seconds(),self.preparation_cutoff)
        })());
        let Some(Ok(validated_cutoff)) = self.state.temporal.as_ref() else {
            self.first = Some(First::Temporal);
            return;
        };
        // Later native phases must use this same fully validated minimum.
        // A later paired sample can yield a different conservative wall-expiry
        // translation; unsigned Root DATA cannot widen the client's bound.
        self.cutoff = self.cutoff.min(*validated_cutoff);
        self.state.settlement = Some((|| {
            let state = &mut *self.state;
            let before = state.peer_before.as_mut().ok_or(NormalRootStartupErrorV1::Service)?;
            before.settle_positive_once()?;
            state.peer_after.as_mut().ok_or(NormalRootStartupErrorV1::Service)?
                .settle_positive_once()?;
            self.stable = before.take_initial_binding();
            if self.stable.is_none() { return Err(NormalRootStartupErrorV1::Service); }
            Ok(())
        })());
        if matches!(self.state.settlement, Some(Ok(()))) {
            // Both native archives are positively settled. Only the actual
            // transferred immutable Root anchor survives; no failed leaf is
            // reset or credited back to the original financial ledger.
            drop(self.state.peer_before.take());
            drop(self.state.peer_after.take());
            self.admitted = true;
        } else {
            self.first = Some(First::Settlement);
        }
    }

    /// Borrows only a fully completed original unsigned admission.
    ///
    /// The unchanged socket and native anchors stay resident in this owner.
    /// The loan is short: it must end before a mutable semantic/native stage.
    ///
    /// # Errors
    /// Refuses an incomplete/failed owner or a foreign current C23 association.
    #[doc(hidden)]
    pub fn borrow_admission_v1<'a,'b,'c>(&'a self,
        loan:&'a OriginalCreateProvisioningRootLoanV1<'b,'c>,controller:&'a Journal,
    )->Result<RootStorageApplyAdmissionOriginalV1<'a>,Closed> {
        if !self.admitted || self.stable.is_none() || self.first.is_some()
            || self.final_exchange.started_v1() || self.parent!=loan.parent_operation_v1()
            || !std::ptr::eq(self.profile.as_ref(),loan.profile_v1()) {return Err(self.closed);}
        loan.require_current_v1(controller).map_err(|_|self.closed)?;
        let lease=loan.ownership_lease_v1().map_err(|_|self.closed)?;
        Ok(RootStorageApplyAdmissionOriginalV1 {client:self,lease,receiving:loan.original_receiving_v1(),controller})
    }

    /// Borrows the same original C debit cause at the selected funding frontier.
    ///
    /// An earlier pure geometry error does not select a later native-post
    /// failure. The exact parent/profile identity is checked without new IO.
    #[must_use]
    pub fn failure_with_original_v1<'cause>(&'cause self,
        original:&'cause crate::CreateProvisioningOriginalsV1,
    )->Option<&'cause (dyn Error+'static)> {
        if self.first.is_none() {
            return self.publication_failure_with_original_v1(original)
                .or_else(|| self.final_failure_with_original_v1(original));
        }
        if matches!(self.first,Some(First::Admission)) && self.funding_original
            && original.belongs_to_operation_v1(self.parent)
            && original.has_same_profile_v1(&self.profile) {
            original.failure().or_else(||self.failure())
        } else {self.failure()}
    }

    /// Borrows the first retained financial, native, wire or temporal cause.
    #[must_use]
    pub fn failure(&self)->Option<&(dyn Error+'static)> {
        let Some(first) = self.first else {
            return self.publication.failure().or_else(|| self.final_failure_v1());
        };
        match first {
            First::Nonce=>cause(&self.state.entropy),
            First::Metadata=>cause(&self.state.metadata),
            First::Query=>cause(&self.state.native_inputs).or_else(||cause(&self.state.query)).or_else(||cause(&self.state.query_encoding)).or_else(||self.state.data_failure.as_ref().map(|e|e as _)),
            First::Connect=>self.state.connection.failure().or_else(||cause(&self.state.connect)),
            First::BeforeClock=>self.state.before_clock.failure().or_else(||cause(&self.state.before_sample)),
            First::Before=>self.state.peer_before.as_deref().and_then(PeerSampleV1::failure).or_else(||cause(&self.state.before)),
            First::Reporting=>cause(&self.state.reporting),
            First::Send=>self.state.query_sender.failure().or_else(||self.state.sender.failure()).or_else(||cause(&self.state.sent)),
            First::Admission=>cause(&self.admission),
            First::Receive=>self.state.chunk.as_ref().and_then(|c|c.failure(&self.state.received))
                .or_else(||self.state.received.failure()).or_else(||cause(&self.state.preparation)).or_else(||cause(&self.state.extension)),
            First::Reply=>self.state.data_failure.as_ref().map(|e|e as _).or_else(||cause(&self.state.reply)),
            First::After=>self.state.peer_after.as_deref().and_then(PeerSampleV1::failure).or_else(||cause(&self.state.after)),
            First::AfterClock=>self.state.after_clock.failure().or_else(||cause(&self.state.after_sample)),
            First::Temporal=>cause(&self.state.temporal),
            First::Settlement=>self.state.peer_before.as_deref().and_then(PeerSampleV1::failure).or_else(||self.state.peer_after.as_deref().and_then(PeerSampleV1::failure)).or_else(||cause(&self.state.settlement)),
        }.or(Some(&self.closed as _))
    }
}

/// Lends actual Root reply, original lease and immutable accepted horizon.
///
/// Private fields prevent parsed bytes from constructing this positive owner.
#[doc(hidden)]
pub struct RootStorageApplyAdmissionOriginalV1<'a> {
    client:&'a RootStorageApplyClientOriginalV1,
    lease:&'a aos_sandbox_ownership_protocol::SignedOwnershipLease,
    receiving:&'a crate::CreateProvisioningOriginalsV1,
    controller:&'a Journal,
}

impl RootStorageApplyAdmissionOriginalV1<'_> {
    /// Returns the genuine accepted parent retained by the actual client.
    #[must_use]
    pub const fn parent_operation_v1(&self) -> aos_sandbox_core::OperationId {
        self.client.parent
    }

    pub(crate) fn require_current_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        if !self.receiving.belongs_to_operation_v1(self.client.parent)
            || !self.receiving.has_same_profile_v1(&self.client.profile) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.receiving.require_current_v1(self.controller)
    }

    /// Borrows the independently normalized unsigned plan and statement.
    ///
    /// # Errors
    /// Refuses malformed retained framing; no buffer is copied or adopted.
    pub fn reply_v1(&self)->Result<StorageApplyReplyDataV1<'_>,Closed> {
        StorageApplyReplyDataV1::decode_v1(self.client.state.received.bytes()).map_err(|_|self.client.closed)
    }

    /// Borrows the same previously verified signed ownership lease.
    #[must_use]
    pub const fn lease_v1(&self)->&aos_sandbox_ownership_protocol::SignedOwnershipLease {self.lease}

    /// Returns the actual accepted sample and unchanged original cutoff.
    #[must_use]
    pub fn original_horizon_v1(&self)->(RawPairedClockSample,u64) {(self.client.origin,self.client.original_cutoff)}

    /// Returns the already checked minimum original authority cutoff.
    ///
    /// # Errors
    /// Refuses missing retained temporal completion.
    pub fn cutoff_v1(&self)->Result<u64,Closed> {
        self.client.state.temporal.as_ref().and_then(|r|r.as_ref().ok()).copied().ok_or(self.client.closed)
    }
}

fn positive<T>(slot:&Option<Result<T,ApplyRootDataErrorV1>>)->Result<&T,ApplyRootDataErrorV1> {
    slot.as_ref().and_then(|r|r.as_ref().ok()).ok_or(ApplyRootDataErrorV1::Malformed)
}
fn cause<T,E:Error+'static>(slot:&Option<Result<T,E>>)->Option<&(dyn Error+'static)> {
    slot.as_ref()?.as_ref().err().map(|cause|cause as _)
}

fn require_temporal_v1(origin:RawPairedClockSample,cutoff:u64,query:StorageApplyQueryDataV1,
    admission:StorageApplyAdmissionDataV1,before:RawPairedClockSample,after:RawPairedClockSample,
    lease_issued:i64,lease_expires:i64,preparation_cutoff:u64,
)->Result<u64,ApplyRootDataErrorV1> {
    let bad=||ApplyRootDataErrorV1::Malformed;
    origin.validate_later_sample(before).map_err(|_|bad())?;
    before.validate_later_sample(after).map_err(|_|bad())?;
    let observed=RawPairedClockSample::new_untrusted(origin.provenance(),admission.original_boot,
        admission.observed_wall_seconds,admission.observed_boottime_ns).map_err(|_|bad())?;
    before.validate_later_sample(observed).map_err(|_|bad())?;
    observed.validate_later_sample(after).map_err(|_|bad())?;
    let lease_cutoff=before.conservative_expiry_deadline_data_v1(lease_expires).ok_or_else(bad)?;
    let policy_cutoff=before.conservative_expiry_deadline_data_v1(admission.policy_expires_seconds).ok_or_else(bad)?;
    let root_flight=observed.boottime_nanoseconds().checked_add(65_000_000_000).ok_or_else(bad)?;
    let bound=cutoff.min(preparation_cutoff).min(lease_cutoff).min(policy_cutoff).min(root_flight)
        .min(admission.preparation_expires_boottime_ns).min(admission.cutoff_ns);
    if admission.controller_nonce!=query.controller_nonce || admission.query_digest!=query.digest_v1()?
        || admission.original_boot!=origin.host_boot_id()
        || admission.original_boottime_ns!=origin.boottime_nanoseconds()
        || admission.original_cutoff_ns!=cutoff || admission.lease_expires_seconds!=lease_expires
        || before.wall_seconds()<lease_issued || after.wall_seconds()>=lease_expires
        || after.wall_seconds()>=admission.policy_expires_seconds
        || after.boottime_nanoseconds()>=bound {return Err(bad());}
    Ok(bound)
}

impl Drop for RootStorageApplyClientOriginalV1 {
    fn drop(&mut self) {
        if !self.terminal_complete {
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::RawClockProvenance;

    fn sample(wall:i64,boot:u64)->RawPairedClockSample {
        RawPairedClockSample::new_untrusted(RawClockProvenance::new_untrusted([1;16]).unwrap(),
            [2;16],wall,boot*1_000_000_000).unwrap()
    }

    fn data()->(StorageApplyQueryDataV1,StorageApplyAdmissionDataV1) {
        let query=StorageApplyQueryDataV1 {controller_nonce:[3;16],original_boot:[2;16],
            original_boottime_ns:10_000_000_000,original_cutoff_ns:70_000_000_000,
            subject_bytes:1234,subject_digest:[4;32],controller_next:19,controller_end:9876};
        let admission=StorageApplyAdmissionDataV1 {root_nonce:[5;16],controller_nonce:query.controller_nonce,
            query_digest:query.digest_v1().unwrap(),original_boot:query.original_boot,
            original_boottime_ns:query.original_boottime_ns,original_cutoff_ns:query.original_cutoff_ns,
            observed_wall_seconds:102,observed_boottime_ns:12_000_000_000,cutoff_ns:65_000_000_000,
            policy_expires_seconds:200,lease_expires_seconds:190,preparation_expires_boottime_ns:69_000_000_000};
        (query,admission)
    }

    #[test]
    fn opening_requires_same_query_and_native_clock_bracket() {
        let (query,admission)=data();
        let check=|q,a,after|require_temporal_v1(sample(100,10),70_000_000_000,q,a,
            sample(101,11),after,90,190,60_000_000_000);

        assert_eq!(check(query,admission,sample(103,13)).unwrap(),60_000_000_000);
        let mut foreign=query;
        foreign.controller_end+=1;
        assert!(check(foreign,admission,sample(103,13)).is_err());
        assert!(check(query,admission,sample(101,11)).is_err());
    }

    #[test]
    fn actual_preparation_horizon_cannot_be_extended_by_root_data() {
        let (query,mut admission)=data();
        admission.cutoff_ns=68_000_000_000;
        let result=require_temporal_v1(sample(100,10),70_000_000_000,query,admission,
            sample(101,11),sample(160,70),90,190,60_000_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn reply_cannot_replace_original_or_verified_lease_horizon() {
        let (query,mut admission)=data();
        admission.lease_expires_seconds+=1;
        assert!(require_temporal_v1(sample(100,10),70_000_000_000,query,admission,
            sample(101,11),sample(103,13),90,190,60_000_000_000).is_err());
        admission.lease_expires_seconds=190;
        admission.original_boottime_ns+=1;
        assert!(require_temporal_v1(sample(100,10),70_000_000_000,query,admission,
            sample(101,11),sample(103,13),90,190,60_000_000_000).is_err());
    }

    #[test]
    fn client_policy_translation_can_tighten_a_timely_root_cutoff() {
        let (query, mut admission) = data();
        admission.policy_expires_seconds = 120;
        admission.observed_boottime_ns = 12_500_000_000;
        admission.cutoff_ns = 29_500_000_000;

        let validated = require_temporal_v1(sample(100, 10), 70_000_000_000,
            query, admission, sample(101, 11), sample(103, 13),
            90, 190, 60_000_000_000).unwrap();

        assert_eq!(validated, 29_000_000_000);
        assert!(validated < admission.cutoff_ns);
        assert!(require_temporal_v1(sample(100, 10), 70_000_000_000,
            query, admission, sample(101, 11), sample(120, 30),
            90, 190, 60_000_000_000).is_err());
    }
}
