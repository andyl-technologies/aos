//! Retains the exact sent CurrentProofs and received UseAuthorized native DATA.
//!
//! The Root loan supplies this private mechanical owner only after the genuine
//! Cache producer has completed. Receiving a valid frame does not construct U:
//! the original loan must close every owed post before lending these fields to
//! its same-bank purpose-15 issuer.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use aos_sandbox_linux::unix_stream::RetainedUnixStream;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1,
    cache_held::current_proof::CACHE_CURRENT_PROOF_PACKET_BYTES_V1,
    current_proofs::CurrentProofsDataV1,
    ready::InputsReadyNativeReceiptDataV1,
    root_open::RootHelloDataV1,
    transport::{FrameCoordinatesV1, FrameEnvelopeV1, FrameKindV1, TransferIndexV1,
        FRAME_HEADER_BYTES},
    use_authorized::{UseAuthorizedBodyDataV1, UseAuthorizedNativeReceiptDataV1,
        CURRENT_PROOFS_PAYLOAD_BYTES_V1, USE_AUTHORIZED_FRAME_BYTES_V1,
        current_proofs_commitment_v1},
};

use crate::policy_compiler::bounded_stream_io::{
    DeadlineStreamDirectionV1, FixedDeadlineStreamIoV1,
};
use crate::controller_resource_reservation::ResourceReservationErrorV1;

use super::{CacheControlOriginalsV1, CacheCurrentnessOriginalV1,
    CreateContinuationCaptureOwnerV1, CreateStorageRootExchangeClosedV1,
    CreateStorageRootPeerReceivingOriginalsV1, OriginalCreateStorageReadyV1,
    OriginalCreateStorageRootExchangeV1, RootExchangeOriginalsV1,
    RootPostFrontierV1, RootReceivePurposeV1, RootExactSubjectReceiveV1};
use super::super::super::history::inputs_ready::InputsReadyOriginalsV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::ready::InputsReadyBodyDataV1;

const CURRENT_PROOFS_FRAME_BYTES: usize = FRAME_HEADER_BYTES + CURRENT_PROOFS_PAYLOAD_BYTES_V1;

#[derive(Clone, Copy)]
enum FailureStage {
    ProofsEncoding,
    ProofsSend,
    AuthorizationFrame,
    AuthorizationBody,
    OriginalComparison,
    ProofsComparison,
    AssignmentComparison,
    LeaseComparison,
}

pub(super) struct RootUseAuthorizedOriginalsV1 {
    proofs_frame: [u8; CURRENT_PROOFS_FRAME_BYTES],
    proofs_encoding: Option<Result<(), HistoryErrorV1>>,
    proofs_commitment: Option<[u8; 32]>,
    proofs_send: FixedDeadlineStreamIoV1<CURRENT_PROOFS_FRAME_BYTES>,
    authorization_frame: [u8; USE_AUTHORIZED_FRAME_BYTES_V1],
    frame_decoding: Option<Result<(), HistoryErrorV1>>,
    body_decoding: Option<Result<UseAuthorizedBodyDataV1, HistoryErrorV1>>,
    originals: Option<Result<(), HistoryErrorV1>>,
    proofs: Option<Result<(), HistoryErrorV1>>,
    assignment: Option<Result<(), HistoryErrorV1>>,
    lease: Option<Result<(), HistoryErrorV1>>,
    first: Option<FailureStage>,
    closed: Option<HistoryErrorV1>,
}

impl Default for RootUseAuthorizedOriginalsV1 {
    fn default() -> Self {
        Self {
            proofs_frame: [0; CURRENT_PROOFS_FRAME_BYTES],
            proofs_encoding: None,
            proofs_commitment: None,
            proofs_send: Default::default(),
            authorization_frame: [0; USE_AUTHORIZED_FRAME_BYTES_V1],
            frame_decoding: None,
            body_decoding: None,
            originals: None,
            proofs: None,
            assignment: None,
            lease: None,
            first: None,
            closed: None,
        }
    }
}

impl RootUseAuthorizedOriginalsV1 {
    // Only the Root child can call this mechanical encoder. Its actual upper
    // entry must lend the completed Cache owner's packet, never a caller's
    // purported proof. The packet remains borrowed while exact bytes are copied.
    pub(super) fn prepare_current_proofs_once(
        &mut self,
        hello: &RootHelloDataV1<'_>,
        index: TransferIndexV1,
        controller: InputsReadyNativeReceiptDataV1<'_>,
        cache: &[u8; CACHE_CURRENT_PROOF_PACKET_BYTES_V1],
    ) -> Result<(), HistoryErrorV1> {
        if self.proofs_encoding.is_some() || self.closed.is_some() {
            return self.close();
        }
        self.proofs_encoding = Some((|| {
            if index.digest() != hello.body.open.ready {
                return Err(HistoryErrorV1::Correlation);
            }
            let payload: &mut [u8; CURRENT_PROOFS_PAYLOAD_BYTES_V1] =
                (&mut self.proofs_frame[FRAME_HEADER_BYTES..]).try_into()
                    .map_err(|_| HistoryErrorV1::Extent)?;
            CurrentProofsDataV1 { controller, cache_packet: cache }
                .encode_into(hello.body.open.lane, payload)?;
            self.proofs_commitment = Some(current_proofs_commitment_v1(payload));
            let header = coordinates(hello, index, FrameKindV1::CurrentProofs, 4)?
                .encode_header(payload)?;
            self.proofs_frame[..FRAME_HEADER_BYTES].copy_from_slice(&header);
            Ok(())
        })());
        if matches!(self.proofs_encoding, Some(Ok(()))) {
            Ok(())
        } else {
            self.first.get_or_insert(FailureStage::ProofsEncoding);
            Err(HistoryErrorV1::Correlation)
        }
    }

    pub(super) fn send_current_proofs_once(
        &mut self,
        stream: &mut RetainedUnixStream,
        cutoff: u64,
    ) -> Result<(), HistoryErrorV1> {
        if self.closed.is_some() || !matches!(self.proofs_encoding, Some(Ok(()))) {
            return self.close();
        }
        let sent = self.proofs_send.run_once(
            stream, &mut self.proofs_frame, cutoff, DeadlineStreamDirectionV1::Write,
        );
        if sent.is_err() {
            self.first.get_or_insert(FailureStage::ProofsSend);
        }
        sent
    }

    // This consumes the already retained strict subject receiver's exact
    // bytes. Every completed model/result is installed before a later equality
    // can refuse. The Source commitment remains authenticated Root DATA only.
    pub(super) fn compare_use_authorized_once(
        &mut self,
        bytes: &[u8],
        hello: &RootHelloDataV1<'_>,
        index: TransferIndexV1,
        inputs: InputsReadyNativeReceiptDataV1<'_>,
        assignment: [u8; 32],
        lease: [u8; 32],
    ) -> Result<(), HistoryErrorV1> {
        if self.frame_decoding.is_some() || self.closed.is_some()
            || !self.proofs_send.completed_exact() || self.proofs_send.failure().is_some() {
            return self.close();
        }
        self.frame_decoding = Some((|| {
            if index.digest() != hello.body.open.ready || bytes.len() != self.authorization_frame.len() {
                return Err(HistoryErrorV1::Correlation);
            }
            self.authorization_frame.copy_from_slice(bytes);
            FrameEnvelopeV1::decode(&self.authorization_frame,
                coordinates(hello, index, FrameKindV1::UseAuthorized, 5)?)?;
            Ok(())
        })());
        if !matches!(self.frame_decoding, Some(Ok(()))) {
            self.first.get_or_insert(FailureStage::AuthorizationFrame);
            return Err(HistoryErrorV1::Correlation);
        }

        // Exact frame validation already established the only payload offset.
        // Each later operation uses the same bytes, not a regenerated receipt.
        let receipt = UseAuthorizedNativeReceiptDataV1::decode(
            &self.authorization_frame[FRAME_HEADER_BYTES..], hello.body.open.lane,
        );
        self.body_decoding = Some(receipt.and_then(|receipt| receipt.body(hello.body.open.lane)));
        if !matches!(self.body_decoding, Some(Ok(_))) {
            self.first.get_or_insert(FailureStage::AuthorizationBody);
            return Err(HistoryErrorV1::Correlation);
        }
        self.originals = Some(receipt.and_then(|receipt| receipt.require_originals(hello, inputs)));
        if !matches!(self.originals, Some(Ok(()))) {
            self.first.get_or_insert(FailureStage::OriginalComparison);
            return Err(HistoryErrorV1::Correlation);
        }
        let body = self.body_decoding.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(HistoryErrorV1::Correlation)?;
        self.proofs = Some(if self.proofs_commitment == Some(body.current_proofs) {
            Ok(())
        } else { Err(HistoryErrorV1::Correlation) });
        if !matches!(self.proofs, Some(Ok(()))) {
            self.first.get_or_insert(FailureStage::ProofsComparison);
            return Err(HistoryErrorV1::Correlation);
        }
        self.assignment = Some(if body.assignment == assignment { Ok(()) }
            else { Err(HistoryErrorV1::Correlation) });
        if !matches!(self.assignment, Some(Ok(()))) {
            self.first.get_or_insert(FailureStage::AssignmentComparison);
            return Err(HistoryErrorV1::Correlation);
        }
        self.lease = Some(if body.ownership_lease == lease { Ok(()) }
            else { Err(HistoryErrorV1::Correlation) });
        if !matches!(self.lease, Some(Ok(()))) {
            self.first.get_or_insert(FailureStage::LeaseComparison);
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }

    // This is only the original fixed frame DATA. The completed Root/U lender
    // remains the sole caller boundary that can authorize later signing work.
    pub(super) fn original_authorization_frame_v1(&self)
        -> &[u8; USE_AUTHORIZED_FRAME_BYTES_V1]
    {
        &self.authorization_frame
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first {
            Some(FailureStage::ProofsEncoding) => cause(&self.proofs_encoding),
            Some(FailureStage::ProofsSend) => self.proofs_send.failure(),
            Some(FailureStage::AuthorizationFrame) => cause(&self.frame_decoding),
            Some(FailureStage::AuthorizationBody) => cause(&self.body_decoding),
            Some(FailureStage::OriginalComparison) => cause(&self.originals),
            Some(FailureStage::ProofsComparison) => cause(&self.proofs),
            Some(FailureStage::AssignmentComparison) => cause(&self.assignment),
            Some(FailureStage::LeaseComparison) => cause(&self.lease),
            None => None,
        }.or_else(|| self.closed.as_ref().map(|error| error as _))
    }

    fn close<T>(&mut self) -> Result<T, HistoryErrorV1> {
        self.closed.get_or_insert(HistoryErrorV1::Correlation);
        Err(HistoryErrorV1::Correlation)
    }
}

fn coordinates(
    hello: &RootHelloDataV1<'_>,
    index: TransferIndexV1,
    kind: FrameKindV1,
    base_sequence: u64,
) -> Result<FrameCoordinatesV1, HistoryErrorV1> {
    Ok(FrameCoordinatesV1 {
        kind,
        lane: hello.body.open.lane,
        sequence: u64::from(index.count()).checked_add(base_sequence)
            .ok_or(HistoryErrorV1::Extent)?,
        root_nonce: hello.body.root_nonce,
        controller_nonce: hello.body.open.controller_nonce,
    })
}

fn cause<T>(value: &Option<Result<T, HistoryErrorV1>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _)
}

#[derive(Clone, Copy)]
enum CurrentFailure {
    Originals,
    Geometry,
    Funding,
    Before,
    BeforePeer,
    Encoding,
    Send,
    SendPost,
    Receive,
    Comparison,
    ComparisonPost,
}

/// Retains the actual new turn's admission and chronological bookends.
#[derive(Default)]
pub(super) struct RootCurrentTurnGateOriginalsV1 {
    entered: bool,
    originals: Option<Result<([u8; 32], [u8; 32]), ResourceReservationErrorV1>>,
    base: Option<ResourceVector>,
    geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    before: CacheCurrentnessOriginalV1,
    before_result: Option<Result<(), ResourceReservationErrorV1>>,
    before_peer: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    encoding: Option<Result<(), HistoryErrorV1>>,
    sent: Option<Result<(), HistoryErrorV1>>,
    send_post: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    received: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    comparison: Option<Result<(), HistoryErrorV1>>,
    comparison_post: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    complete: bool,
    first: Option<CurrentFailure>,
}

impl RootCurrentTurnGateOriginalsV1 {
    pub(super) fn has_entered_v1(&self) -> bool { self.entered }

    pub(super) fn base_without_traffic_v1(&self) -> Option<ResourceVector> { self.base }

    pub(super) fn before_is_owed_v1(&self) -> bool {
        matches!(self.funding, Some(Ok(()))) && self.before_result.is_some()
            && self.before_peer.is_none()
    }

    pub(super) fn send_post_is_owed_v1(&self) -> bool {
        matches!(self.funding, Some(Ok(()))) && self.originals.is_some()
            && self.send_post.is_none()
    }

    pub(super) fn comparison_post_is_owed_v1(&self) -> bool {
        matches!(self.funding, Some(Ok(()))) && self.comparison.is_some()
            && self.comparison_post.is_none()
    }

    fn mark(&mut self, failed: bool, stage: CurrentFailure) {
        if failed { self.first.get_or_insert(stage); }
    }

    pub(super) fn failure<'cause>(&'cause self,
        actual: &'cause RootUseAuthorizedOriginalsV1,
        receiver: &'cause RootExactSubjectReceiveV1,
        peer: &'cause CreateStorageRootPeerReceivingOriginalsV1,
        property_geometry: &'cause Option<Result<ResourceVector, ResourceReservationErrorV1>>,
        property_funding: &'cause Option<Result<(), ResourceReservationErrorV1>>,
    ) -> Option<&'cause (dyn Error + 'static)> {
        match self.first? {
            CurrentFailure::Originals => original_cause(&self.originals),
            CurrentFailure::Geometry => original_cause(&self.geometry),
            CurrentFailure::Funding => original_cause(&self.funding),
            CurrentFailure::Before => self.before.failure().or_else(|| original_cause(&self.before_result)),
            CurrentFailure::BeforePeer => peer.failure().or_else(|| original_cause(&self.before_peer)),
            CurrentFailure::Encoding => actual.failure().or_else(|| cause(&self.encoding)),
            CurrentFailure::Send => actual.failure().or_else(|| cause(&self.sent)),
            CurrentFailure::SendPost => peer.failure().or_else(|| original_cause(&self.send_post)),
            CurrentFailure::Receive if receiver.admission_failure_is_selected_v1() =>
                original_cause(property_geometry).or_else(|| original_cause(property_funding))
                    .or_else(|| receiver.failure(peer)),
            CurrentFailure::Receive => receiver.failure(peer).or_else(|| original_cause(&self.received)),
            CurrentFailure::Comparison => actual.failure().or_else(|| cause(&self.comparison)),
            CurrentFailure::ComparisonPost => peer.failure().or_else(|| original_cause(&self.comparison_post)),
        }
    }

    fn receiving_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        use super::super::ownership::VerifiedCreateStorageOwnershipV1;
        use aos_sandbox_protocol::domain_ledger::create_storage_history::transport::TransferIndexV1;

        // Four fixed argument/local/return/comparison planes. The tuple also
        // names the temporary InputsReady/header arrays, hash state and all22
        // proposed receiving entries; no earlier unrelated scratch pays them.
        // Every member is a reached existing allocation-free DATA codec or an
        // actual borrowed original; no encoded width creates a native grant.
        type Models = (UseAuthorizedBodyDataV1, UseAuthorizedNativeReceiptDataV1<'static>,
            RootHelloDataV1<'static>, InputsReadyNativeReceiptDataV1<'static>,
            InputsReadyBodyDataV1, FrameCoordinatesV1, TransferIndexV1,
            FrameEnvelopeV1<'static>, VerifiedCreateStorageOwnershipV1<'static, 'static>,
            [u8; FRAME_HEADER_BYTES], [u8; 516], ResourceVector, sha2::Sha256,
            [u8; 32], [u8; 32]);
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(size_of::<RootUseAuthorizedOriginalsV1>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(size_of::<RootExactSubjectReceiveV1>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(size_of::<Models>().checked_mul(4)?))
            .and_then(|bytes| bytes.checked_add(USE_AUTHORIZED_FRAME_BYTES_V1))
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        // This new turn owns fixed buffers and fixed comparison DATA. It
        // creates no additional resident map/index/catalog namespace. Rust
        // Option/result/scalar fields are covered by compiled bytes rather
        // than being charged as namespace MetadataEntries. The earlier paid
        // raw subject/peer namespace peak is reused only after actual disposal.
        let fixed = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?)
            .with(D::NetworkBytes, (CURRENT_PROOFS_FRAME_BYTES + USE_AUTHORIZED_FRAME_BYTES_V1) as u64)
            .with(D::OutputBytes, CURRENT_PROOFS_FRAME_BYTES as u64);
        // Old positive subject chunks and peer/J originals are actually gone
        // before entry. On refusal the one extra before sample plus its single
        // owed Root pair fits the already-paid four-J-sample peak; failure
        // fences all later work. Its byte backing is additional; the reused
        // native namespace peak creates no new resident map/index entries.
        let backing = CacheCurrentnessOriginalV1::receiving_backing_demand_v1(1)?;
        Ok(fixed.checked_add(backing.with(D::MetadataEntries, 0))?)
    }
}

/// Borrows only the actual completed authenticated Root turn for same-C U.
///
/// No public constructor or conversion from frame/body/vector DATA exists.
/// The enclosing Ready retains the original stream, peer, Cache and writers.
/// Its genuine U issuer must independently derive the actual purpose15 shape,
/// ceiling and association before any bank/native mutation.
pub(in crate::controller_resource_reservation::create_intake)
struct OriginalCreateStorageRootUseAuthorizationV1<'held> {
    turn: &'held RootUseAuthorizedOriginalsV1,
    inputs: &'held InputsReadyOriginalsV1,
    hello: &'held aos_sandbox_protocol::domain_ledger::create_storage_history::root_open::RootOpenBodyDataV1,
}

impl<'held> OriginalCreateStorageRootUseAuthorizationV1<'held> {
    pub(in crate::controller_resource_reservation::create_intake)
    fn body_v1(&self) -> Result<&'held UseAuthorizedBodyDataV1, ResourceReservationErrorV1> {
        self.turn.body_decoding.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    // This passive borrow preserves the already-authenticated Root cutoff;
    // a parsed UseAuthorized body cannot supply or renew the Hello deadline.
    pub(in crate::controller_resource_reservation::create_intake)
    fn cutoff_v1(&self) -> Result<u64, ResourceReservationErrorV1> {
        Ok(self.body_v1()?.association.cutoff.min(self.hello.cutoff))
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn frame_v1(&self) -> &'held [u8; USE_AUTHORIZED_FRAME_BYTES_V1] {
        &self.turn.authorization_frame
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn inputs_ready_v1(&self) -> Result<InputsReadyNativeReceiptDataV1<'held>, ResourceReservationErrorV1> {
        self.inputs.native_receipt_v1()
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn association_v1(&self) -> Result<InputsReadyBodyDataV1, ResourceReservationErrorV1> {
        self.inputs.body_data_v1()
    }
}

impl RootExchangeOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake::ready)
    fn borrow_use_authorization_v1(&self)
        -> Result<OriginalCreateStorageRootUseAuthorizationV1<'_>, ResourceReservationErrorV1>
    {
        let gate = &self.turn.use_gate;
        if !gate.complete || gate.first.is_some() || self.failure().is_some()
            || !matches!(gate.funding, Some(Ok(())))
            || !matches!(gate.before_result, Some(Ok(())))
            || !matches!(gate.before_peer, Some(Ok(())))
            || !matches!(gate.sent, Some(Ok(()))) || !matches!(gate.send_post, Some(Ok(())))
            || !matches!(gate.received, Some(Ok(()))) || !matches!(gate.comparison, Some(Ok(())))
            || !matches!(gate.comparison_post, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.cache_current_proof.completed_packet_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let hello = self.turn.transport.hello_body()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok(OriginalCreateStorageRootUseAuthorizationV1 {
            turn: &self.turn.use_turn, inputs: &self.inputs, hello,
        })
    }
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Sends this original's completed CurrentProofs and receives Root's exact authorization turn.
    ///
    /// Every reached native/error original stays on this same Ready. The short
    /// private completed-turn borrower is solely an input to the genuine C-bank
    /// issuer; this method neither admits U nor runs Prepare or terminal release.
    ///
    /// # Errors
    /// Retains wrong original, fixed/reached admission, native send/receive,
    /// exact correlation, original cutoff or independently owed post refusal.
    #[doc(hidden)]
    pub fn exchange_root_current_turn_once(&mut self) -> Result<(), CreateStorageRootExchangeClosedV1> {
        if self.failure().is_some() || self.original.owner.root_exchange.turn.use_gate.entered {
            return Err(CreateStorageRootExchangeClosedV1);
        }
        self.original.owner.root_exchange.cache_current_proof.completed_packet_v1()?;
        self.original.owner.root_exchange.turn.use_gate.entered = true;
        let root = &mut self.original.owner.root_exchange;
        root.turn.use_gate.geometry = Some((|| {
            if !root.turn.ready_complete || !root.turn.invitation_complete {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let base = root.turn.cache_current.base_without_traffic_v1()
                .ok_or(ResourceReservationErrorV1::Conflict)?
                .checked_add(RootCurrentTurnGateOriginalsV1::receiving_demand_v1()?)?;
            root.turn.use_gate.base = Some(base);
            // RootBefore, send's independent post, and one entry/receiver
            // refusal post are all paid before any new bookend or allocation.
            let required = root.turn.property_used.checked_add(3)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let (wire, logs) = CreateStorageRootPeerReceivingOriginalsV1::query_traffic_v1(required)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            Ok(base.checked_add(ResourceVector::ZERO.with(D::NetworkBytes, wire).with(D::LogBytes, logs))?)
        })());
        root.turn.use_gate.mark(!matches!(root.turn.use_gate.geometry, Some(Ok(_))), CurrentFailure::Geometry);
        root.turn.use_gate.funding = Some(match &root.turn.use_gate.geometry {
            Some(Ok(demand)) => self.original.owner.intake.reserve_create_capture_complete(
                CreateContinuationCaptureOwnerV1::RootExchange, *demand),
            _ => Err(ResourceReservationErrorV1::Conflict),
        });
        root.turn.use_gate.mark(!matches!(root.turn.use_gate.funding, Some(Ok(()))), CurrentFailure::Funding);
        if root.turn.use_gate.first.is_some() { return Err(CreateStorageRootExchangeClosedV1); }
        root.turn.property_paid = root.turn.property_used.checked_add(3).ok_or(CreateStorageRootExchangeClosedV1)?;

        // The actual borrowed assignment/lease invocation and its copied
        // digests begin only after this turn's complete fixed admission.
        let originals = self.verified_ownership_v1().and_then(|actual| {
            actual.require_original()?;
            Ok((*actual.manifest().digest().as_bytes(), *actual.lease().digest().as_bytes()))
        });
        let gate = &mut self.original.owner.root_exchange.turn.use_gate;
        gate.originals = Some(originals);
        gate.mark(!matches!(gate.originals, Some(Ok(_))), CurrentFailure::Originals);
        let original_cutoff = self.original.accepted().map_err(|_| CreateStorageRootExchangeClosedV1)?.original_cutoff;
        let owner = &mut *self.original.owner;
        let root = &mut owner.root_exchange;
        let mut loan = OriginalCreateStorageRootExchangeV1 {
            use_receiving: None,
            parent: &owner.parent, intake: &mut owner.intake, controller: self.original.controller,
            source: self.original.source, profile: self.original.profile, cache: &mut self.cache,
            state: &mut root.turn,
        };
        loan.run_current_turn_once(&mut root.peer, &root.inputs, &root.cache_current_proof, original_cutoff)
    }
}

impl OriginalCreateStorageRootExchangeV1<'_, '_, '_> {
    fn run_current_turn_once(&mut self, peer: &mut CreateStorageRootPeerReceivingOriginalsV1,
        inputs: &InputsReadyOriginalsV1,
        cache: &super::super::cache_current_proof::OriginalCreateStorageCacheCurrentProofV1,
        original_cutoff: u64,
    ) -> Result<(), CreateStorageRootExchangeClosedV1> {
        let expected = self.state.expected_cache.ok_or(CreateStorageRootExchangeClosedV1)?;
        let position = self.state.expected_controller.ok_or(CreateStorageRootExchangeClosedV1)?;
        let cutoff = self.state.transport.hello_body().map_err(|_| CreateStorageRootExchangeClosedV1)?
            .cutoff.min(original_cutoff);
        if self.state.use_gate.first.is_none() {
            self.state.use_gate.before_result = Some(self.state.use_gate.before.observe_operation_once(
            CacheControlOriginalsV1 { parent: self.parent, intake: self.intake,
                controller: self.controller, source: self.source, profile: self.profile },
                self.cache, expected, Ok(position)));
            self.state.use_gate.mark(!matches!(self.state.use_gate.before_result, Some(Ok(()))), CurrentFailure::Before);
        }
        if self.state.use_gate.first.is_none() {
            self.state.owed_post = Some(RootPostFrontierV1::CurrentBefore);
            let result = peer.recheck_once(self);
            self.state.use_gate.before_peer = Some(result);
            self.state.use_gate.mark(!matches!(self.state.use_gate.before_peer, Some(Ok(()))), CurrentFailure::BeforePeer);
        }
        if self.state.use_gate.first.is_none() {
            self.state.use_gate.encoding = Some((|| {
                let open = self.state.transport.hello_body()?.open;
                let hello = RootHelloDataV1::decode(self.state.transport.hello_frame(), open)?;
                let index = self.state.transport.completed_index()?;
                let receipt = inputs.native_receipt_v1().map_err(|_| HistoryErrorV1::Correlation)?;
                let packet = cache.completed_packet_v1().map_err(|_| HistoryErrorV1::Correlation)?;
                self.state.use_turn.prepare_current_proofs_once(&hello, index, receipt, packet)
            })());
            self.state.use_gate.mark(!matches!(self.state.use_gate.encoding, Some(Ok(()))), CurrentFailure::Encoding);
        }
        if self.state.use_gate.first.is_none() {
            let state = &mut self.state;
            state.use_gate.sent = Some(match state.transport.stream_mut() {
                Ok(stream) => state.use_turn.send_current_proofs_once(stream, cutoff),
                Err(error) => Err(error),
            });
            state.use_gate.mark(!matches!(state.use_gate.sent, Some(Ok(()))), CurrentFailure::Send);
        }

        // The before pass, encoder and contacted send all share this one paid
        // independently owed Root/J post. Earlier cause selection stays fixed.
        self.state.owed_post = Some(RootPostFrontierV1::CurrentSendPost);
        let result = peer.recheck_once(self);
        self.state.use_gate.send_post = Some(result);
        self.state.use_gate.mark(!matches!(self.state.use_gate.send_post, Some(Ok(()))), CurrentFailure::SendPost);
        if self.state.use_gate.first.is_some() { return Err(CreateStorageRootExchangeClosedV1); }

        let geometry = CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1()
            .map_err(|_| CreateStorageRootExchangeClosedV1)?;
        let received = self.receive_root_subject_once(peer, cutoff, &geometry, RootReceivePurposeV1::Authorization);
        self.state.use_gate.received = Some(received);
        self.state.use_gate.mark(!matches!(self.state.use_gate.received, Some(Ok(()))), CurrentFailure::Receive);
        if self.state.use_gate.first.is_some() { return Err(CreateStorageRootExchangeClosedV1); }

        self.state.use_gate.comparison = Some((|| {
            let open = self.state.transport.hello_body()?.open;
            let hello = RootHelloDataV1::decode(self.state.transport.hello_frame(), open)?;
            let index = self.state.transport.completed_index()?;
            let receipt = inputs.native_receipt_v1().map_err(|_| HistoryErrorV1::Correlation)?;
            let (assignment, lease) = self.state.use_gate.originals.as_ref()
                .and_then(|result| result.as_ref().ok()).copied().ok_or(HistoryErrorV1::Correlation)?;
            self.state.use_turn.compare_use_authorized_once(self.state.authorization_receive.buffer.bytes(),
                &hello, index, receipt, assignment, lease)
        })());
        self.state.use_gate.mark(!matches!(self.state.use_gate.comparison, Some(Ok(()))), CurrentFailure::Comparison);
        self.state.owed_post = Some(RootPostFrontierV1::CurrentComparison);
        let result = peer.recheck_once(self);
        self.state.use_gate.comparison_post = Some(result);
        self.state.use_gate.mark(!matches!(self.state.use_gate.comparison_post, Some(Ok(()))), CurrentFailure::ComparisonPost);
        self.state.use_gate.complete = self.state.use_gate.first.is_none()
            && self.state.use_turn.failure().is_none();
        if self.state.use_gate.complete { Ok(()) } else { Err(CreateStorageRootExchangeClosedV1) }
    }
}

fn original_cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;
    use aos_sandbox_protocol::domain_ledger::create_storage_history::{
        association::AcceptedAssociationDataV1, KeyV1, LatestHeadV1, OwnerV1, PhaseV1,
        RecordCoordinatesV1, RecordEnvelopeV1,
        ready::INPUTS_READY_RECORD_BYTES_V1,
        root_open::RootOpenBodyDataV1,
        transport::OpenQueryV1,
        use_authorized::USE_AUTHORIZED_RECORD_BYTES_V1,
    };

    // Canonical comparison DATA only: no fixture constructs a native Root/J
    // original, accepted peer, signer authority, completed Ready or U grant.
    struct Fixture {
        hello: [u8; 612],
        input: [u8; INPUTS_READY_RECORD_BYTES_V1],
        input_head: [u8; 40],
        open: OpenQueryV1,
        names: ProtectedJournalNamesV1,
        association: AcceptedAssociationDataV1,
    }

    impl Fixture {
        fn new() -> Self {
            let names = ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6));
            let open = OpenQueryV1 { controller_nonce: [1; 16], lane: [2; 16],
                seed: [3; 32], ready: [4; 32] };
            let root = RootOpenBodyDataV1 { open, root_nonce: [5; 16], boot: [6; 16],
                started: 110, cutoff: 180, authority_names: names,
                policy_names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (7, 8), (9, 10)),
                authority_next: 10, policy_next: 1, root_profile: [12; 32],
                root_recipient: [13; 16], root_producer: [14; 16], root_pid: 15,
                controller_pid: 16, controller_uid: 17, controller_gid: 18 };
            let mut hello = [0; 612];
            RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
                key: KeyV1::new(open.lane, OwnerV1::Root, 1).unwrap(),
                phase: PhaseV1::new(OwnerV1::Root, 1).unwrap(),
                predecessor: [0; 32], correlation: open.seed,
            }, &root.encode().unwrap(), &mut hello[FRAME_HEADER_BYTES..]).unwrap();
            let header = FrameCoordinatesV1 { kind: FrameKindV1::Hello, lane: open.lane,
                sequence: 1, root_nonce: root.root_nonce, controller_nonce: open.controller_nonce }
                .encode_header(&hello[FRAME_HEADER_BYTES..]).unwrap();
            hello[..FRAME_HEADER_BYTES].copy_from_slice(&header);

            let association = AcceptedAssociationDataV1 { operation: [7; 16], project: [8; 16],
                sandbox: [9; 16], accepted_request: [10; 32], coissuance_binding: [11; 32],
                seed: open.seed, controller_nonce: open.controller_nonce, boot: root.boot,
                started: 100, cutoff: 200 };
            let body = InputsReadyBodyDataV1 { association, assignment_planned: [12; 32],
                ready: open.ready, bundle_bytes: 15 };
            let mut input = [0; INPUTS_READY_RECORD_BYTES_V1];
            let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
                key: KeyV1::new(open.lane, OwnerV1::Controller, 3).unwrap(),
                phase: PhaseV1::new(OwnerV1::Controller, 2).unwrap(),
                predecessor: body.assignment_planned, correlation: open.seed,
            }, &body.encode().unwrap(), &mut input).unwrap();
            Self { hello, input, input_head: LatestHeadV1::new(3, checksum).unwrap().encode(),
                open, names, association }
        }

        fn receipt(&self) -> InputsReadyNativeReceiptDataV1<'_> {
            InputsReadyNativeReceiptDataV1 { record: &self.input, latest_head: self.input_head,
                names: self.names, after_next: 20, after_end: 1000 }
        }
    }

    #[test]
    fn changed_ready_index_retains_first_encoding_failure_without_rearming() {
        let fixture = Fixture::new();
        let hello = RootHelloDataV1::decode(&fixture.hello, fixture.open).unwrap();
        let changed = TransferIndexV1::new(15, [42; 32]).unwrap();
        let mut owner = RootUseAuthorizedOriginalsV1::default();

        assert!(owner.prepare_current_proofs_once(&hello, changed, fixture.receipt(), &[7; 1064]).is_err());
        let first = owner.failure().unwrap() as *const dyn Error as *const ();
        assert!(!owner.proofs_send.completed_exact());
        assert!(owner.prepare_current_proofs_once(&hello,
            TransferIndexV1::new(15, fixture.open.ready).unwrap(), fixture.receipt(), &[8; 1064]).is_err());
        assert_eq!(owner.failure().unwrap() as *const dyn Error as *const (), first);
        assert!(owner.proofs_frame.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn real_sent_payload_and_canonical_authorization_survive_later_assignment_refusal() {
        let fixture = Fixture::new();
        let hello = RootHelloDataV1::decode(&fixture.hello, fixture.open).unwrap();
        let index = TransferIndexV1::new(15, fixture.open.ready).unwrap();
        let mut owner = RootUseAuthorizedOriginalsV1::default();
        // Arbitrary fixed Cache bytes test forwarding only. No Controller
        // signature verification or Root authorization is inferred from them.
        owner.prepare_current_proofs_once(&hello, index, fixture.receipt(), &[7; 1064]).unwrap();
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        owner.proofs_send.run_once(&mut sender, &mut owner.proofs_frame,
            u64::MAX, DeadlineStreamDirectionV1::Write).unwrap();
        let mut sent = [0; CURRENT_PROOFS_FRAME_BYTES];
        receiver.read_exact(&mut sent).unwrap();
        assert_eq!(sent, owner.proofs_frame);
        assert_eq!(owner.proofs_commitment,
            Some(current_proofs_commitment_v1(sent[FRAME_HEADER_BYTES..].try_into().unwrap())));

        let input_record = RecordEnvelopeV1::decode(&fixture.input,
            KeyV1::new(fixture.open.lane, OwnerV1::Controller, 3).unwrap(),
            PhaseV1::new(OwnerV1::Controller, 2).unwrap()).unwrap();
        let body = UseAuthorizedBodyDataV1 { association: fixture.association,
            root_nonce: hello.body.root_nonce, root_open: hello.checksum, ready: fixture.open.ready,
            inputs_ready: input_record.checksum(), current_proofs: owner.proofs_commitment.unwrap(),
            source_current: [15; 32], assignment: [16; 32], ownership_lease: [17; 32],
            receiving: ResourceVector::ZERO.with(D::MemoryBytes, 4096) };
        let mut record = [0; USE_AUTHORIZED_RECORD_BYTES_V1];
        let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key: KeyV1::new(fixture.open.lane, OwnerV1::Root, 2).unwrap(),
            phase: PhaseV1::new(OwnerV1::Root, 2).unwrap(),
            predecessor: hello.checksum, correlation: fixture.open.seed,
        }, &body.encode().unwrap(), &mut record).unwrap();
        let receipt = UseAuthorizedNativeReceiptDataV1 { record: &record,
            latest_head: LatestHeadV1::new(2, checksum).unwrap().encode(), names: fixture.names,
            after_next: hello.body.authority_next + 8, after_end: 10000 };
        let mut frame = [0; USE_AUTHORIZED_FRAME_BYTES_V1];
        frame[FRAME_HEADER_BYTES..].copy_from_slice(&receipt.encode(fixture.open.lane).unwrap());
        let header = coordinates(&hello, index, FrameKindV1::UseAuthorized, 5).unwrap()
            .encode_header(&frame[FRAME_HEADER_BYTES..]).unwrap();
        frame[..FRAME_HEADER_BYTES].copy_from_slice(&header);

        assert!(owner.compare_use_authorized_once(&frame, &hello, index,
            fixture.receipt(), [42; 32], body.ownership_lease).is_err());
        assert_eq!(owner.authorization_frame, frame);
        assert_eq!(owner.body_decoding.as_ref().unwrap().as_ref().unwrap(), &body);
        assert!(matches!(owner.originals, Some(Ok(()))));
        assert!(matches!(owner.proofs, Some(Ok(()))));
        assert!(matches!(owner.assignment, Some(Err(_))));
        assert!(owner.lease.is_none());
        let first = owner.failure().unwrap() as *const dyn Error as *const ();
        assert!(owner.compare_use_authorized_once(&[0; USE_AUTHORIZED_FRAME_BYTES_V1],
            &hello, index, fixture.receipt(), body.assignment, body.ownership_lease).is_err());
        assert_eq!(owner.authorization_frame, frame);
        assert_eq!(owner.failure().unwrap() as *const dyn Error as *const (), first);
    }
}
