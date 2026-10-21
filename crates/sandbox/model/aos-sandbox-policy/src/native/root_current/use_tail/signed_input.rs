//! Retains the actual signed index/chunks and their genuine phase borrowers.
//!
//! The surrounding purpose owns admissions, original writer/live bookends and
//! verification. These private factories borrow those actual phase owners;
//! indexed bytes remain DATA, with no supplied receiving completion or grant.

use std::collections::TryReserveError;
use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::receiving::RootSelectedControllerSubjectSampleV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::unix_stream::{RetainedSubjectStreamReadV1, SubjectStreamReadErrorV1, SubjectStreamReceiveGeometryV1};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, indexed_transfer::IndexedTransferPurposeDataV1,
    transport::{FRAME_HEADER_BYTES, INDEX_BYTES, CHUNK_HEADER_BYTES,
        FrameCoordinatesV1, FrameEnvelopeV1, FrameKindV1, TransferIndexV1},
};
use crate::native::PolicyNativeJournalErrorV1 as NativeError;
use super::super::initial_open::{RootInitialOpenErrorV1, RootInitialOpenPreparedOriginalV1};
use super::super::initial_ready::RootInitialReadyOriginalV1;
use super::super::initial_receiving::RootInitialStageOriginalV1;
use super::super::initial_source_exchange::{RootInitialSourceExchangeErrorV1, RootInitialSourceExchangeOriginalV1};
use super::super::initial_subject::{RootInitialSubjectOriginalV1, RootInitialSubjectFrameBorrowV1};
use super::super::owned::RootCurrentAcceptedOriginalsV1;
use super::reserved::{RootUseReservedOriginalV1, RootUseReservedErrorV1};
use super::admitted::{RootUseAdmittedOriginalV1, RootUseAdmittedErrorV1};
use aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::SignedPreparationBundleDataV1;

/// Retains the actual signed receiving or canonical comparison refusal.
#[derive(Debug, thiserror::Error)]
pub enum RootSignedInputErrorV1 {
    /// Retains the same actual Open/subject/receiving-stage refusal.
    #[error(transparent)]
    Open(#[from] RootInitialOpenErrorV1),
    /// Retains refusal of the actual preceding Admitted owner.
    #[error(transparent)]
    Phase(#[from] RootUseAdmittedErrorV1),
    /// Retains refusal of the actual Reserved Controller owner.
    #[error(transparent)]
    Reserved(#[from] RootUseReservedErrorV1),
    /// Retains the actual same-file Controller model refusal.
    #[error(transparent)]
    Controller(#[from] super::super::initial_controller::RootInitialControllerReadonlyErrorV1),
    /// Retains the actual Source interval refusal.
    #[error(transparent)]
    Source(#[from] RootInitialSourceExchangeErrorV1),
    /// Retains an unrepresentable actual quote.
    #[error(transparent)]
    Native(#[from] NativeError),
    /// Retains the actual readonly model/geometry refusal.
    #[error(transparent)]
    Read(#[from] crate::native::readonly::RootReadonlyErrorV1),
    /// Retains canonical frame, sequence, count or digest refusal.
    #[error(transparent)]
    Format(#[from] HistoryErrorV1),
    /// The same physical frame or receiving programme is incomplete/reentered.
    #[error("signed input programme is incomplete")]
    Incomplete,
}
type E = RootSignedInputErrorV1;
type Slot<T, F = E> = Option<Result<T, F>>;

pub(in crate::native::root_current) struct RootSignedInputOriginalV1 {
    geometry: Result<SubjectStreamReceiveGeometryV1, SeqpacketError>,
    maxima: Slot<[usize; 3]>,
    cutoff: Slot<u64, RootInitialSourceExchangeErrorV1>,
    index_preparation: Slot<(),SubjectStreamReadErrorV1>,
    index_frame: RetainedSubjectStreamReadV1,
    index: Slot<TransferIndexV1,HistoryErrorV1>,
    first_sequence: Slot<u64>,
    extent: Slot<usize>,
    allocation: Slot<(), TryReserveError>,
    bytes: Vec<u8>,
    frame: Option<RetainedSubjectStreamReadV1>,
    frame_binding: Slot<(),HistoryErrorV1>,
    next_chunk: u32,
    chunks: RootInitialSubjectOriginalV1,
    digest: Slot<(),HistoryErrorV1>,
    decoded: Slot<(),HistoryErrorV1>,
    index_entered: bool,
    closed: bool,
}

impl RootSignedInputOriginalV1 {
    pub(in crate::native::root_current) fn new() -> Self {
        Self {
            geometry: RootSelectedControllerSubjectSampleV1::receive_geometry_v1(),
            maxima: None,
            cutoff: None,
            index_preparation: None,
            index_frame: RetainedSubjectStreamReadV1::new(),
            index: None,
            first_sequence: None,
            extent: None,
            allocation: None,
            bytes: Vec::new(),
            frame: None,
            frame_binding: None,
            next_chunk: 0,
            chunks: RootInitialSubjectOriginalV1::new(),
            digest: None,
            decoded: None,
            index_entered: false,
            closed: false,
        }
    }

    // Only the genuine containing purpose selects its own fixed/variable
    // Stage. The enum retains that actual borrow; callers cannot supply a quote
    // or acquire a public arbitrary-Stage receive constructor.
    pub(in crate::native::root_current) fn borrow_fixed_v1<'cut, 'startup>(
        &'cut mut self, originals: &'cut mut RootCurrentAcceptedOriginalsV1<'startup>,
        open: &'cut RootInitialOpenPreparedOriginalV1,
        ready: &'cut RootInitialReadyOriginalV1,
        phase: &'cut RootUseAdmittedOriginalV1, reserved: &'cut RootUseReservedOriginalV1,
        source: &'cut RootInitialSourceExchangeOriginalV1,
        stage: &'cut RootInitialStageOriginalV1,
    ) -> Result<RootSignedInputBorrowV1<'cut, 'startup>,E> {
        let scope = RootSignedInputBorrowV1 { state: self, originals, open, ready, phase,
            reserved, source,
            admission: InputAdmissionBorrowV1::Fixed(stage) };
        scope.require_fixed_v1()?;
        Ok(scope)
    }

    pub(in crate::native::root_current) fn borrow_variable_v1<'cut, 'startup>(
        &'cut mut self, originals: &'cut mut RootCurrentAcceptedOriginalsV1<'startup>,
        open: &'cut RootInitialOpenPreparedOriginalV1,
        ready: &'cut RootInitialReadyOriginalV1,
        phase: &'cut RootUseAdmittedOriginalV1, reserved: &'cut RootUseReservedOriginalV1,
        source: &'cut RootInitialSourceExchangeOriginalV1,
        stage: &'cut RootInitialStageOriginalV1,
    ) -> Result<RootSignedInputBorrowV1<'cut, 'startup>,E> {
        let scope = RootSignedInputBorrowV1 { state: self, originals, open, ready, phase,
            reserved, source,
            admission: InputAdmissionBorrowV1::Variable(stage) };
        scope.require_variable_v1()?;
        Ok(scope)
    }

    pub(in crate::native::root_current) fn index_data_v1(&self) -> Result<TransferIndexV1, E> {
        positive(&self.index).copied()
    }

    pub(in crate::native::root_current) fn received_bundle_v1(&self) -> Result<SignedPreparationBundleDataV1<'_>,E> {
        self.require_received_v1()?;
        SignedPreparationBundleDataV1::decode(&self.bytes, *positive(&self.maxima)?).map_err(E::from)
    }

    pub(in crate::native::root_current) fn received_bytes_v1(&self) -> Result<&[u8],E> {
        self.require_received_v1()?;
        Ok(&self.bytes)
    }

    pub(in crate::native::root_current) fn require_received_v1(&self) -> Result<(), E> {
        if self.closed || self.frame.is_some() || !self.chunks.disposed_v1() { return Err(E::Incomplete); }
        positive(&self.digest)?;
        positive(&self.decoded)?;
        Ok(())
    }

    pub(in crate::native::root_current) fn additional_received_demand_v1(&self, reserved: &RootUseReservedOriginalV1)
        -> Result<ResourceVector, E> {
        let index = positive(&self.index).map_err(|_| E::Incomplete)?;
        let raw = index.total();
        let policy = reserved.completed_controller_v1()?.prospective_use_plan_v1()?.trust_policy_length_v1();
        let parsed = raw.checked_add(u64::try_from(policy).map_err(|_| E::Native(NativeError::geometry()))?)
            .ok_or(E::Native(NativeError::geometry()))?;
        let cell = [std::mem::size_of::<aos_sandbox_model::model::Signature>(),
            std::mem::size_of::<aos_sandbox_model::BrokerAuthorizationPlan>(),
            std::mem::size_of::<aos_sandbox_model::BrokerGrant>(),
            std::mem::size_of::<aos_sandbox_model::FeatureRef>(),
            std::mem::size_of::<aos_sandbox_model::model::TrustPolicy>(),
            std::mem::size_of::<aos_sandbox_model::model::KeyReference>(),
            std::mem::size_of::<aos_sandbox_model::model::SignatureStatement>()].into_iter().max()
            .ok_or(E::Native(NativeError::geometry()))?;
        // Canonical prevalidation bounds collection count by actual encoded
        // bytes. Eight full carrier planes cover Vec growth/current values,
        // decoded plan/signature, reparsed ORIGINAL pinned trust policy and shared
        // request reencoding beside raw input. The policy extent is actual
        // captured configuration, not another supplied signing authority.
        let memory = parsed.checked_mul(u64::try_from(cell).map_err(|_| E::Native(NativeError::geometry()))?)
            .and_then(|bytes| bytes.checked_mul(8))
            .and_then(|bytes| bytes.checked_add(raw.checked_mul(3)?))
            .ok_or(E::Native(NativeError::geometry()))?;
        let wire = raw.checked_add(u64::from(index.count()).checked_mul((FRAME_HEADER_BYTES + CHUNK_HEADER_BYTES) as u64)
            .ok_or(E::Native(NativeError::geometry()))?).ok_or(E::Native(NativeError::geometry()))?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory).with(D::NetworkBytes, wire))
    }

    // Direct constructor/interface controls only. The containing purpose must pay
    // these before construction. Captured transfer/model backing remains in
    // additional_received_demand_v1; the actual subject programme is unchanged.
    pub(in crate::native::root_current) fn receiving_construction_bytes_v1() -> Option<usize> {
        // Literal Self construction and its returned Self are distinct from
        // the enclosing purpose's resident field header.
        let construction = size_of::<Self>().checked_mul(2)?;
        // Input::new constructs both originals before returning the complete
        // input. These transient returns are separate from its resident fields.
        let input_constructors = size_of::<RootInitialSubjectOriginalV1>().checked_mul(2)?
            .checked_add(size_of::<RetainedSubjectStreamReadV1>().checked_mul(2)?)?
            .checked_add(size_of::<Result<SubjectStreamReceiveGeometryV1, SeqpacketError>>()
                .checked_mul(3)?)?;

        // Both private factories construct a local scope, wrap/return it, and
        // receive the same actual original/phase/stage argument tuple.
        let factories = size_of::<RootSignedInputBorrowV1<'static, 'static>>().checked_mul(4)?
            .checked_add(size_of::<Result<RootSignedInputBorrowV1<'static, 'static>,E>>().checked_mul(2)?)?
            .checked_add(size_of::<InputAdmissionBorrowV1<'static>>().checked_mul(2)?)?
            .checked_add(size_of::<(&mut Self,&mut RootCurrentAcceptedOriginalsV1<'static>,
                &RootInitialOpenPreparedOriginalV1,&RootInitialReadyOriginalV1,
                &RootUseAdmittedOriginalV1,&RootUseReservedOriginalV1,
                &RootInitialSourceExchangeOriginalV1,&RootInitialStageOriginalV1)>().checked_mul(2)?)?;

        // Index, chunk frame-return sites each carry the actual subject
        // scope constructor/return and both typed Result interfaces.
        let frame_returns = size_of::<RootInitialSubjectFrameBorrowV1<'static, 'static>>()
            .checked_mul(4)?
            .checked_add(size_of::<Result<RootInitialSubjectFrameBorrowV1<'static, 'static>,
                RootInitialOpenErrorV1>>().checked_mul(2)?)?
            .checked_add(size_of::<Result<RootInitialSubjectFrameBorrowV1<'static, 'static>,E>>()
                .checked_mul(2)?)?;

        // Finite direct method receiver/return sites, stage-completion result,
        // positive-slot adapters and saved first-sequence Result planes. The
        // CONTROL-ROSTER records each source site; no MetadataEntries conversion.
        let interfaces = size_of::<&mut RootSignedInputBorrowV1<'static, 'static>>()
            .checked_mul(12)?
            .checked_add(size_of::<&RootSignedInputBorrowV1<'static, 'static>>().checked_mul(9)?)?
            .checked_add(size_of::<(&RootSignedInputBorrowV1<'static, 'static>,&RootInitialStageOriginalV1)>())?
            .checked_add(size_of::<Result<ResourceVector,RootInitialOpenErrorV1>>().checked_mul(2)?)?
            .checked_add(size_of::<Result<(), E>>().checked_mul(24)?)?
            .checked_add(size_of::<Result<bool, E>>())?
            .checked_add(size_of::<Result<u64, E>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<usize, E>>().checked_mul(4)?)?
            .checked_add(size_of::<Result<[usize; 3],E>>().checked_mul(2)?)?
            .checked_add(size_of::<Result<TransferIndexV1,HistoryErrorV1>>().checked_mul(2)?)?
            .checked_add(size_of::<Result<TransferIndexV1, E>>().checked_mul(2)?)?
            .checked_add(size_of::<Result<ResourceVector,E>>().checked_mul(2)?)?
            .checked_add(size_of::<Result<SignedPreparationBundleDataV1<'static>,E>>().checked_mul(2)?)?
            .checked_add(size_of::<Result<&[u8],E>>())?
            .checked_add(size_of::<Option<&(dyn Error+'static)>>().checked_mul(29)?)?;

        // Each positive-slot adapter has a concrete borrowed-T Result at its
        // helper return and callsite; these do not reuse the resident slot.
        let adapters = 0_usize
            .checked_add(size_of::<Result<&[usize; 3],E>>().checked_mul(12)?)?
            .checked_add(size_of::<Result<&u64,E>>().checked_mul(8)?)?
            .checked_add(size_of::<Result<&(),E>>().checked_mul(22)?)?
            .checked_add(size_of::<Result<&TransferIndexV1,E>>().checked_mul(18)?)?
            .checked_add(size_of::<Result<&usize,E>>().checked_mul(8)?)?;

        // New quote checked-sum scalar locals, Option returns and source-native
        // first-sequence/active-frame branches are explicit Memory controls.
        let quote = size_of::<usize>().checked_mul(12)?
            .checked_add(size_of::<Option<usize>>().checked_mul(40)?)?
            .checked_add(size_of::<(&Self,&RootUseReservedOriginalV1)>())?
            .checked_add(size_of::<(&Self,&RetainedSubjectStreamReadV1)>())?
            .checked_add(size_of::<Option<&RetainedSubjectStreamReadV1>>().checked_mul(2)?)?
            .checked_add(size_of::<bool>().checked_mul(22)?)?;
        construction.checked_add(input_constructors)?.checked_add(factories)?.checked_add(frame_returns)?
            .checked_add(interfaces)?.checked_add(adapters)?.checked_add(quote)
    }

    pub(in crate::native::root_current) fn geometry_failure_v1(&self)
        -> Option<&(dyn Error+'static)>
    {
        self.geometry.as_ref().err().map(|cause|cause as _)
    }

    pub(in crate::native::root_current) fn before_variable_failure_v1(&self)
        -> Option<&(dyn Error+'static)>
    {
        if let Some(cause) = cause(&self.maxima) { return Some(cause); }
        if let Some(cause) = cause(&self.cutoff) { return Some(cause); }
        if let Some(cause) = self.index_frame.failure() { return Some(cause); }
        if let Some(cause) = cause(&self.index_preparation) { return Some(cause); }
        if let Some(cause) = cause(&self.index) { return Some(cause); }
        None
    }

    pub(in crate::native::root_current) fn after_variable_failure_v1(&self)
        -> Option<&(dyn Error+'static)>
    {
        if let Some(cause) = cause(&self.first_sequence) { return Some(cause); }
        if let Some(cause) = cause(&self.extent) { return Some(cause); }
        if let Some(cause) = cause(&self.allocation) { return Some(cause); }
        if let Some(frame) = self.frame.as_ref() {
            if let Some(cause) = frame.failure() { return Some(cause); }
        }
        let active = self.frame.as_ref().unwrap_or(&self.index_frame);
        if let Some(cause) = self.chunks.failure_v1(active) { return Some(cause); }
        if let Some(cause) = cause(&self.frame_binding) { return Some(cause); }
        if let Some(cause) = cause(&self.digest) { return Some(cause); }
        if let Some(cause) = cause(&self.decoded) { return Some(cause); }
        None
    }

    pub(in crate::native::root_current) fn failure_v1(&self) -> Option<&(dyn Error+'static)> {
        if let Some(cause) = self.geometry_failure_v1() { return Some(cause); }
        if let Some(cause) = self.before_variable_failure_v1() { return Some(cause); }
        self.after_variable_failure_v1()
    }

}

enum InputAdmissionBorrowV1<'cut> {
    Fixed(&'cut RootInitialStageOriginalV1),
    Variable(&'cut RootInitialStageOriginalV1),
}

/// Borrows the same real Admitted/Reserved owners and private received slots.
///
/// The constructor stays in native Root. No public Stage/vector, mutable frame getter,
/// supplied bytes or caller-owned completion can construct this borrower.
pub struct RootSignedInputBorrowV1<'cut, 'startup> {
    state: &'cut mut RootSignedInputOriginalV1,
    admission: InputAdmissionBorrowV1<'cut>,
    originals: &'cut mut RootCurrentAcceptedOriginalsV1<'startup>,
    open: &'cut RootInitialOpenPreparedOriginalV1,
    ready: &'cut RootInitialReadyOriginalV1,
    phase: &'cut RootUseAdmittedOriginalV1,
    reserved: &'cut RootUseReservedOriginalV1,
    source: &'cut RootInitialSourceExchangeOriginalV1,
}

impl<'startup> RootSignedInputBorrowV1<'_, 'startup> {
    fn require_stage_v1(&self, stage: &RootInitialStageOriginalV1) -> Result<(), E> {
        self.phase.require_complete_v1()?;
        self.reserved.require_complete_v1()?;
        stage.require_complete_v1()?;
        let financial = stage.financial.as_ref().ok_or(E::Incomplete)?;
        if self.state.closed || !self.phase.same_financial_v1(financial)
            || !self.reserved.same_financial_v1(financial) { return Err(E::Incomplete); }
        Ok(())
    }

    fn require_fixed_v1(&self) -> Result<(), E> {
        match &self.admission {
            InputAdmissionBorrowV1::Fixed(stage) => self.require_stage_v1(stage),
            InputAdmissionBorrowV1::Variable(_) => Err(E::Incomplete),
        }
    }

    fn require_variable_v1(&self) -> Result<(), E> {
        match &self.admission {
            InputAdmissionBorrowV1::Variable(stage) => self.require_stage_v1(stage),
            InputAdmissionBorrowV1::Fixed(_) => Err(E::Incomplete),
        }
    }

    /// Returns the same received index DATA without granting phase completion.
    ///
    /// # Errors
    /// Refuses absent or failed canonical index decoding.
    pub fn index_data_v1(&self) -> Result<TransferIndexV1, E> {
        self.state.index_data_v1()
    }

    fn maxima_data_v1(&self) -> Result<[usize; 3],E> {
        let plan = self.reserved.completed_controller_v1()?.prospective_use_plan_v1()?;
        Ok([plan.preparation_data_v1().canonical_plan().len(),
            plan.signature_maximum_bytes_v1(),plan.request_body_maximum_bytes_v1()])
    }

    fn decode_index_data_v1(&self) -> Result<TransferIndexV1,HistoryErrorV1> {
        let body = self.open.body_v1().map_err(|_|HistoryErrorV1::Correlation)?;
        let sequence = 10_u64.checked_add(u64::from(self.ready.original_transfer_index_v1()
            .map_err(|_|HistoryErrorV1::Correlation)?.count())).ok_or(HistoryErrorV1::Extent)?;
        let frame = FrameEnvelopeV1::decode(self.state.index_frame.bytes(),FrameCoordinatesV1 {
            kind:FrameKindV1::SignedIndex,lane:body.open.lane,sequence,
            root_nonce:body.root_nonce,controller_nonce:body.open.controller_nonce })?;
        let index = TransferIndexV1::decode(frame.payload())?;
        let maxima = *positive(&self.state.maxima).map_err(|_|HistoryErrorV1::Extent)?;
        let maximum = maxima.into_iter().try_fold(20_usize,|bytes,field|
            bytes.checked_add(field).ok_or(HistoryErrorV1::Extent))?;
        if index.total()>u64::try_from(maximum).map_err(|_|HistoryErrorV1::Extent)? { return Err(HistoryErrorV1::Extent); }
        Ok(index)
    }

    /// Borrows the first actual retained receive/canonical cause without IO.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error+'static)> { self.state.failure_v1() }

    /// Prepares only the fixed index frame at the original post-bookend slot.
    ///
    /// # Errors
    /// Refuses prior entry, incomplete actual phase, maxima/cutoff or allocation.
    pub fn prepare_index_once_v1(&mut self) -> Result<(), E> {
        self.require_fixed_v1()?;
        if self.state.index_entered || self.state.closed { self.state.closed = true; return Err(E::Incomplete); }
        self.state.index_entered = true;
        self.state.maxima = Some(self.maxima_data_v1());
        positive(&self.state.maxima)?;
        self.state.geometry.as_ref().map_err(|_|E::Incomplete)?;
        self.state.cutoff = Some(self.source.original_cutoff_v1());
        positive(&self.state.cutoff)?;
        self.state.index_preparation = Some(self.state.index_frame.prepare_exact_once(FRAME_HEADER_BYTES+INDEX_BYTES));
        positive(&self.state.index_preparation).map(|_|())
    }

    /// Borrows the actual fixed index through the sole same-peer subject engine.
    ///
    /// # Errors
    /// Refuses an absent fixed preparation, actual Source or retained native cause.
    pub fn borrow_index_frame_v1(&mut self) -> Result<RootInitialSubjectFrameBorrowV1<'_, 'startup>,E> {
        self.require_fixed_v1()?;
        positive(&self.state.index_preparation)?;
        let geometry = *self.state.geometry.as_ref().map_err(|_|E::Incomplete)?;
        self.state.chunks.borrow_source_frame_v1(&mut self.state.index_frame,
            self.originals,self.open,self.source,geometry).map_err(E::from)
    }

    /// Decodes the original index before any variable receiving/growth.
    ///
    /// # Errors
    /// Refuses incomplete frame/subject disposal, wrong coordinates or maxima.
    pub fn decode_index_once_v1(&mut self) -> Result<(), E> {
        self.require_fixed_v1()?;
        if self.state.index.is_some() || self.state.closed || !self.state.chunks.disposed_v1()
            || !self.state.index_frame.completed_exact() { return Err(E::Incomplete); }
        self.state.index = Some(self.decode_index_data_v1());
        positive(&self.state.index).map(|_|())
    }

    /// Saves the original first sequence after Variable and before the indexed programme.
    ///
    /// # Errors
    /// Refuses failed actual Stage, absent index, reentry or sequence overflow.
    pub fn begin_chunks_once_v1(&mut self) -> Result<(), E> {
        self.require_variable_v1()?;
        positive(&self.state.index)?;
        if self.state.first_sequence.is_some() { self.state.closed = true; return Err(E::Incomplete); }
        self.state.first_sequence = Some(self.first_sequence_v1());
        positive(&self.state.first_sequence).map(|_|())
    }

    /// Retains the actual indexed extent conversion without accepting a supplied extent.
    ///
    /// # Errors
    /// Refuses failed actual Stage, absent first sequence, reentry or extent overflow.
    pub fn prepare_extent_once_v1(&mut self) -> Result<usize, E> {
        self.require_variable_v1()?;
        positive(&self.state.first_sequence)?;
        if self.state.extent.is_some() { self.state.closed = true; return Err(E::Incomplete); }
        self.state.extent = Some(self.extent_data_v1());
        positive(&self.state.extent).copied()
    }

    fn extent_data_v1(&self) -> Result<usize, E> {
        let index = *positive(&self.state.index)?;
        aos_sandbox_broker::root_indexed_transfer_extent_v1! {
            index:index,total:total,error:E::from(HistoryErrorV1::Extent)
        }
        Ok(total)
    }

    /// Allocates only from this scope's actual converted extent and complete Variable.
    ///
    /// # Errors
    /// Refuses unrelated/failed original financial custody, reentry or allocation.
    pub fn allocate_once_v1(&mut self) -> Result<(), E> {
        self.require_variable_v1()?;
        if self.state.allocation.is_some() { self.state.closed = true; return Err(E::Incomplete); }
        let total = *positive(&self.state.extent)?;
        let allocation = &mut self.state.allocation; let bytes = &mut self.state.bytes;
        aos_sandbox_broker::root_indexed_transfer_allocate_v1! {allocation:allocation,bytes:bytes,total:total,positive:positive}
        Ok(())
    }

    /// Reports whether the same allocated transfer still has an original chunk.
    ///
    /// # Errors
    /// Refuses absent allocation or index.
    pub fn has_next_v1(&self) -> Result<bool, E> {
        self.require_variable_v1()?;
        positive(&self.state.allocation)?;
        Ok(self.state.next_chunk<positive(&self.state.index)?.count())
    }

    /// Prepares one bounded chunk with the sole indexed mechanical recipe.
    ///
    /// # Errors
    /// Refuses failed actual Stage, retained prior frame or invalid next extent.
    pub fn prepare_frame_once_v1(&mut self) -> Result<(), E> {
        self.require_variable_v1()?;
        if !self.has_next_v1()? || self.state.frame.is_some() { self.state.closed = true; return Err(E::Incomplete); }
        let index = *positive(&self.state.index)?; let next_chunk = &mut self.state.next_chunk; let frame = &mut self.state.frame;
        aos_sandbox_broker::root_indexed_transfer_prepare_frame_v1! {index:index,next_chunk:next_chunk,frame:frame,current_frame:current_frame,error:E::Incomplete}
        let _ = current_frame;
        Ok(())
    }

    /// Borrows that exact chunk through the existing same-peer Source frame.
    ///
    /// # Errors
    /// Refuses failed actual Stage, missing frame or actual Source/Open refusal.
    pub fn borrow_chunk_frame_v1(&mut self)
        ->Result<RootInitialSubjectFrameBorrowV1<'_, 'startup>,E>
    {
        self.require_variable_v1()?;
        let geometry = *self.state.geometry.as_ref().map_err(|_|E::Incomplete)?;
        let frame = self.state.frame.as_mut().ok_or(E::Incomplete)?;
        self.state.chunks.borrow_source_frame_v1(frame,self.originals,self.open,self.source,geometry).map_err(E::from)
    }

    fn first_sequence_v1(&self) -> Result<u64, E> {
        11_u64.checked_add(u64::from(self.ready.original_transfer_index_v1()?.count())).ok_or_else(||E::from(HistoryErrorV1::Extent))
    }

    /// Validates and copies only the exact received frame into its owned Vec.
    ///
    /// # Errors
    /// Refuses failed actual Stage/subject, wrong framing, cumulative or capacity bounds.
    pub fn bind_copy_frame_once_v1(&mut self) -> Result<(), E> {
        self.require_variable_v1()?;
        if self.state.frame_binding.is_some() || !self.state.chunks.disposed_v1() { return Err(E::Incomplete); }
        let body = self.open.body_v1()?; let index = *positive(&self.state.index)?;
        let total = *positive(&self.state.extent)?;
        let maxima = *positive(&self.state.maxima)?;
        let purpose = IndexedTransferPurposeDataV1::Signed {maxima};
        let first_sequence = *positive(&self.state.first_sequence)?;
        let current_frame = self.state.frame.as_mut().ok_or(E::Incomplete)?;
        if !current_frame.completed_exact() { return Err(E::Incomplete); }
        let frame_binding = &mut self.state.frame_binding; let next_chunk = &mut self.state.next_chunk; let bytes = &mut self.state.bytes;
        aos_sandbox_broker::root_indexed_transfer_bind_copy_v1! {frame_binding:frame_binding,current_frame:current_frame,purpose:purpose,body:body,first_sequence:first_sequence,next_chunk:next_chunk,index:index,bytes:bytes,total:total,positive:positive}
        Ok(())
    }

    /// Disposes only a positive bound/copied frame before the next original.
    ///
    /// # Errors
    /// Leaves negative native custody resident; refuses failed Stage or overflow.
    pub fn dispose_frame_once_v1(&mut self) -> Result<(), E> {
        self.require_variable_v1()?;
        positive(&self.state.frame_binding)?;
        if !self.state.chunks.disposed_v1() { return Err(E::Incomplete); }
        let frame = &mut self.state.frame; let frame_binding = &mut self.state.frame_binding; let next_chunk = &mut self.state.next_chunk;
        aos_sandbox_broker::root_indexed_transfer_dispose_frame_v1! {frame:frame,frame_binding:frame_binding,next_chunk:next_chunk,error:E::Incomplete}
        Ok(())
    }

    /// Checks the original total and commitment without changing the grammar.
    ///
    /// # Errors
    /// Refuses failed Stage, pending frame/chunks, wrong total or commitment.
    pub fn digest_once_v1(&mut self) -> Result<(), E> {
        self.require_variable_v1()?;
        if self.state.digest.is_some() || self.has_next_v1()? || self.state.frame.is_some() { return Err(E::Incomplete); }
        let index = *positive(&self.state.index)?; let total = *positive(&self.state.extent)?;
        let maxima = *positive(&self.state.maxima)?; let purpose = IndexedTransferPurposeDataV1::Signed {maxima};
        let digest = &mut self.state.digest; let bytes = &mut self.state.bytes;
        aos_sandbox_broker::root_indexed_transfer_digest_v1! {digest:digest,bytes:bytes,total:total,purpose:purpose,index:index,positive:positive}
    }

    /// Parses the same complete canonical bundle after digest and before later work.
    ///
    /// # Errors
    /// Retains the actual canonical decoder refusal; rejects repeated decoding.
    pub fn decode_bundle_once_v1(&mut self) -> Result<(), E> {
        self.require_variable_v1()?;
        positive(&self.state.digest)?;
        if self.state.decoded.is_some() { self.state.closed = true; return Err(E::Incomplete); }
        self.state.decoded = Some(SignedPreparationBundleDataV1::decode(&self.state.bytes,*positive(&self.state.maxima)?).map(|_|()));
        positive(&self.state.decoded).map(|_|())
    }
}

fn positive<T,F>(slot:&Option<Result<T,F>>)->Result<&T,E> {
    slot.as_ref().and_then(|result|result.as_ref().ok()).ok_or(E::Incomplete)
}

fn cause<T,F:Error+'static>(slot:&Option<Result<T,F>>)->Option<&(dyn Error+'static)> {
    slot.as_ref().and_then(|result|result.as_ref().err()).map(|cause|cause as _)
}
