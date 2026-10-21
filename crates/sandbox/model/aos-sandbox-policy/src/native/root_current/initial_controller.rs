//! Retains Initial's independent Controller capture and its three real stages.
//!
//! The actual Current owns this purpose beside its Cache, Source and pins. Its
//! fixed, captured-native and audited-semantic admissions use fresh genuine
//! predecessor loans under separate original exclusion intervals. Native file,
//! replay, model and independent owed posts remain outside those intervals.

use std::error::Error;
use std::fs::Metadata;
use std::mem::size_of;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootJournalFinancialOriginalV1, RootObservationErrorV1,
    RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_model::{
    RawPairedClockSample, RecordNamespace, ResourceDimension as D, ResourceVector,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, KeyV1, OwnerV1, PhaseV1,
    native_suffix::{HistoryPairNativeSuffixProgressV1, HistoryPairSuffixErrorV1},
    ready::{INPUTS_READY_RECEIPT_BYTES_V1, InputsReadyNativeReceiptDataV1, ReadyBundleDataV1},
};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use crate::controller_acceptance_data::{
    ControllerAcceptedHistoryProgressDataV1, ControllerCreateAcceptanceDataV1,
};
use crate::controller_history_data::ControllerHistoryGeometryV1;
use crate::native::PolicyNativeJournalErrorV1 as NativeError;
use crate::native::readonly::{
    RootFixedNativeReadOriginalsV1, RootReadonlyErrorV1 as ReadError, RootReadonlyModelOriginalsV1,
};
use crate::native::startup::RootCurrentWritersPredecessorV1;
use crate::q04_data::RootInertHistoryScanV1;
use crate::root_policy_inputs_data::RootCurrentPolicyInputDataV1;

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_cache::{RootInitialCacheProofErrorV1, RootInitialCacheProofOriginalV1};
use super::initial_location::RootInitialLocationPairOriginalV1;
use super::initial_open::{
    RootInitialClockErrorV1, RootInitialOpenErrorV1, RootInitialOpenPreparedOriginalV1,
};
use super::initial_receiving::RootInitialStageOriginalV1;
use super::readonly_receiving::RootCurrentReadonlyReceivingOriginalV1;

mod body;
mod compare;
mod compiled_policy;
mod controls;
mod posts;
mod prepared;
mod purpose;
mod replay;
mod tail_data;
mod tail_purpose;

pub(in crate::native::root_current) use body::prepare_readonly_pair;
use purpose::RootControllerPurposeBorrowV1;

pub use prepared::RootInitialControllerReadonlyPreparedBorrowV1;
pub use replay::RootInitialControllerReadonlyReplayBorrowV1;

/// Retains refusal of Initial's genuine independent Controller purpose.
#[derive(Debug, thiserror::Error)]
pub enum RootInitialControllerReadonlyErrorV1 {
    /// Retains the original Open, same-writer or original-clock refusal.
    #[error(transparent)]
    Open(#[from] RootInitialOpenErrorV1),
    /// Retains refusal of the same verified Cache proof predecessor.
    #[error(transparent)]
    Cache(#[from] RootInitialCacheProofErrorV1),
    /// Retains the same captured-reader, Audit or held-model cause.
    #[error(transparent)]
    Read(#[from] ReadError),
    /// Retains canonical historical format and correlation refusal.
    #[error(transparent)]
    Format(#[from] HistoryErrorV1),
    /// The actual stage, replay, comparison or owed post is incomplete.
    #[error("initial Controller readonly purpose is incomplete")]
    Incomplete,
}

// The actual quote cause remains owned before the coarse stage-return marker.
// Native suppliers and the flat readonly geometry retain their own categories;
// no conversion stringifies a cause or folds Accounting into a boundary flag.
#[derive(Debug, thiserror::Error)]
pub(in crate::native::root_current) enum DemandError {
    #[error(transparent)]
    Read(#[from] ReadError),
    #[error(transparent)]
    Native(#[from] NativeError),
    #[error(transparent)]
    History(#[from] super::history_post::RootCurrentHistoryArmErrorV1),
}

type E = RootInitialControllerReadonlyErrorV1;
type Clock = RetainedKernelPairedClockAttemptV1<RootInitialClockErrorV1>;
type Slot<T, F = ReadError> = Option<Result<T, F>>;

// The copied receipt has its own disjoint resident field. The linear prepared
// borrower can keep its parsed slices while mutating the SAME body fields;
// neither references its own struct nor reparses at each receiving interval.
pub(super) struct RootInitialControllerReadonlyOriginalV1 {
    receipt: [u8; INPUTS_READY_RECEIPT_BYTES_V1],
    body: RootInitialControllerReadonlyBodyV1,
}

impl RootInitialControllerReadonlyOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            receipt: [0; INPUTS_READY_RECEIPT_BYTES_V1],
            body: RootInitialControllerReadonlyBodyV1::new(),
        }
    }

    pub(super) fn receiving_construction_bytes_v1() -> Option<usize> {
        controls::receiving_construction_bytes_v1()
    }

    pub(in crate::native::root_current) fn same_financial_v1(
        &self,
        financial: &RootJournalFinancialOriginalV1,
    ) -> bool {
        self.body
            .semantic
            .financial
            .as_ref()
            .is_some_and(|same| same.same_original_data_v1(financial))
    }

    pub(super) fn entered_v1(&self) -> bool {
        self.body.fixed.entered
    }

    pub(super) fn refuse_unprepared_v1(&mut self) {
        self.body.closed = true;
    }

    pub(super) fn claim_body_scope_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
    ) -> Result<(), E> {
        self.body.claim_body_scope_once_v1(open)
    }

    pub(super) fn arm_body_peer_once_v1(
        &mut self,
        predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.body
            .arm_body_peer_once_v1(predecessor, startup, exclusion)
    }

    pub(super) fn park_body_peer_refusal_once_v1(&mut self, error: RootObservationErrorV1) {
        self.body.park_body_peer_refusal_once_v1(error);
    }

    pub(super) fn model_v1(&self) -> Result<&RootReadonlyModelOriginalsV1, E> {
        self.require_complete_v1()?;
        Ok(&self.body.model)
    }

    // These loans remain tied to the same completed Controller purpose. The
    // full captured extent and protected-built Storage plan are never adopted
    // from a caller's dimensions or a decoded current receipt.
    pub(super) fn actual_controller_extent_v1(
        &self,
    ) -> Result<&crate::native::readonly::preopen_geometry::ProtectedJournalPreopenReplayExtentV1, E>
    {
        self.require_complete_v1()?;
        self.body.reader.captured_extent_v1().map_err(E::from)
    }

    pub(super) fn prospective_session_extent_v1(
        &self,
    ) -> Result<&crate::native::readonly::preopen_geometry::ProtectedJournalPreopenReplayExtentV1, E>
    {
        self.require_complete_v1()?;
        self.body
            .storage_inventory
            .session_extent_v1()
            .map_err(E::from)
    }

    pub(super) fn prospective_use_plan_v1(
        &self,
    ) -> Result<&crate::root_use_plan_data::RootProspectiveStorageUsePlanV1, E> {
        self.require_complete_v1()?;
        self.body
            .storage_inventory
            .prospective_plan_v1()
            .map_err(E::from)
    }

    pub(super) fn compiled_candidate_v1(&self) -> Result<&crate::CompiledPolicyCandidateV1, E> {
        self.require_complete_v1()?;
        self.body.compiled.candidate_v1().map_err(E::from)
    }

    pub(super) fn protected_storage_preparation_v1(
        &self,
    ) -> Result<&aos_sandbox_protocol::semantics::ProtectedStorageCreatePreparationV1, E> {
        self.require_complete_v1()?;
        self.body
            .storage_inventory
            .protected_preparation_v1()
            .map_err(E::from)
    }

    pub(super) fn accepted_identity_v1(
        &self,
    ) -> Result<&aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1, E> {
        self.require_complete_v1()?;
        self.body
            .accepted_create
            .identity_v1()
            .map_err(|_| E::Incomplete)
    }

    pub(super) fn require_live_at_v1(&self, sample: RawPairedClockSample) -> Result<(), ReadError> {
        self.require_complete_v1()
            .map_err(|_| ReadError::ProtectedBoundary)?;
        self.body.compiled.require_live_at_v1(sample)?;
        self.body.storage_inventory.require_live_at_v1(sample)
    }

    pub(super) fn refuse_body_peer_arm_once_v1(&mut self) {
        self.body
            .park_body_peer_refusal_once_v1(RootObservationErrorV1::Service);
    }

    pub(super) fn claim_fixed_once_v1(&mut self) -> Result<(), RootObservationErrorV1> {
        self.body.claim_fixed_once_v1()
    }

    pub(super) fn park_predecessor_refusal_v1(&mut self, error: RootObservationErrorV1) {
        self.body.park_predecessor_refusal_v1(error);
    }

    pub(in crate::native::root_current) fn new_reserved_after_fixed_v1(
        fixed: RootInitialStageOriginalV1,
    ) -> Self {
        // The sole Reserved owner moves this SAME private actual Stage only
        // after checking its completion, at the original Box frontier.
        let mut original = Self::new();
        original.body.fixed = fixed;
        original.body.suffix_segments = 6;
        original
    }

    pub(in crate::native::root_current) fn reserved_fixed_demand_v1()
    -> Result<ResourceVector, DemandError> {
        let demand = RootInitialControllerReadonlyBodyV1::fixed_demand_for_segments_v1(6)?;
        let controls = Self::receiving_construction_bytes_v1()
            .and_then(|bytes| {
                bytes.checked_add(size_of::<RootInitialStageOriginalV1>().checked_mul(3)?)
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ReadError::JournalTooLarge)?;
        demand
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, controls))
            .map_err(|_| ReadError::JournalTooLarge.into())
    }

    pub(super) fn begin_fixed_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        cache: &RootInitialCacheProofOriginalV1,
        predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.body
            .begin_fixed_once_v1(open, cache, predecessor, startup, exclusion)
    }
}

pub(super) struct RootInitialControllerReadonlyBodyV1 {
    fixed: RootInitialStageOriginalV1,
    fixed_quote: Slot<ResourceVector, DemandError>,
    native: RootInitialStageOriginalV1,
    native_quote: Slot<ResourceVector, DemandError>,
    native_predecessor: Option<RootObservationErrorV1>,
    semantic: RootInitialStageOriginalV1,
    semantic_quote: Slot<ResourceVector, DemandError>,
    semantic_predecessor: Option<RootObservationErrorV1>,
    predecessor: Option<RootObservationErrorV1>,
    receipt_copy: Slot<(), E>,
    receipt_decoding: Slot<(), HistoryErrorV1>,
    expected: Slot<JournalTransaction>,
    previous_expected: [Slot<JournalTransaction>; 2],
    previous_progress: [HistoryPairNativeSuffixProgressV1; 11],
    signed_suffix: tail_data::RootControllerSignedSuffixDataV1,
    outcome_suffix: tail_data::RootControllerOutcomeSuffixDataV1,
    closed_suffix: tail_data::RootControllerClosedSuffixDataV1,
    tail_preparation: Option<Result<(), tail_purpose::TailPurposeErrorV1>>,
    tail_native: Option<Result<(), tail_purpose::TailPurposeErrorV1>>,
    tail_semantic: Option<Result<(), tail_purpose::TailPurposeErrorV1>>,
    purpose_root_nonce: Option<[u8; 16]>,
    suffix_segments: usize,
    expected_end: Option<u64>,
    suffix_progress: HistoryPairNativeSuffixProgressV1,
    suffix_active: usize,
    suffix_construction: Slot<(), HistoryPairSuffixErrorV1>,
    history_geometry: Slot<ControllerHistoryGeometryV1>,
    coordinates: Slot<(u64, u64)>,
    reader: RootFixedNativeReadOriginalsV1,
    model: RootReadonlyModelOriginalsV1,
    receiving: RootCurrentReadonlyReceivingOriginalV1,
    captured_binding: Slot<()>,
    bank_use_geometry: Slot<
        ResourceVector,
        aos_sandbox_protocol::domain_ledger::resource_bank::ResourceBankDataError,
    >,
    native_binding: Slot<()>,
    history_binding: Slot<()>,
    accepted_create: ControllerCreateAcceptanceDataV1,
    accepted_native: ControllerAcceptedHistoryProgressDataV1,
    root_parent: RootInertHistoryScanV1,
    root_parent_result: Slot<(), crate::q04_data::PolicyQ04DataErrorV1>,
    compiled: compiled_policy::RootCurrentCompiledPolicyV1,
    compiler_root_width: Slot<u64>,
    storage_inventory: super::storage_inventory::RootCurrentStorageInventoryV1,
    storage_width: Slot<usize>,
    storage_liveness: Slot<()>,
    compiler_liveness: Slot<()>,
    before: RootInitialLocationPairOriginalV1,
    before_readback: Slot<(), RootInitialOpenErrorV1>,
    before_clock: Clock,
    before_sample: Slot<RawPairedClockSample, RootInitialClockErrorV1>,
    before_cutoff: Slot<(), RootInitialOpenErrorV1>,
    after: RootInitialLocationPairOriginalV1,
    after_readback: Slot<(), RootInitialOpenErrorV1>,
    after_metadata: Option<std::io::Result<Metadata>>,
    after_length: Slot<()>,
    peer_original: Option<RootCurrentHistoryPostOriginalV1>,
    peer_arm: Slot<(), RootObservationErrorV1>,
    peer: Slot<(), RootObservationErrorV1>,
    after_clock: Clock,
    after_sample: Slot<RawPairedClockSample, RootInitialClockErrorV1>,
    after_cutoff: Slot<(), RootInitialOpenErrorV1>,
    interval: Slot<(), aos_sandbox_model::OwnershipLeaseVerificationError>,
    primary: Slot<(), E>,
    body_entered: bool,
    mount_entered: bool,
    audit_entered: bool,
    replay_borrowed: bool,
    model_compared: bool,
    closed: bool,
}

impl RootInitialControllerReadonlyBodyV1 {
    pub(super) fn new() -> Self {
        Self {
            fixed: RootInitialStageOriginalV1::new(),
            fixed_quote: None,
            native: RootInitialStageOriginalV1::new(),
            native_quote: None,
            native_predecessor: None,
            semantic: RootInitialStageOriginalV1::new(),
            semantic_quote: None,
            semantic_predecessor: None,
            predecessor: None,
            receipt_copy: None,
            receipt_decoding: None,
            expected: None,
            previous_expected: [None, None],
            previous_progress: std::array::from_fn(|_| HistoryPairNativeSuffixProgressV1::new()),
            signed_suffix: Default::default(),
            outcome_suffix: Default::default(),
            closed_suffix: Default::default(),
            tail_preparation: None,
            tail_native: None,
            tail_semantic: None,
            purpose_root_nonce: None,
            suffix_segments: 3,
            expected_end: None,
            suffix_progress: HistoryPairNativeSuffixProgressV1::new(),
            suffix_active: 0,
            suffix_construction: None,
            history_geometry: None,
            coordinates: None,
            reader: RootFixedNativeReadOriginalsV1::controller_role_current_v1(),
            model: RootReadonlyModelOriginalsV1::new(),
            receiving: RootCurrentReadonlyReceivingOriginalV1::new(),
            captured_binding: None,
            bank_use_geometry: None,
            native_binding: None,
            history_binding: None,
            accepted_create: Default::default(),
            accepted_native: Default::default(),
            root_parent: Default::default(),
            root_parent_result: None,
            compiled: Default::default(),
            compiler_root_width: None,
            storage_inventory: Default::default(),
            storage_width: None,
            storage_liveness: None,
            compiler_liveness: None,
            before: RootInitialLocationPairOriginalV1::new(),
            before_readback: None,
            before_clock: Clock::default(),
            before_sample: None,
            before_cutoff: None,
            after: RootInitialLocationPairOriginalV1::new(),
            after_readback: None,
            after_metadata: None,
            after_length: None,
            peer_original: None,
            peer_arm: None,
            peer: None,
            after_clock: Clock::default(),
            after_sample: None,
            after_cutoff: None,
            interval: None,
            primary: None,
            body_entered: false,
            mount_entered: false,
            audit_entered: false,
            replay_borrowed: false,
            model_compared: false,
            closed: false,
        }
    }

    pub(super) fn claim_fixed_once_v1(&mut self) -> Result<(), RootObservationErrorV1> {
        if self.fixed.entered || self.closed {
            self.closed = true;
            return Err(RootObservationErrorV1::Service);
        }
        self.fixed.entered = true;
        Ok(())
    }

    pub(super) fn park_predecessor_refusal_v1(&mut self, cause: RootObservationErrorV1) {
        self.predecessor.get_or_insert(cause);
        self.closed = true;
    }

    pub(super) fn begin_fixed_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        cache: &RootInitialCacheProofOriginalV1,
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let (initial, financial) = predecessor.split_initial_v1();
        if !self.fixed.entered || self.fixed.permit.is_some() || self.closed {
            self.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.fixed.financial = Some(financial.clone());
        self.fixed.permit =
            Some(self.fixed_permit(initial, open, cache, financial, startup, exclusion));
        self.fixed.finish_v1(initial, startup, exclusion)
    }

    fn fixed_permit(
        &mut self,
        initial: &RootInitialReceivingOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        cache: &RootInitialCacheProofOriginalV1,
        financial: &RootJournalFinancialOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<ResourceVector, NativeError> {
        require_same_initial(initial, open, financial, startup)?;
        cache
            .require_complete_v1()
            .map_err(|_| NativeError::boundary())?;
        if !cache.same_financial_v1(financial) {
            return Err(NativeError::boundary());
        }
        let base = cache
            .completed_prefix_v1()
            .map_err(|_| NativeError::boundary())?;
        self.fixed_quote = Some(Self::fixed_demand_v1());
        let additional = *positive(&self.fixed_quote).map_err(|_| NativeError::boundary())?;
        let demand = base
            .checked_add(additional)
            .map_err(|_| NativeError::boundary())?;
        if financial
            .require_receiving_demand_under_upper_exclusion_v1(exclusion, demand)
            .is_err()
        {
            return Err(NativeError::Financial(financial.clone()));
        }
        Ok(demand)
    }

    pub(super) fn begin_native_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let (initial, financial) = predecessor.split_initial_v1();
        if self.native.entered || self.closed {
            self.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.native.entered = true;
        self.native.financial = Some(financial.clone());
        self.native.permit = Some(self.native_permit(initial, open, financial, startup, exclusion));
        self.native.finish_v1(initial, startup, exclusion)
    }

    fn native_permit(
        &mut self,
        initial: &RootInitialReceivingOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        financial: &RootJournalFinancialOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<ResourceVector, NativeError> {
        require_same_initial(initial, open, financial, startup)?;
        require_stage_financial(&self.fixed, financial)?;
        let base = self
            .fixed
            .require_complete_v1()
            .map_err(|_| NativeError::boundary())?;
        self.native_quote = Some(
            self.additional_native_demand_v1()
                .map_err(DemandError::Read),
        );
        let additional = *positive(&self.native_quote).map_err(|_| NativeError::boundary())?;
        let demand = base
            .checked_add(additional)
            .map_err(|_| NativeError::boundary())?;
        if financial
            .require_receiving_demand_under_upper_exclusion_v1(exclusion, demand)
            .is_err()
        {
            return Err(NativeError::Financial(financial.clone()));
        }
        Ok(demand)
    }

    pub(super) fn begin_semantic_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let (initial, financial) = predecessor.split_initial_v1();
        if self.semantic.entered || self.closed {
            self.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.semantic.entered = true;
        self.semantic.financial = Some(financial.clone());
        self.semantic.permit =
            Some(self.semantic_permit(initial, open, financial, startup, exclusion));
        self.semantic.finish_v1(initial, startup, exclusion)
    }

    fn semantic_permit(
        &mut self,
        initial: &RootInitialReceivingOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        financial: &RootJournalFinancialOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<ResourceVector, NativeError> {
        require_same_initial(initial, open, financial, startup)?;
        require_stage_financial(&self.native, financial)?;
        let base = self
            .native
            .require_complete_v1()
            .map_err(|_| NativeError::boundary())?;
        self.semantic_quote = Some(
            self.additional_semantic_demand_v1()
                .map_err(DemandError::Read),
        );
        let additional = *positive(&self.semantic_quote).map_err(|_| NativeError::boundary())?;
        let demand = base
            .checked_add(additional)
            .map_err(|_| NativeError::boundary())?;
        if financial
            .require_receiving_demand_under_upper_exclusion_v1(exclusion, demand)
            .is_err()
        {
            return Err(NativeError::Financial(financial.clone()));
        }
        Ok(demand)
    }
}

impl RootInitialControllerReadonlyBodyV1 {
    fn additional_native_demand_v1(&self) -> Result<ResourceVector, ReadError> {
        if !matches!(self.captured_binding, Some(Ok(()))) {
            return Err(ReadError::ProtectedBoundary);
        }
        let extent = self.reader.captured_extent_v1()?;
        let native = crate::native::readonly::RootControllerReadonlyGeometryAuditV1::additional_native_demand_v1(extent)?;
        let geometry =
            positive(&self.history_geometry).map_err(|_| ReadError::ProtectedBoundary)?;
        let continuation = if self.suffix_segments >= 10 {
            extent.native_bytes.checked_mul(4).ok_or(ReadError::JournalTooLarge)?
        } else { 0 };
        let copies = continuation.checked_add(geometry.copy_bytes).ok_or(ReadError::JournalTooLarge)?;
        native
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, copies)
                    .with(D::OutputBytes, geometry.copy_bytes),
            )
            .map_err(|_| ReadError::ProtectedBoundary)
    }

    fn additional_semantic_demand_v1(&self) -> Result<ResourceVector, ReadError> {
        self.native
            .require_complete_v1()
            .map_err(|_| ReadError::ProtectedBoundary)?;
        let geometry =
            positive(&self.history_geometry).map_err(|_| ReadError::ProtectedBoundary)?;
        let audit = self.reader.current_audit_original_v1();
        let state = audit
            .native_data_v1()
            .and_then(|native| native.state())
            .ok_or(ReadError::ProtectedBoundary)?;
        let origin = state.iter().filter(|((namespace, key), _)| {
            *namespace == RecordNamespace::ControllerPolicyHold
                && key.as_slice() == aos_sandbox_protocol::domain_ledger::resource_bank::CONTROLLER_INPUT_ORIGIN_KEY
        }).map(|(_, bytes)| bytes.len()).max().unwrap_or(0);
        let current_effect = state
            .iter()
            .filter(|((namespace, _), _)| *namespace == RecordNamespace::Effect)
            .map(|(_, bytes)| bytes.len())
            .max()
            .unwrap_or(0);
        let encoded = geometry
            .accepted_bytes
            .checked_add(u64::try_from(origin).map_err(|_| ReadError::JournalTooLarge)?)
            .and_then(|bytes| bytes.checked_add(u64::try_from(current_effect).ok()?))
            .ok_or(ReadError::JournalTooLarge)?;
        let accepted = ControllerCreateAcceptanceDataV1::additional_receiving_demand_v1(encoded)
            .map_err(ReadError::from)?;
        let compiler_bytes = geometry
            .compiler_bytes
            .checked_add(
                *positive(&self.compiler_root_width).map_err(|_| ReadError::ProtectedBoundary)?,
            )
            .ok_or(ReadError::JournalTooLarge)?;
        let compiler =
            compiled_policy::RootCurrentCompiledPolicyV1::additional_receiving_demand_v1(
                compiler_bytes,
            )?;
        let storage_width =
            *positive(&self.storage_width).map_err(|_| ReadError::ProtectedBoundary)?;
        let storage =
            super::storage_inventory::RootCurrentStorageInventoryV1::additional_demand_v1(
                storage_width,
            )?;
        let bank = *positive(&self.bank_use_geometry).map_err(|_| ReadError::ProtectedBoundary)?;
        let model = RootReadonlyModelOriginalsV1::receiving_demand_v1(&self.reader)?;
        let query = RootReadonlyModelOriginalsV1::current_controller_query_control_bytes_v1()
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ReadError::JournalTooLarge)?;

        audit
            .additional_semantic_demand_v1()?
            .checked_add(bank)
            .and_then(|value| value.checked_add(accepted))
            .and_then(|value| value.checked_add(compiler))
            .and_then(|value| value.checked_add(storage))
            .and_then(|value| value.checked_add(model))
            .and_then(|value| value.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, query)))
            .map_err(|_| ReadError::JournalTooLarge)
    }
}

pub(super) fn require_same_initial(
    initial: &RootInitialReceivingOriginalV1,
    open: &RootInitialOpenPreparedOriginalV1,
    financial: &RootJournalFinancialOriginalV1,
    startup: &RootSelectedStartupBorrowV1<'_>,
) -> Result<(), NativeError> {
    let body = open.body_v1().map_err(|_| NativeError::boundary())?;
    let enrollment = initial.enrollment_v1().ok_or_else(NativeError::boundary)?;
    if initial.failure().is_some()
        || !matches!(initial.recipient_binding_result_v1(), Some(Ok(())))
        || (body.root_recipient, body.root_producer)
            != (
                enrollment.recipient_invocation,
                enrollment.identity.native_fields().invocation,
            )
        || !startup.same_financial_original_data_v1(financial)
    {
        return Err(NativeError::boundary());
    }
    Ok(())
}

fn require_stage_financial(
    stage: &RootInitialStageOriginalV1,
    financial: &RootJournalFinancialOriginalV1,
) -> Result<(), NativeError> {
    if stage
        .financial
        .as_ref()
        .is_some_and(|same| same.same_original_data_v1(financial))
    {
        Ok(())
    } else {
        Err(NativeError::boundary())
    }
}

fn positive<T, F>(slot: &Option<Result<T, F>>) -> Result<&T, E> {
    slot.as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(E::Incomplete)
}

fn cause<T, F: Error + 'static>(slot: &Option<Result<T, F>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()
        .and_then(|result| result.as_ref().err())
        .map(|error| error as _)
}
