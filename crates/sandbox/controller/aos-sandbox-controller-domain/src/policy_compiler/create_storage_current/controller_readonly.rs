//! Retains Root's independent fixed Controller reader through both real passes.
//!
//! The authenticated Phase4 receipt supplies comparison DATA only. The same R
//! pays opening, the actual captured native history and its semantic maximum in
//! sequence. The existing Domain parser then replays that same file and checks
//! its exact Intent/AssignmentPlanned/InputsReady suffix; no Controller writer
//! is borrowed or reopened.

use std::error::Error as StdError;
use std::fs::{File, Metadata};
use std::mem::size_of;
use std::path::Path;

use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, KeyV1, OwnerV1, PhaseV1,
    ready::{InputsReadyNativeReceiptDataV1, INPUTS_READY_RECEIPT_BYTES_V1, ReadyBundleDataV1},
};

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::{
    JournalError, JournalTransaction, ProtectedJournalCurrentnessOriginalsV1,
    ProtectedJournalPreopenReplayExtentV1, ReadOnlyJournalOpenOriginalsV1,
    ROOT_CONTROLLER_DIRECTORY_V1, ROOT_CONTROLLER_JOURNAL_V1,
    RootControllerReadonlyGeometryAuditV1, RootControllerReadonlyReceivingContextV1,
};
use crate::journal::create_storage_history::{
    HistoryPairNativeSuffixProgressV1, ControllerHistoryNativeSuffixV1, HistoryPairSuffixErrorV1,
};
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;

use super::{
    RootCreateStorageCurrentErrorV1 as Error,
    cache_current::{RootCurrentCacheProofStateV1, observe_writer_names_v1, require_clock,
        root_current_post_backing_demand_v1},
    ready::RootCurrentReadyStateV1,
    root_open::RootCurrentOpenStateV1,
    source_current::RootCurrentSourceExchangeStateV1,
};
use super::super::root_current_writers::RootCreateStorageCurrentWritersV1;

mod compiled_policy;
pub(crate) mod storage_inventory;
mod session_extent;
pub(crate) mod native_read;
pub(crate) mod outcome;
pub(crate) mod closed;
mod signed;
mod use_plan;

type WriterResult = Option<Result<(), JournalError>>;

#[derive(Clone, Copy)]
enum ControllerReadPurposeV1<'current> {
    Initial,
    Closed {
        authorization: &'current super::use_authorized::RootCurrentUseAuthorizedStateV1,
        received: &'current super::use_reserved::received::RootCurrentUseReservedReceivedV1,
        reserved: &'current super::use_reserved::RootCurrentUseReservedStateV1,
        signed: &'current super::signed_bound::RootCurrentSignedBoundStateV1,
        outcome: &'current super::outcome::RootCurrentOutcomeStateV1,
        input: &'current super::closed::input::RootReleaseInputV1,
    },
    Signed {
        authorization: &'current super::use_authorized::RootCurrentUseAuthorizedStateV1,
        received: &'current super::use_reserved::received::RootCurrentUseReservedReceivedV1,
        admitted: &'current super::use_admitted::RootCurrentUseAdmittedStateV1,
        input: &'current super::signed_bound::input::RootSignedInputV1,
    },
    Outcome {
        authorization: &'current super::use_authorized::RootCurrentUseAuthorizedStateV1,
        received: &'current super::use_reserved::received::RootCurrentUseReservedReceivedV1,
        admitted: &'current super::use_admitted::RootCurrentUseAdmittedStateV1,
        signed: &'current super::signed_bound::RootCurrentSignedBoundStateV1,
        input: &'current super::outcome::input::RootOutcomeInputV1,
    },
    Reserved {
        authorization: &'current super::use_authorized::RootCurrentUseAuthorizedStateV1,
        received: &'current super::use_reserved::received::RootCurrentUseReservedReceivedV1,
    },
}

impl ControllerReadPurposeV1<'_> {
    fn observe_writers(self, writers: &mut RootCreateStorageCurrentWritersV1,
        root: &RootCurrentOpenStateV1, originals: &mut [ProtectedJournalCurrentnessOriginalsV1; 2],
        results: &mut [WriterResult; 2], readback: &mut Option<Result<(), JournalError>>)
    {
        *readback = Some(match observe_writer_names_v1(writers, originals, results) {
            Ok((authority, policy)) => match self {
                Self::Closed { outcome, .. } => outcome.readback_current_v1(authority, policy).map(|_| ()),
                Self::Signed { admitted, .. } => admitted.readback_current_v1(authority, policy).map(|_| ()),
                Self::Initial => root.readback_current(authority, policy).map(|_| ()),
                Self::Outcome { signed, .. } => signed.readback_current_v1(authority, policy).map(|_| ()),
                Self::Reserved { authorization, .. } => authorization.readback_current_v1(authority, policy).map(|_| ()),
            },
            Err(cause) => Err(cause),
        });
    }

    fn after_end(self, lane: [u8; 16], inputs: InputsReadyNativeReceiptDataV1<'_>) -> Result<u64, Error> {
        match self {
            Self::Closed { input, .. } => Ok(input.controller_receipt_v1(lane)?.after_end),
            Self::Signed { .. } => Err(Error::Original),
            Self::Initial => Ok(inputs.after_end),
            Self::Outcome { input, .. } => Ok(input.recorded_receipt_v1(lane)?.after_end),
            Self::Reserved { received, .. } => Ok(received.receipt_v1(lane)?.after_end),
        }
    }
}


use aos_sandbox_linux::signer_mount::{RootReadonlyViewV1,
    SignerMountReadbackAttemptV1, SignerMountReadbackClosedV1};

pub(crate) struct RootCurrentControllerReadonlyStateV1 {
    mount_source_uid: u32,
    mount_before: SignerMountReadbackAttemptV1,
    mount_before_result: Option<Result<(), SignerMountReadbackClosedV1>>,
    mount_after: SignerMountReadbackAttemptV1,
    mount_after_result: Option<Result<(), SignerMountReadbackClosedV1>>,
    mount_binding: Option<Result<(), JournalError>>,
    receipt: [u8; INPUTS_READY_RECEIPT_BYTES_V1],
    receipt_copy: Option<Result<(), Error>>,
    receipt_decoding: Option<Result<(), HistoryErrorV1>>,
    expected: Option<Result<JournalTransaction, JournalError>>,
    previous_expected: [Option<Result<JournalTransaction, JournalError>>; 2],
    previous_progress: [HistoryPairNativeSuffixProgressV1; 11],
    suffix_segments: usize,
    outcome_suffix: outcome::RootControllerOutcomeSuffixDataV1,
    closed_suffix: closed::RootControllerClosedSuffixDataV1,
    signed_suffix: signed::RootControllerSignedSuffixDataV1,
    history_geometry: Option<Result<ControllerHistoryGeometryV1, JournalError>>,
    suffix_active: usize,
    coordinates: Option<Result<(u64, u64), JournalError>>,
    reader: ReadOnlyJournalOpenOriginalsV1,
    lock_name: Option<String>,
    preparation_admission: Option<Result<(), NormalRootStartupErrorV1>>,
    preparation_frontier: Option<Result<(), JournalError>>,
    captured_binding: Option<Result<(), JournalError>>,
    native_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    audit: RootControllerReadonlyGeometryAuditV1,
    bank_use_geometry: Option<Result<ResourceVector, aos_sandbox_protocol::domain_ledger::resource_bank::ResourceBankDataError>>,
    semantic_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    suffix_progress: HistoryPairNativeSuffixProgressV1,
    suffix_construction: Option<Result<(), HistoryPairSuffixErrorV1>>,
    replay_admission: Option<Result<(), NormalRootStartupErrorV1>>,
    replay_frontier: Option<Result<(), JournalError>>,
    native_binding: Option<Result<(), JournalError>>,
    history_binding: Option<Result<(), JournalError>>,
    accepted_create: crate::journal::RootControllerCreateAcceptanceOriginalsV1,
    accepted_native: crate::journal::RootControllerAcceptedNativeProgressV1,
    root_parent: crate::policy_compiler::create_q04::RootInertHistoryScanV1,
    root_parent_result: Option<Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1>>,
    compiled: compiled_policy::RootCurrentCompiledPolicyV1,
    compiler_root_width: Option<Result<u64, JournalError>>,
    storage_inventory: storage_inventory::RootCurrentStorageInventoryV1,
    storage_width: Option<Result<usize, JournalError>>,
    storage_liveness: Option<Result<(), JournalError>>,
    compiler_liveness: Option<Result<(), JournalError>>,
    before: [ProtectedJournalCurrentnessOriginalsV1; 2],
    before_result: [WriterResult; 2],
    before_readback: Option<Result<(), JournalError>>,
    before_clock: RetainedKernelPairedClockAttemptV1,
    before_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    before_cutoff: Option<Result<(), JournalError>>,
    after: [ProtectedJournalCurrentnessOriginalsV1; 2],
    after_result: [WriterResult; 2],
    after_readback: Option<Result<(), JournalError>>,
    after_metadata: Option<std::io::Result<Metadata>>,
    after_length: Option<Result<(), JournalError>>,
    peer_original: Option<Result<crate::normal_root::RootHistoryPeerPostV1, NormalRootStartupErrorV1>>,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    after_clock: RetainedKernelPairedClockAttemptV1,
    after_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_cutoff: Option<Result<(), JournalError>>,
    interval: Option<Result<(), aos_sandbox_model::OwnershipLeaseVerificationError>>,
    primary: Option<Result<(), Error>>,
    complete: bool,
    entered: bool,
    closed: Option<Error>,
}

impl RootCurrentControllerReadonlyStateV1 {
    pub(super) fn new() -> Self {
        Self {
            mount_source_uid: 0,
            mount_before: SignerMountReadbackAttemptV1::new(), mount_before_result: None,
            mount_after: SignerMountReadbackAttemptV1::new(), mount_after_result: None,
            mount_binding: None,
            receipt: [0; INPUTS_READY_RECEIPT_BYTES_V1],
            receipt_copy: None,
            receipt_decoding: None,
            expected: None,
            previous_expected: [None, None],
            previous_progress: std::array::from_fn(|_| HistoryPairNativeSuffixProgressV1::new()),
            history_geometry: None,
            suffix_active: 0,
            suffix_segments: 3,
            outcome_suffix: Default::default(), closed_suffix: Default::default(),
            signed_suffix: Default::default(),
            coordinates: None,
            reader: ReadOnlyJournalOpenOriginalsV1::new(),
            lock_name: None,
            preparation_admission: None,
            preparation_frontier: None,
            captured_binding: None,
            native_funding: None,
            audit: RootControllerReadonlyGeometryAuditV1::new(),
            bank_use_geometry: None,
            semantic_funding: None,
            suffix_progress: HistoryPairNativeSuffixProgressV1::new(),
            suffix_construction: None,
            replay_admission: None,
            replay_frontier: None,
            native_binding: None,
            history_binding: None,
            accepted_create: Default::default(),
            accepted_native: Default::default(),
            root_parent: Default::default(),
            root_parent_result: None,
            compiled: Default::default(), compiler_root_width: None, compiler_liveness: None,
            storage_inventory: Default::default(), storage_width: None, storage_liveness: None,
            before: std::array::from_fn(|_| ProtectedJournalCurrentnessOriginalsV1::new()),
            before_result: [None, None],
            before_readback: None,
            before_clock: Default::default(),
            before_sample: None,
            before_cutoff: None,
            after: std::array::from_fn(|_| ProtectedJournalCurrentnessOriginalsV1::new()),
            after_result: [None, None],
            after_readback: None,
            after_metadata: None,
            after_length: None,
            peer_original: None,
            peer: None,
            after_clock: Default::default(),
            after_sample: None,
            after_cutoff: None,
            interval: None,
            primary: None,
            complete: false,
            entered: false,
            closed: None,
        }
    }

    pub(crate) fn fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::JournalTooLarge;
        let path = Path::new(ROOT_CONTROLLER_DIRECTORY_V1);
        let anchors = path.components()
            .filter(|part| matches!(part, std::path::Component::Normal(_)))
            .count().checked_add(1).ok_or_else(invalid)?;
        // The same rooted resolver reserves its exact ancestor roster before
        // opening. Three backing planes include construction/reallocation; path,
        // journal, witness and the retained lock-name have fixed compiled roots.
        let ancestry = anchors.checked_mul(3 * size_of::<File>()).ok_or_else(invalid)?;
        let strings = ROOT_CONTROLLER_DIRECTORY_V1.len()
            .checked_add(ROOT_CONTROLLER_JOURNAL_V1.len()).and_then(|bytes| bytes.checked_add(5))
            .and_then(|bytes| bytes.checked_mul(8)).ok_or_else(invalid)?;
        let pair_bytes = 412_usize.checked_add(40).and_then(|bytes| bytes.checked_add(2 * 43))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<crate::journal::JournalRecord>()))
            .ok_or_else(invalid)?;
        let mount_bytes = SignerMountReadbackAttemptV1::receiving_memory_bound_v1()
            .and_then(|bytes| bytes.checked_mul(2)).ok_or_else(invalid)?;
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(mount_bytes))
            .and_then(|bytes| bytes.checked_add(ancestry))
            .and_then(|bytes| bytes.checked_add(strings))
            .and_then(|bytes| bytes.checked_add(4 * 4096))
            .and_then(|bytes| bytes.checked_add(pair_bytes))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<ReadonlyFixedFramesV1>()))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<usize>())).ok_or_else(invalid)?;
        // Inline controls use byte permits. The named reader, native
        // indexes and semantic maps price their actual namespace entries.
        let mut demand = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?)
            .with(D::OpenFiles, u64::try_from(anchors.checked_add(4).ok_or_else(invalid)?)
                .map_err(|_| invalid())?);
        let audit = RootControllerReadonlyGeometryAuditV1::fixed_demand_v1()?;
        let own_audit = u64::try_from(2 * size_of::<RootControllerReadonlyGeometryAuditV1>())
            .map_err(|_| invalid())?;
        let audit = audit.with(D::MemoryBytes,
            audit.get(D::MemoryBytes).checked_sub(own_audit).ok_or_else(invalid)?);
        // State's two sizeof planes already include the audit's resident and
        // constructor fields. Its independent geometry backing remains.
        let context = RootControllerReadonlyReceivingContextV1::fixed_receiving_demand_v1()?;
        let names = ReadOnlyJournalOpenOriginalsV1::root_controller_named_receiving_demand_v1()?;
        let posts = root_current_post_backing_demand_v1()?;
        let chain_frames = ControllerHistoryNativeSuffixV1::<3>::receiving_frame_demand_v1()?;
        demand = demand.checked_add(audit)
            .and_then(|value| value.checked_add(context))
            .and_then(|value| value.checked_add(names))
            .and_then(|value| value.checked_add(posts))
            .and_then(|value| value.checked_add(chain_frames))
            .and_then(|value| value.checked_add(
                crate::journal::root_controller_replay_fixed_controls_v1(),
            ))
            .map_err(|_| invalid())?;
        demand = demand.checked_add(ReadyBundleDataV1::fixed_framing_receiving_demand_v1()
            .ok_or_else(invalid)?).map_err(|_| invalid())?;
        demand = demand.checked_add(storage_inventory::RootCurrentStorageInventoryV1::fixed_demand_v1()?)
            .map_err(|_| invalid())?;
        demand = demand.checked_add(crate::normal_root::RootHistoryPeerPostV1::additional_resident_demand_v1()
            .map_err(|_| invalid())?).map_err(|_| invalid())?;
        // Control-only getter calls do not emit bytes. Preserve the original
        // output geometry before adding their separate Memory footprint.
        let output = demand.get(D::OutputBytes).max(demand.get(D::MemoryBytes));
        let getter_controls = u64::try_from(
            crate::policy_compiler::create_q04::root_history_chunk_getter_control_bytes_v1()
                .ok_or_else(invalid)?,
        ).map_err(|_| invalid())?;
        let memory = demand.get(D::MemoryBytes).checked_add(getter_controls).ok_or_else(invalid)?;
        Ok(demand.with(D::OutputBytes, output).with(D::MemoryBytes, memory))
    }

    pub(crate) fn reserved_fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        let base = Self::fixed_demand_v1()?;
        let full = ControllerHistoryNativeSuffixV1::<6>::receiving_frame_demand_v1()?;
        let initial = ControllerHistoryNativeSuffixV1::<3>::receiving_frame_demand_v1()?;
        let construction = std::mem::size_of::<([&JournalTransaction; 3], [(u64, u64); 7],
            [(u64, u64); 4], [(u64, u64); 4])>().checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        base.checked_add(full.checked_sub(initial).map_err(|_| JournalError::JournalTooLarge)?)
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, construction)))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(crate) fn signed_fixed_demand_v1(input: &super::signed_bound::input::RootSignedInputV1)
        -> Result<ResourceVector, JournalError>
    {
        let base = Self::fixed_demand_v1()?;
        let full = ControllerHistoryNativeSuffixV1::<7>::receiving_frame_demand_v1()?;
        let initial = ControllerHistoryNativeSuffixV1::<3>::receiving_frame_demand_v1()?;
        let bundle = input.completed_bundle_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        let raw = bundle.encoded_bytes().map_err(|_| JournalError::ProtectedBoundary)?;
        // Fixed C6 framing, its temporary body/record and owned expected pair
        // coexist with the received bundle. Conservative bytes price all copies;
        // none of these controls creates a namespace entry.
        let framing = aos_sandbox_protocol::domain_ledger::create_storage_history::RECORD_OVERHEAD_BYTES
            .checked_add(aos_sandbox_protocol::domain_ledger::create_storage_history::controller_use::SIGNED_BODY_PREFIX_BYTES_V1)
            .ok_or(JournalError::JournalTooLarge)?;
        let bytes = raw.checked_add(framing).and_then(|bytes| bytes.checked_mul(8))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<JournalTransaction>()))
            .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<crate::journal::JournalRecord>()))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<([&JournalTransaction; 7], [(u64, u64); 8])>()))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        base.checked_add(full.checked_sub(initial).map_err(|_| JournalError::JournalTooLarge)?)
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::OutputBytes, bytes)))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(crate) fn failed_signed_financial_entry_v1(&self)
        -> Option<super::signed_bound::SignedControllerFinancialStageV1>
    {
        use super::signed_bound::SignedControllerFinancialStageV1 as Stage;
        if matches!(self.native_funding, Some(Err(_))) { Some(Stage::Native) }
        else if matches!(self.semantic_funding, Some(Err(_))) { Some(Stage::Semantic) }
        else { None }
    }

    pub(crate) fn failed_outcome_financial_entry_v1(&self)
        -> Option<super::outcome::OutcomeFinancialStageV1> {
        use super::outcome::OutcomeFinancialStageV1 as Stage;
        if matches!(self.native_funding, Some(Err(_))) { Some(Stage::ControllerNative) }
        else if matches!(self.semantic_funding, Some(Err(_))) { Some(Stage::ControllerSemantic) }
        else { None }
    }

    pub(crate) fn outcome_fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        let base = Self::fixed_demand_v1()?;
        let full = ControllerHistoryNativeSuffixV1::<10>::receiving_frame_demand_v1()?;
        let initial = ControllerHistoryNativeSuffixV1::<3>::receiving_frame_demand_v1()?;
        let construction = std::mem::size_of::<([&JournalTransaction; 10], [(u64, u64); 11],
            [(u64, u64); 4], [(u64, u64); 4], [(u64, u64); 5])>().checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        base.checked_add(full.checked_sub(initial).map_err(|_| JournalError::JournalTooLarge)?)
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, construction)))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(crate) fn closed_fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        let base = Self::fixed_demand_v1()?;
        let full = ControllerHistoryNativeSuffixV1::<12>::receiving_frame_demand_v1()?;
        let initial = ControllerHistoryNativeSuffixV1::<3>::receiving_frame_demand_v1()?;
        let construction = std::mem::size_of::<([&JournalTransaction; 12], [(u64, u64); 13],
            [(u64, u64); 4], [(u64, u64); 4], [(u64, u64); 5], [(u64, u64); 3])>()
            .checked_mul(2).and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        base.checked_add(full.checked_sub(initial).map_err(|_| JournalError::JournalTooLarge)?)
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, construction)))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(crate) fn additional_native_demand_v1(&self) -> Result<ResourceVector, JournalError> {
        if self.captured_binding.as_ref().is_none_or(Result::is_err) {
            return Err(JournalError::ProtectedBoundary);
        }
        let native = RootControllerReadonlyGeometryAuditV1::additional_native_demand_v1(
            self.reader.captured_extent().ok_or(JournalError::ProtectedBoundary)?,
        )?;
        let geometry = positive(&self.history_geometry)?;
        let continuation = if self.suffix_segments >= 10 {
            self.reader.captured_extent().ok_or(JournalError::ProtectedBoundary)?.native_bytes
                .checked_mul(4).ok_or(JournalError::JournalTooLarge)?
        } else { 0 };
        let copies = continuation.checked_add(geometry.copy_bytes).ok_or(JournalError::JournalTooLarge)?;
        native.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, copies)
            .with(D::OutputBytes, geometry.copy_bytes))
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(crate) fn additional_semantic_demand_v1(&self) -> Result<ResourceVector, JournalError> {
        if !matches!(self.native_funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        let geometry = positive(&self.history_geometry)?;
        let state = self.audit.native_data_v1().and_then(|native| native.state())
            .ok_or(JournalError::ProtectedBoundary)?;
        let origin = state.iter().filter(|((namespace, key), _)| {
            *namespace == crate::journal::RecordNamespace::ControllerPolicyHold
                && key.as_slice() == aos_sandbox_protocol::domain_ledger::resource_bank::CONTROLLER_INPUT_ORIGIN_KEY
        }).map(|(_, bytes)| bytes.len()).max().unwrap_or(0);
        let current_effect = state.iter().filter(|((namespace, _), _)| {
            *namespace == crate::journal::RecordNamespace::Effect
        }).map(|(_, bytes)| bytes.len()).max().unwrap_or(0);
        let encoded = geometry.accepted_bytes
            .checked_add(u64::try_from(origin).map_err(|_| JournalError::JournalTooLarge)?)
            .and_then(|bytes| bytes.checked_add(u64::try_from(current_effect).ok()?))
            .ok_or(JournalError::JournalTooLarge)?;
        let accepted = crate::journal::RootControllerCreateAcceptanceOriginalsV1::
            additional_receiving_demand_v1(encoded)?;
        let compiler_bytes = geometry.compiler_bytes.checked_add(*positive(&self.compiler_root_width)?)
            .ok_or(JournalError::JournalTooLarge)?;
        let compiler = compiled_policy::RootCurrentCompiledPolicyV1::additional_receiving_demand_v1(compiler_bytes)?;
        let storage = storage_inventory::RootCurrentStorageInventoryV1::additional_demand_v1(*positive(&self.storage_width)?)?;
        self.audit.additional_semantic_demand_v1()?.checked_add(*positive(&self.bank_use_geometry)?)
            .and_then(|value| value.checked_add(accepted))
            .and_then(|value| value.checked_add(compiler))
            .and_then(|value| value.checked_add(storage))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(super) fn capture_once(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
        root: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1,
        cache: &RootCurrentCacheProofStateV1,
        source: &RootCurrentSourceExchangeStateV1,
        ownership: &super::bundle_ownership::RootCurrentBundleOwnershipStateV1,
        policy_data: &super::policy_inputs::RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Error> {
        self.capture_for_purpose(flight, writers, root, ready, cache, source, ownership, policy_data, ControllerReadPurposeV1::Initial)
    }

    pub(super) fn capture_reserved_once(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
        root: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1,
        cache: &RootCurrentCacheProofStateV1,
        source: &RootCurrentSourceExchangeStateV1,
        ownership: &super::bundle_ownership::RootCurrentBundleOwnershipStateV1,
        policy_data: &super::policy_inputs::RootCurrentPolicyInputDataV1<'_>,
        authorization: &super::use_authorized::RootCurrentUseAuthorizedStateV1,
        received: &super::use_reserved::received::RootCurrentUseReservedReceivedV1,
    ) -> Result<(), Error> {
        authorization.require_complete_v1()?;
        received.require_received_v1()?;
        self.capture_for_purpose(flight, writers, root, ready, cache, source, ownership, policy_data,
            ControllerReadPurposeV1::Reserved { authorization, received })
    }

    pub(super) fn capture_signed_once(&mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>, writers: &mut RootCreateStorageCurrentWritersV1,
        root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        cache: &RootCurrentCacheProofStateV1, source: &RootCurrentSourceExchangeStateV1,
        ownership: &super::bundle_ownership::RootCurrentBundleOwnershipStateV1,
        policy_data: &super::policy_inputs::RootCurrentPolicyInputDataV1<'_>,
        authorization: &super::use_authorized::RootCurrentUseAuthorizedStateV1,
        reserved: &super::use_reserved::RootCurrentUseReservedStateV1,
        admitted: &super::use_admitted::RootCurrentUseAdmittedStateV1,
        input: &super::signed_bound::input::RootSignedInputV1,
    ) -> Result<(), Error> {
        admitted.require_complete_v1()?;
        input.require_complete_v1()?;
        self.capture_for_purpose(flight, writers, root, ready, cache, source, ownership, policy_data,
            ControllerReadPurposeV1::Signed { authorization,
                received: reserved.received_original_v1()?, admitted, input })
    }

    pub(super) fn capture_outcome_once(&mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>, writers: &mut RootCreateStorageCurrentWritersV1,
        root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        cache: &RootCurrentCacheProofStateV1, source: &RootCurrentSourceExchangeStateV1,
        ownership: &super::bundle_ownership::RootCurrentBundleOwnershipStateV1,
        policy_data: &super::policy_inputs::RootCurrentPolicyInputDataV1<'_>,
        authorization: &super::use_authorized::RootCurrentUseAuthorizedStateV1,
        reserved: &super::use_reserved::RootCurrentUseReservedStateV1,
        admitted: &super::use_admitted::RootCurrentUseAdmittedStateV1,
        signed: &super::signed_bound::RootCurrentSignedBoundStateV1,
        input: &super::outcome::input::RootOutcomeInputV1,
    ) -> Result<(), Error> {
        signed.require_complete_v1()?;
        input.require_complete_v1()?;
        self.capture_for_purpose(flight, writers, root, ready, cache, source, ownership, policy_data,
            ControllerReadPurposeV1::Outcome { authorization, received: reserved.received_original_v1()?,
                admitted, signed, input })
    }

    pub(crate) fn capture_closed_once(&mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>, writers: &mut RootCreateStorageCurrentWritersV1,
        root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        cache: &RootCurrentCacheProofStateV1, source: &RootCurrentSourceExchangeStateV1,
        ownership: &super::bundle_ownership::RootCurrentBundleOwnershipStateV1,
        policy: &super::policy_inputs::RootCurrentPolicyInputDataV1<'_>,
        authorization: &super::use_authorized::RootCurrentUseAuthorizedStateV1,
        reserved: &super::use_reserved::RootCurrentUseReservedStateV1,
        signed: &super::signed_bound::RootCurrentSignedBoundStateV1,
        outcome: &super::outcome::RootCurrentOutcomeStateV1,
        input: &super::closed::input::RootReleaseInputV1,
    ) -> Result<(), Error> {
        outcome.require_complete_v1()?; input.require_complete_v1()?;
        self.capture_for_purpose(flight, writers, root, ready, cache, source, ownership, policy,
            ControllerReadPurposeV1::Closed { authorization, received: reserved.received_original_v1()?,
                reserved, signed, outcome, input })
    }

    fn capture_for_purpose(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
        root: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1,
        cache: &RootCurrentCacheProofStateV1,
        source: &RootCurrentSourceExchangeStateV1,
        ownership: &super::bundle_ownership::RootCurrentBundleOwnershipStateV1,
        policy_data: &super::policy_inputs::RootCurrentPolicyInputDataV1<'_>,
        purpose: ControllerReadPurposeV1<'_>,
    ) -> Result<(), Error> {
        if self.entered || self.closed.is_some() {
            self.closed.get_or_insert(Error::Original);
            return Err(Error::Original);
        }
        self.entered = true;
        self.mount_source_uid = root.completed_body().map(|body| body.controller_uid).unwrap_or(0);
        self.suffix_segments = match purpose { ControllerReadPurposeV1::Closed { .. } => 12, ControllerReadPurposeV1::Initial => 3, ControllerReadPurposeV1::Signed { .. } => 7, ControllerReadPurposeV1::Outcome { .. } => 10,
            ControllerReadPurposeV1::Reserved { .. } => 6 };
        self.peer_original = Some(flight.arm_history_peer_post_v1());
        self.primary = Some(match &self.peer_original {
            Some(Ok(original)) if original.require_armed_v1().is_ok() =>
                self.capture_inner(flight, writers, root, ready, cache, source, ownership, policy_data, purpose),
            _ => Err(Error::Original),
        });

        // Every entered fixed-paid primary retains its original partials while
        // the independent writer, external-reader, peer and raw-clock posts run.
        purpose.observe_writers(writers, root, &mut self.after, &mut self.after_result,
            &mut self.after_readback);
        self.reader.recheck_named_once();
        self.mount_after_result = Some(self.mount_after.observe_root_readonly_once(
            RootReadonlyViewV1::Controller, self.mount_source_uid,
            rustix::process::getegid().as_raw(), None));
        self.mount_binding = Some(match (self.mount_before.witness(), self.mount_after.witness()) {
            (Some(before), Some(after)) if before == after => Ok(()),
            _ => Err(JournalError::ProtectedBoundary),
        });
        self.storage_inventory.finish_post_once();
        self.after_metadata = self.reader.observe_root_controller_file_metadata_v1();
        self.after_length = Some((|| {
            let metadata = positive(&self.after_metadata)?;
            let lane = root.completed_body().map_err(|_| JournalError::ProtectedBoundary)?.open.lane;
            let receipt = self.receipt_data_v1(lane).map_err(|_| JournalError::ProtectedBoundary)?;
            if metadata.len() != self.purpose_after_end_v1(purpose, lane, receipt).map_err(|_| JournalError::ProtectedBoundary)? {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        self.peer = Some(match &mut self.peer_original {
            Some(Ok(original)) => flight.observe_history_peer_post_once_v1(original),
            _ => Err(NormalRootStartupErrorV1::Service),
        });
        self.after_sample = Some(self.after_clock.observe_once(None));
        self.after_cutoff = Some(require_clock(root, source, &self.after_sample));
        if let Some(Ok(sample)) = &self.after_sample {
            if self.storage_inventory.failure().is_none() && self.storage_width.is_some() {
                self.storage_liveness = Some(self.storage_inventory.require_live_at_v1(*sample));
            }
        }
        if self.compiled.require_complete().is_ok() {
            self.compiler_liveness = Some(positive(&self.after_sample).and_then(|sample| {
                self.compiled.require_live_at_v1(*sample)
            }));
        }
        if let (Some(Ok(before)), Some(Ok(after))) = (&self.before_sample, &self.after_sample) {
            self.interval = Some(before.validate_later_sample(*after));
        }
        self.complete = matches!(self.primary, Some(Ok(())))
            && self.after_result.iter().all(|value| matches!(value, Some(Ok(()))))
            && matches!(self.after_readback, Some(Ok(_)))
            && matches!(self.after_length, Some(Ok(())))
            && matches!(self.peer, Some(Ok(())))
            && matches!(self.after_cutoff, Some(Ok(())))
            && matches!(self.compiler_liveness, Some(Ok(())))
            && matches!(self.storage_liveness, Some(Ok(())))
            && self.storage_inventory.require_complete().is_ok()
            && matches!(self.interval, Some(Ok(())))
            && self.suffix_progress.is_complete()
            && self.previous_progress[..self.suffix_active].iter().all(|progress| progress.is_complete())
            && self.suffix_active + 1 == self.suffix_segments
            && self.failure_with_original(flight).is_none();
        if self.complete { Ok(()) } else { Err(Error::History) }
    }

    fn capture_inner(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
        root: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1,
        cache: &RootCurrentCacheProofStateV1,
        source: &RootCurrentSourceExchangeStateV1,
        ownership: &super::bundle_ownership::RootCurrentBundleOwnershipStateV1,
        policy_data: &super::policy_inputs::RootCurrentPolicyInputDataV1<'_>,
        purpose: ControllerReadPurposeV1<'_>,
    ) -> Result<(), Error> {
        cache.require_complete_v1()?;
        source.require_complete_v1()?;
        if let ControllerReadPurposeV1::Signed { received, admitted, input, .. } = purpose {
            self.signed_suffix.prepare_once(root.completed_body()?.open.lane, received, admitted, input)?;
        }
        self.receipt_copy = Some(cache.controller_receipt_v1(root, ready)
            .and_then(|receipt| receipt.encode(root.completed_body()?.open.lane)
                .map_err(|_| Error::History)).map(|bytes| self.receipt = bytes));
        positive(&self.receipt_copy).map_err(|_| Error::History)?;
        let body = root.completed_body()?;
        let receipt = match InputsReadyNativeReceiptDataV1::decode(&self.receipt, body.open.lane) {
            Ok(receipt) => {
                self.receipt_decoding = Some(Ok(()));
                receipt
            }
            Err(cause) => {
                self.receipt_decoding = Some(Err(cause));
                return Err(Error::History);
            }
        };
        let key = KeyV1::new(body.open.lane, OwnerV1::Controller, 3).map_err(|_| Error::History)?;
        let phase = PhaseV1::new(OwnerV1::Controller, 2).map_err(|_| Error::History)?;
        self.expected = Some(crate::journal::create_storage_history::prepare_readonly_history_pair_v1(
            key, phase, receipt.record, &receipt.latest_head,
        ));
        let expected = positive(&self.expected).map_err(|_| Error::History)?;
        self.coordinates = Some((|| {
            let bytes = crate::journal::encoded_transaction_append_bytes(expected)?;
            let next = receipt.after_next.checked_sub(4).filter(|next| *next != 0)
                .ok_or(JournalError::ProtectedBoundary)?;
            let end = receipt.after_end.checked_sub(bytes).ok_or(JournalError::ProtectedBoundary)?;
            Ok((next, end))
        })());
        positive(&self.coordinates).map_err(|_| Error::History)?;
        let bundle = ReadyBundleDataV1::borrow_field_framing_data_v1(ready.raw_ready_bytes()?)
            .map_err(|_| Error::History)?;
        self.storage_width = Some(storage_inventory::RootCurrentStorageInventoryV1::encoded_width_v1(bundle));
        positive(&self.storage_width).map_err(|_| Error::History)?;
        self.compiler_root_width = Some(policy_data.encoded_width_v1());
        positive(&self.compiler_root_width).map_err(|_| Error::History)?;
        self.history_geometry = Some(ControllerHistoryGeometryV1::from_bundle(bundle, receipt));
        positive(&self.history_geometry).map_err(|_| Error::History)?;
        purpose.observe_writers(writers, root, &mut self.before, &mut self.before_result,
            &mut self.before_readback);
        for result in &self.before_result { positive(result).map_err(|_| Error::History)?; }
        positive(&self.before_readback).map_err(|_| Error::History)?;
        self.before_sample = Some(self.before_clock.observe_once(None));
        self.before_cutoff = Some(require_clock(root, source, &self.before_sample));
        positive(&self.before_cutoff).map_err(|_| Error::History)?;
        let startup = flight.current_cut_startup().map_err(|_| Error::Original)?;
        self.mount_before_result = Some(self.mount_before.observe_root_readonly_once(
            RootReadonlyViewV1::Controller, body.controller_uid,
            rustix::process::getegid().as_raw(), Some(receipt.names.directory())));
        positive(&self.mount_before_result).map_err(|_| Error::History)?;
        {
            let mut context = match purpose {
                ControllerReadPurposeV1::Closed { signed, outcome, .. } => RootControllerReadonlyReceivingContextV1::preparation_closed(
                    startup, root, signed, outcome, &mut self.preparation_admission, &mut self.preparation_frontier, &mut self.lock_name),
                ControllerReadPurposeV1::Signed { admitted, .. } => RootControllerReadonlyReceivingContextV1::preparation_signed(
                    startup, root, admitted, &mut self.preparation_admission, &mut self.preparation_frontier, &mut self.lock_name),
                ControllerReadPurposeV1::Outcome { signed, .. } => RootControllerReadonlyReceivingContextV1::preparation_outcome(
                    startup, root, signed, &mut self.preparation_admission, &mut self.preparation_frontier, &mut self.lock_name),
                ControllerReadPurposeV1::Initial => RootControllerReadonlyReceivingContextV1::preparation(
                    startup, root, &mut self.preparation_admission, &mut self.preparation_frontier, &mut self.lock_name),
                ControllerReadPurposeV1::Reserved { authorization, .. } => RootControllerReadonlyReceivingContextV1::preparation_reserved(
                    startup, root, authorization, &mut self.preparation_admission,
                    &mut self.preparation_frontier, &mut self.lock_name),
            };
            self.reader.prepare_captured_root_controller_once(
                body.controller_uid, receipt.names.directory(), &mut context,
            );
        }
        if self.reader.root_controller_primary_failure_v1().is_some() {
            return Err(Error::History);
        }
        self.captured_binding = Some((|| {
            let extent = self.reader.captured_extent().ok_or(JournalError::ProtectedBoundary)?;
            if extent.native_bytes != self.purpose_after_end_v1(purpose, body.open.lane, receipt)
                .map_err(|_| JournalError::ProtectedBoundary)? {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        positive(&self.captured_binding).map_err(|_| Error::History)?;
        self.native_funding = Some(match purpose {
            ControllerReadPurposeV1::Closed { signed, outcome, .. } => startup.prepay_create_storage_closed_controller_native_once(root, signed, outcome, self),
            ControllerReadPurposeV1::Signed { admitted, .. } => startup.prepay_create_storage_signed_controller_native_once(root, admitted, self),
            ControllerReadPurposeV1::Outcome { signed, .. } => startup.prepay_create_storage_outcome_controller_native_once(root, signed, self),
            ControllerReadPurposeV1::Initial => startup.prepay_create_storage_controller_readonly_native_once(root, self),
            ControllerReadPurposeV1::Reserved { authorization, .. } =>
                startup.prepay_create_storage_use_controller_readonly_native_once(root, authorization, self),
        });
        positive(&self.native_funding).map_err(|_| Error::History)?;
        // These two variable-width comparison copies were included in the SAME
        // actual Native-stage debit, before their first allocation.
        let geometry = positive(&self.history_geometry).map_err(|_| Error::History)?;
        for (index, record) in [bundle.intent_record, bundle.assignment_planned].into_iter().enumerate() {
            self.previous_expected[index] = Some(crate::journal::create_storage_history::prepare_readonly_history_pair_v1(
                KeyV1::new(bundle.lane, OwnerV1::Controller, (index + 1) as u64)
                    .map_err(|_| Error::History)?,
                PhaseV1::new(OwnerV1::Controller, [1, 12][index]).map_err(|_| Error::History)?,
                record, &geometry.heads[index],
            ));
            positive(&self.previous_expected[index]).map_err(|_| Error::History)?;
        }
        self.audit.observe_captured_once(&self.reader);
        if self.audit.failure().is_some() { return Err(Error::History); }
        // The full captured bank, including prior lanes, determines the exact
        // additional U-position backing before the shared observer can grow.
        self.bank_use_geometry = Some(aos_sandbox_protocol::domain_ledger::resource_bank::PhysicalHistory::
            additional_use_receiving_demand_v1(self.audit.native_data_v1()
                .and_then(|native| native.state()).ok_or(Error::History)?));
        positive(&self.bank_use_geometry).map_err(|_| Error::History)?;
        if let ControllerReadPurposeV1::Outcome { received, admitted, signed, input, .. } = purpose {
            self.outcome_suffix.observe_once(self.audit.native_data_v1().and_then(|native| native.state())
                .ok_or(Error::History)?, body.open.lane, signed, admitted, received,
                input.recorded_receipt_v1(body.open.lane)?)?;
        }
        if let ControllerReadPurposeV1::Closed { reserved, outcome, input, .. } = purpose {
            self.closed_suffix.observe_once(self.audit.native_data_v1().and_then(|native| native.state())
                .ok_or(Error::History)?, body.open.lane, reserved, outcome, input)?;
        }
        self.semantic_funding = Some(match purpose {
            ControllerReadPurposeV1::Closed { signed, outcome, .. } => startup.prepay_create_storage_closed_controller_semantic_once(root, signed, outcome, self),
            ControllerReadPurposeV1::Signed { admitted, .. } => startup.prepay_create_storage_signed_controller_semantic_once(root, admitted, self),
            ControllerReadPurposeV1::Outcome { signed, .. } => startup.prepay_create_storage_outcome_controller_semantic_once(root, signed, self),
            ControllerReadPurposeV1::Initial => startup.prepay_create_storage_controller_readonly_semantic_once(root, self),
            ControllerReadPurposeV1::Reserved { authorization, .. } =>
                startup.prepay_create_storage_use_controller_readonly_semantic_once(root, authorization, self),
        });
        positive(&self.semantic_funding).map_err(|_| Error::History)?;
        {
            let mut context = match purpose {
                ControllerReadPurposeV1::Initial => {
                    let [first, second, ..] = &mut self.previous_progress;
                    let suffix = ControllerHistoryNativeSuffixV1::new(
                        [positive(&self.previous_expected[0]).map_err(|_| Error::History)?,
                            positive(&self.previous_expected[1]).map_err(|_| Error::History)?,
                            positive(&self.expected).map_err(|_| Error::History)?],
                        [first, second, &mut self.suffix_progress], &mut self.suffix_active,
                        positive(&self.history_geometry).map_err(|_| Error::History)?.positions);
                    let suffix = match suffix {
                        Ok(suffix) => { self.suffix_construction = Some(Ok(())); suffix }
                        Err(cause) => { self.suffix_construction = Some(Err(cause)); return Err(Error::History); }
                    };
                    let (original, admission_data) = decode_replay_original_v1(bundle)?;
                    RootControllerReadonlyReceivingContextV1::replay(startup, root, &self.audit, suffix,
                        &mut self.replay_admission, &mut self.replay_frontier, &mut self.lock_name,
                        original, admission_data, &mut self.accepted_native)
                }
                ControllerReadPurposeV1::Closed { received, signed, outcome, .. } => {
                    let reserved = received.expected_v1()?;
                    let prior = outcome.completed_controller_v1()?.outcome_suffix_v1()?;
                    let continuation = prior.expected_v1()?;
                    let final_pairs = self.closed_suffix.expected_v1()?;
                    let initial = positive(&self.history_geometry).map_err(|_| Error::History)?.positions;
                    let tail = received.positions_v1()?;
                    let later = prior.positions_v1()?;
                    let closing = self.closed_suffix.positions_v1()?;
                    if initial[3] != tail[0] || tail[3] != later[0] || later[4] != closing[0] {
                        return Err(Error::History);
                    }
                    let positions = [initial[0],initial[1],initial[2],initial[3],tail[1],tail[2],tail[3],
                        later[1],later[2],later[3],later[4],closing[1],closing[2]];
                    let [p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10] = &mut self.previous_progress;
                    let binding = aos_sandbox_protocol::domain_ledger::resource_bank::CreateStorageUseBindingV1::
                        decode(received.receipt_v1(bundle.lane)?.body(bundle.lane).map_err(|_| Error::History)?.binding)
                        .map_err(|_| Error::History)?;
                    let suffix = ControllerHistoryNativeSuffixV1::<12>::new_closed(
                        [positive(&self.previous_expected[0]).map_err(|_| Error::History)?,
                            positive(&self.previous_expected[1]).map_err(|_| Error::History)?,
                            positive(&self.expected).map_err(|_| Error::History)?, reserved[0],reserved[1],reserved[2],
                            continuation[0],continuation[1],continuation[2],continuation[3],final_pairs[0],final_pairs[1]],
                        [p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,&mut self.suffix_progress],
                        &mut self.suffix_active, positions, binding);
                    let suffix = match suffix {
                        Ok(suffix) => { self.suffix_construction = Some(Ok(())); suffix },
                        Err(cause) => { self.suffix_construction = Some(Err(cause)); return Err(Error::History); },
                    };
                    let (original, admission) = decode_replay_original_v1(bundle)?;
                    RootControllerReadonlyReceivingContextV1::replay_closed(startup, root, signed, outcome,
                        &self.audit, suffix, &mut self.replay_admission, &mut self.replay_frontier,
                        &mut self.lock_name, original, admission,
                        received.receipt_v1(bundle.lane)?.body(bundle.lane).map_err(|_| Error::History)?, &mut self.accepted_native)
                }
                ControllerReadPurposeV1::Signed { authorization, received, admitted, .. } => {
                    let expected = received.expected_v1()?;
                    let tail = received.positions_v1()?;
                    let later = self.signed_suffix.positions_v1()?;
                    let initial = positive(&self.history_geometry).map_err(|_| Error::History)?.positions;
                    if initial[3] != tail[0] || tail[3] != later[0] { return Err(Error::History); }
                    let positions = [initial[0], initial[1], initial[2], initial[3],
                        tail[1], tail[2], tail[3], later[1]];
                    let [p0, p1, p2, p3, p4, p5, ..] = &mut self.previous_progress;
                    let suffix = ControllerHistoryNativeSuffixV1::<7>::new_signed(
                        [positive(&self.previous_expected[0]).map_err(|_| Error::History)?,
                            positive(&self.previous_expected[1]).map_err(|_| Error::History)?,
                            positive(&self.expected).map_err(|_| Error::History)?,
                            expected[0], expected[1], expected[2], self.signed_suffix.expected_v1()?],
                        [p0, p1, p2, p3, p4, p5, &mut self.suffix_progress],
                        &mut self.suffix_active, positions);
                    let suffix = match suffix {
                        Ok(suffix) => { self.suffix_construction = Some(Ok(())); suffix }
                        Err(cause) => { self.suffix_construction = Some(Err(cause)); return Err(Error::History); }
                    };
                    let (original, admission_data) = decode_replay_original_v1(bundle)?;
                    RootControllerReadonlyReceivingContextV1::replay_signed(startup, root, admitted, authorization,
                        &self.audit, suffix, &mut self.replay_admission, &mut self.replay_frontier,
                        &mut self.lock_name, original, admission_data,
                        received.receipt_v1(bundle.lane)?.body(bundle.lane).map_err(|_| Error::History)?,
                        &mut self.accepted_native)
                }
                ControllerReadPurposeV1::Outcome { authorization, received, signed, .. } => {
                    let expected = received.expected_v1()?;
                    let continuation = self.outcome_suffix.expected_v1()?;
                    let tail = received.positions_v1()?;
                    let later = self.outcome_suffix.positions_v1()?;
                    let initial = positive(&self.history_geometry).map_err(|_| Error::History)?.positions;
                    if initial[3] != tail[0] || tail[3] != later[0] { return Err(Error::History); }
                    let positions = [initial[0], initial[1], initial[2], initial[3], tail[1], tail[2], tail[3],
                        later[1], later[2], later[3], later[4]];
                    let [p0,p1,p2,p3,p4,p5,p6,p7,p8,..] = &mut self.previous_progress;
                    let suffix = ControllerHistoryNativeSuffixV1::<10>::new_outcome(
                        [positive(&self.previous_expected[0]).map_err(|_| Error::History)?,
                            positive(&self.previous_expected[1]).map_err(|_| Error::History)?,
                            positive(&self.expected).map_err(|_| Error::History)?, expected[0], expected[1], expected[2],
                            continuation[0], continuation[1], continuation[2], continuation[3]],
                        [p0,p1,p2,p3,p4,p5,p6,p7,p8,&mut self.suffix_progress], &mut self.suffix_active, positions);
                    let suffix = match suffix {
                        Ok(suffix) => { self.suffix_construction = Some(Ok(())); suffix }
                        Err(cause) => { self.suffix_construction = Some(Err(cause)); return Err(Error::History); }
                    };
                    let (original, admission_data) = decode_replay_original_v1(bundle)?;
                    RootControllerReadonlyReceivingContextV1::replay_outcome(startup, root, signed, authorization,
                        &self.audit, suffix, &mut self.replay_admission, &mut self.replay_frontier,
                        &mut self.lock_name, original, admission_data,
                        received.receipt_v1(bundle.lane)?.body(bundle.lane).map_err(|_| Error::History)?,
                        &mut self.accepted_native)
                }
                ControllerReadPurposeV1::Reserved { authorization, received } => {
                    let expected = received.expected_v1()?;
                    let tail = received.positions_v1()?;
                    let initial = positive(&self.history_geometry).map_err(|_| Error::History)?.positions;
                    if initial[3] != tail[0] { return Err(Error::History); }
                    let positions = [initial[0], initial[1], initial[2], initial[3], tail[1], tail[2], tail[3]];
                    let [first, second, third, fourth, bank, ..] = &mut self.previous_progress;
                    let suffix = ControllerHistoryNativeSuffixV1::<6>::new_reserved(
                        [positive(&self.previous_expected[0]).map_err(|_| Error::History)?,
                            positive(&self.previous_expected[1]).map_err(|_| Error::History)?,
                            positive(&self.expected).map_err(|_| Error::History)?, expected[0], expected[1], expected[2]],
                        [first, second, third, fourth, bank, &mut self.suffix_progress],
                        &mut self.suffix_active, positions);
                    let suffix = match suffix {
                        Ok(suffix) => { self.suffix_construction = Some(Ok(())); suffix }
                        Err(cause) => { self.suffix_construction = Some(Err(cause)); return Err(Error::History); }
                    };
                    let (original, admission_data) = decode_replay_original_v1(bundle)?;
                    RootControllerReadonlyReceivingContextV1::replay_reserved(startup, root, authorization,
                        &self.audit, suffix, &mut self.replay_admission, &mut self.replay_frontier,
                        &mut self.lock_name, original, admission_data,
                        received.receipt_v1(bundle.lane)?.body(bundle.lane).map_err(|_| Error::History)?,
                        &mut self.accepted_native)
                }
            };
            self.reader.replay_captured_root_controller_once(&mut context);
        }
        if self.reader.root_controller_primary_failure_v1().is_some() {
            return Err(Error::History);
        }
        let view = self.reader.readback_mut().ok_or(Error::History)?;
        self.native_binding = Some(match purpose {
            ControllerReadPurposeV1::Closed { input, .. } => view.require_root_controller_outcome_replay_data_v1(
                &self.audit, input.controller_receipt_v1(bundle.lane)?),
            ControllerReadPurposeV1::Signed { received, .. } => view.require_root_controller_signed_replay_data_v1(
                &self.audit, received.receipt_v1(bundle.lane)?.names, self.signed_suffix.positions_v1()?[1]),
            ControllerReadPurposeV1::Outcome { input, .. } => view.require_root_controller_outcome_replay_data_v1(
                &self.audit, input.recorded_receipt_v1(bundle.lane)?),
            ControllerReadPurposeV1::Initial => view.require_root_controller_replay_data_v1(&self.audit, receipt),
            ControllerReadPurposeV1::Reserved { received, .. } => view.require_root_controller_use_replay_data_v1(
                &self.audit, received.receipt_v1(bundle.lane)?),
        });
        positive(&self.native_binding).map_err(|_| Error::History)?;
        let raw = ready.raw_ready_bytes()?;
        let bundle = ReadyBundleDataV1::borrow_field_framing_data_v1(raw).map_err(|_| Error::History)?;
        self.history_binding = Some(match purpose {
            ControllerReadPurposeV1::Closed { input, outcome, .. } => {
                let prior = outcome.completed_controller_v1()?.outcome_suffix_v1()?.expected_v1()?;
                let tail = self.closed_suffix.expected_v1()?;
                view.require_root_controller_closed_history_data_v1(bundle.lane, input.controller_receipt_v1(bundle.lane)?,
                    [prior[0],prior[1],prior[2],prior[3],tail[1]])
            },
            ControllerReadPurposeV1::Signed { received, .. } => view.require_root_controller_signed_history_data_v1(
                bundle, receipt, received.expected_v1()?[0], received.receipt_v1(bundle.lane)?,
                self.signed_suffix.expected_v1()?),
            ControllerReadPurposeV1::Outcome { input, .. } => view.require_root_controller_outcome_history_data_v1(
                bundle.lane, input.recorded_receipt_v1(bundle.lane)?, self.outcome_suffix.expected_v1()?),
            ControllerReadPurposeV1::Initial => view.require_root_controller_bundle_history_data_v1(bundle, receipt),
            ControllerReadPurposeV1::Reserved { received, .. } => view.require_root_controller_use_bundle_history_data_v1(
                bundle, receipt, received.expected_v1()?[0], received.receipt_v1(bundle.lane)?),
        });
        positive(&self.history_binding).map_err(|_| Error::History)?;
        view.observe_root_controller_accepted_create_v1(&mut self.accepted_create, bundle)
            .map_err(|_| Error::History)?;
        self.accepted_native.require_complete().map_err(|_| Error::History)?;
        let identity = self.accepted_create.identity_v1().map_err(|_| Error::History)?;
        let root_final = self.accepted_create.root_final_v1().map_err(|_| Error::History)?;
        let (authority, _) = writers.authority_and_policy().map_err(|_| Error::History)?;
        self.root_parent_result = Some(authority.observe_original_root_q04_parent_v1(
            &mut self.root_parent, identity, root_final,
        ));
        positive(&self.root_parent_result).map_err(|_| Error::History)?;
        let (_, policy) = writers.authority_and_policy().map_err(|_| Error::History)?;
        let source_fields = source.fields_v1()?;
        let cache_body = cache.verified_body_v1()?;
        let manifest = ownership.completed_manifest_v1()?;
        let now = positive(&self.before_sample).map_err(|_| Error::History)?.wall_seconds();
        self.compiled.observe_once(view.journal_mut(), policy, policy_data, source_fields,
            cache_body, bundle, identity, manifest, now);
        self.compiled.require_complete().map_err(|_| Error::History)?;
        let candidate = self.compiled.candidate_v1().map_err(|_| Error::History)?;
        self.storage_inventory.observe_once(bundle, manifest, candidate,
            *positive(&self.before_sample).map_err(|_| Error::History)?,
            aos_sandbox_protocol::PeerCredentials { uid: body.controller_uid,
                gid: body.controller_gid, pid: Some(body.controller_pid) },
            ownership.completed_response_v1()?.value().ok_or(Error::History)?,
            self.compiled.expires_at_v1().map_err(|_| Error::History)?, body.cutoff);
        if self.storage_inventory.failure().is_some() { Err(Error::History) } else { Ok(()) }
    }

    fn purpose_after_end_v1(&self, purpose: ControllerReadPurposeV1<'_>, lane: [u8; 16],
        inputs: InputsReadyNativeReceiptDataV1<'_>) -> Result<u64, Error>
    {
        match purpose {
            ControllerReadPurposeV1::Signed { .. } => Ok(self.signed_suffix.positions_v1()?[1].1),
            _ => purpose.after_end(lane, inputs),
        }
    }

    fn receipt_data_v1(&self, lane: [u8; 16]) -> Result<InputsReadyNativeReceiptDataV1<'_>, HistoryErrorV1> {
        InputsReadyNativeReceiptDataV1::decode(&self.receipt, lane)
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), Error> {
        if self.complete && self.closed.is_none() && self.accepted_create.require_complete().is_ok()
            && self.accepted_native.require_complete().is_ok() && self.root_parent.require_complete().is_ok()
            && self.compiled.require_complete().is_ok()
            && self.storage_inventory.require_complete().is_ok()
            && self.suffix_progress.is_complete()
            && self.previous_progress[..self.suffix_active].iter().all(|progress| progress.is_complete())
            && self.suffix_active + 1 == self.suffix_segments
        {
            Ok(())
        } else {
            Err(Error::History)
        }
    }

    pub(super) fn compiled_candidate_v1(&self)
        -> Result<&aos_sandbox_policy::CompiledPolicyCandidateV1, Error>
    {
        self.require_complete_v1()?;
        self.compiled.candidate_v1().map_err(|_| Error::History)
    }

    // Borrows the same completely replayed original; no path or fresh sample
    // can substitute the Controller prefix used by this independent Root read.
    pub(super) fn actual_controller_extent_v1(&self)
        -> Result<&ProtectedJournalPreopenReplayExtentV1, Error>
    {
        self.require_complete_v1()?;
        self.reader.captured_extent().ok_or(Error::History)
    }

    pub(super) fn require_live_at_v1(&self, sample: RawPairedClockSample)
        -> Result<(), JournalError>
    {
        self.require_complete_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        self.compiled.require_live_at_v1(sample)?;
        self.storage_inventory.require_live_at_v1(sample)
    }

    pub(crate) fn completed_sample_v1(&self) -> Result<RawPairedClockSample, Error> {
        self.require_complete_v1()?;
        positive(&self.after_sample).copied().map_err(|_| Error::History)
    }

    pub(crate) fn outcome_suffix_v1(&self) -> Result<&outcome::RootControllerOutcomeSuffixDataV1, Error> {
        self.require_complete_v1()?;
        self.outcome_suffix.require_complete_v1()?;
        Ok(&self.outcome_suffix)
    }

    pub(crate) fn failed_closed_financial_entry_v1(&self) -> Option<super::closed::ClosedFinancialStageV1> {
        use super::closed::ClosedFinancialStageV1 as Stage;
        if matches!(self.preparation_admission, Some(Err(_))) { Some(Stage::Fixed) }
        else if matches!(self.native_funding, Some(Err(_))) { Some(Stage::ControllerNative) }
        else if matches!(self.semantic_funding, Some(Err(_))) { Some(Stage::ControllerSemantic) }
        else { None }
    }

    pub(crate) fn closed_suffix_v1(&self) -> Result<&closed::RootControllerClosedSuffixDataV1, Error> {
        self.require_complete_v1()?;
        self.closed_suffix.require_complete_v1()?;
        Ok(&self.closed_suffix)
    }

    pub(crate) fn storage_inventory_v1(&self) -> Result<&storage_inventory::RootCurrentStorageInventoryV1, Error> {
        self.require_complete_v1()?;
        Ok(&self.storage_inventory)
    }

    pub(super) fn protected_storage_preparation_v1(&self)
        -> Result<&aos_sandbox_protocol::semantics::ProtectedStorageCreatePreparationV1, Error>
    {
        self.require_complete_v1()?;
        self.storage_inventory.protected_preparation_v1().map_err(|_| Error::History)
    }

    pub(super) fn prospective_use_plan_v1(&self)
        -> Result<&use_plan::RootProspectiveStorageUsePlanV1, Error>
    {
        self.require_complete_v1()?;
        self.storage_inventory.prospective_plan_v1().map_err(|_| Error::History)
    }

    pub(super) fn prospective_session_extent_v1(&self)
        -> Result<&ProtectedJournalPreopenReplayExtentV1, Error>
    {
        self.require_complete_v1()?;
        self.storage_inventory.session_extent_v1().map_err(|_| Error::History)
    }

    pub(super) fn accepted_identity_v1(&self)
        -> Result<&crate::policy_compiler::create_q04::Q04CutIdentityV1, Error>
    {
        self.require_complete_v1()?;
        self.accepted_create.identity_v1().map_err(|_| Error::History)
    }

    pub(super) fn failure_with_original<'a>(
        &'a self,
        flight: &'a RootPolicyAcceptedFlightV1<'_, '_>,
    ) -> Option<&'a (dyn StdError + 'static)> {
        self.signed_suffix.failure().or_else(|| cause(&self.receipt_copy))
            .or_else(|| cause(&self.receipt_decoding))
            .or_else(|| cause(&self.expected)).or_else(|| cause(&self.coordinates))
            .or_else(|| cause(&self.storage_width))
            .or_else(|| cause(&self.compiler_root_width)).or_else(|| cause(&self.history_geometry))
            .or_else(|| self.before.iter().find_map(|value| value.failure()))
            .or_else(|| self.before_result.iter().find_map(cause)).or_else(|| cause(&self.before_readback))
            .or_else(|| self.before_clock.failure()).or_else(|| cause(&self.before_sample))
            .or_else(|| cause(&self.before_cutoff))
            .or_else(|| self.mount_before.failure()).or_else(|| cause(&self.mount_before_result))
            .or_else(|| if matches!(self.preparation_admission, Some(Err(_))) { flight.failure() } else { None })
            .or_else(|| cause(&self.preparation_admission)).or_else(|| cause(&self.preparation_frontier))
            .or_else(|| {
                // A failed typed context hook returns the reader's mapped
                // boundary marker. Its exact original remains on this owner;
                // unrelated earlier native/Source failures still use the
                // reader's own chronological selector unchanged.
                let context_failed = matches!(self.replay_admission, Some(Err(_)))
                    || matches!(self.replay_frontier, Some(Err(_)))
                    || self.accepted_native.failure().is_some()
                    || self.suffix_progress.failure().is_some()
                    || self.previous_progress.iter().any(|progress| progress.failure().is_some());
                if context_failed { None } else { self.reader.root_controller_primary_failure_v1() }
            })
            .or_else(|| cause(&self.captured_binding))
            .or_else(|| if matches!(self.native_funding, Some(Err(_))) { flight.failure() } else { None })
            .or_else(|| cause(&self.native_funding))
            .or_else(|| self.previous_expected.iter().find_map(cause))
            .or_else(|| self.audit.failure()).or_else(|| self.outcome_suffix.failure()).or_else(|| self.closed_suffix.failure())
            .or_else(|| if matches!(self.semantic_funding, Some(Err(_))) { flight.failure() } else { None })
            .or_else(|| cause(&self.bank_use_geometry))
            .or_else(|| cause(&self.semantic_funding))
            .or_else(|| self.accepted_native.failure())
            .or_else(|| self.previous_progress.iter().find_map(|progress| progress.failure()).map(|cause| cause as _))
            .or_else(|| self.suffix_progress.failure().map(|cause| cause as _))
            .or_else(|| cause(&self.suffix_construction))
            .or_else(|| if matches!(self.replay_admission, Some(Err(_))) { flight.failure() } else { None })
            .or_else(|| cause(&self.replay_admission))
            .or_else(|| cause(&self.replay_frontier))
            .or_else(|| self.reader.root_controller_primary_failure_v1())
            .or_else(|| cause(&self.native_binding))
            .or_else(|| cause(&self.history_binding)).or_else(|| self.accepted_create.failure())
            .or_else(|| self.root_parent.failure()).or_else(|| cause(&self.root_parent_result))
            .or_else(|| self.compiled.failure()).or_else(|| self.storage_inventory.failure())
            .or_else(|| cause(&self.primary))
            .or_else(|| self.after.iter().find_map(|value| value.failure()))
            .or_else(|| self.after_result.iter().find_map(cause)).or_else(|| cause(&self.after_readback))
            .or_else(|| self.reader.failure())
            .or_else(|| self.mount_after.failure()).or_else(|| cause(&self.mount_after_result))
            .or_else(|| cause(&self.mount_binding)).or_else(|| self.storage_inventory.post_failure())
            .or_else(|| cause(&self.after_metadata))
            .or_else(|| cause(&self.after_length)).or_else(|| self.peer_original.as_ref().and_then(|original| match original {
                Ok(original) => original.failure(), Err(cause) => Some(cause as _),
            })).or_else(|| cause(&self.peer))
            .or_else(|| self.after_clock.failure()).or_else(|| cause(&self.after_sample))
            .or_else(|| cause(&self.after_cutoff)).or_else(|| cause(&self.storage_liveness))
            .or_else(|| cause(&self.compiler_liveness))
            .or_else(|| cause(&self.interval))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value.as_ref().and_then(|result| result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: StdError + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn StdError + 'static)> {
    value.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}

// This is comparison geometry derived from the same immutable B and actual
// Phase4. It supplies no authority and allocates no encoded record or model.
struct ControllerHistoryGeometryV1 {
    positions: [(u64, u64); 4],
    heads: [[u8; 40]; 2],
    copy_bytes: u64,
    accepted_bytes: u64,
    compiler_bytes: u64,
}

impl ControllerHistoryGeometryV1 {
    fn from_bundle(
        bundle: ReadyBundleDataV1<'_>,
        receipt: InputsReadyNativeReceiptDataV1<'_>,
    ) -> Result<Self, JournalError> {
        use aos_sandbox_protocol::domain_ledger::create_storage_history::{
            LatestHeadV1, RecordEnvelopeV1, KEY_BYTES,
            controller_intent::ControllerIntentBodyDataV1,
            ready::IntentNativeReceiptDataV1,
        };
        let invalid = || JournalError::ProtectedBoundary;
        let key = |revision| KeyV1::new(bundle.lane, OwnerV1::Controller, revision)
            .map_err(|_| invalid());
        let phase = |value| PhaseV1::new(OwnerV1::Controller, value).map_err(|_| invalid());
        let intent = RecordEnvelopeV1::decode(bundle.intent_record, key(1)?, phase(1)?)
            .map_err(|_| invalid())?;
        let planned = RecordEnvelopeV1::decode(bundle.assignment_planned, key(2)?, phase(12)?)
            .map_err(|_| invalid())?;
        let inputs = RecordEnvelopeV1::decode(receipt.record, key(3)?, phase(2)?)
            .map_err(|_| invalid())?;
        let original = ControllerIntentBodyDataV1::decode(intent.body())
            .map_err(|_| invalid())?.identity;
        let accepted_bytes = u64::try_from(intent.body().len()).map_err(|_| invalid())?;
        let compiler_bytes = [bundle.compiler_origin, bundle.policy_sources, bundle.specification]
            .into_iter().try_fold(0_u64, |total, bytes| {
                total.checked_add(u64::try_from(bytes.len()).map_err(|_| invalid())?)
                    .ok_or_else(invalid)
            })?;
        let native = IntentNativeReceiptDataV1::decode(bundle.intent_native_receipt)
            .map_err(|_| invalid())?;
        if original.lane != bundle.lane || original.j_names != receipt.names
            || native.names != receipt.names || intent.coordinates().predecessor != [0; 32]
            || planned.coordinates().predecessor != intent.checksum()
            || inputs.coordinates().predecessor != planned.checksum()
            || planned.coordinates().correlation != intent.coordinates().correlation
            || inputs.coordinates().correlation != intent.coordinates().correlation
        {
            return Err(invalid());
        }
        let append = |bytes| {
            aos_sandbox_journal::geometry::encoded_transaction_append_bytes([
                aos_sandbox_journal::geometry::RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(bytes) },
                aos_sandbox_journal::geometry::RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(40) },
            ].into_iter()).map_err(|_| invalid())
        };
        let start = (original.j_commit.checked_add(1).ok_or_else(invalid)?, original.j_end);
        let after_intent = (start.0.checked_add(4).ok_or_else(invalid)?,
            start.1.checked_add(append(bundle.intent_record.len())?).ok_or_else(invalid)?);
        let after_planned = (after_intent.0.checked_add(4).ok_or_else(invalid)?,
            after_intent.1.checked_add(append(bundle.assignment_planned.len())?).ok_or_else(invalid)?);
        let after_inputs = (after_planned.0.checked_add(4).ok_or_else(invalid)?,
            after_planned.1.checked_add(append(receipt.record.len())?).ok_or_else(invalid)?);
        if start.0 == 0 || native.after_next != after_intent.0 || native.after_end != after_intent.1
            || receipt.after_next != after_inputs.0 || receipt.after_end != after_inputs.1
        {
            return Err(invalid());
        }
        let heads = [native.latest_head,
            LatestHeadV1::new(2, planned.checksum()).map_err(|_| invalid())?.encode()];
        let copy_bytes = bundle.intent_record.len().checked_add(bundle.assignment_planned.len())
            .and_then(|bytes| bytes.checked_add(2 * (40 + 2 * KEY_BYTES
                + 2 * size_of::<crate::journal::JournalRecord>())))
            .and_then(|bytes| bytes.checked_mul(2)).ok_or_else(invalid)?;
        Ok(Self { positions: [start, after_intent, after_planned, after_inputs], heads,
            copy_bytes: u64::try_from(copy_bytes).map_err(|_| invalid())?, accepted_bytes, compiler_bytes })
    }
}

#[allow(dead_code)]
struct ReadonlyFixedFramesV1 {
    bundles: [ReadyBundleDataV1<'static>; 2],
    receipts: [InputsReadyNativeReceiptDataV1<'static>; 4],
    hellos: [aos_sandbox_protocol::domain_ledger::create_storage_history::root_open::RootHelloDataV1<'static>; 2],
    proofs: [aos_sandbox_protocol::domain_ledger::create_storage_history::current_proofs::CurrentProofsDataV1<'static>; 2],
    frames: [aos_sandbox_protocol::domain_ledger::create_storage_history::transport::FrameEnvelopeV1<'static>; 2],
    keys: [KeyV1; 24],
    records: [aos_sandbox_protocol::domain_ledger::create_storage_history::RecordEnvelopeV1<'static>; 12],
    readers: [aos_sandbox_model::bounded_codec::BoundedReader<'static, HistoryErrorV1>; 16],
    hashers: [sha2::Sha256; 8],
    extents: [ProtectedJournalPreopenReplayExtentV1; 2],
    transactions: [JournalTransaction; 6],
    record_constructors: [crate::journal::JournalRecord; 12],
    history_geometry: [ControllerHistoryGeometryV1; 2],
    demands: [ResourceVector; 8],
    results: [Result<ResourceVector, JournalError>; 8],
    positions: [(u64, u64); 4],
    metadata: [Result<Metadata, std::io::Error>; 2],
}


fn decode_replay_original_v1<'data>(bundle: ReadyBundleDataV1<'data>)
    -> Result<(aos_sandbox_protocol::domain_ledger::create_storage_history::controller_intent::ControllerIntentBodyDataV1<'data>,
        aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ControllerAdmissionDataV1<'data>), Error>
{
    let intent = aos_sandbox_protocol::domain_ledger::create_storage_history::RecordEnvelopeV1::decode(
        bundle.intent_record, KeyV1::new(bundle.lane, OwnerV1::Controller, 1).map_err(|_| Error::History)?,
        PhaseV1::new(OwnerV1::Controller, 1).map_err(|_| Error::History)?)
        .map_err(|_| Error::History)?;
    let original = aos_sandbox_protocol::domain_ledger::create_storage_history::controller_intent::ControllerIntentBodyDataV1::decode(intent.body())
        .map_err(|_| Error::History)?;
    let admission = aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ControllerAdmissionDataV1::decode(
        bundle.controller_admission).map_err(|_| Error::History)?;
    Ok((original, admission))
}

pub(in crate::policy_compiler) mod public_trust;

mod apply_plan;

// Supplies only the same existing compiler's actual receiving geometry. The
// closed fresh-purpose owner still obtains its own real stage admission.
pub(crate) fn current_compiler_receiving_demand_v1(encoded_bytes: u64)
    -> Result<ResourceVector, JournalError>
{
    compiled_policy::RootCurrentCompiledPolicyV1::additional_receiving_demand_v1(encoded_bytes)
}

pub(in crate::policy_compiler) use apply_plan::RootProspectiveStorageApplyPlanV1;
