//! Binds Root's independent Controller replay to its continuously held R.
//!
//! This context adds no decoder, writer or receiving account. The existing
//! retained readonly opener and role replay call these closed gates only after
//! their actual fixed, captured-native and audited-semantic stages complete.

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_policy::controller_history_data as history_data;

use crate::normal_root::{NormalRootStartupErrorV1, ProductionNormalRootStartupV1};
use crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1;

use super::{
    JournalError, JournalTransaction, ReadOnlyJournalOpenOriginalsV1,
    ReadOnlyProtectedJournal, RecordNamespace, RootControllerReadonlyGeometryAuditV1,
};

use super::create_storage_history::ControllerHistoryNativeSuffixV1;

type State = std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

pub(crate) const ROOT_CONTROLLER_DIRECTORY_V1: &str =
    aos_sandbox_linux::signer_mount::RootReadonlyViewV1::Controller.view_path_v1();
pub(crate) const ROOT_CONTROLLER_JOURNAL_V1: &str = "controller.journal";

// Supplements the actual-prefix variable recipe with authority Arc bytes.
// The enclosing reader's two sizeof planes already cover inline owners. Maps,
// records and native paths remain separately priced by their real providers.
pub(crate) fn root_controller_replay_fixed_controls_v1() -> ResourceVector {
    // Arc counters contribute bytes. Replay/model/control field counts do not
    // create resident namespace entries; real path/index providers are separate.
    ResourceVector::ZERO
        .with(D::MemoryBytes, (2 * std::mem::size_of::<usize>()) as u64)
}

enum RootControllerReadonlyPurposeV1<'original> {
    Initial,
    ClosedPreparation {
        signed: &'original crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1,
        outcome: &'original crate::policy_compiler::create_storage_current::outcome::RootCurrentOutcomeStateV1,
    },
    ClosedReplay {
        signed: &'original crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1,
        outcome: &'original crate::policy_compiler::create_storage_current::outcome::RootCurrentOutcomeStateV1,
    },
    SignedPreparation(&'original crate::policy_compiler::create_storage_current::use_admitted::RootCurrentUseAdmittedStateV1),
    SignedReplay(&'original crate::policy_compiler::create_storage_current::use_admitted::RootCurrentUseAdmittedStateV1),
    OutcomePreparation(&'original crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1),
    OutcomeReplay(&'original crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1),
    ReservedPreparation(&'original crate::policy_compiler::create_storage_current::use_authorized::RootCurrentUseAuthorizedStateV1),
    ReservedReplay {
        authorization: &'original crate::policy_compiler::create_storage_current::use_authorized::RootCurrentUseAuthorizedStateV1,
    },
}

enum RootControllerHistorySuffixV1<'data, 'progress> {
    Closed(ControllerHistoryNativeSuffixV1<'data, 'progress, 12>),
    Signed(ControllerHistoryNativeSuffixV1<'data, 'progress, 7>),
    Outcome(ControllerHistoryNativeSuffixV1<'data, 'progress, 10>),
    Initial(ControllerHistoryNativeSuffixV1<'data, 'progress, 3>),
    Reserved(ControllerHistoryNativeSuffixV1<'data, 'progress, 6>),
}

impl RootControllerHistorySuffixV1<'_, '_> {
    fn observe(&mut self, transaction: &JournalTransaction, begin: u64, commit: u64,
        before_end: u64, after_end: u64) -> Result<(), super::create_storage_history::HistoryPairSuffixErrorV1>
    {
        match self {
            Self::Closed(suffix) => suffix.observe(transaction, begin, commit, before_end, after_end),
            Self::Signed(suffix) => suffix.observe(transaction, begin, commit, before_end, after_end),
            Self::Outcome(suffix) => suffix.observe(transaction, begin, commit, before_end, after_end),
            Self::Initial(suffix) => suffix.observe(transaction, begin, commit, before_end, after_end),
            Self::Reserved(suffix) => suffix.observe(transaction, begin, commit, before_end, after_end),
        }
    }

    fn finish(&mut self, next: u64, end: u64, captured_end: u64)
        -> Result<(), super::create_storage_history::HistoryPairSuffixErrorV1>
    {
        match self {
            Self::Closed(suffix) => suffix.finish(next, end, captured_end),
            Self::Signed(suffix) => suffix.finish(next, end, captured_end),
            Self::Outcome(suffix) => suffix.finish(next, end, captured_end),
            Self::Initial(suffix) => suffix.finish(next, end, captured_end),
            Self::Reserved(suffix) => suffix.finish(next, end, captured_end),
        }
    }
}

pub(crate) struct RootControllerReadonlyReceivingContextV1<'borrow, 'original, 'data> {
    startup: &'borrow ProductionNormalRootStartupV1,
    root: &'borrow RootCurrentOpenStateV1,
    purpose: RootControllerReadonlyPurposeV1<'borrow>,
    audit: Option<&'original RootControllerReadonlyGeometryAuditV1>,
    suffix: Option<RootControllerHistorySuffixV1<'data, 'borrow>>,
    admission: &'borrow mut Option<Result<(), NormalRootStartupErrorV1>>,
    frontier: &'borrow mut Option<Result<(), JournalError>>,
    lock_name: &'borrow mut Option<String>,
    accepted: Option<super::controller_policy_hold::RootControllerAcceptedNativeV1<'original, 'data, 'borrow>>,
}

impl<'borrow, 'original, 'data>
    RootControllerReadonlyReceivingContextV1<'borrow, 'original, 'data>
{
    pub(crate) fn preparation(
        startup: &'borrow ProductionNormalRootStartupV1,
        root: &'borrow RootCurrentOpenStateV1,
        admission: &'borrow mut Option<Result<(), NormalRootStartupErrorV1>>,
        frontier: &'borrow mut Option<Result<(), JournalError>>,
        lock_name: &'borrow mut Option<String>,
    ) -> Self {
        Self { startup, root, purpose: RootControllerReadonlyPurposeV1::Initial,
            audit: None, suffix: None, admission, frontier, lock_name, accepted: None }
    }

    pub(crate) fn replay(
        startup: &'borrow ProductionNormalRootStartupV1,
        root: &'borrow RootCurrentOpenStateV1,
        audit: &'original RootControllerReadonlyGeometryAuditV1,
        suffix: ControllerHistoryNativeSuffixV1<'data, 'borrow>,
        admission: &'borrow mut Option<Result<(), NormalRootStartupErrorV1>>,
        frontier: &'borrow mut Option<Result<(), JournalError>>,
        lock_name: &'borrow mut Option<String>,
        original: aos_sandbox_protocol::domain_ledger::create_storage_history::controller_intent::ControllerIntentBodyDataV1<'data>,
        admission_data: aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ControllerAdmissionDataV1<'data>,
        progress: &'borrow mut super::RootControllerAcceptedNativeProgressV1,
    ) -> Self {
        let accepted = audit.native_data_v1().and_then(|native| native.state())
            .and_then(|state| super::controller_policy_hold::RootControllerAcceptedNativeV1::new(state, original, admission_data, progress));
        Self { startup, root, purpose: RootControllerReadonlyPurposeV1::Initial,
            audit: Some(audit), suffix: Some(RootControllerHistorySuffixV1::Initial(suffix)),
            admission, frontier, lock_name, accepted }
    }

    pub(crate) fn preparation_reserved(
        startup: &'borrow ProductionNormalRootStartupV1,
        root: &'borrow RootCurrentOpenStateV1,
        authorization: &'borrow crate::policy_compiler::create_storage_current::use_authorized::RootCurrentUseAuthorizedStateV1,
        admission: &'borrow mut Option<Result<(), NormalRootStartupErrorV1>>,
        frontier: &'borrow mut Option<Result<(), JournalError>>,
        lock_name: &'borrow mut Option<String>,
    ) -> Self {
        let mut context = Self::preparation(startup, root, admission, frontier, lock_name);
        context.purpose = RootControllerReadonlyPurposeV1::ReservedPreparation(authorization);
        context
    }

    pub(crate) fn replay_reserved(
        startup: &'borrow ProductionNormalRootStartupV1,
        root: &'borrow RootCurrentOpenStateV1,
        authorization: &'borrow crate::policy_compiler::create_storage_current::use_authorized::RootCurrentUseAuthorizedStateV1,
        audit: &'original RootControllerReadonlyGeometryAuditV1,
        suffix: ControllerHistoryNativeSuffixV1<'data, 'borrow, 6>,
        admission: &'borrow mut Option<Result<(), NormalRootStartupErrorV1>>,
        frontier: &'borrow mut Option<Result<(), JournalError>>,
        lock_name: &'borrow mut Option<String>,
        original: aos_sandbox_protocol::domain_ledger::create_storage_history::controller_intent::ControllerIntentBodyDataV1<'data>,
        admission_data: aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ControllerAdmissionDataV1<'data>,
        received: aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::UseReservedBodyDataV1<'data>,
        progress: &'borrow mut super::RootControllerAcceptedNativeProgressV1,
    ) -> Self {
        let accepted = audit.native_data_v1().and_then(|native| native.state())
            .and_then(|state| super::controller_policy_hold::RootControllerAcceptedNativeV1::new_reserved(
                state, original, admission_data, received, progress));
        Self { startup, root,
            purpose: RootControllerReadonlyPurposeV1::ReservedReplay { authorization },
            audit: Some(audit), suffix: Some(RootControllerHistorySuffixV1::Reserved(suffix)),
            admission, frontier, lock_name, accepted }
    }

    pub(crate) fn preparation_outcome(
        startup: &'borrow ProductionNormalRootStartupV1, root: &'borrow RootCurrentOpenStateV1,
        signed: &'borrow crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1,
        admission: &'borrow mut Option<Result<(), NormalRootStartupErrorV1>>,
        frontier: &'borrow mut Option<Result<(), JournalError>>, lock_name: &'borrow mut Option<String>,
    ) -> Self {
        let mut context = Self::preparation(startup, root, admission, frontier, lock_name);
        context.purpose = RootControllerReadonlyPurposeV1::OutcomePreparation(signed);
        context
    }

    pub(crate) fn replay_outcome(
        startup: &'borrow ProductionNormalRootStartupV1, root: &'borrow RootCurrentOpenStateV1,
        signed: &'borrow crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1,
        _authorization: &'borrow crate::policy_compiler::create_storage_current::use_authorized::RootCurrentUseAuthorizedStateV1,
        audit: &'original RootControllerReadonlyGeometryAuditV1,
        suffix: ControllerHistoryNativeSuffixV1<'data, 'borrow, 10>,
        admission: &'borrow mut Option<Result<(), NormalRootStartupErrorV1>>,
        frontier: &'borrow mut Option<Result<(), JournalError>>, lock_name: &'borrow mut Option<String>,
        original: aos_sandbox_protocol::domain_ledger::create_storage_history::controller_intent::ControllerIntentBodyDataV1<'data>,
        admission_data: aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ControllerAdmissionDataV1<'data>,
        received: aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::UseReservedBodyDataV1<'data>,
        progress: &'borrow mut super::RootControllerAcceptedNativeProgressV1,
    ) -> Self {
        let accepted = audit.native_data_v1().and_then(|native| native.state())
            .and_then(|state| super::controller_policy_hold::RootControllerAcceptedNativeV1::new_reserved(
                state, original, admission_data, received, progress));
        Self { startup, root, purpose: RootControllerReadonlyPurposeV1::OutcomeReplay(signed),
            audit: Some(audit), suffix: Some(RootControllerHistorySuffixV1::Outcome(suffix)),
            admission, frontier, lock_name, accepted }
    }

    pub(crate) fn preparation_closed(
        startup: &'borrow ProductionNormalRootStartupV1, root: &'borrow RootCurrentOpenStateV1,
        signed: &'borrow crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1,
        outcome: &'borrow crate::policy_compiler::create_storage_current::outcome::RootCurrentOutcomeStateV1,
        admission: &'borrow mut Option<Result<(), NormalRootStartupErrorV1>>,
        frontier: &'borrow mut Option<Result<(), JournalError>>, lock_name: &'borrow mut Option<String>,
    ) -> Self {
        let mut context = Self::preparation(startup, root, admission, frontier, lock_name);
        context.purpose = RootControllerReadonlyPurposeV1::ClosedPreparation { signed, outcome };
        context
    }

    pub(crate) fn replay_closed(
        startup: &'borrow ProductionNormalRootStartupV1, root: &'borrow RootCurrentOpenStateV1,
        signed: &'borrow crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1,
        outcome: &'borrow crate::policy_compiler::create_storage_current::outcome::RootCurrentOutcomeStateV1,
        audit: &'original RootControllerReadonlyGeometryAuditV1,
        suffix: ControllerHistoryNativeSuffixV1<'data, 'borrow, 12>,
        admission: &'borrow mut Option<Result<(), NormalRootStartupErrorV1>>,
        frontier: &'borrow mut Option<Result<(), JournalError>>, lock_name: &'borrow mut Option<String>,
        original: aos_sandbox_protocol::domain_ledger::create_storage_history::controller_intent::ControllerIntentBodyDataV1<'data>,
        admission_data: aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ControllerAdmissionDataV1<'data>,
        received: aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::UseReservedBodyDataV1<'data>,
        progress: &'borrow mut super::RootControllerAcceptedNativeProgressV1,
    ) -> Self {
        let accepted = audit.native_data_v1().and_then(|native| native.state())
            .and_then(|state| super::controller_policy_hold::RootControllerAcceptedNativeV1::new_committed(
                state, original, admission_data, received, progress));
        Self { startup, root, purpose: RootControllerReadonlyPurposeV1::ClosedReplay { signed, outcome },
            audit: Some(audit), suffix: Some(RootControllerHistorySuffixV1::Closed(suffix)),
            admission, frontier, lock_name, accepted }
    }

    pub(crate) fn preparation_signed(
        startup: &'borrow ProductionNormalRootStartupV1, root: &'borrow RootCurrentOpenStateV1,
        signed: &'borrow crate::policy_compiler::create_storage_current::use_admitted::RootCurrentUseAdmittedStateV1,
        admission: &'borrow mut Option<Result<(), NormalRootStartupErrorV1>>,
        frontier: &'borrow mut Option<Result<(), JournalError>>, lock_name: &'borrow mut Option<String>,
    ) -> Self {
        let mut context = Self::preparation(startup, root, admission, frontier, lock_name);
        context.purpose = RootControllerReadonlyPurposeV1::SignedPreparation(signed);
        context
    }

    pub(crate) fn replay_signed(
        startup: &'borrow ProductionNormalRootStartupV1, root: &'borrow RootCurrentOpenStateV1,
        signed: &'borrow crate::policy_compiler::create_storage_current::use_admitted::RootCurrentUseAdmittedStateV1,
        _authorization: &'borrow crate::policy_compiler::create_storage_current::use_authorized::RootCurrentUseAuthorizedStateV1,
        audit: &'original RootControllerReadonlyGeometryAuditV1,
        suffix: ControllerHistoryNativeSuffixV1<'data, 'borrow, 7>,
        admission: &'borrow mut Option<Result<(), NormalRootStartupErrorV1>>,
        frontier: &'borrow mut Option<Result<(), JournalError>>, lock_name: &'borrow mut Option<String>,
        original: aos_sandbox_protocol::domain_ledger::create_storage_history::controller_intent::ControllerIntentBodyDataV1<'data>,
        admission_data: aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ControllerAdmissionDataV1<'data>,
        received: aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::UseReservedBodyDataV1<'data>,
        progress: &'borrow mut super::RootControllerAcceptedNativeProgressV1,
    ) -> Self {
        let accepted = audit.native_data_v1().and_then(|native| native.state())
            .and_then(|state| super::controller_policy_hold::RootControllerAcceptedNativeV1::new_reserved(
                state, original, admission_data, received, progress));
        Self { startup, root, purpose: RootControllerReadonlyPurposeV1::SignedReplay(signed),
            audit: Some(audit), suffix: Some(RootControllerHistorySuffixV1::Signed(suffix)),
            admission, frontier, lock_name, accepted }
    }

    pub(crate) fn fixed_receiving_demand_v1() -> Result<ResourceVector, JournalError> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .ok_or(JournalError::JournalTooLarge)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| JournalError::JournalTooLarge)?))
    }

    pub(in crate::journal) fn retained_lock_name_destination_v1(&mut self) -> &mut Option<String> {
        self.lock_name
    }

    pub(in crate::journal) fn require_fixed_named_preparation(&mut self) -> Result<(), JournalError> {
        if self.admission.is_some() || self.audit.is_some() || self.suffix.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        *self.admission = Some(match &self.purpose {
            RootControllerReadonlyPurposeV1::ClosedPreparation { signed, outcome } =>
                self.startup.require_create_storage_closed_controller_fixed(self.root, signed, outcome),
            RootControllerReadonlyPurposeV1::ClosedReplay { .. } => return Err(JournalError::ProtectedBoundary),
            RootControllerReadonlyPurposeV1::SignedPreparation(admitted) =>
                self.startup.require_create_storage_signed_controller_fixed(self.root, admitted),
            RootControllerReadonlyPurposeV1::SignedReplay(_) => return Err(JournalError::ProtectedBoundary),
            RootControllerReadonlyPurposeV1::OutcomePreparation(signed) =>
                self.startup.require_create_storage_outcome_controller_fixed(self.root, signed),
            RootControllerReadonlyPurposeV1::OutcomeReplay(_) => return Err(JournalError::ProtectedBoundary),
            RootControllerReadonlyPurposeV1::Initial => self.startup.require_create_storage_controller_readonly_fixed(self.root),
            RootControllerReadonlyPurposeV1::ReservedPreparation(authorization) =>
                self.startup.require_create_storage_use_controller_readonly_fixed(self.root, authorization),
            RootControllerReadonlyPurposeV1::ReservedReplay { .. } => return Err(JournalError::ProtectedBoundary),
        });
        require_positive(self.admission)
    }

    pub(in crate::journal) fn require_captured_file_end(&mut self, end: u64) -> Result<(), JournalError> {
        if self.admission.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        *self.admission = Some(match &self.purpose {
            RootControllerReadonlyPurposeV1::ClosedReplay { signed, outcome } =>
                self.startup.require_create_storage_closed_controller_semantic(self.root, signed, outcome),
            RootControllerReadonlyPurposeV1::ClosedPreparation { .. } => return Err(JournalError::ProtectedBoundary),
            RootControllerReadonlyPurposeV1::SignedReplay(admitted) =>
                self.startup.require_create_storage_signed_controller_semantic(self.root, admitted),
            RootControllerReadonlyPurposeV1::SignedPreparation(_) => return Err(JournalError::ProtectedBoundary),
            RootControllerReadonlyPurposeV1::OutcomeReplay(signed) =>
                self.startup.require_create_storage_outcome_controller_semantic(self.root, signed),
            RootControllerReadonlyPurposeV1::OutcomePreparation(_) => return Err(JournalError::ProtectedBoundary),
            RootControllerReadonlyPurposeV1::Initial => self.startup.require_create_storage_controller_readonly_semantic(self.root),
            RootControllerReadonlyPurposeV1::ReservedReplay { authorization, .. } =>
                self.startup.require_create_storage_use_controller_readonly_semantic(self.root, authorization),
            RootControllerReadonlyPurposeV1::ReservedPreparation(_) => return Err(JournalError::ProtectedBoundary),
        });
        require_positive(self.admission)?;
        *self.frontier = Some((|| {
            let actual = self.audit.and_then(|audit| audit.captured_extent_v1())
                .ok_or(JournalError::ProtectedBoundary)?;
            if actual.native_bytes != end || self.suffix.is_none() {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        require_positive(self.frontier)
    }

    pub(in crate::journal) fn before_semantic_replay(
        &mut self,
        state: &State,
        transaction: Option<&JournalTransaction>,
    ) -> Result<(), JournalError> {
        require_positive(self.admission)?;
        if self.frontier.as_ref().is_some_and(Result::is_err) {
            return Err(JournalError::ProtectedBoundary);
        }
        *self.frontier = Some(self.audit.ok_or(JournalError::ProtectedBoundary)?
            .require_actual_semantic_frontier_v1(state, transaction));
        require_positive(self.frontier)
    }

    pub(in crate::journal) fn observe_native_commit(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
    ) -> Result<(), JournalError> {
        require_positive(self.admission)?;
        self.accepted.as_mut().ok_or(JournalError::ProtectedBoundary)?
            .observe(transaction, begin_sequence, commit_sequence, begin_offset, end_offset)?;
        self.suffix.as_mut().ok_or(JournalError::ProtectedBoundary)?
            .observe(transaction, begin_sequence, commit_sequence, begin_offset, end_offset)
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(in crate::journal) fn finish_native_replay(
        &mut self,
        next: u64,
        end: u64,
    ) -> Result<(), JournalError> {
        require_positive(self.admission)?;
        let captured_end = self.audit.and_then(|audit| audit.captured_extent_v1())
            .ok_or(JournalError::ProtectedBoundary)?.native_bytes;
        self.suffix.as_mut().ok_or(JournalError::ProtectedBoundary)?
            .finish(next, end, captured_end).map_err(|_| JournalError::ProtectedBoundary)?;
        let audit = self.audit.ok_or(JournalError::ProtectedBoundary)?;
        let ids = audit.native_data_v1().and_then(|native| native.transaction_ids_data_v1())
            .ok_or(JournalError::ProtectedBoundary)?;
        self.accepted.as_mut().ok_or(JournalError::ProtectedBoundary)?.finish_original_names(ids).map_err(JournalError::from)
    }
}

impl ReadOnlyJournalOpenOriginalsV1 {
    // This fstat borrows whichever actual file owner has been reached. It never
    // reopens a name or requires a positive replay before independent posts.
    pub(crate) fn observe_root_controller_file_metadata_v1(
        &self,
    ) -> Option<std::io::Result<std::fs::Metadata>> {
        if let Some(readback) = &self.readback {
            return Some(readback.journal.native.metadata());
        }
        if !self.native.has_native_file_data_v1() { return None; }
        Some(self.native.observe_metadata_v1())
    }
}

impl ReadOnlyProtectedJournal {
    // Exact map/identity/native-coordinate comparison against the first native
    // pass. This is DATA equality; the caller retains real R and physical posts.
    pub(crate) fn require_root_controller_replay_data_v1(
        &self,
        audit: &RootControllerReadonlyGeometryAuditV1,
        receipt: aos_sandbox_protocol::domain_ledger::create_storage_history::ready::InputsReadyNativeReceiptDataV1<'_>,
    ) -> Result<(), JournalError> {
        self.require_root_controller_native_cut_v1(audit, receipt.names, receipt.after_next, receipt.after_end)
    }

    pub(crate) fn require_root_controller_use_replay_data_v1(
        &self,
        audit: &RootControllerReadonlyGeometryAuditV1,
        receipt: aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::UseReservedNativeReceiptDataV1<'_>,
    ) -> Result<(), JournalError> {
        self.require_root_controller_native_cut_v1(audit, receipt.names, receipt.after_next, receipt.after_end)
    }

    pub(crate) fn require_root_controller_signed_replay_data_v1(&self,
        audit: &RootControllerReadonlyGeometryAuditV1,
        names: super::ProtectedJournalNamesV1, position: (u64, u64),
    ) -> Result<(), JournalError> {
        self.require_root_controller_native_cut_v1(audit, names, position.0, position.1)
    }

    pub(crate) fn require_root_controller_signed_history_data_v1(&self,
        bundle: aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ReadyBundleDataV1<'_>,
        inputs: aos_sandbox_protocol::domain_ledger::create_storage_history::ready::InputsReadyNativeReceiptDataV1<'_>,
        validated: &JournalTransaction,
        reserved: aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::UseReservedNativeReceiptDataV1<'_>,
        signed: &JournalTransaction,
    ) -> Result<(), JournalError> {
        use aos_sandbox_protocol::domain_ledger::create_storage_history::{KeyV1, OwnerV1};
        self.journal.ensure_healthy()?;
        let [validated, _] = validated.records() else { return Err(JournalError::ProtectedBoundary); };
        let [signed, head] = signed.records() else { return Err(JournalError::ProtectedBoundary); };
        history_data::require_lane_history_data_v1(self.journal.native.state(), bundle.lane, [
            (KeyV1::new(bundle.lane, OwnerV1::Controller, 1), bundle.intent_record),
            (KeyV1::new(bundle.lane, OwnerV1::Controller, 2), bundle.assignment_planned),
            (KeyV1::new(bundle.lane, OwnerV1::Controller, 3), inputs.record.as_slice()),
            (KeyV1::new(bundle.lane, OwnerV1::Controller, 4), validated.value().ok_or(JournalError::ProtectedBoundary)?),
            (KeyV1::new(bundle.lane, OwnerV1::Controller, 5), reserved.record.as_slice()),
            (KeyV1::new(bundle.lane, OwnerV1::Controller, 6), signed.value().ok_or(JournalError::ProtectedBoundary)?),
            (KeyV1::new(bundle.lane, OwnerV1::Controller, 0), head.value().ok_or(JournalError::ProtectedBoundary)?),
        ]).map_err(JournalError::from)
    }

    pub(crate) fn require_root_controller_outcome_replay_data_v1(&self,
        audit: &RootControllerReadonlyGeometryAuditV1,
        receipt: aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::ContinuationNativeReceiptDataV1<'_>,
    ) -> Result<(), JournalError> {
        self.require_root_controller_native_cut_v1(audit, receipt.names, receipt.after_next, receipt.after_end)
    }

    pub(crate) fn require_root_controller_outcome_history_data_v1(&self, lane: [u8; 16],
        receipt: aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::ContinuationNativeReceiptDataV1<'_>,
        later: [&JournalTransaction; 4],
    ) -> Result<(), JournalError> {
        self.require_root_controller_continuation_history_data_v1(lane, receipt, later)
    }

    pub(crate) fn require_root_controller_closed_history_data_v1(&self, lane: [u8; 16],
        receipt: aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::ContinuationNativeReceiptDataV1<'_>,
        later: [&JournalTransaction; 5],
    ) -> Result<(), JournalError> {
        self.require_root_controller_continuation_history_data_v1(lane, receipt, later)
    }

    fn require_root_controller_continuation_history_data_v1<const N: usize>(&self, lane: [u8; 16],
        receipt: aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::ContinuationNativeReceiptDataV1<'_>,
        later: [&JournalTransaction; N],
    ) -> Result<(), JournalError> {
        self.journal.ensure_healthy()?;
        history_data::require_continuation_history_data_v1(
            self.journal.native.state(), lane, receipt, later,
        ).map_err(JournalError::from)
    }

    fn require_root_controller_native_cut_v1(&self, audit: &RootControllerReadonlyGeometryAuditV1,
        names: super::ProtectedJournalNamesV1, next: u64, end: u64) -> Result<(), JournalError>
    {
        self.journal.ensure_healthy()?;
        let extent = audit.captured_extent_v1().ok_or(JournalError::ProtectedBoundary)?;
        let native = audit.native_data_v1().ok_or(JournalError::ProtectedBoundary)?;
        if self.physical_names_v1() != names
            || self.journal.native.next_sequence() != next
            || extent.native_bytes != end
            || !native.matches_coordinator_view_v1(self.journal.native.read_view())
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn observe_root_controller_accepted_create_v1(
        &self,
        originals: &mut super::controller_policy_hold::RootControllerCreateAcceptanceOriginalsV1,
        bundle: aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ReadyBundleDataV1<'_>,
    ) -> Result<(), JournalError> {
        use aos_sandbox_protocol::domain_ledger::create_storage_history::{
            KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1,
            controller_intent::ControllerIntentBodyDataV1,
        };
        self.journal.ensure_healthy()?;
        let key = KeyV1::new(bundle.lane, OwnerV1::Controller, 1)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let phase = PhaseV1::new(OwnerV1::Controller, 1)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let intent = RecordEnvelopeV1::decode(bundle.intent_record, key, phase)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let original = ControllerIntentBodyDataV1::decode(intent.body())
            .map_err(|_| JournalError::ProtectedBoundary)?;
        originals.observe_once(self.journal.native.state(), original);
        originals.require_complete().map_err(JournalError::from)
    }

    pub(crate) fn require_root_controller_bundle_history_data_v1(
        &self,
        bundle: aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ReadyBundleDataV1<'_>,
        receipt: aos_sandbox_protocol::domain_ledger::create_storage_history::ready::InputsReadyNativeReceiptDataV1<'_>,
    ) -> Result<(), JournalError> {
        history_data::require_bundle_history_data_v1(
            self.journal.native.state(), bundle.lane, bundle.intent_record,
            bundle.assignment_planned, receipt,
        ).map_err(JournalError::from)
    }

    pub(crate) fn require_root_controller_use_bundle_history_data_v1(
        &self,
        bundle: aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ReadyBundleDataV1<'_>,
        inputs: aos_sandbox_protocol::domain_ledger::create_storage_history::ready::InputsReadyNativeReceiptDataV1<'_>,
        validated: &JournalTransaction,
        receipt: aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::UseReservedNativeReceiptDataV1<'_>,
    ) -> Result<(), JournalError> {
        use aos_sandbox_protocol::domain_ledger::create_storage_history::{KeyV1, OwnerV1};
        let [record, _] = validated.records() else { return Err(JournalError::ProtectedBoundary); };
        history_data::require_lane_history_data_v1(self.journal.native.state(), bundle.lane, [
            (KeyV1::new(bundle.lane, OwnerV1::Controller, 1), bundle.intent_record),
            (KeyV1::new(bundle.lane, OwnerV1::Controller, 2), bundle.assignment_planned),
            (KeyV1::new(bundle.lane, OwnerV1::Controller, 3), inputs.record.as_slice()),
            (KeyV1::new(bundle.lane, OwnerV1::Controller, 4), record.value().ok_or(JournalError::ProtectedBoundary)?),
            (KeyV1::new(bundle.lane, OwnerV1::Controller, 5), receipt.record.as_slice()),
            (KeyV1::new(bundle.lane, OwnerV1::Controller, 0), receipt.latest_head.as_slice()),
        ]).map_err(JournalError::from)
    }

}



fn require_positive<T, E>(result: &Option<Result<T, E>>) -> Result<(), JournalError> {
    match result {
        Some(Ok(_)) => Ok(()),
        _ => Err(JournalError::ProtectedBoundary),
    }
}
