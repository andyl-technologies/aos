//! Selects exact Delete acceptance on the sole semantic/native append engine.
//!
//! The journal-private trait erases only borrower lifetimes. Its only concrete
//! implementation below holds the actual SourceReady fence, retained Root
//! original, same Launch/profile and exact already-paid admission transaction.
//! No external implementation, supplied proof, budget or callback enters it.

use super::*;
use crate::normal_root::RootDeleteClientOriginalV1;
use crate::public_mutation_compiler::delete_admission::PlanningClockError;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchOriginalV1;
use aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1;
use aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

mod sealed {
    pub trait Sealed {}
}

mod completion;
pub(crate) use completion::ControllerDeleteTerminalOriginalV4;

pub(super) trait DeleteAdmissionOriginalV3: sealed::Sealed {
    fn require_transition_v3(
        &mut self,
        journal: &Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError>;
    fn matches_identity_v3(
        &self,
        identity: &crate::policy_compiler::create_q04::Q04CutIdentityV1,
    ) -> bool;
    fn final_crossing_v3(&mut self, journal: &Journal) -> Result<(), JournalError>;
}

type Pair = RetainedKernelPairedClockAttemptV1<PlanningClockError>;

struct DeleteAdmissionLoanV3<'call, 'fence, 'source, 'original, 'authorization, 'profile> {
    fence: &'call mut SourceDeletePendingFenceV1<'fence, 'source, 'original, 'authorization>,
    root: &'call mut RootDeleteClientOriginalV1<'profile>,
    launch: &'call ControllerBankLaunchOriginalV1,
    profile: &'call ControllerSelfProfileOriginalV1,
    transaction: &'call JournalTransaction,
    identity: &'call crate::policy_compiler::create_q04::Q04CutIdentityV1,
    clock: &'call mut Pair,
    sampled: &'call mut Option<Result<aos_sandbox_model::RawPairedClockSample, PlanningClockError>>,
    time: &'call mut Option<Result<(), JournalError>>,
}

impl sealed::Sealed for DeleteAdmissionLoanV3<'_, '_, '_, '_, '_, '_> {}

impl DeleteAdmissionOriginalV3 for DeleteAdmissionLoanV3<'_, '_, '_, '_, '_, '_> {
    fn require_transition_v3(
        &mut self,
        journal: &Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        if transaction != self.transaction {
            return Err(JournalError::ProtectedBoundary);
        }
        self.fence.require_source_ready_v3()?;
        self.root
            .require_controller_admission_before_v3(self.fence, journal, self.launch)?;
        self.fence
            .require_prepaid_controller_admission_v3(journal, self.launch, self.profile)
    }

    fn matches_identity_v3(
        &self,
        identity: &crate::policy_compiler::create_q04::Q04CutIdentityV1,
    ) -> bool {
        self.identity == identity && self.fence.matches_cleared_create_identity_v3(identity)
    }

    fn final_crossing_v3(&mut self, journal: &Journal) -> Result<(), JournalError> {
        if self.sampled.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let bound =
            self.root
                .require_controller_admission_before_v3(self.fence, journal, self.launch)?;
        *self.sampled = Some(self.clock.observe_once(None));
        *self.time = Some((|| {
            let sample = *self
                .sampled
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            bound.require_sample_v3(sample)
        })());
        if matches!(self.time, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }
}

#[derive(Clone, Copy)]
enum First {
    Entry,
    DecodeFunding,
    Geometry,
    Funding,
    RootEntry,
    Before,
    Identity,
    Models,
    AppendFunding,
    Append,
    Readback,
    RootAfter,
    PostClock,
    Reentry,
}

type Cause = Box<dyn std::error::Error + Send + Sync>;

/// Retains the actual desired-state admission and full native C readback.
///
/// Construction is inert. Only record_once_v3 below can populate it, while
/// continuously borrowing the same actual SourceReady/Root/C17 originals.
pub(crate) struct ControllerDeleteAdmissionOriginalV3 {
    entered: bool,
    entry: Option<Result<(), JournalError>>,
    decode_funding: Option<Result<(), JournalError>>,
    geometry: Option<Result<ResourceVector, Cause>>,
    funding: Option<Result<(), JournalError>>,
    root_entry: Option<Result<(), JournalError>>,
    before: Option<Result<(), JournalError>>,
    identity: Option<Result<crate::policy_compiler::create_q04::Q04CutIdentityV1, JournalError>>,
    models: Option<Result<(crate::OperationPlan, JournalTransaction), Cause>>,
    append_funding: Option<Result<(), JournalError>>,
    clock: Pair,
    sample: Option<Result<aos_sandbox_model::RawPairedClockSample, PlanningClockError>>,
    time: Option<Result<(), JournalError>>,
    append: Option<Result<CommitResult, JournalError>>,
    readback: Option<Result<[u8; 64], super::delete_batch::NativeReadbackErrorV1>>,
    root_after: Option<Result<(), JournalError>>,
    post_clock: Option<Result<(), JournalError>>,
    funding_selected: bool,
    first: Option<First>,
}

impl Default for ControllerDeleteAdmissionOriginalV3 {
    fn default() -> Self {
        Self {
            entered: false,
            entry: None,
            decode_funding: None,
            geometry: None,
            funding: None,
            root_entry: None,
            before: None,
            identity: None,
            models: None,
            append_funding: None,
            clock: Default::default(),
            sample: None,
            time: None,
            append: None,
            readback: None,
            root_after: None,
            post_clock: None,
            funding_selected: false,
            first: None,
        }
    }
}

impl ControllerDeleteAdmissionOriginalV3 {
    pub(crate) fn record_once_v3(
        &mut self,
        journal: &mut Journal,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        root: &mut RootDeleteClientOriginalV1<'_>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), JournalError> {
        if self.entered {
            self.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        self.entered = true;
        self.entry = Some(fence.require_source_ready_v3());
        if !matches!(self.entry, Some(Ok(()))) {
            self.first = Some(First::Entry);
            return Err(JournalError::ProtectedBoundary);
        }
        self.decode_funding = Some((|| {
            let width = fence.batch_bytes()?.len();
            let bytes = aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchViewV1::decode_receiving_bytes_v1(width)
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>().checked_mul(3)?))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<DeleteAdmissionLoanV3<
                    'static, 'static, 'static, 'static, 'static, 'static>>().checked_mul(3)?))
                .and_then(|bytes| bytes.checked_add(Pair::dominant_requested_bytes_v1()?.checked_mul(3)?))
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
            let names = aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchViewV1::nested_decode_metadata_entries_v1(width)
                .and_then(|names| names.checked_add(Pair::receiving_metadata_cells_v1()?))
                .and_then(|names| u64::try_from(names).ok()).ok_or(JournalError::JournalTooLarge)?;
            let files = u64::try_from(Pair::MAXIMUM_RETAINED_FILES_V1)
                .map_err(|_| JournalError::JournalTooLarge)?;
            fence.reserve_preaccept_additional_v1(
                journal,
                launch,
                profile,
                ResourceVector::ZERO
                    .with(D::MemoryBytes, bytes)
                    .with(D::OpenFiles, files)
                    .with(D::MetadataEntries, names),
            )
        })());
        if !matches!(self.decode_funding, Some(Ok(()))) {
            self.funding_selected = fence.intake_failure_view_v1(profile).is_some();
            self.first = Some(First::DecodeFunding);
            return Err(JournalError::ProtectedBoundary);
        }
        self.geometry = Some(model_receiving_demand_v3(journal, fence));
        let demand = match self
            .geometry
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
        {
            Some(demand) => demand,
            None => {
                self.first = Some(First::Geometry);
                return Err(JournalError::ProtectedBoundary);
            }
        };
        self.funding =
            Some(fence.reserve_preaccept_additional_v1(journal, launch, profile, demand));
        if !matches!(self.funding, Some(Ok(()))) {
            self.funding_selected = fence.intake_failure_view_v1(profile).is_some();
            self.first = Some(First::Funding);
            return Err(JournalError::ProtectedBoundary);
        }
        self.root_entry = Some(
            root.begin_controller_admission_interval_once_v3(fence, journal, launch)
                .map_err(|_| JournalError::ProtectedBoundary),
        );
        if !matches!(self.root_entry, Some(Ok(()))) {
            self.first = Some(First::RootEntry);
            return Err(JournalError::ProtectedBoundary);
        }
        let body = self.record_body_v3(journal, fence, root, launch, profile);
        if let Err(first) = body {
            self.first = Some(first);
            root.refuse_source_readiness_primary_v3();
        }
        // Independent Root/C observations remain owed after any entered body.
        self.root_after = Some(
            root.finish_source_readiness_interval_once_v3(journal)
                .map_err(|_| JournalError::ProtectedBoundary),
        );
        if !matches!(self.root_after, Some(Ok(()))) {
            self.first.get_or_insert(First::RootAfter);
        }
        if self.first.is_none() {
            self.post_clock = Some((|| {
                let latest = *self
                    .sample
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(JournalError::ProtectedBoundary)?;
                root.require_source_readiness_post_clock_v3(latest)
            })());
            if !matches!(self.post_clock, Some(Ok(()))) {
                self.first = Some(First::PostClock);
            }
        }
        if self.first.is_none() {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    fn record_body_v3(
        &mut self,
        journal: &mut Journal,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        root: &mut RootDeleteClientOriginalV1<'_>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), First> {
        self.before = Some(
            root.require_controller_admission_before_v3(fence, journal, launch)
                .map(|_| ()),
        );
        if !matches!(self.before, Some(Ok(()))) {
            return Err(First::Before);
        }
        self.identity = Some((|| {
            let history = journal
                .controller_q04_history_v1()?
                .ok_or(JournalError::ProtectedBoundary)?;
            let old = journal
                .get(
                    RecordNamespace::Operation,
                    history.identity.operation().as_bytes(),
                )
                .ok_or(JournalError::ProtectedBoundary)?;
            let operation = aos_sandbox_protocol::domain_ledger::operation::decode_operation(old)
                .map_err(crate::reconciler::ReconcilerError::from)
                .map_err(|cause| JournalError::Q04ControllerLedger(Box::new(cause)))?;
            if operation.state()
                != aos_sandbox_protocol::domain_ledger::public_operation::OperationState::Succeeded
                || !fence.matches_cleared_create_identity_v3(&history.identity)
            {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(history.identity)
        })());
        if !matches!(self.identity, Some(Ok(_))) {
            return Err(First::Identity);
        }
        self.models = Some(crate::reconciler::prepare_delete_admission_transaction_v3(
            fence,
        ));
        let (_, transaction) = self
            .models
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(First::Models)?;
        self.append_funding = Some((|| {
            let demand = journal
                .append_receiving_demand_v1(transaction.records().iter().map(|record| {
                    aos_sandbox_journal::geometry::RecordShape {
                        key_bytes: record.key().len(),
                        value_bytes: record.value().map(<[u8]>::len),
                    }
                }))
                .map_err(|cause| match cause {
                    super::JournalAppendReceivingDemandErrorV1::Journal(cause) => cause,
                    super::JournalAppendReceivingDemandErrorV1::Accounting(cause) => {
                        JournalError::ReceivingAccounting(cause)
                    }
                })?;
            fence.reserve_preaccept_additional_v1(journal, launch, profile, demand)
        })());
        if !matches!(self.append_funding, Some(Ok(()))) {
            self.funding_selected = fence.intake_failure_view_v1(profile).is_some();
            return Err(First::AppendFunding);
        }
        let identity = self
            .identity
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(First::Identity)?;
        let mut loan = DeleteAdmissionLoanV3 {
            fence,
            root,
            launch,
            profile,
            transaction,
            identity,
            clock: &mut self.clock,
            sampled: &mut self.sample,
            time: &mut self.time,
        };
        self.append = Some(journal.commit_create_storage_original_v1(
            transaction,
            super::create_storage_append::CreateStorageAppendOriginalV1::DeleteAdmission(&mut loan),
        ));
        if !matches!(self.append, Some(Ok(_))) {
            return Err(First::Append);
        }
        drop(loan);
        self.readback = Some(journal.observe_delete_batch_native_proof_v1(
            fence.batch_bytes().map_err(|_| First::Readback)?,
        ));
        if !matches!(self.readback, Some(Ok(_))) {
            return Err(First::Readback);
        }
        Ok(())
    }

    pub(crate) fn funding_failure_is_selected_v3(&self) -> bool {
        self.funding_selected
    }

    pub(crate) fn root_failure_is_selected_v3(&self) -> bool {
        matches!(
            self.first,
            Some(First::RootEntry | First::Before | First::RootAfter)
        )
    }

    /// Borrows only intrinsic same-C native completion while the originals live.
    pub(crate) fn completed_native_v3(
        &self,
        journal: &Journal,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>,
    ) -> Result<&[u8; 64], Cause> {
        journal.ensure_protected_authority()?;
        if self.first.is_some()
            || !matches!(self.append, Some(Ok(_)))
            || !matches!(self.time, Some(Ok(())))
            || !matches!(self.root_after, Some(Ok(())))
            || !matches!(self.post_clock, Some(Ok(())))
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let (_, transaction) = self
            .models
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let native = self
            .readback
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let batch = aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchViewV1::decode(
            fence.batch_bytes()?,
        )?;
        let commit = u64::from_be_bytes(
            native[48..56]
                .try_into()
                .map_err(|_| JournalError::ProtectedBoundary)?,
        );
        let end = u64::from_be_bytes(
            native[56..64]
                .try_into()
                .map_err(|_| JournalError::ProtectedBoundary)?,
        );
        let current_end = journal
            .controller_coordinator_for_bank_read_v1()?
            .durable_prefix_end_data_v1();
        let handoff = aos_sandbox_protocol::domain_ledger::delete_batch::encode_handoff_from_source_pending_data_v2(
            batch, fence.native_position_data_v1()?)?;
        let key = aos_sandbox_protocol::domain_ledger::delete_batch::handoff_key(
            batch.project(),
            batch.operation(),
        );
        if native[..16] != *transaction.id()
            || transaction.id() != &batch.transaction()
            || commit.checked_add(1) != Some(journal.snapshot_sequence())
            || end != current_end
            || journal.get(RecordNamespace::DesiredState, &key) != Some(handoff.as_slice())
            || transaction
                .records()
                .iter()
                .any(|record| journal.get(record.namespace(), record.key()) != record.value())
        {
            return Err(JournalError::StaleAuthoritySnapshot.into());
        }
        Ok(native)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T, E: std::error::Error + 'static>(
            value: &Option<Result<T, E>>,
        ) -> Option<&(dyn std::error::Error + 'static)> {
            value.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        match self.first? {
            First::Entry => cause(&self.entry),
            First::DecodeFunding => cause(&self.decode_funding),
            First::Geometry => self
                .geometry
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref() as _),
            First::Funding => cause(&self.funding),
            First::RootEntry => cause(&self.root_entry),
            First::Before => cause(&self.before),
            First::Identity => cause(&self.identity),
            First::Models => self
                .models
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref() as _),
            First::AppendFunding => cause(&self.append_funding),
            First::Append => self
                .clock
                .failure()
                .or_else(|| cause(&self.time))
                .or_else(|| cause(&self.append)),
            First::Readback => cause(&self.readback),
            First::RootAfter => cause(&self.root_after),
            First::PostClock => cause(&self.post_clock),
            First::Reentry => None,
        }
    }
}

fn model_receiving_demand_v3(
    journal: &Journal,
    fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>,
) -> Result<ResourceVector, Cause> {
    journal.ensure_protected_authority()?;
    let prefix = journal
        .controller_coordinator_for_bank_read_v1()?
        .durable_prefix_end_data_v1();
    let extent =
        protected_journal_preopen_replay_extent_for_prefix_v1(journal.native.limits(), prefix)?;
    let batch = aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchViewV1::decode(
        fence.batch_bytes()?,
    )?;
    let rows = batch
        .count(0)
        .checked_add(batch.count(2))
        .and_then(|count| count.checked_add(6))
        .ok_or(JournalError::JournalTooLarge)?;
    // The existing common semantic kernel prices every canonical row, deep
    // byte/string/protobuf copy and map/set plane. The actual held batch and
    // original public request bound the new record values; neither a configured
    // maximum nor prior highwater replaces this simultaneous model invoice.
    let encoded = usize::try_from(prefix)
        .ok()
        .and_then(|bytes| bytes.checked_add(fence.batch_bytes().ok()?.len()))
        .and_then(|bytes| bytes.checked_add(fence.original_public_request_data_v3().len()))
        .ok_or(JournalError::JournalTooLarge)?;
    let semantic = super::semantic_receiving::semantic_representation_demand_v1(
        encoded,
        rows.checked_add(journal.native.state().len())
            .ok_or(JournalError::JournalTooLarge)?,
    )?;
    let carrier = std::mem::size_of::<crate::OperationPlan>()
        .checked_mul(3)
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<JournalTransaction>().checked_mul(3)?)
        })
        .and_then(|bytes| {
            bytes.checked_add(
                std::mem::size_of::<JournalRecord>()
                    .checked_mul(rows)?
                    .checked_mul(6)?,
            )
        })
        .and_then(|bytes| bytes.checked_add(
            crate::reconciler::admission_records::delete_comparison_forwarding_control_bytes_v3()?,
        ))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(JournalError::JournalTooLarge)?;
    let native = extent.dominant_native_receiving_demand_v1()?;
    let replay = extent.dominant_semantic_receiving_demand_v1()?;
    Ok(semantic
        .checked_add(native)?
        .checked_add(replay)?
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, carrier))?)
}
