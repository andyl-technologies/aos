//! Pays reached State recovery encoding under the actual installed writer.
//!
//! The first paid State replay supplies the existing Journal-instance link.
//! Initial startup and a later paid Session Domain borrow the same encoder
//! with distinct retained interval owners. Each prepays an independent post
//! before any variable model or encoder debit can refuse. It exposes neither
//! the ledger nor an independent account, and it never changes Journal guards.

use super::*;
use crate::journal::{
    JournalAppendReceivingDemandErrorV1, ProtectedJournalCurrentnessOriginalsV1,
    StorageNativeOpeningOwnerLinkV1,
};
use aos_sandbox_model::{AccountingError, ResourceDimension};
use aos_sandbox_journal::geometry::RecordShape;
use aos_sandbox_linux::seqpacket::SeqpacketSocket;

#[derive(Clone, Copy)]
enum RecoveryPurposeV1<'cut> {
    Initial,
    Domain {
        session: &'cut crate::Journal,
        socket: &'cut SeqpacketSocket,
    },
}

#[derive(Clone, Copy)]
pub(super) enum RecoveryOwnerV1 {
    Initial,
    Domain,
}

impl RecoveryPurposeV1<'_> {
    fn owner(self) -> RecoveryOwnerV1 {
        match self {
            Self::Initial => RecoveryOwnerV1::Initial,
            Self::Domain { .. } => RecoveryOwnerV1::Domain,
        }
    }
}

impl StorageReceivingOriginalV1 {
    fn recovery_original_v1(&mut self, owner: RecoveryOwnerV1) -> &mut StateRecoveryEncodingOriginalV1 {
        match owner {
            RecoveryOwnerV1::Initial => &mut self.state_recovery,
            RecoveryOwnerV1::Domain => &mut self.lifecycle.state_recovery,
        }
    }

    fn reserve_recovery_v1(&mut self, owner: RecoveryOwnerV1, demand: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        match owner {
            RecoveryOwnerV1::Initial => self.reserve(demand),
            RecoveryOwnerV1::Domain => self.reserve_domain_state_bound_v1(demand),
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum StateRecoveryDemandErrorV1 {
    #[error(transparent)]
    Journal(#[from] crate::JournalError),
    #[error(transparent)]
    Accounting(#[from] AccountingError),
}

#[derive(Clone, Copy)]
enum RecoveryFailure {
    FixedDemand,
    FixedPayment,
    Models,
    Encoding,
    AppendDemand,
    AppendPayment,
    SnapshotPayment,
    WorkspaceEncoding,
    NamesHealth,
    Names,
    Post,
    Closed,
    GuestRootQuiescence,
}

pub(super) struct StateRecoveryEncodingOriginalV1 {
    fixed_demand: Option<Result<ResourceVector, StateRecoveryDemandErrorV1>>,
    fixed_payment: Option<Result<(), StorageReceivingClosedV1>>,
    model_payment: Option<Result<(), StorageReceivingClosedV1>>,
    encoding_arithmetic: Option<AccountingError>,
    append_demand: Option<Result<ResourceVector, JournalAppendReceivingDemandErrorV1>>,
    append_payment: Option<Result<(), StorageReceivingClosedV1>>,
    snapshot_payment: Option<Result<(), StorageReceivingClosedV1>>,
    workspace_encoding: Option<Result<(), aos_sandbox_protocol::canonical_map::CanonicalMapReceivingErrorV1>>,
    names_originals: ProtectedJournalCurrentnessOriginalsV1,
    names_health: Option<Result<(), crate::JournalError>>,
    names: Option<Result<(), crate::JournalError>>,
    post: Option<NativeResult>,
    pub(super) guest_root_quiescence: Option<super::initial_pin_quiescence::InitialPinQuiescenceOriginalV1>,
    guest_root_quiescence_demand: Option<Result<ResourceVector, super::initial_pin_quiescence::DemandError>>,
    guest_root_quiescence_payment: Option<Result<(), StorageReceivingClosedV1>>,
    guest_root_quiescence_entered: bool,
    guest_root_replay_name_paid: bool,
    first: Option<RecoveryFailure>,
    entered: bool,
    finished: bool,
}

impl StateRecoveryEncodingOriginalV1 {
    pub(super) const fn new() -> Self {
        Self {
            fixed_demand: None,
            fixed_payment: None,
            model_payment: None,
            encoding_arithmetic: None,
            append_demand: None,
            append_payment: None,
            snapshot_payment: None,
            workspace_encoding: None,
            names_originals: ProtectedJournalCurrentnessOriginalsV1::new(),
            names_health: None,
            names: None,
            post: None,
            guest_root_quiescence: None, guest_root_quiescence_demand: None,
            guest_root_quiescence_payment: None, guest_root_quiescence_entered: false,
            guest_root_replay_name_paid: false,
            first: None,
            entered: false,
            finished: false,
        }
    }

    pub(super) fn mark_guest_root_quiescence_failure_v2(&mut self) {
        self.first.get_or_insert(RecoveryFailure::GuestRootQuiescence);
    }

    pub(super) fn entered_v1(&self) -> bool {
        self.entered
    }

    pub(super) fn is_positive_or_unused_v1(&self) -> bool {
        !self.entered
            || (self.finished
                && self.first.is_none()
                && matches!(self.model_payment, Some(Ok(())))
                && matches!(self.names_health, Some(Ok(())))
                && matches!(self.names, Some(Ok(())))
                && matches!(self.post, Some(Ok(())))
                && (!self.guest_root_quiescence_entered || self.guest_root_quiescence.as_ref()
                    .is_some_and(super::initial_pin_quiescence::InitialPinQuiescenceOriginalV1::completed_v2)))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause: Option<&(dyn Error + 'static)> = match self.first? {
            RecoveryFailure::FixedDemand => self.fixed_demand.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error),
            RecoveryFailure::FixedPayment => self.fixed_payment.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error),
            RecoveryFailure::Models => self.model_payment.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error),
            RecoveryFailure::Encoding => self.encoding_arithmetic.as_ref()
                .map(|cause| cause as &dyn Error),
            RecoveryFailure::AppendDemand => self.append_demand.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error),
            RecoveryFailure::AppendPayment => self.append_payment.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error),
            RecoveryFailure::SnapshotPayment => self.snapshot_payment.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error),
            RecoveryFailure::WorkspaceEncoding => self.workspace_encoding.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error),
            RecoveryFailure::NamesHealth => self.names_health.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error),
            RecoveryFailure::Names => self.names_originals.failure().or_else(|| self.names.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error)),
            RecoveryFailure::Post => native_failure(&self.post),
            RecoveryFailure::Closed => None,
            RecoveryFailure::GuestRootQuiescence => self.guest_root_quiescence_demand.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error)
                .or_else(|| self.guest_root_quiescence_payment.as_ref()
                    .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error))
                .or_else(|| self.guest_root_quiescence.as_ref().and_then(
                    super::initial_pin_quiescence::InitialPinQuiescenceOriginalV1::failure)),
        };
        cause.or(Some(&StorageReceivingClosedV1))
    }
}

/// Continuously borrows the genuine State recovery payer through encoding.
///
/// Its named methods restrict the same paid writer. Numeric capacities are
/// demand DATA; they cannot construct this stage or establish State authority.
/// Dropping an unfinished stage closes the original and preserves its evidence.
#[must_use]
pub struct StorageStateRecoveryEncodingLoanV1<'cut, 'original> {
    receiving: &'cut mut StoragePrepareReceivingLoanV1<'original>,
    writer: StorageNativeOpeningOwnerLinkV1,
    finished: bool,
    purpose: RecoveryPurposeV1<'cut>,
}

impl<'original> StoragePrepareReceivingLoanV1<'original> {
    /// Enters one paid recovery interval on the actual completed State writer.
    ///
    /// The original's fixed name and separately paid observer post precede the
    /// variable model debit. A later debit refusal therefore cannot suppress
    /// the independent observation owed by this same continuously held stage.
    ///
    /// # Errors
    /// Refuses absent completed startup, another writer, reentry, changed
    /// original custody or fixed post capacity that does not fit.
    pub fn borrow_state_recovery_encoding_once_v1<'cut>(
        &'cut mut self,
        journal: &crate::Journal,
    ) -> Result<StorageStateRecoveryEncodingLoanV1<'cut, 'original>, StorageReceivingClosedV1> {
        self.original.recheck().map_err(|_| StorageReceivingClosedV1)?;
        self.borrow_state_encoding_inner_v1(journal, RecoveryPurposeV1::Initial)
    }
}

impl<'cut, 'original> super::lifecycle::StorageLifecycleSessionLoanV1<'cut, 'original> {
    /// Borrows the existing State encoding engine for this paid Session Domain.
    ///
    /// The mutable parent guard stays borrowed until the State interval ends.
    /// Actual State and Session writers and the connected socket remain joined;
    /// the completed boot interval is neither replaced nor reopened.
    ///
    /// # Errors
    /// Refuses absent consumed operation traffic, wrong Domain phase, another
    /// State writer, reentry or a same-original payment/currentness failure.
    pub fn borrow_state_encoding_v1<'stage>(
        &'stage mut self,
        session: &'stage crate::Journal,
        socket: &'stage SeqpacketSocket,
        state: &crate::Journal,
    ) -> Result<StorageStateRecoveryEncodingLoanV1<'stage, 'original>, StorageReceivingClosedV1> {
        let receiving = self.receiving_domain_v1(session, socket)?;
        receiving.borrow_domain_state_encoding_v1(session, socket, state)
    }
}

impl<'original> StoragePrepareReceivingLoanV1<'original> {
    fn borrow_domain_state_encoding_v1<'cut>(
        &'cut mut self,
        session: &'cut crate::Journal,
        socket: &'cut SeqpacketSocket,
        state: &crate::Journal,
    ) -> Result<StorageStateRecoveryEncodingLoanV1<'cut, 'original>, StorageReceivingClosedV1> {
        // The sole caller holds the freshly checked parent Domain borrow.
        self.borrow_state_encoding_inner_v1(state, RecoveryPurposeV1::Domain { session, socket })
    }

    fn borrow_state_encoding_inner_v1<'cut>(
        &'cut mut self,
        state: &crate::Journal,
        purpose: RecoveryPurposeV1<'cut>,
    ) -> Result<StorageStateRecoveryEncodingLoanV1<'cut, 'original>, StorageReceivingClosedV1> {
        let owner = purpose.owner();
        {
            let receiving = self.receiving()?;
            let completed_initial = matches!(purpose, RecoveryPurposeV1::Initial)
                || (receiving.state_recovery.finished
                    && receiving.state_recovery.is_positive_or_unused_v1());
            if !receiving.startup.state_recovery_ready_v1(state)
                || !completed_initial || receiving.recovery_original_v1(owner).entered
            {
                receiving.first.get_or_insert(Failure::Closed);
                return Err(StorageReceivingClosedV1);
            }
            receiving.recovery_original_v1(owner).entered = true;
        }
        // Fixed reservation may itself refuse. Arm its genuine independent
        // service post first; no caller marker stands in for that observation.
        self.arm_service_acquisition_observation_post_v1()?;
        let fixed = {
            let receiving = self.receiving()?;
            receiving.recovery_original_v1(owner).fixed_demand = Some(state_interval_demand_v1(owner));
            match receiving.recovery_original_v1(owner).fixed_demand.as_ref()
                .and_then(|result| result.as_ref().ok()).copied()
            {
                Some(demand) => {
                    receiving.recovery_original_v1(owner).fixed_payment = Some(receiving.reserve_recovery_v1(owner, demand));
                    if matches!(receiving.recovery_original_v1(owner).fixed_payment, Some(Ok(()))) {
                        true
                    } else {
                        receiving.recovery_original_v1(owner).first = Some(RecoveryFailure::FixedPayment);
                        false
                    }
                }
                None => {
                    receiving.recovery_original_v1(owner).first = Some(RecoveryFailure::FixedDemand);
                    receiving.first.get_or_insert(Failure::StateRecovery);
                    false
                }
            }
        };
        if !fixed {
            // No State/name operation has been entered or funded. Its actual
            // original service observation is nevertheless already owed/paid.
            let post = self.finish_initial_observation_native_post_v1();
            if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
                self.original.recipient.as_mut()
            {
                receiving.recovery_original_v1(owner).post = Some(post);
                receiving.recovery_original_v1(owner).finished = true;
            }
            self.original.open = false;
            return Err(StorageReceivingClosedV1);
        }
        let writer = self.receiving()?.startup.state_identity_v1();
        let Some(writer) = writer else {
            // Readiness above implies this identity exists and no intervening
            // code mutates startup. Keep owed observations real even if that
            // internal invariant is violated, without granting a State loan.
            if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
                self.original.recipient.as_mut()
            {
                let original = receiving.recovery_original_v1(owner);
                original.first.get_or_insert(RecoveryFailure::Closed);
                original.names_health = Some(state.ensure_healthy());
                original.names = Some(state.observe_held_names_post_retaining_v1(&mut original.names_originals));
                receiving.first.get_or_insert(Failure::StateRecovery);
            }
            let post = self.finish_initial_observation_native_post_v1();
            if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
                self.original.recipient.as_mut()
            {
                receiving.recovery_original_v1(owner).post = Some(post);
                receiving.recovery_original_v1(owner).finished = true;
            }
            self.original.open = false;
            return Err(StorageReceivingClosedV1);
        };
        Ok(StorageStateRecoveryEncodingLoanV1 {
            receiving: self,
            writer,
            finished: false,
            purpose,
        })
    }
}

fn state_interval_demand_v1(owner: RecoveryOwnerV1) -> Result<ResourceVector, StateRecoveryDemandErrorV1> {
    let names = ProtectedJournalCurrentnessOriginalsV1::named_demand_v1("storage-state.journal")?;
    let invalid = || AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
    let loan_bytes = std::mem::size_of::<StorageStateRecoveryEncodingLoanV1<'_, '_>>()
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<ResourceVector>()))
        .and_then(|bytes| match owner {
            RecoveryOwnerV1::Initial => Some(bytes),
            RecoveryOwnerV1::Domain => bytes.checked_add(3 * std::mem::size_of::<StateRecoveryEncodingOriginalV1>()),
        })
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(invalid)?;
    let mut demand = names.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, loan_bytes))?;
    // Preserve the predecessor's initial fixed claim. A recurring interval adds
    // no scalar/Option fees to the namespace dimension; real held-name entries
    // remain in their unchanged shared supplier.
    if matches!(owner, RecoveryOwnerV1::Initial) {
        demand = demand.checked_add(ResourceVector::ZERO.with(D::MetadataEntries, 24))?;
    }
    Ok(demand)
}

impl<'original> StorageStateRecoveryEncodingLoanV1<'_, 'original> {
    fn require_domain_current_v1(&mut self) -> Result<(), StorageReceivingClosedV1> {
        if let RecoveryPurposeV1::Domain { session, socket } = self.purpose {
            self.receiving.require_lifecycle_domain_current_v1(session, socket)?;
        }
        Ok(())
    }

    fn require_writer(&mut self, journal: &crate::Journal) -> Result<(), StorageReceivingClosedV1> {
        let owner = self.purpose.owner();
        self.require_domain_current_v1()?;
        let receiving = self.receiving.receiving()?;
        if self.finished || receiving.recovery_original_v1(owner).finished
            || !self.writer.matches_journal_v1(journal)
        {
            receiving.recovery_original_v1(owner).first.get_or_insert(RecoveryFailure::Closed);
            receiving.first.get_or_insert(Failure::StateRecovery);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    fn require_workspace_writer(
        &mut self,
        state: &crate::Journal,
        workspace: &crate::Journal,
    ) -> Result<(), StorageReceivingClosedV1> {
        let owner = self.purpose.owner();
        self.require_writer(state)?;
        let receiving = self.receiving.receiving()?;
        if !receiving.startup.matches_workspace_journal_v1(workspace)
            || !matches!(receiving.recovery_original_v1(owner).model_payment, Some(Ok(())))
        {
            receiving.recovery_original_v1(owner).first.get_or_insert(RecoveryFailure::Closed);
            receiving.first.get_or_insert(Failure::StateRecovery);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    /// Rechecks this actual writer and its already-paid State model interval.
    ///
    /// # Errors
    /// Refuses another State/Session/socket, unfinished parent admission or
    /// missing model payment. No quantity or authority is returned to callers.
    pub fn require_models_current_v1(
        &mut self,
        state: &crate::Journal,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_writer(state)?;
        let owner = self.purpose.owner();
        let receiving = self.receiving.receiving()?;
        if !matches!(receiving.recovery_original_v1(owner).model_payment, Some(Ok(()))) {
            receiving.first.get_or_insert(Failure::StateRecovery);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    /// Pays reached Workspace model/slot bytes under this same State interval.
    ///
    /// # Errors
    /// Refuses another State/Workspace writer, unpaid models or the same ledger's
    /// sticky refusal. The Workspace identity is its original paid-replay Arc.
    pub fn reserve_workspace_capacity_v1(
        &mut self,
        state: &crate::Journal,
        workspace: &crate::Journal,
        capacity: usize,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_workspace_writer(state, workspace)?;
        self.reserve_encoded_capacity_v1(capacity, 0)
    }

    /// Encodes the actual Workspace head under the SAME genuine Core ledger.
    ///
    /// # Errors
    /// Refuses wrong writers, original closure, actual encoding arithmetic,
    /// serialization or the exact same ledger's preallocation refusal.
    pub fn encode_workspace_head_v1<T: serde::Serialize>(
        &mut self,
        state: &crate::Journal,
        workspace: &crate::Journal,
        head: &T,
        version: u16,
    ) -> Result<Vec<u8>, StorageReceivingClosedV1> {
        let owner = self.purpose.owner();
        self.require_workspace_writer(state, workspace)?;
        let receiving = self.receiving.receiving()?;
        let result = match self.purpose {
            RecoveryPurposeV1::Initial => aos_sandbox_protocol::canonical_map::encode_head_receiving_v1(
                head, version, &mut receiving.ledger,
            ),
            RecoveryPurposeV1::Domain { .. } => {
                Self::reserve_workspace_encoding_v1(receiving,
                    aos_sandbox_protocol::canonical_map::head_encoding_demand_v1(head, version))
                    .and_then(|()| aos_sandbox_protocol::canonical_map::encode_head(head, version)
                        .map_err(Into::into))
            }
        };
        Self::finish_workspace_encoding_v1(receiving, owner, result)
    }

    /// Encodes the actual Workspace record under the SAME genuine Core ledger.
    ///
    /// # Errors
    /// Refuses wrong writers, original closure, encoding/size/arithmetic failure
    /// or the original Core ledger's retained preallocation refusal.
    pub fn encode_workspace_record_v1<T: serde::Serialize>(
        &mut self,
        state: &crate::Journal,
        workspace: &crate::Journal,
        record: &T,
        version: u16,
        maximum: usize,
    ) -> Result<Vec<u8>, StorageReceivingClosedV1> {
        let owner = self.purpose.owner();
        self.require_workspace_writer(state, workspace)?;
        let receiving = self.receiving.receiving()?;
        let result = match self.purpose {
            RecoveryPurposeV1::Initial => aos_sandbox_protocol::canonical_map::encode_record_receiving_v1(
                record, version, maximum, &mut receiving.ledger,
            ),
            RecoveryPurposeV1::Domain { .. } => {
                Self::reserve_workspace_encoding_v1(receiving,
                    aos_sandbox_protocol::canonical_map::record_encoding_demand_v1(record, version))
                    .and_then(|()| aos_sandbox_protocol::canonical_map::encode_record(record, version, maximum)
                        .map_err(Into::into))
            }
        };
        Self::finish_workspace_encoding_v1(receiving, owner, result)
    }

    fn reserve_workspace_encoding_v1(
        receiving: &mut StorageReceivingOriginalV1,
        demand: Result<ResourceVector, aos_sandbox_protocol::canonical_map::CanonicalMapReceivingErrorV1>,
    ) -> Result<(), aos_sandbox_protocol::canonical_map::CanonicalMapReceivingErrorV1> {
        receiving.reserve_recovery_v1(RecoveryOwnerV1::Domain, demand?)
            .map_err(|_| aos_sandbox_protocol::canonical_map::CanonicalMapReceivingErrorV1::Accounting)
    }

    fn finish_workspace_encoding_v1(
        receiving: &mut StorageReceivingOriginalV1,
        owner: RecoveryOwnerV1,
        result: Result<Vec<u8>, aos_sandbox_protocol::canonical_map::CanonicalMapReceivingErrorV1>,
    ) -> Result<Vec<u8>, StorageReceivingClosedV1> {
        match result {
            Ok(bytes) => {
                receiving.recovery_original_v1(owner).workspace_encoding = Some(Ok(()));
                Ok(bytes)
            }
            Err(cause) => {
                let accounting = matches!(cause,
                    aos_sandbox_protocol::canonical_map::CanonicalMapReceivingErrorV1::Accounting);
                receiving.recovery_original_v1(owner).workspace_encoding = Some(Err(cause));
                receiving.recovery_original_v1(owner).first.get_or_insert(RecoveryFailure::WorkspaceEncoding);
                receiving.first.get_or_insert(if accounting { Failure::Accounting } else { Failure::StateRecovery });
                Err(StorageReceivingClosedV1)
            }
        }
    }

    /// Pays the exact immutable Workspace sequence before advisory simulation.
    ///
    /// # Errors
    /// Refuses another State/Workspace writer, held-file/shape failure or the
    /// same ledger's first refusal. Each real transaction retains its framing;
    /// the complete resulting physical history is priced before preflight.
    pub fn reserve_workspace_appends_v1(
        &mut self,
        state: &crate::Journal,
        workspace: &crate::Journal,
        transactions: &[crate::JournalTransaction],
    ) -> Result<(), StorageReceivingClosedV1> {
        let owner = self.purpose.owner();
        self.require_workspace_writer(state, workspace)?;
        let demand = workspace.append_sequence_receiving_demand_v1(
            transactions.iter().map(|transaction| Ok(transaction.records().iter().map(|record| RecordShape {
                key_bytes: record.key().len(), value_bytes: record.value().map(<[u8]>::len),
            }))),
        );
        Self::reserve_append_demand_v1(self.receiving.receiving()?, owner, demand)
    }

    /// Pays the actual retained recovery models before cloning or decoding.
    ///
    /// # Errors
    /// Refuses reentry, a different writer, a nonresident demand dimension, or
    /// the actual original's sticky arithmetic/ceiling failure.
    pub fn reserve_models_once_v1(
        &mut self,
        journal: &crate::Journal,
        demand: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        let owner = self.purpose.owner();
        self.require_writer(journal)?;
        let receiving = self.receiving.receiving()?;
        let models = ResourceVector::ZERO
            .with(D::MemoryBytes, demand.get(D::MemoryBytes))
            .with(D::MetadataEntries, demand.get(D::MetadataEntries));
        if demand != models || receiving.recovery_original_v1(owner).model_payment.is_some() {
            receiving.recovery_original_v1(owner).first.get_or_insert(RecoveryFailure::Closed);
            receiving.first.get_or_insert(Failure::StateRecovery);
            return Err(StorageReceivingClosedV1);
        }
        receiving.recovery_original_v1(owner).model_payment = Some(receiving.reserve_recovery_v1(owner, demand));
        if matches!(receiving.recovery_original_v1(owner).model_payment, Some(Ok(()))) {
            Ok(())
        } else {
            receiving.recovery_original_v1(owner).first.get_or_insert(RecoveryFailure::Models);
            Err(StorageReceivingClosedV1)
        }
    }

    /// Pays one reached encoder capacity before its actual allocation.
    ///
    /// The three-buffer bound includes a growing buffer's old and new backing.
    /// Its related domain models and already encoded arguments are separate.
    ///
    /// # Errors
    /// Refuses an unpaid model stage, another writer, arithmetic overflow or
    /// the same original's first capacity refusal. No charge is released.
    pub fn reserve_encoded_capacity_v1(
        &mut self,
        capacity: usize,
        cells: usize,
    ) -> Result<(), StorageReceivingClosedV1> {
        let owner = self.purpose.owner();
        self.require_domain_current_v1()?;
        let receiving = self.receiving.receiving()?;
        if self.finished || receiving.recovery_original_v1(owner).finished
            || !matches!(receiving.recovery_original_v1(owner).model_payment, Some(Ok(())))
        {
            receiving.recovery_original_v1(owner).first.get_or_insert(RecoveryFailure::Closed);
            receiving.first.get_or_insert(Failure::StateRecovery);
            return Err(StorageReceivingClosedV1);
        }
        let invalid = || AccountingError::ArithmeticOverflow {
            dimension: ResourceDimension::MemoryBytes,
        };
        let demand = u64::try_from(capacity).ok().and_then(|bytes| bytes.checked_mul(3))
            .zip(u64::try_from(cells).ok())
            .map(|(bytes, cells)| ResourceVector::ZERO
                .with(D::MemoryBytes, bytes).with(D::MetadataEntries, cells));
        let Some(demand) = demand else {
            receiving.recovery_original_v1(owner).encoding_arithmetic = Some(invalid());
            receiving.recovery_original_v1(owner).first.get_or_insert(RecoveryFailure::Encoding);
            receiving.first.get_or_insert(Failure::StateRecovery);
            return Err(StorageReceivingClosedV1);
        };
        receiving.reserve_recovery_v1(owner, demand)
    }

    /// Bounds the fixed Apply admission and physical-effect clock recipe.
    ///
    /// The actual shared Apply schedule needs at most five paired samples;
    /// eight slots conservatively cover its initial and conditional checks.
    pub const MAXIMUM_APPLY_CLOCK_SAMPLES_V1: usize = 8;

    /// Pays the actual recurring Apply's fixed kernel boot-reader destinations.
    ///
    /// The existing closed reader retires each actual positive EOF file before
    /// the next read; a failed reader retains its file and stops the recipe.
    /// Bytes retain all raw/native/sample results; this port
    /// grants no clock, writer, effect or caller-created receiving original.
    ///
    /// # Errors
    /// Refuses an initial/closed/unpaid State stage, a different writer or the
    /// same ledger's actual arithmetic/capacity refusal before file opening.
    pub fn reserve_apply_clock_observations_v1(
        &mut self,
        journal: &crate::Journal,
        bytes: usize,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_models_current_v1(journal)?;
        if !matches!(self.purpose, RecoveryPurposeV1::Domain { .. }) {
            let receiving = self.receiving.receiving()?;
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        self.reserve_encoded_capacity_v1(bytes, 0)?;
        let receiving = self.receiving.receiving()?;
        receiving.reserve_recovery_v1(RecoveryOwnerV1::Domain, ResourceVector::ZERO.with(
            D::OpenFiles, 1,
        ))
    }

    /// Pays the actual State advisory sequence before Native preflight growth.
    ///
    /// This uses the same held physical prefix and immutable transaction widths
    /// as actual append funding. It executes no transaction and grants no effect.
    ///
    /// # Errors
    /// Refuses wrong State/Session/socket identity, unpaid models, actual native
    /// geometry or the same original's checked reservation refusal.
    pub fn reserve_preflight_sequence_v1(
        &mut self,
        journal: &crate::Journal,
        transactions: &[crate::JournalTransaction],
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_writer(journal)?;
        let owner = self.purpose.owner();
        let receiving = self.receiving.receiving()?;
        if !matches!(receiving.recovery_original_v1(owner).model_payment, Some(Ok(()))) {
            receiving.first.get_or_insert(Failure::StateRecovery);
            return Err(StorageReceivingClosedV1);
        }
        let demand = journal.append_sequence_receiving_demand_v1(
            transactions.iter().map(|transaction| Ok(transaction.records().iter().map(|record| RecordShape {
                key_bytes: record.key().len(), value_bytes: record.value().map(<[u8]>::len),
            }))),
        );
        Self::reserve_append_demand_v1(receiving, owner, demand)
    }

    /// Pays the actual complete transaction before Native clone/frame growth.
    ///
    /// # Errors
    /// Refuses another writer, unpaid models, actual held-prefix/native geometry
    /// failure or the same ledger's refusal. Existing semantic guards remain.
    pub fn reserve_append_v1(
        &mut self,
        journal: &crate::Journal,
        transaction: &crate::JournalTransaction,
    ) -> Result<(), StorageReceivingClosedV1> {
        let owner = self.purpose.owner();
        self.require_writer(journal)?;
        let receiving = self.receiving.receiving()?;
        if !matches!(receiving.recovery_original_v1(owner).model_payment, Some(Ok(()))) {
            receiving.first.get_or_insert(Failure::StateRecovery);
            return Err(StorageReceivingClosedV1);
        }
        Self::reserve_append_inner_v1(receiving, owner, journal, transaction)
    }

    fn reserve_append_inner_v1(
        receiving: &mut StorageReceivingOriginalV1,
        owner: RecoveryOwnerV1,
        journal: &crate::Journal,
        transaction: &crate::JournalTransaction,
    ) -> Result<(), StorageReceivingClosedV1> {
        let demand = journal.append_receiving_demand_v1(
            transaction.records().iter().map(|record| RecordShape {
                key_bytes: record.key().len(),
                value_bytes: record.value().map(<[u8]>::len),
            }),
        );
        Self::reserve_append_demand_v1(receiving, owner, demand)
    }

    fn reserve_append_demand_v1(
        receiving: &mut StorageReceivingOriginalV1,
        owner: RecoveryOwnerV1,
        demand: Result<ResourceVector, JournalAppendReceivingDemandErrorV1>,
    ) -> Result<(), StorageReceivingClosedV1> {
        receiving.recovery_original_v1(owner).append_demand = Some(demand);
        let Some(demand) = receiving.recovery_original_v1(owner).append_demand.as_ref().and_then(|result| result.as_ref().ok()).copied() else {
            receiving.recovery_original_v1(owner).first.get_or_insert(RecoveryFailure::AppendDemand);
            receiving.first.get_or_insert(Failure::StateRecovery);
            return Err(StorageReceivingClosedV1);
        };
        receiving.recovery_original_v1(owner).append_payment = Some(receiving.reserve_recovery_v1(owner, demand));
        if matches!(receiving.recovery_original_v1(owner).append_payment, Some(Ok(()))) {
            Ok(())
        } else {
            receiving.recovery_original_v1(owner).first.get_or_insert(RecoveryFailure::AppendPayment);
            Err(StorageReceivingClosedV1)
        }
    }

    /// Pays one actual operation-bound Snapshot metadata file observation.
    ///
    /// The upper closed reader supplies its fixed native/Result geometry before
    /// IO. This entry remains under the authenticated recovery model stage and
    /// joins the actual State writer; it creates no metadata or effect authority.
    ///
    /// # Errors
    /// Refuses a different writer, unpaid models, unrelated demand dimensions,
    /// or the original ledger's sticky ceiling/arithmetic refusal.
    pub fn reserve_snapshot_metadata_read_v1(
        &mut self,
        journal: &crate::Journal,
        demand: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.reserve_native_readback_v1(journal, demand)
    }

    /// Pays the actual Inventory native readback and retained model shape.
    ///
    /// # Errors
    /// Refuses another State writer, unpaid models, unrelated dimensions or a
    /// sticky original accounting/currentness failure. It opens no boot stage.
    pub fn reserve_inventory_readback_v1(
        &mut self,
        journal: &crate::Journal,
        demand: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.reserve_native_readback_v1(journal, demand)
    }

    /// Pays the reached protected policy and Prepare model/readback shape.
    ///
    /// # Errors
    /// Refuses another writer, unpaid models, unrelated dimensions or a closed
    /// original. No initial catalog/Inventory latch is entered or renewed.
    pub fn reserve_preparation_models_v1(
        &mut self,
        journal: &crate::Journal,
        demand: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.reserve_native_readback_v1(journal, demand)
    }

    /// Pays this real preparation's additional retained final kernel clock.
    ///
    /// # Errors
    /// Refuses another writer, unpaid models or a closed original. The same
    /// additive State bound owns the actual byte/FD liability before Native.
    pub fn reserve_preparation_clock_v1(
        &mut self,
        journal: &crate::Journal,
        demand: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.reserve_native_readback_v1(journal, demand)
    }

    fn reserve_native_readback_v1(
        &mut self,
        journal: &crate::Journal,
        demand: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        let owner = self.purpose.owner();
        self.require_writer(journal)?;
        let receiving = self.receiving.receiving()?;
        let native = ResourceVector::ZERO
            .with(D::MemoryBytes, demand.get(D::MemoryBytes))
            .with(D::MetadataEntries, demand.get(D::MetadataEntries))
            .with(D::OpenFiles, demand.get(D::OpenFiles));
        if demand != native
            || !matches!(receiving.recovery_original_v1(owner).model_payment, Some(Ok(())))
        {
            receiving.recovery_original_v1(owner).first.get_or_insert(RecoveryFailure::Closed);
            receiving.first.get_or_insert(Failure::StateRecovery);
            return Err(StorageReceivingClosedV1);
        }
        receiving.recovery_original_v1(owner).snapshot_payment = Some(receiving.reserve_recovery_v1(owner, demand));
        if matches!(receiving.recovery_original_v1(owner).snapshot_payment, Some(Ok(()))) {
            Ok(())
        } else {
            receiving.recovery_original_v1(owner).first.get_or_insert(RecoveryFailure::SnapshotPayment);
            Err(StorageReceivingClosedV1)
        }
    }

    /// Prepays the actual independent name post of one Capture State commit.
    ///
    /// This is separate from the Journal append's internal native interval and
    /// the State loan's final post. It grants no append or catalog authority.
    ///
    /// # Errors
    /// Refuses an unpaid/foreign writer, fixed-name geometry or the same
    /// original's reservation failure before native post construction.
    pub fn reserve_capture_commit_post_v3(
        &mut self, state: &crate::Journal,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.reserve_domain_commit_post_inner_v2(state)
    }

    /// Pays method31's actual same-State native commit bookends.
    ///
    /// # Errors
    /// Refuses unpaid models, a foreign writer, initial custody or native/ledger
    /// geometry failure before arming the same retained commit engine.
    pub fn reserve_guest_root_commit_post_v2(
        &mut self, state: &crate::Journal,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.reserve_domain_commit_post_inner_v2(state)
    }

    fn reserve_domain_commit_post_inner_v2(
        &mut self, state: &crate::Journal,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_models_current_v1(state)?;
        if !matches!(self.purpose, RecoveryPurposeV1::Domain { .. }) {
            return Err(StorageReceivingClosedV1);
        }
        let demand = ProtectedJournalCurrentnessOriginalsV1::named_demand_v1("storage-state.journal");
        let owner = self.purpose.owner();
        Self::reserve_append_demand_v1(self.receiving.receiving()?, owner, demand.map_err(Into::into))
    }

    /// Pays a reached Capture Output transaction on this same State interval.
    ///
    /// The startup's actual Output writer identity and current State/Session
    /// join remain mandatory. This prices native representation only and does
    /// not authorize a record, physical worker, writer or completion.
    ///
    /// # Errors
    /// Refuses another Output/State writer, unpaid models, an initial interval
    /// or any actual append-shape/currentness/ledger failure before native IO.
    pub fn reserve_capture_output_append_v3(
        &mut self,
        state: &crate::Journal,
        output: &crate::Journal,
        transaction: &crate::JournalTransaction,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_models_current_v1(state)?;
        if !matches!(self.purpose, RecoveryPurposeV1::Domain { .. }) {
            return Err(StorageReceivingClosedV1);
        }
        let receiving = self.receiving.receiving()?;
        if !receiving.startup.output_currentness_ready_v1(output) {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        Self::reserve_append_inner_v1(receiving, RecoveryOwnerV1::Domain, output, transaction)
    }

    pub(super) fn receiving_capture_worker_v3(
        &mut self,
        journal: &crate::Journal,
    ) -> Result<&mut StoragePrepareReceivingLoanV1<'original>, StorageReceivingClosedV1> {
        if !matches!(self.purpose, RecoveryPurposeV1::Domain { .. }) {
            return Err(StorageReceivingClosedV1);
        }
        self.receiving_worker_v1(journal)
    }

    pub(super) fn receiving_worker_v1(
        &mut self,
        journal: &crate::Journal,
    ) -> Result<&mut StoragePrepareReceivingLoanV1<'original>, StorageReceivingClosedV1> {
        self.require_writer(journal)?;
        let owner = self.purpose.owner();
        if !matches!(self.receiving.receiving()?.recovery_original_v1(owner).model_payment, Some(Ok(()))) {
            return Err(StorageReceivingClosedV1);
        }
        Ok(self.receiving)
    }

    /// Performs the prepaid names and independent original posts once.
    ///
    /// This completes only receiving bookkeeping. The caller retains its actual
    /// domain Result and every negative record/append/worker owner independently.
    ///
    /// # Errors
    /// Refuses missing/failed model payment, a different writer, actual native
    /// post failure or any earlier accounting/encoding failure. Earlier causes
    /// retain priority; a positive post never heals refused work.
    pub fn finish_once_v1(&mut self, journal: &crate::Journal) -> Result<(), StorageReceivingClosedV1> {
        let owner = self.purpose.owner();
        if self.finished {
            return Err(StorageReceivingClosedV1);
        }
        self.finished = true;
        if let RecoveryPurposeV1::Domain { session, socket } = self.purpose {
            // The local socket/State names and already-armed service observation
            // still run after poison. They cannot authorize another operation.
            self.receiving.observe_domain_state_socket_post_v1(session, socket);
        }
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.receiving.original.recipient.as_mut()
        else {
            return Err(StorageReceivingClosedV1);
        };
        if !self.writer.matches_journal_v1(journal) {
            receiving.recovery_original_v1(owner).first.get_or_insert(RecoveryFailure::Closed);
        } else {
            let original = receiving.recovery_original_v1(owner);
            original.names_health = Some(journal.ensure_healthy());
            original.names = Some(journal.observe_held_names_post_retaining_v1(&mut original.names_originals));
            if matches!(receiving.recovery_original_v1(owner).names_health, Some(Err(_))) {
                receiving.recovery_original_v1(owner).first.get_or_insert(RecoveryFailure::NamesHealth);
            }
            if !matches!(receiving.recovery_original_v1(owner).names, Some(Ok(()))) {
                receiving.recovery_original_v1(owner).first.get_or_insert(RecoveryFailure::Names);
            }
        }
        // No poisoned ordinary reborrow occurs before this actual pending post.
        let post = self.receiving.finish_initial_observation_native_post_v1();
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.receiving.original.recipient.as_mut()
        else {
            return Err(StorageReceivingClosedV1);
        };
        receiving.recovery_original_v1(owner).post = Some(post);
        receiving.recovery_original_v1(owner).finished = true;
        if !matches!(receiving.recovery_original_v1(owner).post, Some(Ok(()))) {
            receiving.recovery_original_v1(owner).first.get_or_insert(RecoveryFailure::Post);
        }
        if receiving.recovery_original_v1(owner).first.is_some() || receiving.first.is_some()
            || !matches!(receiving.recovery_original_v1(owner).model_payment, Some(Ok(())))
        {
            receiving.first.get_or_insert(Failure::StateRecovery);
            self.receiving.original.open = false;
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }
}

impl Drop for StorageStateRecoveryEncodingLoanV1<'_, '_> {
    fn drop(&mut self) {
        let owner = self.purpose.owner();
        if !self.finished {
            self.receiving.original.open = false;
            if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
                self.receiving.original.recipient.as_mut()
            {
                receiving.recovery_original_v1(owner).first.get_or_insert(RecoveryFailure::Closed);
                receiving.first.get_or_insert(Failure::StateRecovery);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entered_state_owner_cannot_retire_before_both_real_post_slots_complete() {
        let mut original = StateRecoveryEncodingOriginalV1::new();
        assert!(original.is_positive_or_unused_v1());

        original.entered = true;
        original.model_payment = Some(Ok(()));
        original.names_health = Some(Ok(()));
        original.names = Some(Ok(()));
        original.post = Some(Ok(()));
        assert!(!original.is_positive_or_unused_v1());

        original.finished = true;
        assert!(original.is_positive_or_unused_v1());
        original.names = Some(Err(crate::JournalError::Poisoned));
        original.first = Some(RecoveryFailure::Names);
        assert!(!original.is_positive_or_unused_v1());
        assert!(original.failure().unwrap().downcast_ref::<crate::JournalError>().is_some());
    }
}


impl StorageStateRecoveryEncodingLoanV1<'_, '_> {
    /// Pays the reached method31 model or native readback before growth.
    ///
    /// The actual authenticated ServerReceive request selects this closed
    /// purpose; the vector describes only the concrete retained callee.
    ///
    /// # Errors
    /// Refuses a foreign State/request, unpaid models, wrong phase or the
    /// same original's arithmetic, capacity or currentness refusal.
    pub fn reserve_guest_root_publication_models_v2(
        &mut self,
        state: &crate::Journal,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        demand: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_guest_root_publication_method_v2(state, request)?;
        {
            let receiving = self.receiving.receiving()?;
            if !receiving.lifecycle.state_recovery.guest_root_replay_name_paid {
                // A successful worker leaves one permanent per-effect claim.
                // Charge that actual namespace directly to the SAME ledger;
                // a reusable State/worker highwater cannot pay future files.
                let names = if receiving.guest_root_serialization_name_paid { 1 } else { 2 };
                receiving.reserve(ResourceVector::ZERO.with(D::MetadataEntries, names))?;
                receiving.guest_root_serialization_name_paid = true;
                receiving.lifecycle.state_recovery.guest_root_replay_name_paid = true;
            }
        }
        self.reserve_native_readback_v1(state, demand)
    }

    pub(super) fn require_guest_root_publication_method_v2(&mut self, state: &crate::Journal,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_models_current_v1(state)?;
        if !matches!(self.purpose, RecoveryPurposeV1::Domain { .. })
            || request.method() != aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT
            || request.direction() != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || request.authorization().is_none() {
            let receiving = self.receiving.receiving()?;
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }
}


impl<'original> StorageStateRecoveryEncodingLoanV1<'_, 'original> {
    /// Borrows one fresh remnant scan under the actual admitted method31 turn.
    ///
    /// The same shared observer engine prepays each entered before/owed-after;
    /// the initial Pin once slot is neither lent nor reset. The fixed physical
    /// worker must be between flights before any cancellation can begin.
    ///
    /// # Errors
    /// Refuses a foreign request/writer, unpaid models, active worker, repeated
    /// scan or actual same-F complete demand refusal before native construction.
    pub fn borrow_guest_root_quiescence_once_v2<'scan>(
        &'scan mut self, state: &'scan crate::Journal,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<super::initial_pin_quiescence::StorageGuestRootQuiescenceLoanV2<'scan, 'original>, StorageReceivingClosedV1> {
        self.require_guest_root_publication_method_v2(state, request)?;
        let (session, socket) = match self.purpose {
            RecoveryPurposeV1::Domain { session, socket } => (session, socket),
            RecoveryPurposeV1::Initial => return Err(StorageReceivingClosedV1),
        };
        let writer = self.writer.clone();
        let receiving = self.receiving.receiving()?;
        if !receiving.physical_worker.is_between_flights_v2()
            || receiving.lifecycle.state_recovery.guest_root_quiescence_entered
        {
            receiving.lifecycle.state_recovery.mark_guest_root_quiescence_failure_v2();
            receiving.first.get_or_insert(Failure::StateRecovery);
            return Err(StorageReceivingClosedV1);
        }
        receiving.lifecycle.state_recovery.guest_root_quiescence_entered = true;
        let demand = super::initial_pin_quiescence::initial_pin_demand();
        receiving.lifecycle.state_recovery.guest_root_quiescence_demand = Some(demand);
        let demand = receiving.lifecycle.state_recovery.guest_root_quiescence_demand.as_ref()
            .and_then(|result| result.as_ref().ok()).copied();
        let Some(demand) = demand else {
            receiving.lifecycle.state_recovery.mark_guest_root_quiescence_failure_v2();
            receiving.first.get_or_insert(Failure::StateRecovery);
            return Err(StorageReceivingClosedV1);
        };
        let payment = receiving.reserve_recovery_v1(RecoveryOwnerV1::Domain, demand);
        receiving.lifecycle.state_recovery.guest_root_quiescence_payment = Some(payment);
        if !matches!(receiving.lifecycle.state_recovery.guest_root_quiescence_payment, Some(Ok(()))) {
            receiving.lifecycle.state_recovery.mark_guest_root_quiescence_failure_v2();
            receiving.first.get_or_insert(Failure::StateRecovery);
            return Err(StorageReceivingClosedV1);
        }
        Ok(super::initial_pin_quiescence::StorageGuestRootQuiescenceLoanV2::from_state_v2(
            self.receiving, state, writer, session, socket,
        ))
    }
}
