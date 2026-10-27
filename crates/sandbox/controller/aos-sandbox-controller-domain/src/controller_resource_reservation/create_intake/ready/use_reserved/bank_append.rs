//! Borrows the actual completed Root authorization for one Controller U CAS.
//!
//! The same private Ready producer retains the Root stream, RootValidated
//! append/readback, accepted parent and funded independent use recipe. This
//! closed loan selects the existing bank transition engine without enabling
//! generic purpose15 Account mutations or renewing any original cutoff.

use std::cell::{Cell, OnceCell};
use std::error::Error;
use aos_sandbox_model::{RawPairedClockSample, ResourceVector};
use crate::journal::{CommitResult, CreateStorageWriterPositionOriginalV1,
    Journal, JournalError, JournalTransaction};
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::controller_resource_reservation::{AccountTransition,
    ProjectPreparationReservationAttemptV1, ResourceReservationErrorV1, State,
    Transition, TransitionOriginal, bank};
use super::super::root_exchange::OriginalCreateStorageRootUseAuthorizationV1;
use super::super::super::history::{HistoryRoleV1, CreateStorageWriterPositionV1,
    root_validated::RootValidatedOriginalsV1};
use crate::controller_resource_reservation::q04_intake::Q04OriginalIntakeAttemptV1;

use super::{OriginalCreateStorageOutcomeV1, super::root_exchange::OriginalCreateStorageRootOutcomeV1};

struct UseCommitBindingV1<'held> {
    recorded: &'held OriginalCreateStorageOutcomeV1<'held>,
    root: &'held OriginalCreateStorageRootOutcomeV1<'held>,
}

impl UseCommitBindingV1<'_> {
    fn require_current_v1(&self, lane: [u8; 16]) -> Result<(), ResourceReservationErrorV1> {
        use aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::ContinuationKindV1;
        let recorded = self.recorded.receipt_v1()?.record_data(lane, ContinuationKindV1::ControllerOutcomeRecorded)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let body = self.recorded.body_v1()?;
        let root = self.root.body_v1()?;
        self.root.receipt_v1()?.record_data(lane, ContinuationKindV1::OutcomeRecorded)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if root.controller_outcome != recorded.checksum() || root.prepared_receipt != body.prepared_receipt {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}

/// Keeps the original closed recipe's equality and immutable proposed mutation.
///
/// Only the enclosing genuine Ready producer constructs these private fields,
/// after independently deriving the same complete receiving requirement.
pub(super) struct UseReservationPreparedV1 {
    pub(super) recipe: Result<ResourceVector, ResourceReservationErrorV1>,
    pub(super) claim: bank::Claim,
    pub(super) binding: bank::CreateStorageUseBindingV1,
}

#[derive(Default)]
pub(crate) struct UseBankObservationOriginalsV1 {
    positions: [OnceCell<CreateStorageWriterPositionOriginalV1>; 3],
    position_calls: Cell<usize>,
    clock: OnceCell<(RetainedKernelPairedClockAttemptV1,
        Result<RawPairedClockSample, SourceGenesisErrorV1>)>,
}

impl UseBankObservationOriginalsV1 {
    fn position_once(&self, journal: &Journal, index: usize)
        -> Result<CreateStorageWriterPositionV1, JournalError>
    {
        let slot = self.positions.get(index).ok_or(JournalError::ProtectedBoundary)?;
        if slot.get().is_some() { return Err(JournalError::ProtectedBoundary); }
        let actual = slot.get_or_init(|| {
            let mut actual = CreateStorageWriterPositionOriginalV1::default();
            actual.capture_once(journal, HistoryRoleV1::Controller);
            actual
        });
        actual.position()
    }

    pub(super) fn primary_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.positions[..2].iter().find_map(|slot| slot.get().and_then(|value| value.failure()))
            .or_else(|| self.clock.get().and_then(|(original, _)| original.failure()))
            .or_else(|| self.clock.get().and_then(|(_, result)| result.as_ref().err())
                .map(|cause| cause as _))
    }

    pub(super) fn completed_position_v1(&self)
        -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1>
    {
        self.positions[2].get().ok_or(ResourceReservationErrorV1::Conflict)?
            .position().map_err(ResourceReservationErrorV1::from)
    }

    pub(super) fn post_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.positions[2].get().and_then(|value| value.failure())
    }

    pub(crate) fn observe_post_once(&self, journal: &Journal,
        transaction: Option<&Result<JournalTransaction, ResourceReservationErrorV1>>,
        native: Option<&Result<CommitResult, JournalError>>,
    ) -> Result<(), JournalError> {
        let position = self.position_once(journal, 2)?;
        let (Some(Ok(transaction)), Some(Ok(native))) = (transaction, native) else {
            // The independent observation is retained even after native Err.
            return Ok(());
        };
        let append = crate::journal::encoded_transaction_append_bytes(transaction)?;
        let before = self.positions[0].get().ok_or(JournalError::ProtectedBoundary)?.position()?;
        if position.names != before.names
            || before.next.checked_add(u64::try_from(transaction.records().len())
                .map_err(|_| JournalError::JournalTooLarge)?.checked_add(2)
                .ok_or(JournalError::JournalTooLarge)?) != Some(position.next)
            || before.end.checked_add(append) != Some(position.end)
            || native.commit_sequence.checked_add(1) != Some(position.next)
            || native.durable_bytes != position.end {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

// This type's fields and constructor remain inside the genuine Ready subtree.
// The shared ReturnedAppend can only bind its already-retained transition.
pub(crate) struct CreateStorageUseBankOriginalsV1<'held> {
    parent: &'held ProjectPreparationReservationAttemptV1,
    intake: &'held Q04OriginalIntakeAttemptV1,
    validated: &'held RootValidatedOriginalsV1,
    authorization: &'held OriginalCreateStorageRootUseAuthorizationV1<'held>,
    prepared: &'held UseReservationPreparedV1,
    observations: &'held UseBankObservationOriginalsV1,
    terminal: Option<UseCommitBindingV1<'held>>,
}

impl<'held> CreateStorageUseBankOriginalsV1<'held> {
    pub(crate) fn fixed_receiving_demand_v1()
        -> Result<ResourceVector, ResourceReservationErrorV1>
    {
        type Carriers = (AccountTransition, crate::controller_resource_reservation::ReturnedAppend,
            UseBankObservationOriginalsV1, UseReservationPreparedV1,
            super::receiving::UseReceivingOriginalsV1,
            CreateStorageUseBankOriginalsV1<'static>, CreateStorageUseBankAppendV1<'static>);
        let clock = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_mul(2)).ok_or(ResourceReservationErrorV1::Conflict)?;
        let bytes = std::mem::size_of::<Carriers>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(
                aos_sandbox_broker::controller_receiving::bank_launch::
                    ControllerCreateStorageUseReceivingOriginalV1::receiving_construction_bytes_v1()?
            ))
            .and_then(|bytes| bytes.checked_add(clock))
            .and_then(|bytes| bytes.checked_add(6 * 4096))
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        // Actual new owning components/construction and fixed path backing.
        // Native files reuse only the genuine clean22 HistoryNames peak;
        // compiled controls are not namespace MetadataEntries.
        Ok(ResourceVector::ZERO.with(aos_sandbox_model::ResourceDimension::MemoryBytes,
            u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?))
    }

    pub(super) fn reserve(parent: &'held ProjectPreparationReservationAttemptV1,
        intake: &'held Q04OriginalIntakeAttemptV1,
        validated: &'held RootValidatedOriginalsV1,
        authorization: &'held OriginalCreateStorageRootUseAuthorizationV1<'held>,
        prepared: &'held UseReservationPreparedV1,
        observations: &'held UseBankObservationOriginalsV1,
    ) -> Result<Self, ResourceReservationErrorV1> {
        validated.position()?;
        let required = prepared.recipe.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if *required != authorization.body_v1()?.receiving
            || prepared.claim.native_fields().amount != *required
            || prepared.binding.use_authorized_checksum() != authorization_checksum(authorization, intake.create_lane()?)?
            || prepared.binding.root_validated_checksum() != validated.checksum_v1(intake.create_lane()?)?
            || prepared.binding.claim_id() != prepared.claim.native_fields().id {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(Self { parent, intake, validated, authorization, prepared, observations, terminal: None })
    }

    pub(super) fn commit(parent: &'held ProjectPreparationReservationAttemptV1,
        intake: &'held Q04OriginalIntakeAttemptV1, validated: &'held RootValidatedOriginalsV1,
        authorization: &'held OriginalCreateStorageRootUseAuthorizationV1<'held>,
        prepared: &'held UseReservationPreparedV1, observations: &'held UseBankObservationOriginalsV1,
        recorded: &'held OriginalCreateStorageOutcomeV1<'held>, root: &'held OriginalCreateStorageRootOutcomeV1<'held>,
    ) -> Result<Self, ResourceReservationErrorV1> {
        let mut original = Self::reserve(parent, intake, validated, authorization, prepared, observations)?;
        let terminal = UseCommitBindingV1 { recorded, root };
        terminal.require_current_v1(intake.create_lane()?)?;
        if recorded.reserved_v1().claim_v1()? != prepared.claim { return Err(ResourceReservationErrorV1::Conflict); }
        original.terminal = Some(terminal);
        Ok(original)
    }

    pub(crate) fn observations_v1(&self) -> &'held UseBankObservationOriginalsV1 {
        self.observations
    }

    pub(crate) fn bind_transition_v1(self, transition: &'held AccountTransition)
        -> CreateStorageUseBankAppendV1<'held>
    {
        CreateStorageUseBankAppendV1 { transition, original: self }
    }
}

pub(crate) struct CreateStorageUseBankAppendV1<'held> {
    transition: &'held AccountTransition,
    original: CreateStorageUseBankOriginalsV1<'held>,
}

impl CreateStorageUseBankAppendV1<'_> {
    pub(crate) fn matches_identity(&self, identity: &crate::policy_compiler::create_q04::Q04CutIdentityV1) -> bool {
        self.original.parent.matches_create_continuation_identity(identity)
    }

    pub(crate) fn require_current(&self, state: &State, transaction: &JournalTransaction)
        -> Result<(), JournalError>
    {
        let original = &self.original;
        original.parent.require_create_continuation_state(state).map_err(native_error)?;
        original.intake.require_retained_capture().map_err(native_error)?;
        let amount = original.prepared.recipe.as_ref().map_err(|_| JournalError::ProtectedBoundary)?;
        if original.authorization.body_v1().map_err(native_error)?.receiving != *amount
            || self.transition.create_storage_use != Some(original.prepared.binding)
            || self.transition.child.is_some() || self.transition.preparation.is_some() || self.transition.terminal.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        match &original.terminal {
            None => {
                if self.transition.claim != original.prepared.claim || self.transition.previous_claim.is_some()
                    || self.transition.original_clock != Some(original.intake.create_storage_j_data_v1().map_err(native_error)?.clock)
                    || self.transition.transaction_id != original.prepared.binding.reserve_transaction_id().map_err(native_error)?
                    || transaction.records().len() != 3 { return Err(JournalError::ProtectedBoundary); }
            }
            Some(terminal) => {
                terminal.require_current_v1(original.intake.create_lane().map_err(native_error)?).map_err(native_error)?;
                if self.transition.previous_claim != Some(original.prepared.claim)
                    || self.transition.claim.native_fields().state != bank::ClaimState::Committed
                    || self.transition.claim.native_fields().id != original.prepared.claim.native_fields().id
                    || self.transition.claim.native_fields().amount != *amount
                    || self.transition.original_clock != Some(terminal.root.clock_v1().map_err(native_error)?)
                    || self.transition.transaction_id != original.prepared.binding.commit_transaction_id().map_err(native_error)?
                    || transaction.records().len() != 2 { return Err(JournalError::ProtectedBoundary); }
            }
        }
        self.transition.require_current(state, transaction)
    }

    pub(crate) fn require_native_position(&self, journal: &Journal) -> Result<(), JournalError> {
        let index = self.original.observations.position_calls.get();
        if index >= 2 { return Err(JournalError::ProtectedBoundary); }
        self.original.observations.position_calls.set(index + 1);
        let current = self.original.observations.position_once(journal, index)?;
        let expected = match &self.original.terminal {
            Some(terminal) => terminal.recorded.position_v1().map_err(native_error)?,
            None => self.original.validated.position().map_err(native_error)?,
        };
        if current != expected {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn final_crossing(&self,
        result: &OnceCell<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    ) -> Result<(), JournalError> {
        if result.get().is_some() || self.original.observations.clock.get().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let (initial, cutoff) = match &self.original.terminal {
            Some(terminal) => (terminal.root.clock_v1().map_err(native_error)?, terminal.root.cutoff_v1().map_err(native_error)?),
            None => (self.original.intake.create_storage_j_data_v1().map_err(native_error)?.clock,
                self.original.authorization.cutoff_v1().map_err(native_error)?),
        };
        let actual = self.original.observations.clock.get_or_init(|| {
            let mut original = RetainedKernelPairedClockAttemptV1::default();
            let observed = original.observe_once(Some(initial)).and_then(|sample| {
                if sample.boottime_nanoseconds() >= cutoff { return Err(SourceGenesisErrorV1::Stale); }
                Ok(sample)
            });
            (original, observed)
        });
        let projected = match actual.1.as_ref() {
            Ok(sample) => Ok(*sample),
            Err(_) => Err(SourceGenesisErrorV1::Stale),
        };
        let success = projected.is_ok();
        result.set(projected).map_err(|_| JournalError::ProtectedBoundary)?;
        if success { Ok(()) } else { Err(JournalError::ProtectedBoundary) }
    }
}

impl Transition<'_> {
    pub(crate) fn create_storage_use(&self) -> Option<&CreateStorageUseBankAppendV1<'_>> {
        match &self.original { TransitionOriginal::CreateStorageUse(original) => Some(original), _ => None }
    }
}

pub(super) fn authorization_checksum(authorization: &OriginalCreateStorageRootUseAuthorizationV1<'_>, lane: [u8; 16])
    -> Result<[u8; 32], ResourceReservationErrorV1>
{
    use aos_sandbox_protocol::domain_ledger::create_storage_history::{KeyV1, OwnerV1, PhaseV1,
        RecordEnvelopeV1, transport::FRAME_HEADER_BYTES, use_authorized::UseAuthorizedNativeReceiptDataV1};
    let receipt = UseAuthorizedNativeReceiptDataV1::decode(&authorization.frame_v1()[FRAME_HEADER_BYTES..], lane)
        .map_err(|_| ResourceReservationErrorV1::Conflict)?;
    RecordEnvelopeV1::decode(receipt.record,
        KeyV1::new(lane, OwnerV1::Root, 2).map_err(|_| ResourceReservationErrorV1::Conflict)?,
        PhaseV1::new(OwnerV1::Root, 2).map_err(|_| ResourceReservationErrorV1::Conflict)?)
        .map(|record| record.checksum()).map_err(|_| ResourceReservationErrorV1::Conflict)
}

fn native_error(error: impl Into<ResourceReservationErrorV1>) -> JournalError {
    JournalError::Q04RootOriginal(Box::new(crate::controller_resource_reservation::q04_resource_error(error)))
}
