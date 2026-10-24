//! Subdivides an already-paid Project interval in the first Q04 hold.
//!
//! The native association is replay DATA, not a transferable permission:
//! ```text
//! AOSRSQ01 | original787 | grant531 | use531 | Spec/compile joins184 | SHA32
//! AOSRSQ02 | same body2041 | normalized32 | input-sha32 | input-bytes8 |
//!            Project-continuation176 | Q-intake-id16 | observer-quota8 | SHA32
//! ```
//! All six bank members share the existing Controller hold transaction. Q02
//! adds the full AOSPCO03 input after them, without changing bank indices. The
//! parent remains charged for the original total, and the child remains charged
//! for its operation use even after the owning invocation becomes uncertain.

use std::cell::OnceCell;

use aos_sandbox_model::RawPairedClockSample;

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::policy_compiler::create_q04::{
    CreateQ04ErrorV1, OriginalCreateQ04InvocationV1, Q04ControllerPreparationV1,
    Q04CutIdentityV1,
};
use crate::{Journal, JournalRecord, JournalTransaction, RecordNamespace};

use aos_sandbox_protocol::domain_ledger::resource_bank::{
    CoissuanceBinding as Binding, CoissuanceMutation, InputAssociation, BANK_MEMBERS,
};

use super::{
    AccountHead, Claim, NativeCrossing, ResourceReservationErrorV1, Transition, TransitionOriginal,
    State, bank, q04_resource_error,
};


/// Owns the exact co-issued native mutation and its sole crossing observation.
pub(crate) struct Q04ResourceTransferV1 {
    before: AccountHead,
    after: AccountHead,
    residual: Claim,
    child: AccountHead,
    pub(super) binding: Binding,
    pub(super) original_clock: RawPairedClockSample,
    crossing: OnceCell<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    last_clock: OnceCell<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    transaction: OnceCell<JournalTransaction>,
    specification: crate::sandbox_spec_state::DurableSandboxSpecV1,
    input_origin: Vec<u8>,
}

impl Q04ResourceTransferV1 {
    pub(crate) fn prepare(
        journal: &Journal,
        root: &OriginalCreateQ04InvocationV1<'_>,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        prepared: &Q04ControllerPreparationV1,
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, CreateQ04ErrorV1> {
        root.recheck_resource_bank(journal)?;
        let original = root.resource_preparation()?;
        let retained = original.original_binding().map_err(q04_resource_error)?;
        let root_loan = root.cache_terminal_loan(identity)?;
        root_loan.cache_signing_challenge(prepared.staged(), prepared.proposed())?;
        ledger.require_identity(identity)?;
        let candidate = prepared.candidate();
        if identity.bytes()[488..520] != *candidate.commitment().digest().as_bytes()
            || !retained.matches_q04_cut(identity)
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }

        // The immutable Spec comes from the same original Request/Desired
        // descriptor, not a Runtime (which does not yet exist for fresh Create).
        let specification = crate::sandbox_spec_state::get(journal, ledger.specification())
            .map_err(|error| q04_resource_error(ResourceReservationErrorV1::Specification(Box::new(error))))?
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        aos_sandbox_policy::require_specification_resource_profile_v1(
            specification.spec().resource_profile(), candidate.hard_resources().core_profile(),
        ).map_err(|_| CreateQ04ErrorV1::ChangedCut)?;
        let amount = aos_sandbox_policy::q04_candidate_capacity_v1!(
            candidate, crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut
        )?;
        let demand = root.original_input_demand(amount)?;
        let retained_use = demand.retained();
        let (intake, observations) = root.original_intake_association()?;
        prepared.input_origin().require_identity(identity)?;
        let origin = InputAssociation::from_parts((
            identity.bytes()[456..488]
                .try_into()
                .map_err(|_| CreateQ04ErrorV1::Bounds)?,
            prepared.input_origin().raw_digest(),
            u64::try_from(prepared.input_origin().bytes().len())
                .map_err(|_| CreateQ04ErrorV1::Bounds)?,
            demand.continuation(),
            intake,
            observations,
        ));
        let residual_amount = retained
            .claim()
            .native_fields()
            .amount
            .checked_sub(amount)
            .map_err(q04_resource_error)?;
        let residual = retained.claim().with_amount(residual_amount);
        let state = journal.controller_resource_state_v1()?;
        bank::validate(state)
            .map_err(q04_resource_error)?;
        let before = bank::find_head(state, retained.claim().native_fields().account)
            .map_err(q04_resource_error)?;
        let generation = before
            .native_fields()
            .generation
            .checked_add(1)
            .ok_or(CreateQ04ErrorV1::Bounds)?;
        // Subdivision changes no total charge in this immediate parent.
        let after = before.with_generation(generation);
        let sandbox = identity.sandbox().into_bytes();
        let child = bank::sandbox_child(before, sandbox, amount, retained_use)
            .map_err(q04_resource_error)?;
        let grant = bank::inclusive_claim_for_cut(retained.claim(), identity, sandbox, amount);
        let use_claim = bank::retained_use_claim_for_cut(grant, identity, sandbox, retained_use);
        let binding = Binding::from_parts((
            retained,
            grant,
            use_claim,
            *specification.descriptor().digest().as_bytes(),
            specification.descriptor().encoded_size(),
            *specification.record_digest().as_bytes(),
            specification.operation_id().into_bytes(),
            *specification.request_digest().as_bytes(),
            *candidate.commitment().digest().as_bytes(),
            *identity.binding().as_bytes(),
            Some(origin),
        ));
        let transfer = Self {
            before, after, residual, child, binding,
            original_clock: original.original_clock().map_err(q04_resource_error)?,
            crossing: OnceCell::new(),
            last_clock: OnceCell::new(),
            transaction: OnceCell::new(),
            specification,
            input_origin: prepared.input_origin().bytes().to_vec(),
        };
        transfer.require_predecessor(state).map_err(q04_resource_error)?;
        root_loan.recheck()?;
        Ok(transfer)
    }

    // AOSPCO03 remains the exact already-held compiler proposal, not a fresh
    // currentness permit. Its existing format owner performs any later decode.
    pub(super) fn create_storage_input_origin_bytes_v1(&self) -> &[u8] {
        &self.input_origin
    }

    // This association uses the original retained Spec and co-issuance owner.
    // It identifies one charged lane; it grants no fresh policy or effect use.
    pub(super) fn create_continuation_lane(
        &self,
        operation: [u8; 16],
    ) -> Result<[u8; 16], ResourceReservationErrorV1> {
        use sha2::{Digest as _, Sha256};

        if self.binding.native_fields().original_claim.operation() != operation
            || self.crossing_failure().is_some()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let mut hash = Sha256::new();
        hash.update(b"aos.sandbox.create-storage.lane.v1\0");
        hash.update(operation);
        hash.update(self.child.native_fields().id);
        // Spec publication is an earlier operation referenced by this Create.
        // Its provenance remains distinct from the accepted claim operation.
        hash.update(self.specification.operation_id().as_bytes());
        hash.update(self.specification.request_digest().as_bytes());
        hash.update(self.specification.record_digest().as_bytes());
        hash.update(self.binding.commitment()?);
        hash.update([15]);
        let digest = hash.finalize();
        let mut lane = [0; 16];
        lane.copy_from_slice(&digest[..16]);
        if lane == [0; 16] {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(lane)
    }

    // Borrows the actual retained first Q04 transaction's canonical coissuance.
    // This is original comparison DATA; it neither opens nor reconstructs a bank.
    pub(super) fn create_storage_original_components_v1(
        &self,
        commitment: [u8; 32],
    ) -> Result<(&crate::sandbox_spec_state::DurableSandboxSpecV1, &[u8]), ResourceReservationErrorV1> {
        let transaction = self.transaction.get().ok_or(ResourceReservationErrorV1::Conflict)?;
        let coissuance = transaction.records().iter().filter_map(|record| record.value())
            .find(|value| value.starts_with(b"AOSRSQ01") || value.starts_with(b"AOSRSQ02"))
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        use sha2::{Digest as _, Sha256};
        if <[u8; 32]>::from(Sha256::digest(coissuance)) != commitment {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok((&self.specification, coissuance))
    }

    pub(super) fn assignment_proposal_inputs_v1(
        &self,
    ) -> Result<(&crate::sandbox_spec_state::DurableSandboxSpecV1, aos_sandbox_model::ResourceVector), ResourceReservationErrorV1> {
        if self.crossing_failure().is_some() || self.transaction.get().is_none() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok((&self.specification, self.child.finite_ceilings()?))
    }

    pub(crate) fn append_records(&self, records: &mut Vec<JournalRecord>) -> Result<(), CreateQ04ErrorV1> {
        records.try_reserve_exact(BANK_MEMBERS + 1)?;
        records.extend(self.records().map_err(q04_resource_error)?);
        records.push(self.origin_record());
        Ok(())
    }

    fn origin_record(&self) -> JournalRecord {
        JournalRecord::put(RecordNamespace::ControllerPolicyHold,
            bank::CONTROLLER_INPUT_ORIGIN_KEY.to_vec(),
            self.input_origin.clone())
    }

    fn history(&self) -> CoissuanceMutation<'_> {
        CoissuanceMutation::new((
            &self.before,
            &self.after,
            &self.residual,
            &self.child,
            &self.binding,
        ))
    }

    fn records(&self) -> Result<[JournalRecord; BANK_MEMBERS], ResourceReservationErrorV1> {
        self.history()
            .records()
            .map_err(ResourceReservationErrorV1::from)
    }

    fn require_predecessor(&self, state: &State) -> Result<(), ResourceReservationErrorV1> {
        self.history()
            .require_predecessor(state)
            .map_err(ResourceReservationErrorV1::from)
    }

    pub(crate) fn require_current(
        &self,
        state: &State,
        transaction: &JournalTransaction,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_predecessor(state)?;
        if transaction.records().len() != 4 + BANK_MEMBERS
            || transaction.records()[3..9] != self.records()?
            || !self.matches_retained_origin(&transaction.records()[9])
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(crate) fn crossing(&self) -> Transition<'_> {
        let deadline = match self
            .binding
            .native_fields()
            .original_claim
            .native_fields()
            .cut
        {
            super::ClaimCut::Operation {
                deadline_boottime_nanoseconds,
                ..
            } => deadline_boottime_nanoseconds,
            super::ClaimCut::BootLifetime => 0,
        };
        Transition {
            original: TransitionOriginal::Q04(self),
            crossing: Some(NativeCrossing {
                original: self.original_clock, deadline, result: &self.crossing,
            }),
        }
    }

    pub(crate) fn crossing_failure(&self) -> Option<&SourceGenesisErrorV1> {
        self.crossing.get().and_then(|result| result.as_ref().err())
    }

    pub(crate) fn capture_last_clock(&self) -> Result<(), ()> {
        if self.last_clock.get().is_some() { return Err(()); }
        let result = self.last_clock.get_or_init(|| {
            crate::policy_compiler::observe_root_first_source_successor_clock_v2(Some(self.original_clock))
                .and_then(|sample| match self.binding.native_fields().original_claim.native_fields().cut {
                    super::ClaimCut::Operation { deadline_boottime_nanoseconds, .. }
                        if sample.boottime_nanoseconds() < deadline_boottime_nanoseconds => Ok(sample),
                    _ => Err(SourceGenesisErrorV1::Stale),
                })
        });
        if result.is_ok() { Ok(()) } else { Err(()) }
    }

    pub(crate) fn last_clock_failure(&self) -> Option<&SourceGenesisErrorV1> {
        self.last_clock.get().and_then(|result| result.as_ref().err())
    }

    pub(crate) fn require_last_clock(&self) -> Result<(), ResourceReservationErrorV1> {
        if matches!(self.last_clock.get(), Some(Ok(_))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    pub(crate) fn retain_transaction(&self, transaction: &JournalTransaction) -> Result<(), CreateQ04ErrorV1> {
        if self.transaction.get().is_some() || transaction.records().len() != 4 + BANK_MEMBERS
            || transaction.records()[3..9] != self.records().map_err(q04_resource_error)?
            || !self.matches_retained_origin(&transaction.records()[9])
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.transaction.set(transaction.clone()).map_err(|_| CreateQ04ErrorV1::ChangedCut)
    }

    pub(crate) fn require_readback(&self, journal: &Journal) -> Result<(), ResourceReservationErrorV1> {
        if !matches!(self.crossing.get(), Some(Ok(_))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if self.specification.descriptor().digest().as_bytes()
            != &self.binding.native_fields().specification
            || self.specification.record_digest().as_bytes()
                != &self.binding.native_fields().specification_record
            || !self
                .binding
                .matches_origin_bytes(&self.input_origin)
                .map_err(ResourceReservationErrorV1::from)?
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let state = journal.controller_resource_state_v1()?;
        let transaction = self.transaction.get().ok_or(ResourceReservationErrorV1::Conflict)?;
        if !journal.controller_resource_contains_transaction_v1(transaction.id())? {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        bank::validate(state).map_err(ResourceReservationErrorV1::from)?;
        if bank::find_head(state, self.after.native_fields().id)
            .map_err(ResourceReservationErrorV1::from)?
            != self.after
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.binding
            .require_replayed(state)
            .map_err(ResourceReservationErrorV1::from)
    }

    fn matches_retained_origin(&self, record: &JournalRecord) -> bool {
        record.namespace() == RecordNamespace::ControllerPolicyHold
            && record.key() == bank::CONTROLLER_INPUT_ORIGIN_KEY
            && record.value() == Some(self.input_origin.as_slice())
    }
}

#[cfg(test)]
mod terminal_native_tests;
