//! Retains the actual recovered Stop seed and its same-C funding publication.
//!
//! The existing provisioning native body remains the only before/after engine.
//! Publication uses the same staged append kernel and preserves every failed
//! prefix. Its row grants no effect, accepted-operation or disposal authority.

use super::*;
use super::super::operation_intakes::ControllerOperationIntakeOriginalV1;
use super::super::ControllerPreparedAppendV1;
use aos_sandbox_protocol::domain_ledger::{resource_bank as bank, transaction::JournalTransaction};

#[derive(Clone, Copy)]
enum First { Current, Record, Transaction, Prepay, Prepare, Coordinates, Length, Append, Apply, Publish, Readback, Dispose, Reentry }

pub(super) struct RecoveredStopNativeFieldsV3 {
    pub(super) intake: Option<ControllerOperationIntakeOriginalV1>,
    newly_funded: bool,
    entered: bool,
    first: Option<First>,
    current: Option<Result<(), ControllerBankLaunchErrorV1>>,
    record: Option<Result<bank::RecoveredStopSeedFundingDataV3, ControllerBankLaunchErrorV1>>,
    transaction: Option<Result<JournalTransaction, ControllerBankLaunchErrorV1>>,
    prepay: Option<Result<(), ControllerBankLaunchErrorV1>>,
    stage: Option<Result<ControllerPreparedAppendV1, ControllerBankLaunchErrorV1>>,
    result: Option<Result<(), ControllerBankLaunchErrorV1>>,
    closed: ControllerBankLaunchErrorV1,
}

impl RecoveredStopNativeFieldsV3 {
    pub(super) fn receiving_demand_v3() -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(bank::RECOVERED_HOST_STOP_CLEANUP_SEED_BYTES_V1.checked_add(17)?.checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<aos_sandbox_protocol::domain_ledger::transaction::JournalRecord>()))
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<JournalTransaction>()))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    fn new(intake: ControllerOperationIntakeOriginalV1, newly_funded: bool) -> Self {
        Self { intake: Some(intake), newly_funded, entered: false, first: None, current: None, record: None,
            transaction: None, prepay: None, stage: None, result: None,
            closed: ControllerBankLaunchErrorV1::Conflict }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Current => error(&self.current),
            First::Record => error(&self.record),
            First::Transaction => error(&self.transaction),
            First::Reentry => Some(&self.closed),
            First::Prepay => error(&self.prepay),
            _ => self.stage.as_ref().and_then(|stage| match stage {
                Ok(stage) => stage.failure(), Err(cause) => Some(cause as &(dyn Error + 'static)),
            }).or_else(|| error(&self.result)),
        }
    }
}

impl<P> ControllerCoordinatorWriterV1<P> {
    /// Starts a Stop native turn from the actual privately issued seed owner.
    ///
    /// # Errors
    /// The returned native owner retains every entry and native refusal. Its
    /// independent afters remain owed once entered, even if publication fails.
    pub fn begin_recovered_lifecycle_stop_receiving_v3(&mut self,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        intake: ControllerOperationIntakeOriginalV1, complete: ResourceVector,
    ) -> ControllerCreateProvisioningReceivingV1 {
        let predecessor = (|| {
            intake.require_stop_seed_unpublished_v3(self, launch, profile)?;
            let row = intake.stop_seed_record_data_v3(self, launch, profile)?;
            let key = row.key_v3();
            if self.fixed.bank_state_v1()?.iter().any(|((namespace, stored_key), _)| {
                *namespace == aos_sandbox_model::RecordNamespace::ControllerResourceReservation
                    && stored_key.as_slice() == key
            }) {
                // A published seed may only enter the retained-owner path,
                // which prepays a new turn and preserves prior spent traffic.
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            Ok(())
        })();
        let mut native = ControllerCreateProvisioningReceivingV1::begin_purpose_with_predecessor_v2(
            self, launch, profile, complete, ContinuationReceivingPurposeV1::RecoveredLifecycleStop,
            Some(&predecessor),
        );
        // The seed debit already priced this exact heap/header and construction.
        native.recovered_stop = Some(Box::new(RecoveredStopNativeFieldsV3::new(intake, true)));
        native
    }
}

impl ControllerCreateProvisioningReceivingV1 {
    /// Describes the complete native seed carrier before funding construction.
    ///
    /// # Errors
    /// Refuses checked layout or existing profile/name supplier overflow.
    pub fn recovered_stop_receiving_demand_v3(profile: &ControllerSelfProfileOriginalV1)
        -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        Ok(Self::receiving_demand_v1(profile)?
            .checked_add(RecoveredStopNativeFieldsV3::receiving_demand_v3()?)?)
    }

    /// Borrows only the actual retained Stop funding original.
    #[must_use]
    pub fn recovered_stop_intake_v3(&self) -> Option<&ControllerOperationIntakeOriginalV1> {
        self.recovered_stop.as_ref().and_then(|seed| seed.intake.as_ref())
    }

    /// Publishes the private seed through the existing complete append kernel.
    ///
    /// # Errors
    /// Refuses reentry, changed native owner, invalid actual funding cut or any
    /// append/readback/disposal failure. Upper Source/C/clock afters stay owed.
    pub fn publish_recovered_stop_seed_once_v3<P>(&mut self,
        writer: &mut ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        let current = self.require_current_v1(writer, launch, profile);
        let seed = self.recovered_stop.as_mut().ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        if !seed.newly_funded || seed.entered { seed.first.get_or_insert(First::Reentry); return Err(ControllerBankLaunchErrorV1::Conflict); }
        seed.entered = true;
        seed.current = Some(current);
        if !matches!(seed.current, Some(Ok(()))) { seed.first = Some(First::Current); return Err(ControllerBankLaunchErrorV1::Conflict); }
        seed.record = Some((|| {
            seed.intake.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?
                .stop_seed_record_data_v3(writer, launch, profile)
        })());
        if !matches!(seed.record, Some(Ok(_))) { seed.first = Some(First::Record); return Err(ControllerBankLaunchErrorV1::Conflict); }
        seed.transaction = Some((|| {
            Ok(seed.record.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?.transaction_data_v3()?)
        })());
        if !matches!(seed.transaction, Some(Ok(_))) { seed.first = Some(First::Transaction); return Err(ControllerBankLaunchErrorV1::Conflict); }
        seed.result = Some((|| {
            let transaction = seed.transaction.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
            seed.first = Some(First::Prepay);
            seed.prepay = Some((|| {
                bank::validate_recovered_funding_transaction_v2(writer.fixed.bank_state_v1()?, transaction,
                    writer.next_sequence(), writer.durable_prefix_end_data_v1())?;
                writer.prepay_append_interval_once(transaction, std::mem::size_of::<RecoveredStopNativeFieldsV3>())
            })());
            if !matches!(seed.prepay, Some(Ok(()))) { return Err(ControllerBankLaunchErrorV1::Conflict); }
            seed.first = Some(First::Prepare);
            seed.stage = Some(writer.prepare_controller_append_once(transaction));
            let stage = seed.stage.as_mut().and_then(|value| value.as_mut().ok())
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
            seed.first = Some(First::Coordinates);
            writer.controller_append_coordinates_once(stage)?;
            seed.first = Some(First::Length);
            writer.expected_controller_append_length_once(stage)?;
            seed.first = Some(First::Append);
            writer.append_controller_prepared_once(stage)?;
            seed.first = Some(First::Apply);
            while writer.apply_next_controller_record_once(stage)? {}
            seed.first = Some(First::Publish);
            writer.publish_controller_append_once(stage)?;
            seed.first = Some(First::Readback);
            seed.record.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?
                .require_replayed_v3(writer.fixed.physical.native.native().state())?;
            seed.first = Some(First::Dispose);
            writer.finish_controller_append_after_posts_once(stage)?;
            seed.first = None;
            Ok(())
        })());
        if matches!(seed.result, Some(Ok(()))) { Ok(()) } else { Err(ControllerBankLaunchErrorV1::Conflict) }
    }

    /// Borrows the original seed-publication failure, including the same writer.
    #[must_use]
    pub fn recovered_stop_publication_failure_v3<'owner, P>(&'owner self,
        writer: &'owner ControllerCoordinatorWriterV1<P>,
    ) -> Option<&'owner (dyn Error + 'static)> {
        if !self.same_writer(writer) { return None; }
        self.recovered_stop.as_ref().and_then(|seed| {
            if matches!(seed.first, Some(First::Prepay | First::Prepare | First::Coordinates | First::Length
                | First::Append | First::Apply | First::Publish | First::Readback | First::Dispose)) {
                writer.retained_append_failure_v1().or_else(|| seed.failure())
            } else { seed.failure() }
        })
    }
}

impl ControllerCreateProvisioningReceivingV1 {
    /// Borrows the retained publication cause without a replacement writer.
    #[must_use]
    pub fn recovered_stop_publication_local_failure_v3(&self) -> Option<&(dyn Error + 'static)> {
        self.recovered_stop.as_ref()?.failure()
    }
}

impl<P> ControllerCoordinatorWriterV1<P> {
    /// Reborrows the retained Stop payer without issuing or funding another one.
    ///
    /// # Errors
    /// Retains foreign, missing-row, failed or occupied original/native entry.
    pub fn begin_retained_recovered_lifecycle_stop_receiving_v3(&mut self,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        intake: ControllerOperationIntakeOriginalV1, complete: ResourceVector,
    ) -> ControllerCreateProvisioningReceivingV1 {
        let guard = intake.require_recovered_entry_v2(self, launch, profile);
        // A positive retained owner starts a genuinely new paid finite native
        // turn, including cumulative spent traffic. It cannot consume seed
        // prepayment a second time.
        let mut native = if guard.is_ok() {
            ControllerCreateProvisioningReceivingV1::begin_purpose_v1(self, launch, profile,
                complete, ContinuationReceivingPurposeV1::RecoveredLifecycleStop)
        } else {
            ControllerCreateProvisioningReceivingV1::begin_purpose_with_predecessor_v2(self, launch,
                profile, complete, ContinuationReceivingPurposeV1::RecoveredLifecycleStop, Some(&guard))
        };
        native.recovered_stop = Some(Box::new(RecoveredStopNativeFieldsV3::new(intake, false)));
        native
    }
}

impl ControllerCreateProvisioningReceivingV1 {
    /// Reports only whether this actual newly funded owner still owes its row.
    #[must_use]
    pub fn requires_recovered_stop_seed_publication_v3(&self) -> bool {
        self.recovered_stop.as_ref().is_some_and(|seed| seed.newly_funded)
    }

    /// Moves the same paid original only after positive native completion.
    ///
    /// The closed upper Stop owner additionally requires its real terminal
    /// Source/C/SDK conjunction before calling this physical transfer.
    ///
    /// # Errors
    /// Refuses another purpose, missing native posts, original or durable seed.
    pub fn take_completed_recovered_stop_intake_v3<P>(&mut self,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<Option<ControllerOperationIntakeOriginalV1>, ControllerBankLaunchErrorV1> {
        if self.recovered_stop.is_none() { return Ok(None); }
        self.require_lifecycle_stop_completed_v4(writer, launch, profile)?;
        let seed = self.recovered_stop.as_mut().ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        seed.intake.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?
            .require_recovered_entry_v2(writer, launch, profile)?;
        Ok(seed.intake.take())
    }
}

impl ControllerCreateProvisioningReceivingV1 {
    /// Pays exact seed-publication growth through the same genuine native owner.
    ///
    /// # Errors
    /// Refuses another phase, missing actual seed provenance or baseline debit.
    pub fn require_recovered_stop_seed_publication_complete_v3<P>(&mut self,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, complete: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        let seed = self.recovered_stop.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        if !seed.newly_funded || seed.entered { return Err(ControllerBankLaunchErrorV1::Conflict); }
        seed.intake.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?
            .require_stop_seed_unpublished_v3(writer, launch, profile)?;
        self.require_complete_representation_v1(writer, launch, profile, complete)
    }
}

// This child retains optional reached Results; the parent helper accepts an
// already-entered Result. Keep its local borrower exact rather than rebuilding
// an error when a later stage has not entered.
fn error<T>(result: &Option<Result<T, ControllerBankLaunchErrorV1>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause as _)
}
