//! Publishes only the real pair of privately funded same-baseline subdivisions.
//!
//! The actual enrollment original pays before transaction growth and owns the
//! same canonical C append stage through readback. Only completed metadata IO
//! scratch is disposed; outer Source/C/clock observations remain owed, and no
//! operation witness is lent until their actual enrollment native completion.

use super::*;
use crate::controller_receiving::bank_launch::ControllerPreparedAppendV1;
use aos_sandbox_protocol::domain_ledger::{resource_bank as bank, transaction::JournalTransaction};

#[derive(Clone, Copy)]
enum First { Current, Funding, Pair, Transaction, Prepay, Prepare, Coordinates, Length, Append, Apply, Publish, Readback, Dispose, Order }

#[derive(Default)]
pub(super) struct PublicationOriginalV1 {
    entered: bool,
    first: Option<First>,
    current: Option<Result<(), ControllerBankLaunchErrorV1>>,
    funding: Option<Result<(), ControllerBankLaunchErrorV1>>,
    pair: Option<Result<[bank::RecoveredOperationFundingDataV1; 2], ControllerBankLaunchErrorV1>>,
    transaction: Option<Result<JournalTransaction, ControllerBankLaunchErrorV1>>,
    prepay: Option<Result<(), ControllerBankLaunchErrorV1>>,
    stage: Option<Result<ControllerPreparedAppendV1, ControllerBankLaunchErrorV1>>,
    result: Option<Result<(), ControllerBankLaunchErrorV1>>,
    complete: bool,
    reentry: Option<ControllerBankLaunchErrorV1>,
}

impl PublicationOriginalV1 {
    pub(super) fn is_complete_v1(&self) -> bool {
        self.complete && self.first.is_none() && matches!(self.result, Some(Ok(())))
    }

    fn construction_demand_v1() -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let bytes = bank::RECOVERED_OPERATION_FUNDING_BYTES_V1.checked_add(17)
            .and_then(|bytes| bytes.checked_mul(6))
            .and_then(|bytes| bytes.checked_add(6 * std::mem::size_of::<aos_sandbox_protocol::domain_ledger::transaction::JournalRecord>()))
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<JournalTransaction>()))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        // Two actual new protected rows and their canonical index/append models
        // are source-priced again by the sole full-prefix append supplier.
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        let first = self.first?;
        match first {
            First::Current => self.current.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Funding => self.funding.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Pair => self.pair.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Transaction => self.transaction.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Prepay => self.prepay.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Order => self.reentry.as_ref().map(|cause| cause as _),
            _ => self.stage.as_ref().and_then(|stage| match stage {
                Ok(stage) => stage.failure(), Err(cause) => Some(cause as &(dyn Error + 'static)),
            }).or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _)),
        }
    }
}

impl ControllerRecoveredEnrollmentReceivingV2 {
    /// Publishes the exact two private funding receipts inside fresh enrollment.
    ///
    /// Construction and append/index growth are paid before use. No external
    /// row, blob, amount, transaction, claim or successful result is accepted.
    /// The upper calls this after fresh Source/clock before observations and
    /// before independent Source/C afters and final clock comparison.
    ///
    /// # Errors
    /// Retains every refused debit, original native stage and readback prefix.
    pub fn publish_funded_intake_pair_once_v1<P>(&mut self,
        writer: &mut ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.publication.entered {
            self.publication.first.get_or_insert(First::Order);
            self.publication.reentry.get_or_insert(ControllerBankLaunchErrorV1::Conflict);
            if self.native.failure().is_none() { self.publication_selected = true; }
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.publication.entered = true;
        self.publication.current = Some(self.require_current_v2(writer, launch, profile));
        if !matches!(self.publication.current, Some(Ok(()))) {
            self.publication.first = Some(First::Current);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.publication.funding = Some((|| {
            let fixed = *self.native.fixed.as_ref().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
            let retained = match self.native.representation.as_ref() {
                Some(Ok(complete)) => complete.checked_sub(fixed)?,
                Some(Err(_)) => return Err(ControllerBankLaunchErrorV1::Conflict),
                None => self.native.initial_complete,
            };
            self.require_complete_representation_v2(writer, launch, profile,
                retained.checked_add(PublicationOriginalV1::construction_demand_v1()?)?)
        })());
        if !matches!(self.publication.funding, Some(Ok(()))) {
            self.publication.first = Some(First::Funding);
            self.publication_selected = true;
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.publication.pair = Some((|| {
            use crate::controller_receiving::operation_intake::OperationIntakePurposeV1 as Purpose;
            let intakes = self.native.original.operation_intakes.try_lock()
                .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
            let pair = [intakes.slot(Purpose::Delete).recovered_idle_funding_v2()?.record_data_v1(),
                intakes.slot(Purpose::Execution).recovered_idle_funding_v2()?.record_data_v1()];
            bank::require_recovered_funding_pair_data_v1(&pair)?;
            Ok(pair)
        })());
        if !matches!(self.publication.pair, Some(Ok(_))) {
            self.publication.first = Some(First::Pair);
            self.publication_selected = true;
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.publication.transaction = Some((|| {
            let pair = self.publication.pair.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
            Ok(bank::recovered_funding_pair_transaction_data_v1(pair)?)
        })());
        if !matches!(self.publication.transaction, Some(Ok(_))) {
            self.publication.first = Some(First::Transaction);
            self.publication_selected = true;
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.publication.result = Some(self.publish_funding_inner_v1(writer));
        if !matches!(self.publication.result, Some(Ok(()))) {
            self.publication_selected = true;
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.publication.complete = true;
        Ok(())
    }

    fn publish_funding_inner_v1<P>(&mut self, writer: &mut ControllerCoordinatorWriterV1<P>)
        -> Result<(), ControllerBankLaunchErrorV1> {
        let publication = &mut self.publication;
        let transaction = publication.transaction.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        publication.first = Some(First::Prepay);
        publication.prepay = Some((|| {
            bank::validate_recovered_funding_transaction_v1(writer.fixed.bank_state_v1()?, transaction,
                writer.next_sequence(), writer.durable_prefix_end_data_v1())?;
            writer.prepay_append_interval_once(transaction, std::mem::size_of::<PublicationOriginalV1>())
        })());
        if !matches!(publication.prepay, Some(Ok(()))) { return Err(ControllerBankLaunchErrorV1::Conflict); }
        publication.first = Some(First::Prepare);
        publication.stage = Some(writer.prepare_controller_append_once(transaction));
        let stage = publication.stage.as_mut().and_then(|value| value.as_mut().ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        publication.first = Some(First::Coordinates);
        writer.controller_append_coordinates_once(stage)?;
        publication.first = Some(First::Length);
        writer.expected_controller_append_length_once(stage)?;
        publication.first = Some(First::Append);
        writer.append_controller_prepared_once(stage)?;
        publication.first = Some(First::Apply);
        while writer.apply_next_controller_record_once(stage)? {}
        publication.first = Some(First::Publish);
        writer.publish_controller_append_once(stage)?;
        publication.first = Some(First::Readback);
        // The fixed writer still owns this exact active stage. This private
        // comparison reads its actual applied model, not an imported result.
        let state = writer.fixed.physical.native.native().state();
        let pair = publication.pair.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        for row in pair { row.require_replayed_v1(state)?; }
        if bank::validate(state)? != Some(pair[0].enrollment) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        publication.first = Some(First::Dispose);
        // This metadata purpose has no Cache successor or other effect. Its
        // exact row/readback semantic post is complete; the outer native/Source
        // owners remain continuously held and owe their independent afters.
        writer.finish_controller_append_after_posts_once(stage)?;
        publication.first = None;
        Ok(())
    }

    /// Borrows the actual writer's parked source only for publication refusal.
    #[must_use]
    pub fn publication_failure_source_v1<'writer, P>(&'writer self,
        writer: &'writer ControllerCoordinatorWriterV1<P>,
    ) -> Option<&'writer (dyn Error + 'static)> {
        if !self.publication_selected || !self.native.same_writer(writer) { return None; }
        if matches!(self.publication.first, Some(First::Funding)) {
            return self.native.failure().or_else(|| self.publication.failure_v1());
        }
        writer.retained_append_failure_v1().or_else(|| self.publication.failure_v1())
    }
}

impl ControllerRecoveredEnrollmentReceivingV2 {
    pub(super) fn publication_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        if matches!(self.publication.first, Some(First::Funding)) {
            self.native.failure().or_else(|| self.publication.failure_v1())
        } else { self.publication.failure_v1() }
    }
}
