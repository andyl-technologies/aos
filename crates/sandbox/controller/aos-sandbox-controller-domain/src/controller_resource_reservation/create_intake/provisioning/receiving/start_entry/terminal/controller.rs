//! Keeps the final Start CAS, final primitive gate and independent native after.

use super::*;
use crate::journal::{CommitResult, JournalTransaction, LifecycleTerminalMetadataOriginalV4};
use aos_sandbox_model::RawPairedClockSample;
use aos_sandbox_protocol::domain_ledger::effect_history::encode_lifecycle_effect_receipt_v1;
use aos_sandbox_protocol::domain_ledger::operation::StartNativeOriginDataV1;

#[derive(Clone, Copy)]
enum First {
    Next,
    Clock,
    Time,
    Models,
    Funding,
    Publication,
    Preparation,
    AppendFunding,
    Append,
    NativeAfter,
    AfterClock,
    AfterTime,
}

pub(super) struct StartControllerTerminalOriginalV2 {
    entered: bool,
    native_owed: bool,
    next: Option<Result<(), ResourceReservationErrorV1>>,
    before_clock: PairOriginal,
    before: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    time: Option<Result<(), ResourceReservationErrorV1>>,
    models: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    publication: Option<Result<(), SourceAdmissionErrorV1>>,
    metadata: LifecycleTerminalMetadataOriginalV4,
    preparation: Option<Result<(), crate::JournalError>>,
    receipt: Option<
        [u8;
            aos_sandbox_protocol::domain_ledger::effect_history::LIFECYCLE_EFFECT_RECEIPT_BYTES_V1],
    >,
    append_funding: Option<Result<(), ResourceReservationErrorV1>>,
    final_gate: StartTerminalFinalGateV2,
    append: Option<Result<CommitResult, crate::JournalError>>,
    native_after: Option<Result<(), ResourceReservationErrorV1>>,
    after_clock: PairOriginal,
    after: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_time: Option<Result<(), ResourceReservationErrorV1>>,
    first: Option<First>,
}

pub(crate) struct StartTerminalFinalGateV2 {
    clock: PairOriginal,
    sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    time: Option<Result<(), ResourceReservationErrorV1>>,
}

impl StartControllerTerminalOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            entered: false,
            native_owed: false,
            next: None,
            before_clock: Default::default(),
            before: None,
            time: None,
            models: None,
            funding: None,
            publication: None,
            metadata: LifecycleTerminalMetadataOriginalV4::new(),
            preparation: None,
            receipt: None,
            append_funding: None,
            final_gate: StartTerminalFinalGateV2 {
                clock: Default::default(),
                sample: None,
                time: None,
            },
            append: None,
            native_after: None,
            after_clock: Default::default(),
            after: None,
            after_time: None,
            first: None,
        }
    }

    fn fixed_demand_v2() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bytes = size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(PairOriginal::dominant_requested_bytes_v1()?.checked_mul(3)?)
            })
            .and_then(|bytes| bytes.checked_add(size_of::<StartTerminalAppendContextV2<'static>>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(CLOSED)?;
        let files = PairOriginal::MAXIMUM_RETAINED_FILES_V1
            .checked_mul(3)
            .and_then(|files| u64::try_from(files).ok())
            .ok_or(CLOSED)?;
        let names = PairOriginal::receiving_metadata_cells_v1()
            .and_then(|names| names.checked_mul(3))
            .and_then(|names| u64::try_from(names).ok())
            .ok_or(CLOSED)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, bytes)
            .with(D::OpenFiles, files)
            .with(D::MetadataEntries, names))
    }

    pub(super) fn run_once_v2(
        &mut self,
        native: &mut StartNativeStateV1,
        plan: &Arc<crate::OperationPlan>,
        origin: StartNativeOriginDataV1,
        material: &StartTerminalMaterialV2,
        record: crate::lifecycle::LifecycleRecordDigestV1,
        controller: &mut Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.entered {
            return Err(CLOSED);
        }
        self.entered = true;
        self.next = Some((|| {
            let base = native
                .history_resident
                .ok_or(CLOSED)?
                .checked_add(Self::fixed_demand_v2()?)?;
            native.begin_next_start_native_v1(controller, base)
        })());
        self.native_owed = native.after.is_none();
        if !matches!(self.next, Some(Ok(()))) {
            self.first = Some(First::Next);
        }
        if self.first.is_none() {
            self.before = Some(
                self.before_clock
                    .observe_once(Some(origin.first_native_clock_v1())),
            );
            if !matches!(self.before, Some(Ok(_))) {
                self.first = Some(First::Clock);
            }
        }
        if let Some(Ok(sample)) = self.before.as_ref() {
            self.time = Some(StartSourceOriginOriginalV1::require_sample_v1(
                origin, *sample,
            ));
            if !matches!(self.time, Some(Ok(()))) {
                self.first.get_or_insert(First::Time);
            }
        }
        if self.first.is_none() {
            self.models = Some((|| {
                let base = native
                    .history_resident
                    .ok_or(CLOSED)?
                    .checked_add(Self::fixed_demand_v2()?)?
                    .checked_add(native.resources.retained_demand_v2(native.native_turn)?)?;
                Ok(base
                    .checked_add(crate::journal::start_terminal_receiving_demand_v2(
                        controller,
                        plan.operation_id(),
                    )?)?
                    .checked_add(material.published_host_receiving_demand_v2(controller)?)?
                    .checked_add(controller.create_storage_semantic_append_demand_v1()?)?)
            })());
            if !matches!(self.models, Some(Ok(_))) {
                self.first = Some(First::Models);
            }
        }
        if let Some(Ok(complete)) = self.models.as_ref() {
            let complete = *complete;
            self.funding = Some((|| {
                let actual = native
                    .native
                    .as_mut()
                    .and_then(|value| value.as_mut().ok())
                    .ok_or(CLOSED)?;
                native
                    .bank
                    .lock()
                    .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .require_create_provisioning_complete_v1(
                        actual.original_mut_v1(),
                        controller,
                        native.profile.as_ref(),
                        complete,
                    )
            })());
            if !matches!(self.funding, Some(Ok(()))) {
                self.first.get_or_insert(First::Funding);
            }
        }
        if self.first.is_none() {
            self.publication = Some(material.require_published_host_v2(controller));
            if !matches!(self.publication, Some(Ok(()))) {
                self.first = Some(First::Publication);
            }
        }
        if self.first.is_none() {
            self.receipt = Some(encode_lifecycle_effect_receipt_v1(
                plan.operation_id(),
                record.digest(),
            ));
            self.preparation = Some((|| {
                let sample = self
                    .before
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .copied()
                    .ok_or(crate::JournalError::ProtectedBoundary)?;
                let receipt = self
                    .receipt
                    .as_ref()
                    .ok_or(crate::JournalError::ProtectedBoundary)?;
                self.metadata.prepare_once_v2(
                    controller,
                    plan,
                    native
                        .q04_v1()
                        .map_err(|_| crate::JournalError::ProtectedBoundary)?
                        .project(),
                    material.manifest_v2(),
                    receipt,
                    sample,
                )
            })());
            if !matches!(self.preparation, Some(Ok(()))) {
                self.first = Some(First::Preparation);
            }
        }
        if self.first.is_none() {
            self.append_funding = Some((|| {
                let transaction = self.metadata.transaction_v2()?;
                native.require_terminal_append_once_v2(
                    controller,
                    transaction,
                    *self
                        .models
                        .as_ref()
                        .and_then(|value| value.as_ref().ok())
                        .ok_or(CLOSED)?,
                )
            })());
            if !matches!(self.append_funding, Some(Ok(()))) {
                self.first = Some(First::AppendFunding);
            }
        }
        if self.first.is_none() {
            self.append = Some((|| {
                let transaction = self.metadata.transaction_v2()?;
                let context = StartTerminalAppendContextV2 {
                    native,
                    material,
                    plan,
                    origin,
                    metadata: &self.metadata,
                    final_gate: &mut self.final_gate,
                    before: *self
                        .before
                        .as_ref()
                        .and_then(|value| value.as_ref().ok())
                        .ok_or(crate::JournalError::ProtectedBoundary)?,
                };
                let mut loan =
                    crate::reconciler::provisioning::ProvisioningAppendLoanV1::start_terminal_v2(
                        context,
                        transaction,
                    );
                controller.commit_create_provisioning_v1(transaction, &mut loan)
            })());
            if !matches!(self.append, Some(Ok(_))) {
                self.first = Some(First::Append);
            }
        }
        // Once the C native turn entered, its post and final actual paired
        // sample remain independently owed after every primary refusal.
        if self.native_owed && native.after.is_none() {
            self.native_after = Some(native.finish_native_once_v1(controller));
            if !matches!(self.native_after, Some(Ok(()))) {
                self.first.get_or_insert(First::NativeAfter);
            }
        }
        if self.native_owed && native.native.as_ref().is_some_and(Result::is_ok) {
            self.after = Some(
                self.after_clock
                    .observe_once(Some(origin.first_native_clock_v1())),
            );
            if !matches!(self.after, Some(Ok(_))) {
                self.first.get_or_insert(First::AfterClock);
            }
            self.after_time = Some((|| {
                let sample = *self
                    .after
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .ok_or(CLOSED)?;
                StartSourceOriginOriginalV1::require_sample_v1(origin, sample)?;
                self.before
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .ok_or(CLOSED)?
                    .validate_later_sample(sample)
                    .map_err(|_| CLOSED)?;
                if let Some(Ok(final_sample)) = self.final_gate.sample.as_ref() {
                    final_sample
                        .validate_later_sample(sample)
                        .map_err(|_| CLOSED)?;
                }
                Ok(())
            })());
            if !matches!(self.after_time, Some(Ok(()))) {
                self.first.get_or_insert(First::AfterTime);
            }
        }
        if self.first.is_none() {
            Ok(())
        } else {
            Err(CLOSED)
        }
    }

    pub(super) fn native_failure_is_selected_v2(&self) -> bool {
        matches!(
            self.first,
            Some(First::Next | First::Funding | First::AppendFunding | First::NativeAfter)
        )
    }

    pub(super) fn failure<'actual>(
        &'actual self,
        native: Option<&'actual (dyn Error + 'static)>,
    ) -> Option<&'actual (dyn Error + 'static)> {
        match self.first? {
            First::Next => native.or_else(|| cause(&self.next)),
            First::Clock => self.before_clock.failure().or_else(|| cause(&self.before)),
            First::Time => cause(&self.time),
            First::Models => cause(&self.models),
            First::Funding => native.or_else(|| cause(&self.funding)),
            First::Publication => cause(&self.publication),
            First::Preparation => self.metadata.failure().or_else(|| cause(&self.preparation)),
            First::AppendFunding => native.or_else(|| cause(&self.append_funding)),
            First::Append => self.final_gate.failure().or_else(|| cause(&self.append)),
            First::NativeAfter => native.or_else(|| cause(&self.native_after)),
            First::AfterClock => self.after_clock.failure().or_else(|| cause(&self.after)),
            First::AfterTime => cause(&self.after_time),
        }
    }
}

// A single immutable context permits exactly this canonical three-row CAS.
// It borrows the actual Start native owner, not a Journal or payer reconstruction.
pub(crate) struct StartTerminalAppendContextV2<'turn> {
    native: &'turn StartNativeStateV1,
    material: &'turn StartTerminalMaterialV2,
    plan: &'turn Arc<crate::OperationPlan>,
    origin: StartNativeOriginDataV1,
    metadata: &'turn LifecycleTerminalMetadataOriginalV4,
    final_gate: &'turn mut StartTerminalFinalGateV2,
    before: RawPairedClockSample,
}

impl StartTerminalAppendContextV2<'_> {
    pub(crate) fn require_transition_v2(
        &self,
        controller: &Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), crate::JournalError> {
        self.native
            .require_current_v1(controller)
            .map_err(|_| crate::JournalError::ProtectedBoundary)?;
        self.material.require_original_v2(self.plan, self.origin)?;
        self.material.require_native_v2(self.native)?;
        self.metadata.require_before_v2(controller, transaction)?;
        if !matches!(self.native.append_funding.get(8), Some(Some(Ok(())))) {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn matches_q04_v2(&self, identity: &Q04CutIdentityV1) -> bool {
        self.native.q04_v1().is_ok_and(|actual| actual == identity)
    }

    pub(crate) fn final_crossing_v2(
        &mut self,
        controller: &Journal,
    ) -> Result<(), crate::JournalError> {
        self.require_transition_v2(controller, self.metadata.transaction_v2()?)?;
        let gate = &mut self.final_gate;
        if gate.sample.is_some() {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        gate.sample = Some(
            gate.clock
                .observe_once(Some(self.origin.first_native_clock_v1())),
        );
        gate.time = Some((|| {
            let sample = *gate
                .sample
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(CLOSED)?;
            StartSourceOriginOriginalV1::require_sample_v1(self.origin, sample)?;
            self.before
                .validate_later_sample(sample)
                .map_err(|_| CLOSED)
        })());
        if matches!(gate.time, Some(Ok(()))) {
            Ok(())
        } else {
            Err(crate::JournalError::ProtectedBoundary)
        }
    }
}

fn cause<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause as _)
}

impl StartTerminalFinalGateV2 {
    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if self.sample.as_ref().is_some_and(Result::is_err) {
            return self.clock.failure().or_else(|| cause(&self.sample));
        }
        cause(&self.time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_cut_refusal_remains_selected_before_later_append_and_post_errors() {
        let mut original = StartControllerTerminalOriginalV2::new();
        original.final_gate.time = Some(Err(CLOSED));
        original.append = Some(Err(crate::JournalError::ProtectedBoundary));
        original.native_after = Some(Err(ResourceReservationErrorV1::EnrollmentUnavailable));
        original.first = Some(First::Append);
        let selected = original
            .final_gate
            .time
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap_err();

        assert!(std::ptr::eq(
            original
                .failure(None)
                .unwrap()
                .downcast_ref::<ResourceReservationErrorV1>()
                .unwrap(),
            selected
        ));
        assert!(original.append.as_ref().unwrap().is_err());
        assert!(original.native_after.as_ref().unwrap().is_err());
    }

    #[test]
    fn publication_refusal_precedes_independently_retained_late_clock_errors() {
        let mut original = StartControllerTerminalOriginalV2::new();
        original.publication = Some(Err(SourceAdmissionErrorV1::Closed));
        original.after_time = Some(Err(CLOSED));
        original.first = Some(First::Publication);
        let selected = original.publication.as_ref().unwrap().as_ref().unwrap_err();

        assert!(std::ptr::eq(
            original
                .failure(None)
                .unwrap()
                .downcast_ref::<SourceAdmissionErrorV1>()
                .unwrap(),
            selected
        ));
        assert!(original.after_time.as_ref().unwrap().is_err());
    }
}
