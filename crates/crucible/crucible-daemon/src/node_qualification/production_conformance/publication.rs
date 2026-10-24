//! Retains real exact-input reports for durable source-specific publication.
//!
//! Only the existing runtime evidence reader constructs these reports. This
//! owner never executes or acknowledges work and grants no accepted class.

use super::*;
use crate::node_qualification::RetainedMetadataCounter;
use crucible_engine::node_admission::InstalledConformancePlan;
use crucible_engine::node_contract::{
    OperationToken, OriginalInputEvidence, OriginalRuntimeWitness,
};

pub(crate) struct OriginalExactPublicationReport {
    attempted: bool,
    observation: Option<ExactCompletionObservation>,
    native_input: Option<OriginalInputEvidence>,
    reference: Option<ContentRef>,
    bytes: Option<Vec<u8>>,
    verified: bool,
}

impl OriginalExactPublicationReport {
    pub(crate) fn counter_scratch_data()
    -> Result<usize, crucible_engine::node_contract::RuntimeError> {
        use std::mem::{size_of, size_of_val};
        let terms = [
            size_of::<Self>(),
            size_of::<&mut Self>(),
            size_of::<RetainedMetadataCounter>(),
            size_of::<ExactCompletionObservation>(),
            size_of::<&ExactCompletionObservation>(),
            size_of::<Option<OriginalInputEvidence>>(),
            size_of::<OriginalCompletionWitness<'static, 'static>>(),
            size_of::<Result<OriginalCompletionWitness<'static, 'static>, QualificationError>>(),
            size_of::<&mut OriginalRuntimeWitness<'static>>(),
            size_of::<&OperationToken>(),
            size_of::<&ExactCompletionCase>(),
            size_of::<(
                ExactCompletionObservation,
                bool,
                Option<OriginalInputEvidence>,
            )>(),
            size_of::<
                Result<
                    (
                        ExactCompletionObservation,
                        bool,
                        Option<OriginalInputEvidence>,
                    ),
                    QualificationError,
                >,
            >(),
            size_of::<serde_json::Value>(),
            size_of::<Result<serde_json::Value, serde_json::Error>>(),
            size_of::<ContentRef>(),
            size_of::<Result<ContentRef, crucible_node_format::ContractError>>(),
            size_of::<Vec<u8>>(),
            size_of::<Result<Vec<u8>, crucible_node_format::ContractError>>(),
            size_of::<Result<usize, QualificationError>>(),
            size_of::<Option<(&ContentRef, &[u8])>>(),
            InstalledConformancePlan::original_runtime_constructor_data_counter_scratch_data(),
        ];
        terms.iter().try_fold(size_of_val(&terms), |total, bytes| {
            total
                .checked_add(*bytes)
                .ok_or(crucible_engine::node_contract::RuntimeError::ResourceLimit)
        })
    }

    pub(crate) fn new() -> Self {
        Self {
            attempted: false,
            observation: None,
            native_input: None,
            reference: None,
            bytes: None,
            verified: false,
        }
    }

    pub(crate) fn collect(
        &mut self,
        runtime: &mut OriginalRuntimeWitness<'_>,
        token: &OperationToken,
        case: &ExactCompletionCase,
        maximum: usize,
        inspect: impl FnOnce(&OriginalCompletionWitness<'_, '_>) -> Result<(), QualificationError>,
    ) -> Result<(), QualificationError> {
        if self.attempted
            || case.acknowledged
            || case.maximum_bytes == 0
            || case.maximum_bytes > maximum as u64
        {
            return Err(QualificationError::Refused(
                "original publication report is spent",
            ));
        }
        // The existing reader enforces the independent full snapshot/native-body
        // ceiling before its original source read and every corresponding copy.
        self.attempted = true;
        let (observation, matches, native_input) =
            exact_input::collect(runtime, None, token, case)?;
        self.observation = Some(observation);
        self.native_input = native_input;
        if !matches {
            return Err(QualificationError::Refused(
                "complete publication outcome differs from its native oracle",
            ));
        }
        let observation = self
            .observation
            .as_ref()
            .ok_or(QualificationError::Refused(
                "original publication observation absent",
            ))?;
        let retained = self.requested_storage(maximum)?;
        let temporary = bytes_formatter_storage(observation)?;
        // Both references come from canonical::content_ref(_, "application/json"):
        // hash/domain/media backing has identical geometry; only the digest
        // contents and inline length differ. Admit that new independent reference before constructing it.
        let reference_storage = {
            let mut counter = RetainedMetadataCounter::new(maximum);
            counter.charge(&observation.snapshot_ref)?;
            counter.bytes()
        };
        retained
            .checked_add(temporary)
            .and_then(|bytes| bytes.checked_add(reference_storage))
            .filter(|bytes| *bytes <= maximum)
            .ok_or(QualificationError::Refused(
                "publication formatter requested storage",
            ))?;
        let serialization =
            InstalledConformancePlan::original_runtime_constructor_serialization_storage_data(
                observation,
                maximum,
            )
            .map_err(|_| {
                QualificationError::Refused("original publication serialization credit")
            })?;
        retained
            .checked_add(temporary)
            .and_then(|bytes| bytes.checked_add(reference_storage))
            .and_then(|bytes| bytes.checked_add(serialization))
            .filter(|bytes| *bytes <= maximum)
            .ok_or(QualificationError::Refused(
                "complete publication report requested storage",
            ))?;
        let value =
            serde_json::to_value(observation).map_err(crucible_node_format::ContractError::from)?;
        self.bytes = Some(canonical::canonical_json(&value)?);
        drop(value);
        self.reference = Some(canonical::content_ref(
            self.bytes.as_deref().ok_or(QualificationError::Refused(
                "publication report bytes absent",
            ))?,
            "application/json",
        )?);
        self.requested_storage(maximum)?;
        let original = runtime.original_completed_operation(token).map_err(|_| {
            QualificationError::Refused("original publication completion unavailable")
        })?;
        let witness = OriginalCompletionWitness::exact_with_input(
            &original,
            observation,
            self.native_input.as_ref(),
            self.reference.as_ref().ok_or(QualificationError::Refused(
                "publication report reference absent",
            ))?,
            self.bytes.as_deref().ok_or(QualificationError::Refused(
                "publication report bytes absent",
            ))?,
        )?;
        inspect(&witness)?;
        self.verified = true;
        Ok(())
    }

    pub(crate) fn original(&self) -> Option<(&ContentRef, &[u8])> {
        if !self.verified {
            return None;
        }
        Some((self.reference.as_ref()?, self.bytes.as_deref()?))
    }

    pub(crate) fn requested_storage(&self, maximum: usize) -> Result<usize, QualificationError> {
        let mut counter = RetainedMetadataCounter::new(maximum);
        if let Some(observation) = &self.observation {
            counter.charge(observation)?;
        }
        if let Some(input) = &self.native_input {
            let OriginalInputEvidence {
                root,
                objects,
                rows,
            } = input;
            counter.charge(root)?;
            counter.charge(objects)?;
            counter.add(
                rows.capacity()
                    .checked_mul(std::mem::size_of::<
                        crucible_engine::node_contract::OriginalLineageRow,
                    >())
                    .ok_or(QualificationError::Refused("publication input row extent"))?,
            )?;
            for row in rows {
                counter.charge(&row.object)?;
                counter.charge(&row.dependencies)?;
            }
        }
        counter.charge(&self.reference)?;
        counter.charge(&self.bytes)?;
        Ok(counter.bytes())
    }
}

fn bytes_formatter_storage(
    observation: &ExactCompletionObservation,
) -> Result<usize, QualificationError> {
    // Bytes::serialize creates URL_SAFE_NO_PAD output with an allocation sized
    // for padded base64. This is independent of the DOM/canonical visitor row.
    observation
        .snapshot
        .as_slice()
        .len()
        .checked_add(2)
        .and_then(|bytes| bytes.checked_div(3))
        .and_then(|bytes| bytes.checked_mul(4))
        .ok_or(QualificationError::Refused(
            "publication Bytes formatter credit",
        ))
}
