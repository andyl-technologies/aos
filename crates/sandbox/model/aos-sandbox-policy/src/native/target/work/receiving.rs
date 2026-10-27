//! Admits the reached publication operation before clone, encode or replay.
//!
//! Every call reads the actual same Target prefix. Independent capacity and
//! held preparation add their real future four-member width; invocation uses
//! the actual parked capacity members; readback uses the now-retained prefix.
//! No configured maximum, earlier compiler debit or startup credit is reused.

use super::{RootPolicyPublicationErrorV1 as ErrorV1, RootPolicyPublicationWorkV1};
use crate::native::publication::{self, PolicyCompilerJournalSchemaV1,
    PolicyCompilerReplayValidatorV1, Q04IndependentPublicationRecipeV1,
    Q04PolicyPublicationAttemptV1, Q04PolicyPublicationReadbackV1,
    Q04PublicationCapacityV1, PreparedPolicyPublicationV1, VerifiedPolicyPublicationV1};
use crate::CompiledPolicyCandidateV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::records::{DURABLE_MEMBER_FIXED_BYTES, ProtectedRecordRoleV1};
use aos_sandbox_protocol::domain_ledger::transaction::JournalRecord;
use std::mem::size_of;

pub(super) enum PublicationReceivingPhaseV1 { Plan, Prepare, Invoke, Readback }

impl RootPolicyPublicationWorkV1<'_> {
    pub(super) fn admit_publication_materialization_v1(
        &self,
        candidate: &CompiledPolicyCandidateV1,
        validator: &PolicyCompilerReplayValidatorV1,
        phase: PublicationReceivingPhaseV1,
    ) -> Result<(), ErrorV1> {
        let geometry = crate::native::PolicyNativeJournalErrorV1::geometry;
        // The factory is inspected only as a compiler-known function item;
        // the quote never invokes it or constructs its opaque iterator.
        let fold = |(rows, bytes, largest): (usize, usize, usize),
                    (_, key, value): (aos_sandbox_model::RecordNamespace, &[u8], &[u8])| {
            Some((
                rows.checked_add(1)?,
                bytes.checked_add(key.len())?.checked_add(value.len())?,
                largest.max(value.len()),
            ))
        };
        let iterator_controls = iterator_receiving_control_bytes_v1(
            crate::native::journal::RootPolicyJournalV1::all_records,
            &fold,
        )
        .ok_or_else(geometry)?;

        // Fixed helper and conversion planes precede actual traversal,
        // counting and schema helpers. Backing follows the known shape.
        let mut fixed_controls = operation_control_bytes_v1().ok_or_else(geometry)?;
        fixed_controls = fixed_controls
            .checked_add(iterator_controls)
            .ok_or_else(geometry)?;
        // The fixed and dynamic admissions are separate real calls. The
        // operation quote already names one vector/result; this is the other.
        let admission_controls = size_of::<(
            ResourceVector,
            Result<(), crate::native::PolicyNativeJournalErrorV1>,
            Result<u64, std::num::TryFromIntError>,
            Result<u64, std::num::TryFromIntError>,
        )>()
        .checked_mul(3)
        .ok_or_else(geometry)?;
        fixed_controls = fixed_controls
            .checked_add(admission_controls)
            .ok_or_else(geometry)?;
        if matches!(
            phase,
            PublicationReceivingPhaseV1::Plan | PublicationReceivingPhaseV1::Prepare
        ) {
            let counter_controls =
                aos_sandbox_protocol::policy_data::canonical_payload_count_control_bytes_v1()
                    .ok_or_else(geometry)?;
            let failure_backing =
                aos_sandbox_protocol::policy_data::canonical_serialization_failure_backing_bytes_v1()
                    .ok_or_else(geometry)?;
            let mapped_controls = size_of::<(
                Result<usize, crate::PolicyModelError>,
                crate::PolicyModelError,
                ErrorV1,
            )>()
            .checked_mul(3)
            .ok_or_else(geometry)?;
            let counter_controls = counter_controls
                .checked_add(failure_backing)
                .ok_or_else(geometry)?;
            let counter_controls = counter_controls
                .checked_add(mapped_controls)
                .ok_or_else(geometry)?;
            // The primitive already prices its canonical Result's constructor,
            // return and caller planes; only the actual mapped owners are new.
            fixed_controls = fixed_controls
                .checked_add(counter_controls)
                .ok_or_else(geometry)?;
        }
        self.target
            .journal
            .admit_role_observation_v1(ResourceVector::ZERO.with(
                D::MemoryBytes,
                u64::try_from(fixed_controls).map_err(|_| geometry())?,
            ))?;

        // This is the first actual iterator construction and traversal. The
        // fold body and its negative overflow order match the original donor.
        let mut records = self.target.journal.all_records();
        let (rows, encoded, largest_previous) = records
            .try_fold((0_usize, 0_usize, 0_usize), fold)
            .ok_or_else(geometry)?;

        let mut prospective_rows = rows;
        let mut prospective_bytes = encoded;
        let mut fresh_backing = 0_usize;
        if matches!(
            phase,
            PublicationReceivingPhaseV1::Plan | PublicationReceivingPhaseV1::Prepare
        ) {
            let payload =
                aos_sandbox_protocol::policy_data::canonical_payload_size_v1(candidate.explanation())
                    .map_err(crate::PolicyModelError::from)?;
            let frame = payload
                .checked_add(publication::DIAGNOSTICS_DOMAIN.len())
                .and_then(|bytes| bytes.checked_add(16))
                .ok_or_else(geometry)?;
            let shape = publication::q04_publication_byte_shape_v1(candidate, frame)?;
            prospective_rows = rows.checked_add(shape.bodies.len()).ok_or_else(geometry)?;
            for index in 0..shape.bodies.len() {
                let durable = shape.envelopes[index]
                    .checked_add(DURABLE_MEMBER_FIXED_BYTES)
                    .ok_or_else(geometry)?;
                prospective_bytes = prospective_bytes
                    .checked_add(shape.keys[index])
                    .and_then(|bytes| bytes.checked_add(durable))
                    .ok_or_else(geometry)?;
                // The sole planner copy recipe includes Prepared and postcommit
                // representations. A previous selected key cannot exceed the
                // actual largest retained value, including negative prefixes.
                let planned = aos_sandbox_broker::domain_transaction_custody::resident_plan_member_payload_bytes_for_lengths_v1(
                    shape.reducer_payloads[index], shape.keys[index], shape.key_identities[index], largest_previous,
                ).map_err(crate::q04_data::PolicyQ04DataErrorV1::from)?;
                fresh_backing = fresh_backing
                    .checked_add(planned)
                    .and_then(|bytes| bytes.checked_add(shape.bodies[index]))
                    .and_then(|bytes| bytes.checked_add(shape.reducer_payloads[index]))
                    .and_then(|bytes| bytes.checked_add(shape.envelopes[index]))
                    .ok_or_else(geometry)?;
            }
            fresh_backing = fresh_backing
                .checked_add(
                    aos_sandbox_protocol::policy_data::canonical_model_receiving_bytes_v1(
                        payload,
                        publication::DIAGNOSTICS_DOMAIN.len(),
                    )
                    .ok_or_else(geometry)?,
                )
                .ok_or_else(geometry)?;
        } else if matches!(phase, PublicationReceivingPhaseV1::Invoke) {
            let capacity = &self
                .prehold_plan
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(ErrorV1::ChangedCut)?
                .capacity;
            prospective_rows = rows
                .checked_add(capacity.journal_records().len())
                .ok_or_else(geometry)?;
            for record in capacity.journal_records() {
                let value = record.value().ok_or(ErrorV1::ChangedCut)?;
                prospective_bytes = prospective_bytes
                    .checked_add(record.key().len())
                    .and_then(|bytes| bytes.checked_add(value.len()))
                    .ok_or_else(geometry)?;
                // Exact postcommit comparison retains the member and decoded
                // payload independently of the already-resident Prepared.
                fresh_backing = fresh_backing
                    .checked_add(value.len().checked_mul(2).ok_or_else(geometry)?)
                    .and_then(|bytes| bytes.checked_add(record.key().len().checked_mul(2)?))
                    .ok_or_else(geometry)?;
            }
        }
        let models = publication::schema_replay_model_receiving_bytes_v1(
            prospective_rows,
            prospective_bytes,
            validator,
        )
        .ok_or_else(geometry)?;
        let names_growth = if matches!(phase, PublicationReceivingPhaseV1::Readback)
            && self.readback_names.len() == self.readback_names.capacity()
        {
            self.readback_names
                .len()
                .checked_add(1)
                .and_then(|entries| entries.checked_mul(4))
                .and_then(|entries| {
                    entries.checked_mul(size_of::<crate::native::RootPolicyNameObservationOriginalV1>())
                })
                .ok_or_else(geometry)?
        } else {
            0
        };
        let memory = models
            .checked_add(fresh_backing)
            .and_then(|bytes| bytes.checked_add(names_growth))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(geometry)?;
        let names = publication::schema_replay_model_metadata_entries_v1(
            prospective_rows,
            prospective_bytes,
            validator,
        )
        .and_then(|entries| u64::try_from(entries).ok())
        .ok_or_else(geometry)?;
        self.target.journal.admit_role_observation_v1(
            ResourceVector::ZERO
                .with(D::MemoryBytes, memory)
                .with(D::MetadataEntries, names),
        )?;
        Ok(())
    }
}

// Uses the actual method's opaque return type without creating a Journal,
// invoking the factory, traversing rows or accepting a native callback.
fn iterator_receiving_control_bytes_v1<'journal, Factory, Iterator, Fold>(
    _factory: Factory,
    _fold: &Fold,
) -> Option<usize>
where
    Factory: FnOnce(&'journal crate::native::journal::RootPolicyJournalV1) -> Iterator,
    Iterator: std::iter::Iterator,
{
    size_of::<Factory>()
        .checked_mul(3)?
        .checked_add(size_of::<&Fold>().checked_mul(3)?)?
        .checked_add(size_of::<Fold>().checked_mul(3)?)?
        .checked_add(size_of::<Iterator>().checked_mul(3)?)?
        .checked_add(size_of::<Iterator::Item>().checked_mul(3)?)?
        .checked_add(size_of::<Option<Iterator::Item>>().checked_mul(3)?)?
        .checked_add(size_of::<&mut Fold>().checked_mul(3)?)?
        .checked_add(size_of::<&crate::native::journal::RootPolicyJournalV1>().checked_mul(3)?)?
        .checked_add(size_of::<(usize, usize, usize)>().checked_mul(3)?)?
        .checked_add(size_of::<Option<(usize, usize, usize)>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)?
        .checked_add(
            size_of::<Result<usize, crate::native::PolicyNativeJournalErrorV1>>().checked_mul(3)?,
        )?
        .checked_add(size_of::<crate::native::PolicyNativeJournalErrorV1>().checked_mul(3)?)?
        .checked_add(size_of::<ErrorV1>().checked_mul(3)?)
}

fn operation_control_bytes_v1() -> Option<usize> {
    type Schema = PolicyCompilerJournalSchemaV1;
    let publication = size_of::<Q04IndependentPublicationRecipeV1>()
        .checked_add(size_of::<Q04PublicationCapacityV1>())?
        .checked_add(size_of::<PreparedPolicyPublicationV1>())?
        .checked_add(size_of::<VerifiedPolicyPublicationV1>())?
        .checked_add(size_of::<Q04PolicyPublicationAttemptV1>())?
        .checked_add(size_of::<Q04PolicyPublicationReadbackV1>())?
        .checked_add(size_of::<super::RootPolicyReadbackObservationV1>())?
        .checked_add(size_of::<Result<PreparedPolicyPublicationV1, ErrorV1>>())?
        .checked_add(size_of::<Result<Q04PolicyPublicationReadbackV1, ErrorV1>>())?
        .checked_add(size_of::<Result<(), ErrorV1>>())?
        .checked_add(size_of::<super::RootPreholdPublicationPlanV1>())?
        .checked_add(size_of::<Result<super::RootPreholdPublicationPlanV1, ErrorV1>>())?;
    let vectors = size_of::<JournalRecord>().checked_mul(4)?
        .checked_add(size_of::<ProtectedRecordRoleV1>().checked_mul(4)?)?
        .checked_add(size_of::<Option<Vec<u8>>>().checked_mul(4)?)?
        .checked_add(size_of::<Vec<u8>>().checked_mul(4)?)?
        .checked_add(size_of::<crate::native::RootPolicyNameObservationOriginalV1>())?;
    let geometry = size_of::<publication::Q04PublicationByteShapeV1>()
        .checked_add(size_of::<Result<publication::Q04PublicationByteShapeV1,
            publication::PolicyCompilerJournalErrorV1>>())?
        .checked_add(size_of::<[&[u8]; 4]>())?
        .checked_add(size_of::<std::array::IntoIter<&[u8], 4>>())?
        .checked_add(size_of::<Option<usize>>().checked_mul(6)?)?
        .checked_add(size_of::<PublicationReceivingPhaseV1>())?
        .checked_add(size_of::<Result<usize, aos_sandbox_protocol::domain_ledger::JournalTransactionDataError>>())?
        .checked_add(size_of::<Result<usize, crate::q04_data::PolicyQ04DataErrorV1>>())?
        .checked_add(size_of::<Result<usize, publication::PolicyCompilerJournalErrorV1>>())?
        .checked_add(size_of::<ResourceVector>())?
        .checked_add(size_of::<Result<(), crate::native::PolicyNativeJournalErrorV1>>())?;
    publication.checked_add(vectors)?.checked_add(geometry)?.checked_mul(3)?
        .checked_add(crate::native::protected_transaction::receiving_control_bytes_v1::<Schema>()?)
}

impl RootPolicyPublicationWorkV1<'_> {
    pub(super) fn admit_current_verifier_controls_v1(&self) -> Result<(), ErrorV1> {
        let geometry = crate::native::PolicyNativeJournalErrorV1::geometry;
        let bytes = size_of::<super::RootCurrentInputVerifierV1<'_, '_, '_, '_, '_>>()
            .checked_add(size_of::<crate::q04_data::Q04ClaimV1<'_>>())
            .and_then(|bytes| bytes.checked_add(size_of::<Result<crate::q04_data::Q04ClaimV1<'_>,
                crate::q04_data::PolicyQ04DataErrorV1>>()))
            .and_then(|bytes| bytes.checked_add(size_of::<crate::q04_data::Q04PreviewV1<'_>>()))
            .and_then(|bytes| bytes.checked_add(size_of::<Result<crate::q04_data::Q04PreviewV1<'_>,
                crate::q04_data::PolicyQ04DataErrorV1>>()))
            .and_then(|bytes| bytes.checked_add(size_of::<crate::q04_data::Q04PreholdInputDataV1<'_>>()))
            .and_then(|bytes| bytes.checked_add(size_of::<Result<crate::q04_data::Q04PreholdInputDataV1<'_>,
                crate::q04_data::PolicyQ04DataErrorV1>>()))
            .and_then(|bytes| bytes.checked_add(size_of::<Result<(), ErrorV1>>()))
            .and_then(|bytes| bytes.checked_add(size_of::<crate::signed_inputs::PolicyDeploymentInputsV1<'_>>()))
            .and_then(|bytes| bytes.checked_mul(3))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(geometry)?;
        self.target.journal.admit_role_observation_v1(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?;
        Ok(())
    }
}
