//! Assignment-bound output-byte admission in the protected execution journal.
//!
//! The journal's exclusive claim serializes this check with the atomic
//! admission/resource-ledger commit. Terminal process exit does not release
//! retained output; that requires a separately authenticated deletion effect.

use aos_sandbox_core::runtime_backend::{
    AdmissionCommitError, ExecutionAdmissionDraftV1, decode_durable_execution_admission_v1,
};
use aos_sandbox_core::{DecodeLimits, ObjectDigest, ResourceDimension, decode_execution_spec_v1};

use crate::journal::ProtectedJournalAuthority;

use super::{ADMISSION_KEY_PREFIX, map_admission_journal_error};

#[derive(Clone, Copy)]
pub(super) struct OutputClaim {
    assignment: ObjectDigest,
    parent_bytes: u64,
    admitted_bytes: u64,
}

pub(super) struct OutputBudget {
    assignment: ObjectDigest,
    parent_bytes: u64,
    reserved_bytes: u64,
}

impl OutputBudget {
    fn empty(claim: OutputClaim) -> Self {
        Self {
            assignment: claim.assignment,
            parent_bytes: claim.parent_bytes,
            reserved_bytes: 0,
        }
    }

    pub(super) fn from_first(claim: OutputClaim) -> Result<Self, ()> {
        let mut budget = Self::empty(claim);
        budget.include(claim)?;
        Ok(budget)
    }

    pub(super) fn include(&mut self, claim: OutputClaim) -> Result<(), ()> {
        if claim.assignment != self.assignment || claim.parent_bytes != self.parent_bytes {
            return Err(());
        }
        let next = self
            .reserved_bytes
            .checked_add(claim.admitted_bytes)
            .ok_or(())?;
        if next > self.parent_bytes {
            return Err(());
        }
        self.reserved_bytes = next;
        Ok(())
    }
}

pub(super) fn decode_output_claim(specification_bytes: &[u8]) -> Result<OutputClaim, ()> {
    let specification = decode_execution_spec_v1(
        specification_bytes,
        DecodeLimits {
            maximum_bytes: specification_bytes.len(),
            maximum_collection_items: 65_536,
            maximum_total_items: 262_144,
            maximum_byte_string_bytes: 15 * 1_048_576,
            maximum_text_bytes: 1_048_576,
            maximum_depth: 128,
        },
    )
    .map_err(|_| ())?;
    let output = specification.resources().output_bytes();
    Ok(OutputClaim {
        assignment: output.assignment_digest(),
        parent_bytes: output
            .parent_reservations()
            .get(ResourceDimension::OutputBytes),
        admitted_bytes: output.admitted_bytes(),
    })
}

pub(super) fn reserve_output_bytes(
    authority: &ProtectedJournalAuthority<'_>,
    draft: &ExecutionAdmissionDraftV1,
) -> Result<(), AdmissionCommitError> {
    let proposed = decode_output_claim(draft.specification_bytes())
        .map_err(|_| AdmissionCommitError::InvalidDraft)?;
    if proposed.assignment
        != draft
            .currentness()
            .runtime()
            .currentness()
            .assignment_digest()
    {
        return Err(AdmissionCommitError::CurrentnessMismatch);
    }
    let mut budget = OutputBudget::empty(proposed);
    for (key, value) in authority.records().map_err(map_admission_journal_error)? {
        if matches!(key, [ADMISSION_KEY_PREFIX, ..] if key.len() == 17) {
            let admission = decode_durable_execution_admission_v1(value)
                .map_err(|_| AdmissionCommitError::CorruptRecord)?;
            let claim = decode_output_claim(admission.specification_bytes())
                .map_err(|_| AdmissionCommitError::CorruptRecord)?;
            budget
                .include(claim)
                .map_err(|_| AdmissionCommitError::CorruptRecord)?;
        }
    }
    budget
        .include(proposed)
        .map_err(|_| AdmissionCommitError::CapacityUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(assignment: u8, parent_bytes: u64, admitted_bytes: u64) -> OutputClaim {
        OutputClaim {
            assignment: ObjectDigest::from_bytes([assignment; 32]),
            parent_bytes,
            admitted_bytes,
        }
    }

    #[test]
    fn output_budget_retains_prior_admissions_and_rejects_overcommit() {
        let mut budget = OutputBudget::from_first(claim(1, 100, 60)).unwrap();
        budget.include(claim(1, 100, 40)).unwrap();

        assert!(budget.include(claim(1, 100, 1)).is_err());
        assert_eq!(budget.reserved_bytes, 100);
    }

    #[test]
    fn output_budget_rejects_parent_or_assignment_substitution() {
        let mut budget = OutputBudget::from_first(claim(1, 100, 20)).unwrap();

        assert!(budget.include(claim(2, 100, 10)).is_err());
        assert!(budget.include(claim(1, 200, 10)).is_err());
        assert!(OutputBudget::from_first(claim(1, 100, 101)).is_err());
        assert_eq!(budget.reserved_bytes, 20);
    }

    #[test]
    fn output_budget_rejects_counter_overflow() {
        let mut budget = OutputBudget::from_first(claim(1, u64::MAX, u64::MAX)).unwrap();

        assert!(budget.include(claim(1, u64::MAX, 1)).is_err());
        assert_eq!(budget.reserved_bytes, u64::MAX);
    }
}
