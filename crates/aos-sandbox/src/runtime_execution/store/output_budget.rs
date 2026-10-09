//! Assignment-bound output-byte admission in the protected execution journal.
//!
//! The journal's exclusive claim serializes this check with the atomic
//! admission/resource-ledger commit. Terminal process exit does not release
//! retained output; that requires a separately authenticated deletion effect.

use aos_sandbox_core::runtime_backend::{
    AdmissionCommitError, ExecutionAdmissionDraftV1, decode_durable_execution_admission_v1,
};
use aos_sandbox_core::{
    DecodeLimits, ExecutionOutputModeV1, ObjectDigest, ResourceDimension, decode_execution_spec_v1,
};

use crate::execution_output_reservation::RetainedClaim;
use crate::journal::ProtectedJournalAuthority;

use super::{ADMISSION_KEY_PREFIX, OUTPUT_FORMAT_KEY, map_admission_journal_error};

#[derive(Clone, Copy)]
pub(super) struct OutputClaim {
    assignment: ObjectDigest,
    commitment: ObjectDigest,
    parent_profile: ObjectDigest,
    requested_bytes: u64,
    parent_bytes: u64,
    admitted_bytes: u64,
    stream_limits: (u64, u64),
}

impl OutputClaim {
    pub(super) fn matches_provisional(
        self,
        retained: &RetainedClaim,
        execution: &[u8; 16],
        create_operation: &[u8; 16],
        reservation_record: ObjectDigest,
    ) -> bool {
        retained.execution == *execution
            && retained.create_operation == *create_operation
            && retained.assignment == self.assignment
            && retained.parent_profile == self.parent_profile
            && retained.claim_commitment == self.commitment
            && retained.requested_bytes == self.requested_bytes
            && retained.requested_bytes == self.admitted_bytes
            && retained.parent_bytes == self.parent_bytes
            && retained.stream_limits == Some(self.stream_limits)
            && retained.record_digest == reservation_record
    }
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
    let stream_limits = match specification.io().output_mode() {
        ExecutionOutputModeV1::Stream => (0, 0),
        ExecutionOutputModeV1::Capture {
            maximum_stdout_bytes,
            maximum_stderr_bytes,
        } => (maximum_stdout_bytes, maximum_stderr_bytes),
    };
    Ok(OutputClaim {
        assignment: output.assignment_digest(),
        commitment: output.reservation_commitment(),
        parent_profile: specification.resources().parent_profile_commitment(),
        requested_bytes: output.requested_bytes(),
        parent_bytes: output
            .parent_reservations()
            .get(ResourceDimension::OutputBytes),
        admitted_bytes: output.admitted_bytes(),
        stream_limits,
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
    if authority
        .get(OUTPUT_FORMAT_KEY)
        .map_err(map_admission_journal_error)?
        .is_some()
    {
        let bytes = authority
            .get(&crate::execution_output_reservation::claim_key(
                draft.execution(),
            ))
            .map_err(map_admission_journal_error)?
            .ok_or(AdmissionCommitError::InvalidDraft)?;
        let retained = crate::execution_output_reservation::decode_claim(bytes)
            .map_err(|_| AdmissionCommitError::CorruptRecord)?;
        if !proposed.matches_provisional(
            &retained,
            draft.execution().as_bytes(),
            draft.idempotency().operation().as_bytes(),
            draft.currentness().output_reservation(),
        ) {
            return Err(AdmissionCommitError::InvalidDraft);
        }
        // The admission transaction consumes the immutable claim by adding its
        // matching admission record; provisional replay counts the bytes once.
        return Ok(());
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
            commitment: ObjectDigest::from_bytes([admitted_bytes as u8; 32]),
            parent_profile: ObjectDigest::from_bytes([7; 32]),
            requested_bytes: admitted_bytes,
            parent_bytes,
            admitted_bytes,
            stream_limits: (admitted_bytes, 0),
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

    #[test]
    fn provisional_claim_matches_exact_spec_and_durable_receipt() {
        let claim = claim(1, 100, 20);
        let retained = RetainedClaim {
            execution: [2; 16],
            create_operation: [3; 16],
            assignment: claim.assignment,
            parent_profile: claim.parent_profile,
            claim_commitment: claim.commitment,
            requested_bytes: 20,
            parent_bytes: 100,
            stream_limits: Some((20, 0)),
            record_digest: ObjectDigest::from_bytes([4; 32]),
        };

        assert!(claim.matches_provisional(
            &retained,
            &[2; 16],
            &[3; 16],
            ObjectDigest::from_bytes([4; 32]),
        ));
        let changed_split = OutputClaim {
            stream_limits: (19, 1),
            ..claim
        };
        assert!(!changed_split.matches_provisional(
            &retained,
            &[2; 16],
            &[3; 16],
            retained.record_digest
        ));
        assert!(!claim.matches_provisional(&retained, &[2; 16], &[3; 16], claim.commitment));
        assert!(!claim.matches_provisional(
            &retained,
            &[2; 16],
            &[5; 16],
            ObjectDigest::from_bytes([4; 32]),
        ));

        let wrong_parent = OutputClaim {
            parent_profile: ObjectDigest::from_bytes([9; 32]),
            ..claim
        };
        assert!(!wrong_parent.matches_provisional(
            &retained,
            &[2; 16],
            &[3; 16],
            ObjectDigest::from_bytes([4; 32]),
        ));

        let underadmitted = OutputClaim {
            admitted_bytes: 19,
            ..claim
        };
        assert!(!underadmitted.matches_provisional(
            &retained,
            &[2; 16],
            &[3; 16],
            ObjectDigest::from_bytes([4; 32]),
        ));
    }
}
