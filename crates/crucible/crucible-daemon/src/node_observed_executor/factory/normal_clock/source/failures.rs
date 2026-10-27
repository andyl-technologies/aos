//! Authenticates the fixed actual publication and archive refusal experiments.

use super::*;

impl OriginalNormalClockSource {
    pub(in super::super) fn failure_case_data(
        &self,
        name: &str,
    ) -> Result<&ContentRef, QualificationError> {
        self.population
            .plan
            .cases
            .iter()
            .find(|case| case.id == name)
            .map(|case| &case.oracle)
            .ok_or(reject("Clock failure declaration absent"))
    }

    pub(super) fn retain_failure_original(
        &self,
        case: &str,
        oracle: &ContentRef,
        witness: &OriginalClockFailureWitness<'_>,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<CaseVerdict, QualificationError> {
        self.authenticate_current()?;
        self.failed.set(true);
        self.retain_first_result(case, reference, bytes)?;
        if !matches!(
            case,
            super::super::failures::BEFORE
                | super::super::failures::AFTER
                | super::super::failures::DAMAGED
        ) || self.failure_case_data(case)? != oracle
        {
            return Err(reject("Clock original failure case/oracle changed"));
        }
        witness
            .authenticate_source_data(
                case,
                &self.lifetime,
                &self.proposal,
                &self.profile.scenario,
                self.publication_executions,
            )
            .map_err(failure)?;
        let original = witness.original_data().map_err(failure)?;
        if &original.reference != reference || original.bytes != bytes {
            return Err(reject("Clock first original failure report changed"));
        }
        self.evidence
            .try_borrow_mut()
            .map_err(|_| reject("Clock failure evidence bank busy"))?
            .retain_result(reference, bytes)?;
        self.mark_authenticated(case)?;
        self.failed.set(false);
        self.authenticate_current()?;
        Ok(CaseVerdict::Passed)
    }
}
