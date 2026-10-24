//! Authenticates actual same-source adverse owners without promoting missing suites.

use super::*;
use crate::node_qualification::CaseVerdict;

impl OriginalNormalClockSource {
    pub(super) fn retain_adverse_original(
        &self,
        case: &str,
        oracle: &ContentRef,
        witness: &OriginalClockAdverseWitness<'_>,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<CaseVerdict, QualificationError> {
        self.authenticate_current()?;
        self.failed.set(true);
        self.retain_first_result(case, reference, bytes)?;
        let planned = self
            .population
            .plan
            .cases
            .iter()
            .find(|planned| planned.id == population::ADVERSE)
            .ok_or(reject("Clock original adverse declaration absent"))?;
        if case != population::ADVERSE
            || &planned.oracle != oracle
            || reference != witness.reference()
            || bytes != witness.bytes()
        {
            return Err(reject("Clock original adverse case/oracle/report changed"));
        }
        witness
            .authenticate_source_data(
                &self.lifetime,
                &self.proposal,
                &self.profile.scenario,
                self.adverse_executions,
            )
            .map_err(failure)?;
        // These are actual original report bytes. Any unresolved transitive
        // native body remains unavailable at the ordinary evidence gate; this
        // callback does not manufacture it from an expected oracle.
        self.evidence
            .try_borrow_mut()
            .map_err(|_| reject("Clock adverse evidence bank busy"))?
            .retain_result(reference, bytes)?;
        self.mark_authenticated(case)?;
        self.failed.set(false);
        self.authenticate_current()?;
        Ok(CaseVerdict::Passed)
    }
}
