//! Cross-boot recovery transitions for durable Git pack leases.
//!
//! Recovery is separated from ordinary same-boot renewal and closure so a
//! prior boot's monotonic deadline can never be compared with current-boot
//! time. The opaque journal rollover authority authenticates that boundary.

use aos_sandbox_core::Revision;

use super::{
    GitBootRolloverAuthorityV1, GitJournalVerifierV1, GitModelError, GitPackLeaseStatusV1,
    GitPackLeaseV1,
};

impl GitPackLeaseV1 {
    /// Invalidates a prior-boot active lease under verifier-issued rollover.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] unless the expected revision is
    /// current and this lease belongs to an authenticated predecessor boot.
    pub fn invalidate_after_boot_rollover(
        self,
        expected_revision: Revision,
        verifier: &GitJournalVerifierV1,
    ) -> Result<Self, GitModelError> {
        let current_boottime = verifier.current_boottime();
        let rollover: &GitBootRolloverAuthorityV1 = verifier.boot_rollover();
        if self.status() != GitPackLeaseStatusV1::Active
            || expected_revision != self.lease_revision()
            || current_boottime.boot() != rollover.current()
            || !rollover.accepts_predecessor(self.boot())
            || current_boottime.boot() == self.boot()
        {
            return Err(GitModelError::InvalidModel);
        }
        Ok(Self {
            lease_revision: self
                .lease_revision
                .checked_next()
                .map_err(|_| GitModelError::InvalidModel)?,
            boot: current_boottime.boot(),
            observed_at: current_boottime.observed(),
            status: GitPackLeaseStatusV1::Invalidated,
            closed_at: Some(current_boottime.observed().get()),
            predecessor_boot: Some(self.boot),
            ..self
        })
    }
}
