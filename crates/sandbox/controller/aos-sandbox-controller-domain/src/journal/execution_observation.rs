//! Fences the same purpose18 Controller after a retained observation refusal.
//!
//! This identity grants only denial. It cannot read, append, heal a Journal or
//! reconstruct a spent intake. The genuine execution original retains it from
//! its actual Bank/Controller claim through independent Source/C posts.

use super::*;

pub(crate) struct ExecutionObservationJournalIdentityV4 {
    instance: std::sync::Arc<JournalAuthorityInstance>,
}

impl ExecutionObservationJournalIdentityV4 {
    pub(crate) fn is_same_original_v4(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.instance, &other.instance)
    }
}

impl Journal {
    pub(crate) fn execution_observation_identity_v4(
        &self,
    ) -> ExecutionObservationJournalIdentityV4 {
        ExecutionObservationJournalIdentityV4 {
            instance: std::sync::Arc::clone(&self.authority_instance),
        }
    }

    pub(crate) fn fence_execution_observation_v4(
        &mut self,
        identity: &ExecutionObservationJournalIdentityV4,
    ) -> Result<(), JournalError> {
        if !std::sync::Arc::ptr_eq(&identity.instance, &self.authority_instance) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.native.poison();
        Ok(())
    }
}
