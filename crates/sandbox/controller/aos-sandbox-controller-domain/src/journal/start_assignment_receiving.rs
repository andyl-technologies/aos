//! Forwards Start compiler pricing against the held Controller map.

use aos_sandbox_model::ResourceVector;

use super::{Journal, JournalError};
use crate::policy_compiler::provisioning_current::current_compiler_complete_receiving_demand_v1;
use crate::policy_compiler::root_signed_sources::RootSignedProjectSourcesV1;

impl Journal {
    /// Prices the shared compiler from the actual retained Controller rows.
    ///
    /// This passive calculation neither clones the map nor lends admission.
    /// The caller must fund the result before decoding or compiler growth.
    ///
    /// # Errors
    ///
    /// Returns an error when the bounded compiler or selector shape overflows.
    pub(crate) fn start_assignment_compiler_receiving_demand_v2(
        &self,
        encoded_bytes: u64,
        signed: &RootSignedProjectSourcesV1,
    ) -> Result<ResourceVector, JournalError> {
        current_compiler_complete_receiving_demand_v1(encoded_bytes, self.native.state(), signed)
    }
}
