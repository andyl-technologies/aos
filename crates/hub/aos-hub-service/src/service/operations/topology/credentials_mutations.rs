//! Credentials mutations in the topology capability.

use super::*;

impl RpcService {
    /// Applies initial credential configuration.
    ///
    /// # Errors
    ///
    /// Returns an authorization, confirmation, stale-plan, or persistence error.
    pub async fn apply_set_binding_credential(
        &self,
        auth: Option<&str>,
        req: pb::ApplyBindingCredentialRequest,
    ) -> Result<pb::BindingCredentialResponse, RpcError> {
        self.apply_binding_credential(auth, req, false).await
    }

    /// Applies credential rotation.
    ///
    /// # Errors
    ///
    /// Returns an authorization, confirmation, stale-plan, or persistence error.
    pub async fn apply_rotate_binding_credential(
        &self,
        auth: Option<&str>,
        req: pb::ApplyBindingCredentialRequest,
    ) -> Result<pb::BindingCredentialResponse, RpcError> {
        self.apply_binding_credential(auth, req, true).await
    }
}
