//! Credentials plans in the topology capability.

use super::*;

impl RpcService {
    /// Plans initial credential configuration.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, stale-version, or persistence error.
    pub async fn plan_set_binding_credential(
        &self,
        auth: Option<&str>,
        req: pb::PlanBindingCredentialRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_binding_credential(auth, req, false).await
    }

    /// Plans credential rotation.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, stale-version, or persistence error.
    pub async fn plan_rotate_binding_credential(
        &self,
        auth: Option<&str>,
        req: pb::PlanBindingCredentialRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_binding_credential(auth, req, true).await
    }
}
