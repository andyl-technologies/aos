//! Live immutable principal validation shared by RPC permission and replay gates.
//!
//! A signature authenticates the claim bytes. Current SQL authority separately
//! proves that the exact API token or browser session still belongs to the same
//! immutable account incarnation; a recyclable numeric slot is insufficient.

use super::*;

impl RpcService {
    /// Compares the original reviewed account UUID without inferring legacy pins.
    pub(super) fn plan_actor_matches(
        plan: &crate::db::TopologyPlanRecord,
        claims: &Claims,
    ) -> bool {
        plan.actor_kind == claims.owner_kind
            && plan.actor_id == Some(claims.owner_id)
            && claims
                .owner_incarnation
                .as_ref()
                .is_some_and(|incarnation| plan.actor_incarnation.as_ref() == Some(incarnation))
    }

    /// Resolves the caller only while its exact signed provenance remains live.
    ///
    /// # Errors
    /// Returns a database failure or refuses inactive, changed or missing authority.
    pub(super) async fn current_principal(&self, claims: &Claims) -> Result<Principal, RpcError> {
        self.db
            .current_authenticated_actor(claims)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| {
                RpcError::PermissionDenied("active authenticated principal required".into())
            })?;

        // The database validated account kind, numeric slot and incarnation
        // together. This conversion supplies the existing IAM graph address.
        claims_principal(claims).ok_or_else(|| {
            RpcError::PermissionDenied("active authenticated principal required".into())
        })
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

/// Creates real current provisioning-token authority for RPC regression fixtures.
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(super) async fn provisioned_test_auth(
    db: &Database,
    owner: Principal,
    scope: Scope,
    permissions: &[Permission],
) -> crate::db::TokenAuth {
    let (_, secret) = db
        .create_token(
            owner,
            scope.as_str(),
            permissions,
            Some("RPC fixture"),
            None,
        )
        .await
        .unwrap();
    db.validate_token(&secret).await.unwrap().unwrap()
}

/// Creates real cookie provenance for identity-only or overbroad-scope fixtures.
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(super) async fn browser_test_auth(
    db: &Database,
    user: i64,
    permissions: Vec<Permission>,
) -> crate::db::TokenAuth {
    let secret = db.create_session(user, 3600, 1).await.unwrap();
    let session = db.validate_session(&secret).await.unwrap().unwrap();
    crate::db::TokenAuth {
        token_id: format!("browser-session-{user}"),
        owner: Principal::user(user),
        owner_incarnation: Some(session.owner_incarnation),
        browser_session_id_hash: Some(session.session_id_hash),
        scope: Scope::root(),
        permissions,
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod race_tests;
