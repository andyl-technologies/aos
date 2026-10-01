//! Current authenticated authority for Hybrid OCI metadata completion.
//!
//! The repository token remains the original request credential. Every
//! asynchronous boundary rechecks its live underlying principal and registry
//! grant; the final checked batch also holds the real IAM rows.

use axum::http::HeaderMap;

use crate::auth::jwt::Claims;
use crate::backend::CheckedStatement;
use crate::db::{OciRepositoryRecord, RegistryRecord};
use crate::direct_upload::DirectActorSlot;
use crate::domain::Permission;
use crate::service::RpcService;

use super::{now, unavailable_response, Response};

pub(super) struct HybridManifestAuthority {
    authority: String,
    headers: HeaderMap,
    actor: DirectActorSlot,
    token_id: String,
    expires_at: i64,
}

impl HybridManifestAuthority {
    pub(super) async fn resolve(
        service: &RpcService,
        registry: &RegistryRecord,
        repository: &OciRepositoryRecord,
        authority: &str,
        headers: &HeaderMap,
    ) -> Result<Self, Response> {
        let (actor, token_id, expires_at) = service
            .current_direct_oci_actor(registry, &repository.name, authority, headers)
            .await?;
        Ok(Self {
            authority: authority.into(),
            headers: headers.clone(),
            actor,
            token_id,
            expires_at,
        })
    }

    pub(super) async fn recheck(
        &self,
        service: &RpcService,
        registry: &RegistryRecord,
        repository: &OciRepositoryRecord,
    ) -> Result<(), Response> {
        let (actor, token_id, expires_at) = service
            .current_direct_oci_actor(registry, &repository.name, &self.authority, &self.headers)
            .await?;
        if actor != self.actor
            || token_id != self.token_id
            || expires_at != self.expires_at
            || now() >= self.expires_at
        {
            return Err(unavailable_response(
                "current manifest authority changed",
                false,
            ));
        }
        Ok(())
    }

    pub(super) async fn statements(
        &self,
        service: &RpcService,
        registry: &RegistryRecord,
        repository: &OciRepositoryRecord,
    ) -> Result<Vec<CheckedStatement>, Response> {
        self.recheck(service, registry, repository).await?;
        let auth = service
            .db
            .current_token_authority(&self.token_id)
            .await
            .map_err(|_| unavailable_response("current manifest credential is unavailable", false))?
            .ok_or_else(|| {
                unavailable_response("current manifest credential disappeared", false)
            })?;
        let ttl = (self.expires_at - now()).min(60);
        if ttl <= 0 {
            return Err(unavailable_response(
                "current manifest authority expired",
                false,
            ));
        }
        // This local JWT bridge feeds the existing checked IAM builder. Its
        // expiry is clipped to the original OCI grant and is never returned.
        let token = service.jwt_keys.mint(&auth, ttl).map_err(|_| {
            unavailable_response("current manifest credential is unavailable", false)
        })?;
        let mut claims: Claims = service.jwt_keys.verify(&token).map_err(|_| {
            unavailable_response("current manifest credential is unavailable", false)
        })?;
        claims.exp = claims.exp.min(self.expires_at);
        let scope = service
            .db
            .registry_authorization_scope(registry.id)
            .await
            .map_err(|_| unavailable_response("current manifest scope is unavailable", false))?;
        service
            .db
            .direct_iam_statements(&claims, &scope, Permission::Publish, now())
            .await
            .map_err(|_| unavailable_response("current manifest permission changed", false))
    }

    pub(super) fn expires_at(&self) -> i64 {
        self.expires_at
    }
}
