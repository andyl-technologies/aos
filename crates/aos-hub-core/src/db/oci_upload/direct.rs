//! Retained metadata-only OCI allocation outside provider upload lifecycles.
//!
//! A business address contains deployment, immutable account principal and the
//! client's original operation. Registry, repository and content remain frozen
//! inputs, so changing them cannot create a second owner after a lost reply.

use super::*;
use crate::direct_upload::{deterministic_business_operation_id, DirectActorKind, DirectActorSlot};
use anyhow::ensure;
use aos_oci_types::RepositoryName;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "direct/tests.rs"]
mod tests;

/// Exact authenticated inputs for an initial bodyless direct OCI allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginDirectOciUpload {
    /// Explicit protected deployment namespace.
    pub deployment_id: String,
    /// Current authenticated immutable owner, resolved outside the OCI JWT.
    pub actor: DirectActorSlot,
    /// Original client-retained lowercase SHA-256-shaped operation identifier.
    pub client_operation_id: String,
    /// Exact owning registry SQL slot.
    pub registry_id: i64,
    /// Retained registry incarnation, independent of its SQL slot.
    pub registry_stable_id: String,
    /// Exact destination repository SQL slot.
    pub repository_id: i64,
    /// Canonical repository name resolved inside the owning registry.
    pub repository_name: String,
    /// Declared complete blob SHA-256.
    pub expected_digest: Sha256Digest,
    /// Declared complete size; empty blobs remain valid.
    pub expected_size: u64,
    /// Current live underlying API token UUID, used only for authority and audit.
    pub authorization_token_id: String,
    /// Current authorization time in Unix seconds.
    pub now: i64,
    /// Original logical upload expiry; replay never extends it.
    pub expires_at: i64,
}

impl BeginDirectOciUpload {
    fn principal_id(&self) -> Result<String> {
        self.actor.principal_id(&self.deployment_id)
    }

    fn business_id(&self) -> Result<String> {
        Ok(deterministic_business_operation_id(
            &self.deployment_id,
            &self.principal_id()?,
            &self.client_operation_id,
        )?)
    }

    fn actor_kind(&self) -> &'static str {
        match self.actor.kind {
            DirectActorKind::User => "user",
            DirectActorKind::ServiceAccount => "service_account",
        }
    }

    fn retained_upload_input(&self) -> Result<BeginOciUpload> {
        self.actor.validate()?;
        RepositoryName::parse(&self.repository_name)?;
        ensure!(
            self.registry_id > 0
                && self.repository_id > 0
                && crate::direct_upload::valid_direct_identity(&self.registry_stable_id)
                && self.expected_size <= 16 * 1024 * 1024 * 1024,
            "direct OCI allocation identity is invalid"
        );
        validate_session_times(self.now, self.expires_at)?;
        let owner = self.principal_id()?;
        Ok(BeginOciUpload {
            registry_id: self.registry_id,
            repository_id: self.repository_id,
            publication_id: None,
            writer_id: owner.clone(),
            token_id: owner,
            idempotency_key: format!("direct-{}", self.business_id()?),
            expected_digest: Some(self.expected_digest),
            expected_size: Some(self.expected_size),
            maximum_size: 16 * 1024 * 1024 * 1024,
            now: self.now,
            expires_at: self.expires_at,
        })
    }

    pub(super) fn reservation_statement(&self, upload_id: &str) -> Result<CheckedStatement> {
        Ok(Statement::new(
            "INSERT INTO direct_oci_allocations
               (business_id, deployment_id, principal_id, client_operation_id,
                actor_kind, actor_id, actor_incarnation, registry_id,
                registry_stable_id, repository_id, repository_name,
                source_sha256, declared_size, upload_id, original_token_id, created_at)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16
             FROM tokens token
             JOIN authorization_scopes scope ON scope.scope_key = token.scope_key
             LEFT JOIN orgs scope_org ON scope_org.id = scope.org_id
             JOIN registries registry ON registry.id = ?8
             JOIN orgs registry_org ON registry_org.id = registry.org_id
             JOIN oci_repositories repository ON repository.id = ?10
             WHERE token.id = ?15 AND token.owner_kind = ?5 AND token.owner_id = ?6
               AND token.owner_incarnation = ?7
               AND token.revoked_at IS NULL
               AND (token.rotated_at IS NULL OR token.rotated_at > ?17)
               AND (token.expires_at IS NULL OR token.expires_at > ?16)
               AND scope.retired_at IS NULL
               AND (scope.org_id IS NULL OR scope_org.deleted_at IS NULL)
               AND registry_org.deleted_at IS NULL
               AND registry.stable_id = ?9 AND repository.registry_id = registry.id
               AND repository.name = ?11 AND repository.lifecycle_state = 'active'
               AND ((?5 = 'user' AND EXISTS (SELECT 1 FROM users owner
                     WHERE owner.id = ?6 AND owner.principal_incarnation = ?7
                       AND owner.deleted_at IS NULL))
                 OR (?5 = 'service_account' AND EXISTS (SELECT 1 FROM service_accounts owner
                     JOIN orgs org ON org.id = owner.org_id
                     WHERE owner.id = ?6 AND owner.principal_incarnation = ?7
                       AND org.deleted_at IS NULL)))",
            vals![
                self.business_id()?,
                self.deployment_id,
                self.principal_id()?,
                self.client_operation_id,
                self.actor_kind(),
                i64::try_from(self.actor.numeric_id.get())?,
                self.actor.incarnation,
                self.registry_id,
                self.registry_stable_id,
                self.repository_id,
                self.repository_name,
                hex::encode(self.expected_digest.as_bytes()),
                checked_u64(self.expected_size, "direct OCI size")?,
                upload_id,
                self.authorization_token_id,
                self.now,
                self.now.saturating_sub(crate::db::ROTATION_GRACE_SECS)
            ],
        )
        .expecting(1))
    }
}

impl Database {
    /// Allocates or returns the original metadata-only OCI logical session.
    ///
    /// The caller authenticates the OCI domain, exact registered authority,
    /// repository push grant and current IAM before this method. This method
    /// repeats live token/owner provenance and atomically retains the business
    /// reservation with actual quota and upload creation. It invokes no provider.
    /// Token rotation can use the same account UUID; a token ID is never a
    /// business address. Expiry or an absent old upload cannot clear reservation.
    ///
    /// # Errors
    /// Returns an error for invalid inputs, stale token/owner authority, changed
    /// original intent, missing retained upload, quota denial, or database failure.
    pub async fn begin_direct_oci_upload(
        &self,
        input: &BeginDirectOciUpload,
    ) -> Result<OciUploadRecord> {
        let upload = input.retained_upload_input()?;
        self.validate_direct_oci_token(input).await?;
        if let Some(existing) = self.direct_oci_allocation_replay(input).await? {
            return Ok(existing);
        }
        let result = self.begin_oci_upload_retained(&upload, Some(input)).await?;
        self.validate_direct_oci_token(input).await?;
        Ok(result)
    }

    async fn validate_direct_oci_token(&self, input: &BeginDirectOciUpload) -> Result<()> {
        let auth = self
            .current_token_authority(&input.authorization_token_id)
            .await?
            .context("direct OCI token is not current")?;
        ensure!(
            auth.owner.kind.as_str() == input.actor_kind()
                && u64::try_from(auth.owner.id)? == input.actor.numeric_id.get()
                && auth.owner_incarnation.as_ref() == Some(&input.actor.incarnation),
            "direct OCI token belongs to another owner incarnation"
        );
        Ok(())
    }

    pub(super) async fn direct_oci_allocation_replay(
        &self,
        input: &BeginDirectOciUpload,
    ) -> Result<Option<OciUploadRecord>> {
        let Some(row) = self
            .backend
            .query_opt(
                "SELECT deployment_id, principal_id, client_operation_id, actor_kind,
                    actor_id, actor_incarnation, registry_id, registry_stable_id,
                    repository_id, repository_name, source_sha256, declared_size, upload_id
             FROM direct_oci_allocations WHERE business_id = ?1",
                &vals![input.business_id()?],
            )
            .await?
        else {
            return Ok(None);
        };
        ensure!(
            row.get::<String>(0)? == input.deployment_id
                && row.get::<String>(1)? == input.principal_id()?
                && row.get::<String>(2)? == input.client_operation_id
                && row.get::<String>(3)? == input.actor_kind()
                && row.get::<i64>(4)? == i64::try_from(input.actor.numeric_id.get())?
                && row.get::<String>(5)? == input.actor.incarnation
                && row.get::<i64>(6)? == input.registry_id
                && row.get::<String>(7)? == input.registry_stable_id
                && row.get::<i64>(8)? == input.repository_id
                && row.get::<String>(9)? == input.repository_name
                && row.get::<String>(10)? == hex::encode(input.expected_digest.as_bytes())
                && row.get::<i64>(11)? == checked_u64(input.expected_size, "direct OCI size")?,
            "direct OCI operation conflicts with its original allocation"
        );
        let original_id: String = row.get(12)?;
        let retained = input.retained_upload_input()?;
        let upload = self
            .oci_upload_by_idempotency(
                input.registry_id,
                &retained.writer_id,
                &retained.idempotency_key,
            )
            .await?
            .context("retained direct OCI upload is missing; allocation remains occupied")?;
        ensure!(
            upload.id == original_id
                && upload.repository_id == input.repository_id
                && upload.publication_id.is_none()
                && upload.writer_id == retained.writer_id
                && upload.token_id == retained.token_id
                && upload.expected_digest == Some(input.expected_digest)
                && upload.expected_size == Some(input.expected_size)
                && upload.maximum_size == retained.maximum_size,
            "retained direct OCI upload differs from its original allocation"
        );
        // No effect is dispatched here, but even a historical allocation reply
        // still requires the current credential after all retained-state awaits.
        self.validate_direct_oci_token(input).await?;
        Ok(Some(upload))
    }
}
