//! SQL observations and final dependency fences for direct target adapters.

use anyhow::{Context as _, Result};

use super::{Database, SurfacePlacementRecord};
use crate::{
    backend::{CheckedStatement, Statement},
    direct_upload::DirectPlacement,
    value::Value,
};

mod dependency_locks;
mod locks;
mod provenance;
mod publication;
pub use provenance::{validate_direct_presence_provenance, DirectPresenceProvenance};

impl Database {
    /// Resolves the current placement-local immutable writer revision.
    ///
    /// # Errors
    /// Returns an error for absent, stale or unvalidated placement capability.
    pub async fn direct_placement_write_revision(
        &self,
        placement: &SurfacePlacementRecord,
    ) -> Result<i64> {
        let row = self.backend.query_opt(
            "SELECT capability.binding_write_revision
             FROM surface_placement_write_capabilities capability
             JOIN binding_write_revisions revision ON revision.binding_id = capability.binding_id
               AND revision.revision = capability.binding_write_revision
             JOIN binding_credential_revisions credential ON credential.binding_id = revision.binding_id
               AND credential.purpose = revision.write_credential_purpose
               AND credential.generation = revision.write_credential_generation
             WHERE capability.placement_id = ?1 AND capability.binding_id = ?2
               AND capability.placement_write_spec_version = ?3
               AND credential.validation_state = 'valid' AND revision.writes_supported = 1",
            &vals![placement.id, placement.binding_id, placement.write_spec_version],
        ).await?.context("direct placement writer capability unavailable")?;
        row.get(0)
    }

    /// Builds a current complete placement and credential-head fence.
    ///
    /// # Errors
    /// Returns an error for a pin outside the SQL integer range.
    pub fn direct_placement_fence(placement: &DirectPlacement) -> Result<CheckedStatement> {
        let mut values = [
            placement.placement_id,
            placement.placement_resource_version,
            placement.write_spec_version,
            placement.binding_id,
            placement.binding_resource_version,
            placement.binding_write_revision,
        ]
        .into_iter()
        .map(|value| i64::try_from(value.get()).map(Value::Int))
        .collect::<std::result::Result<Vec<_>, _>>()?;
        for credential in [
            &placement.write_credential,
            &placement.read_credential,
            &placement.presign_credential,
        ] {
            values.push(Value::Text(credential.purpose.clone()));
            values.push(Value::Int(i64::try_from(credential.generation.get())?));
        }
        let managed = matches!(
            placement.physical,
            crate::direct_upload::DirectPhysicalContext::DeploymentR2 { .. }
        );
        values.push(Value::Int(i64::from(managed)));
        for credential in [
            &placement.write_credential,
            &placement.read_credential,
            &placement.presign_credential,
        ] {
            values.push(Value::Text(credential.secret_version_ref.clone()));
            values.push(Value::Text(credential.credential_fingerprint.clone()));
        }
        Ok(Statement::new(
            "UPDATE surface_placements SET resource_version = resource_version
             WHERE id = ?1 AND resource_version = ?2 AND write_spec_version = ?3
               AND binding_id = ?4 AND desired_state = 'active'
               AND EXISTS (SELECT 1 FROM bindings binding WHERE binding.id = ?4
                 AND binding.resource_version = ?5)
               AND EXISTS (SELECT 1 FROM surface_placement_write_capabilities capability
                 WHERE capability.placement_id = ?1 AND capability.binding_id = ?4
                   AND capability.placement_write_spec_version = ?3 AND capability.binding_write_revision = ?6)
               AND (EXISTS (SELECT 1 FROM binding_credential_revisions credential
                 JOIN binding_credential_heads head ON head.binding_id = credential.binding_id
                   AND head.purpose = credential.purpose AND head.current_generation = credential.generation
                 WHERE credential.binding_id = ?4 AND credential.purpose = ?7
                   AND credential.generation = ?8 AND credential.validation_state = 'valid'
                   AND credential.secret_version_ref = ?14 AND credential.credential_fingerprint = ?15)
                 OR (?13 = 1 AND EXISTS (SELECT 1 FROM binding_write_revisions revision
                   JOIN binding_credential_revisions credential ON credential.binding_id = revision.binding_id
                     AND credential.purpose = revision.write_credential_purpose
                     AND credential.generation = revision.write_credential_generation
                   WHERE revision.binding_id = ?4 AND revision.revision = ?6
                     AND credential.validation_state = 'valid')))
               AND (?13 = 1 OR EXISTS (SELECT 1 FROM binding_credential_revisions credential
                 JOIN binding_credential_heads head ON head.binding_id = credential.binding_id
                   AND head.purpose = credential.purpose AND head.current_generation = credential.generation
                 WHERE credential.binding_id = ?4 AND credential.purpose = ?9
                   AND credential.generation = ?10 AND credential.validation_state = 'valid'
                   AND credential.secret_version_ref = ?16 AND credential.credential_fingerprint = ?17))
               AND (?13 = 1 OR EXISTS (SELECT 1 FROM binding_credential_revisions credential
                 JOIN binding_credential_heads head ON head.binding_id = credential.binding_id
                   AND head.purpose = credential.purpose AND head.current_generation = credential.generation
                 WHERE credential.binding_id = ?4 AND credential.purpose = ?11
                   AND credential.generation = ?12 AND credential.validation_state = 'valid'
                   AND credential.secret_version_ref = ?18 AND credential.credential_fingerprint = ?19))",
            values,
        ).expecting(1))
    }

    /// Checks whether exact cache content has an authenticated committed direct source.
    ///
    /// # Errors
    /// Returns an error on persistence failure.
    pub async fn direct_cache_content_ready(
        &self,
        cache_id: i64,
        path: &str,
        sha256: &str,
        byte_size: i64,
    ) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM direct_upload_sessions session
             JOIN cache_write_tickets ticket ON ticket.ticket_id = session.cache_ticket_id
             WHERE session.cache_id = ?1 AND session.object_path = ?2
               AND session.source_sha256 = ?3 AND session.declared_size = ?4
               AND session.state = 'committed' AND ticket.state = 'completed'
               AND NOT EXISTS (SELECT 1 FROM cache_write_tickets newer
                 WHERE newer.cache_id = ?1 AND newer.object_key = ?2 AND newer.ticket_id <> ticket.ticket_id
                   AND (newer.active_cache_slot = 1 OR (newer.state = 'completed' AND newer.finished_at >= ticket.finished_at
                     AND (newer.intended_object_hash IS NULL OR newer.intended_object_hash <> ?3))))
               AND NOT EXISTS (SELECT 1 FROM object_deletion_jobs job
                 JOIN surface_objects object ON object.id = job.surface_object_id
                 WHERE job.cache_id = ?1 AND job.active_slot = 1 AND object.object_key = ?2)
               AND EXISTS (SELECT 1 FROM direct_upload_completion_receipts receipt
                 WHERE receipt.session_id = session.session_id)",
                &vals![cache_id, path, sha256, byte_size],
            )
            .await?
            .is_some())
    }
}

impl Database {
    /// Builds an atomic cache NAR dependency and selected signing-key fence.
    ///
    /// # Errors
    /// Returns an error for malformed size or key generation.
    pub fn direct_cache_metadata_fence(
        cache_id: i64,
        path: &str,
        sha256: &str,
        byte_size: i64,
        signing: Option<&super::SigningKeyRecord>,
    ) -> Result<CheckedStatement> {
        anyhow::ensure!(
            cache_id > 0 && byte_size >= 0,
            "invalid direct cache dependency"
        );
        Ok(Statement::new(
            "UPDATE binary_caches SET resource_version = resource_version
             WHERE id = ?1 AND deleted_at IS NULL
               AND (EXISTS (SELECT 1 FROM direct_upload_sessions session
                 JOIN cache_write_tickets ticket ON ticket.ticket_id = session.cache_ticket_id
                 JOIN direct_upload_completion_receipts receipt ON receipt.session_id = session.session_id
                 WHERE session.cache_id = ?1 AND session.object_path = ?2
                   AND session.source_sha256 = ?3 AND session.declared_size = ?4
                   AND session.state = 'committed' AND ticket.state = 'completed'
                   AND NOT EXISTS (SELECT 1 FROM cache_write_tickets newer
                     WHERE newer.cache_id = ?1 AND newer.object_key = ?2 AND newer.ticket_id <> ticket.ticket_id
                       AND (newer.active_cache_slot = 1 OR (newer.state = 'completed' AND newer.finished_at >= ticket.finished_at
                         AND (newer.intended_object_hash IS NULL OR newer.intended_object_hash <> ?3)))))
                 OR EXISTS (SELECT 1 FROM surface_objects object
                   JOIN object_placements presence ON presence.surface_object_id = object.id
                   WHERE object.cache_id = ?1 AND object.object_key = ?2 AND object.lifecycle_state = 'active'
                     AND object.content_hash = ?3 AND object.size = ?4
                     AND presence.state = 'present' AND presence.observed_hash = ?3 AND presence.observed_size = ?4
                     AND presence.catalog_object_resource_version = object.resource_version
                     AND NOT EXISTS (SELECT 1 FROM cache_write_tickets active
                       WHERE active.cache_id = ?1 AND active.object_key = ?2 AND active.active_cache_slot = 1)))
               AND NOT EXISTS (SELECT 1 FROM object_deletion_jobs job
                 JOIN surface_objects object ON object.id = job.surface_object_id
                 WHERE job.cache_id = ?1 AND job.active_slot = 1 AND object.object_key = ?2)
               AND ((CAST(?5 AS VARCHAR) IS NULL AND NOT EXISTS (SELECT 1 FROM signing_key_usages usage
                 WHERE usage.consumer_stable_id = binary_caches.stable_id AND usage.purpose = 'narinfo' AND usage.state = 'active'))
                 OR EXISTS (SELECT 1 FROM signing_key_usages usage
                   JOIN signing_key_generations generation ON generation.signing_key_id = usage.signing_key_id
                     AND generation.generation = usage.signing_key_generation
                   WHERE usage.consumer_stable_id = binary_caches.stable_id AND usage.purpose = 'narinfo'
                     AND usage.state = 'active' AND usage.signing_key_id = ?5
                     AND usage.signing_key_generation = ?6 AND generation.public_key_fingerprint = ?7
                     AND generation.state = 'active' AND generation.retired_at IS NULL))",
            vals![cache_id, path, sha256, byte_size, signing.map(|key| key.stable_id.as_str()),
                signing.map(|key| key.generation), signing.map(|key| key.public_key_fingerprint.as_str())],
        ).expecting(1))
    }

    /// Builds a publication phase, immutable dependency and pointer-watermark fence.
    ///
    /// # Errors
    /// Returns an error for malformed publication identity.
    pub fn direct_publication_phase_fence(
        publication: &str,
        pointer: bool,
    ) -> Result<CheckedStatement> {
        anyhow::ensure!(
            !publication.is_empty(),
            "direct publication identity absent"
        );
        Ok(Statement::new(
            format!("UPDATE registry_publications SET state = state
             WHERE publication_id = ?1
               AND ((?2 = 0 AND state = 'preparing') OR (?2 = 1 AND state = 'writing_pointers'
                 AND {barrier}
                 AND NOT EXISTS (SELECT 1 FROM registry_publication_placements required
                   WHERE required.publication_id = ?1 AND required.required = 1
                     AND NOT EXISTS (SELECT 1 FROM registry_placement_publication_watermarks watermark
                       WHERE watermark.placement_id = required.placement_id
                         AND watermark.pending_publication_id = ?1 AND watermark.mutable_publication_id IS NULL))))", barrier = super::mirror_publication::IMMUTABLE_BARRIER),
            vals![publication, i64::from(pointer)],
        ).expecting(1))
    }

    /// Builds an atomic fence for the exact live credential, account and IAM grant.
    ///
    /// The ordinary RPC permission check precedes this builder. SQL repeats the
    /// exact credential provenance and live ancestor membership at the commit
    /// boundary, so revocation between remote guard readback and commit rolls
    /// back every target accounting statement.
    ///
    /// # Errors
    /// Returns an error for malformed claims, missing current credentials or unsupported permission.
    pub(crate) async fn direct_iam_fence(
        &self,
        claims: &crate::auth::jwt::Claims,
        scope: &str,
        permission: crate::domain::Permission,
        now: i64,
    ) -> Result<CheckedStatement> {
        use crate::domain::{iam::role_grants, Role};

        let incarnation = claims
            .owner_incarnation
            .as_ref()
            .context("direct owner incarnation absent")?;
        if !claims.perms.iter().any(|item| item == permission.as_str()) || claims.exp <= now {
            anyhow::bail!("direct credential lacks current requested permission");
        }
        let roles = [
            Role::Owner,
            Role::Admin,
            Role::Maintainer,
            Role::Developer,
            Role::Viewer,
        ]
        .into_iter()
        .filter(|role| role_grants(*role).contains(&permission))
        .map(|role| role.as_str())
        .collect::<Vec<_>>();
        let role_sql = roles
            .iter()
            .map(|role| format!("'{role}'"))
            .collect::<Vec<_>>()
            .join(", ");
        let raw_permissions = if claims.browser_session_id_hash.is_none() {
            Some(
                self.backend
                    .query_opt(
                        "SELECT permissions FROM tokens WHERE id = ?1",
                        &vals![claims.sub],
                    )
                    .await?
                    .context("direct current token absent")?
                    .get::<String>(0)?,
            )
        } else {
            None
        };
        if let Some(raw) = &raw_permissions {
            let current = super::parse_permission_names(raw);
            if !current.contains(&permission)
                || claims
                    .perms
                    .iter()
                    .any(|claimed| !current.iter().any(|granted| granted.as_str() == claimed))
            {
                anyhow::bail!("direct current token permissions differ");
            }
        }
        let sql = format!(
            "UPDATE authorization_scopes SET retired_at = retired_at
             WHERE scope_key = ?1 AND retired_at IS NULL
               AND (org_id IS NULL OR EXISTS (SELECT 1 FROM orgs org
                 WHERE org.id = authorization_scopes.org_id AND org.deleted_at IS NULL))
               AND ?7 > ?6
               AND ((?2 = 'user' AND EXISTS (SELECT 1 FROM users owner
                 WHERE owner.id = ?3 AND owner.principal_incarnation = ?4 AND owner.deleted_at IS NULL))
                 OR (?2 = 'service_account' AND EXISTS (SELECT 1 FROM service_accounts owner
                   JOIN orgs org ON org.id = owner.org_id
                   WHERE owner.id = ?3 AND owner.principal_incarnation = ?4 AND org.deleted_at IS NULL)))
               AND EXISTS (SELECT 1 FROM authorization_scope_ancestors ancestry
                 WHERE ancestry.descendant_scope_key = ?1 AND ancestry.ancestor_scope_key = ?8)
               AND EXISTS (SELECT 1 FROM memberships membership
                 JOIN authorization_scope_ancestors ancestry ON ancestry.ancestor_scope_key = membership.scope_key
                   AND ancestry.descendant_scope_key = ?1
                 JOIN authorization_scopes granted ON granted.scope_key = membership.scope_key
                 LEFT JOIN orgs org ON org.id = granted.org_id
                 WHERE membership.principal_kind = ?2 AND membership.principal_id = ?3
                   AND membership.role IN ({role_sql}) AND granted.retired_at IS NULL
                   AND (granted.org_id IS NULL OR org.deleted_at IS NULL))
               AND ((CAST(?9 AS VARCHAR) IS NULL AND EXISTS (SELECT 1 FROM tokens token
                   JOIN authorization_scopes token_scope ON token_scope.scope_key = token.scope_key
                   LEFT JOIN orgs token_org ON token_org.id = token_scope.org_id
                   WHERE token.id = ?5 AND token.owner_kind = ?2 AND token.owner_id = ?3
                     AND token.owner_incarnation = ?4 AND token.scope_key = ?8 AND token.permissions = ?10
                     AND token.revoked_at IS NULL AND (token.expires_at IS NULL OR token.expires_at > ?6)
                     AND (token.rotated_at IS NULL OR token.rotated_at > ?11)
                     AND token_scope.retired_at IS NULL
                     AND (token_scope.org_id IS NULL OR token_org.deleted_at IS NULL)))
                 OR (?2 = 'user' AND ?8 = 'instance' AND EXISTS (SELECT 1 FROM sessions session
                   WHERE session.id_hash = ?9 AND session.user_id = ?3 AND session.owner_incarnation = ?4
                     AND session.expires_at > ?6 AND session.last_seen_at >= ?12 AND session.created_at >= ?13)))"
        );
        Ok(Statement::new(
            sql,
            vals![
                scope,
                claims.owner_kind,
                claims.owner_id,
                incarnation,
                claims.sub,
                now,
                claims.exp,
                claims.scope,
                claims.browser_session_id_hash,
                raw_permissions,
                now.saturating_sub(super::ROTATION_GRACE_SECS),
                now.saturating_sub(crate::auth::session::IDLE_TIMEOUT_SECS),
                now.saturating_sub(crate::auth::session::ABSOLUTE_LIFETIME_SECS)
            ],
        )
        .expecting(1))
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
