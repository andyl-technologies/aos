//! Reviewed edits to committed registry metadata.
//!
//! Plans retain an exact parent commit and replacement `registry.toml`. Apply
//! writes a draft signed by the Hub's draft key; a maintainer promotes it with
//! `apr change merge`. Operational policy remains in the registry settings API.

use aos_registry_surface::manifest::RegistryRootConfig;
use aos_registry_surface::support::SupportPolicy;
use serde::{Deserialize, Serialize};

use super::{
    pb, Claims, Oid, Permission, RegistryRecord, RpcError, RpcService, Sha256, SurfaceTarget,
};
use sha2::Digest;

#[cfg(test)]
#[path = "registry_metadata_tests.rs"]
mod tests;

const PLAN_KIND: &str = "update_registry_metadata";
const EDITABLE_FIELDS: &[&str] = &[
    "name",
    "description",
    "readme",
    "default_release",
    "support_toml",
];
const MAX_METADATA_BYTES: usize = 64 * 1024;

/// Retains the exact tree edit reviewed by the caller, independent of later reads.
#[derive(Serialize, Deserialize)]
struct MetadataPlan {
    registry_id: i64,
    slug: String,
    base_commit: String,
    contents: String,
}

impl RpcService {
    /// Returns editable metadata from the registry's verified indexed commit.
    ///
    /// # Errors
    ///
    /// Returns an authorization, missing-index, malformed-metadata, or storage error.
    pub async fn get_registry_metadata(
        &self,
        auth: Option<&str>,
        req: pb::GetRegistryRequest,
    ) -> Result<pb::RegistryMetadataResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.slug).await?;
        self.require_read(auth, &registry).await?;
        let base = self.head_commit(&registry).await?;
        let contents = self.registry_metadata_contents(&registry, base).await?;

        Ok(pb::RegistryMetadataResponse {
            metadata: Some(metadata_from_toml(&contents)?),
            resource_version: base.to_hex(),
        })
    }

    /// Plans an immutable metadata draft against an exact indexed commit.
    ///
    /// # Errors
    ///
    /// Returns an authorization, stale-version, validation, storage, or plan error.
    pub async fn plan_update_registry_metadata(
        &self,
        auth: Option<&str>,
        req: pb::PlanUpdateRegistryMetadataRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.slug).await?;
        let claims = self.authorize_metadata_edit(auth, &registry).await?;
        let base = self.head_commit(&registry).await?;
        require_base(&req.expected_resource_version, base)?;

        let existing = self.registry_metadata_contents(&registry, base).await?;
        let desired = req
            .desired
            .as_ref()
            .ok_or_else(|| RpcError::invalid("desired metadata is required"))?;
        let contents = edit_metadata(&existing, desired, &req.update_mask)?;
        let diff = crate::git::unified_diff("registry.toml", &existing, &contents);
        let input = MetadataPlan {
            registry_id: registry.id,
            slug: registry.slug.clone(),
            base_commit: base.to_hex(),
            contents,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));

        self.create_control_plan(
            &claims,
            PLAN_KIND,
            self.registry_scope(&registry).await?.as_str(),
            &input,
            &req.idempotency_key,
            vec![format!("Create a registry metadata draft:\n{diff}")],
            vec!["The draft becomes live only after apr change merge and re-indexing.".to_string()],
            Some(confirmation_hash),
        )
        .await
    }

    /// Creates the reviewed metadata draft without changing published registry state.
    ///
    /// # Errors
    ///
    /// Returns an authorization, stale-plan, signing, storage, or database error.
    pub async fn update_registry_metadata(
        &self,
        auth: Option<&str>,
        req: pb::ApplyRegistryMutationRequest,
    ) -> Result<pb::RegistryMetadataChangeResponse, RpcError> {
        self.require_control_plan_permission(auth, &req.plan_id, Permission::RegistryConfigure)
            .await?;
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                PLAN_KIND,
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }

        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            PLAN_KIND,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, MetadataPlan) = self
            .load_control_plan(auth, &req.plan_id, PLAN_KIND, Some(&req.confirmation_hash))
            .await?;
        let registry = self.registry_or_not_found(&input.slug).await?;
        let claims = self.authorize_metadata_edit(auth, &registry).await?;
        if registry.id != input.registry_id {
            return Err(RpcError::FailedPrecondition(
                "registry identity changed after planning".to_string(),
            ));
        }

        // A retry after the draft was recorded returns that same change. It must
        // not create a second draft or require the indexed branch to stand still.
        let existing = self
            .db
            .changeset(&plan.plan_id)
            .await
            .map_err(RpcError::internal)?;
        if let Some(existing) = existing {
            if existing.scope != registry.scope_key || existing.git_ref.is_none() {
                return Err(RpcError::FailedPrecondition(
                    "plan id collides with another changeset".to_string(),
                ));
            }
        } else {
            let base = self.head_commit(&registry).await?;
            require_base(&input.base_commit, base)?;
            let sealer = self.sealer.as_ref().ok_or_else(|| {
                RpcError::FailedPrecondition(
                    "Hub draft signing is unavailable; configure HUB_SEAL_KEY".to_string(),
                )
            })?;
            let fetch = crate::placement_read::TopologySurfaceFetch::for_verified_git_objects(
                std::sync::Arc::clone(&self.db),
                std::sync::Arc::clone(&self.surface),
                SurfaceTarget::Registry(registry.id),
            );
            let placement = self
                .effective_surface_writer(SurfaceTarget::Registry(registry.id))
                .await?;
            let writer = self
                .surface_write
                .placement_writer(&placement)
                .await
                .map_err(RpcError::internal)?;

            crate::gitwrite::propose_config_change_at_base(
                &self.db,
                sealer.as_ref(),
                &fetch,
                writer.as_ref(),
                &registry,
                crate::config::ChangeId(plan.plan_id.clone()),
                base,
                "registry.toml",
                &input.contents,
                &claims.owner_kind,
                Some(claims.owner_id),
                &claims.sub,
                plan.created_at,
                crate::gitwrite::ProposeMeta {
                    title: Some("Update registry metadata".to_string()),
                    body: None,
                },
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        }

        let response = pb::RegistryMetadataChangeResponse {
            change_id: plan.plan_id.clone(),
            merge_command: crate::git::merge_command(
                &format!(
                    "{}/{}",
                    self.external_url.trim_end_matches('/'),
                    registry.slug
                ),
                &crate::config::ChangeId(plan.plan_id.clone()),
            ),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    async fn authorize_metadata_edit(
        &self,
        auth: Option<&str>,
        registry: &RegistryRecord,
    ) -> Result<Claims, RpcError> {
        let claims = self.require_claims(auth)?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &self.registry_scope(registry).await?,
        )
        .await?;
        Ok(claims)
    }

    async fn registry_metadata_contents(
        &self,
        registry: &RegistryRecord,
        base: Oid,
    ) -> Result<String, RpcError> {
        let fetch = crate::placement_read::TopologySurfaceFetch::for_verified_git_objects(
            std::sync::Arc::clone(&self.db),
            std::sync::Arc::clone(&self.surface),
            SurfaceTarget::Registry(registry.id),
        );
        crate::git::load_committed_file(&fetch, base, "registry.toml")
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::FailedPrecondition("registry.toml is missing".to_string()))
    }
}

fn require_base(expected: &str, actual: Oid) -> Result<(), RpcError> {
    if expected != actual.to_hex() {
        return Err(RpcError::FailedPrecondition(
            "registry metadata changed; reload before reviewing another draft".to_string(),
        ));
    }
    Ok(())
}

fn parse_metadata(contents: &str) -> Result<RegistryRootConfig, RpcError> {
    toml::from_str(contents)
        .map_err(|error| RpcError::invalid(format!("invalid registry metadata: {error}")))
}

fn metadata_from_toml(contents: &str) -> Result<pb::RegistryMetadata, RpcError> {
    let root = parse_metadata(contents)?;
    Ok(pb::RegistryMetadata {
        name: root.registry.name,
        description: root.registry.description.unwrap_or_default(),
        readme: root.registry.readme.unwrap_or_default(),
        default_release: root.registry.default_release.unwrap_or_default(),
        support_toml: root
            .support
            .as_ref()
            .map(toml::to_string_pretty)
            .transpose()
            .map_err(RpcError::internal)?
            .unwrap_or_default(),
    })
}

/// Updates only selected metadata; preserves all unrelated producer configuration.
fn edit_metadata(
    existing: &str,
    desired: &pb::RegistryMetadata,
    mask: &[String],
) -> Result<String, RpcError> {
    let unique = mask
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if unique.is_empty()
        || unique.len() != mask.len()
        || unique.iter().any(|field| !EDITABLE_FIELDS.contains(field))
    {
        return Err(RpcError::invalid(
            "updateMask must contain unique editable metadata fields",
        ));
    }
    let mut root: toml_edit::DocumentMut = existing
        .parse()
        .map_err(|error| RpcError::invalid(format!("invalid registry.toml: {error}")))?;
    let table = root.as_table_mut();
    let registry = table
        .get_mut("registry")
        .and_then(toml_edit::Item::as_table_like_mut)
        .ok_or_else(|| RpcError::invalid("registry table is missing"))?;

    for (field, value) in [
        ("name", &desired.name),
        ("description", &desired.description),
        ("readme", &desired.readme),
        ("default_release", &desired.default_release),
    ] {
        if !unique.contains(field) {
            continue;
        }
        if value.len() > MAX_METADATA_BYTES {
            return Err(RpcError::invalid(format!("{field} exceeds 64 KiB")));
        }
        if field == "name"
            && (value.trim().is_empty() || value.len() > 256 || value.contains(['\n', '\r']))
        {
            return Err(RpcError::invalid(
                "name must be a non-empty single line of at most 256 bytes",
            ));
        }
        if field != "name" && value.trim().is_empty() {
            registry.remove(field);
        } else {
            let mut replacement = toml_edit::Value::from(value.clone());
            if let Some(current) = registry.get(field).and_then(toml_edit::Item::as_value) {
                *replacement.decor_mut() = current.decor().clone();
            }
            registry.insert(field, toml_edit::Item::Value(replacement));
        }
    }

    if unique.contains("support_toml") {
        if desired.support_toml.len() > MAX_METADATA_BYTES {
            return Err(RpcError::invalid("support policy exceeds 64 KiB"));
        }
        if desired.support_toml.trim().is_empty() {
            table.remove("support");
        } else {
            let support: SupportPolicy = toml::from_str(&desired.support_toml)
                .map_err(|error| RpcError::invalid(format!("invalid support policy: {error}")))?;
            support
                .validate()
                .map_err(|error| RpcError::invalid(error.to_string()))?;
            let policy = desired
                .support_toml
                .parse::<toml_edit::DocumentMut>()
                .map_err(|error| RpcError::invalid(format!("invalid support policy: {error}")))?;
            table.insert("support", toml_edit::Item::Table(policy.into_table()));
        }
    }

    let contents = root.to_string();
    parse_metadata(&contents)?;
    if toml::from_str::<toml::Value>(&contents).map_err(RpcError::internal)?
        == toml::from_str::<toml::Value>(existing).map_err(RpcError::internal)?
    {
        return Err(RpcError::invalid("metadata has no changes"));
    }
    Ok(contents)
}
