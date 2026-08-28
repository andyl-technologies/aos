//! OCI container administration and inspection control plane.
//!
//! The Distribution endpoints remain the byte-transfer plane. These methods
//! expose registry-bound read models and reviewed metadata mutations through
//! the shared native/Worker [`RpcService`](super::RpcService).

mod mutation;
mod read;

use aos_oci_types::{MediaType, RepositoryName, Sha256Digest, Tag};
use aos_proto_types as pb;

use super::{Permission, RpcError, RpcService};
use crate::db::{
    OciAdminLayerRecord, OciAdminManifestRecord, OciAdminPlatformRecord, OciAdminProvenanceRecord,
    OciAdminPublicationRecord, OciAdminReferrerRecord, OciAdminRepositoryRecord,
    OciAdminTagHistoryRecord, OciAdminTagRecord, OciRetentionPolicyRecord, RegistryRecord,
    SurfaceTarget, OCI_ADMIN_MAX_PAGE_SIZE, OCI_RETENTION_DEFAULT_DELETED_TAG_HISTORY_SECONDS,
    OCI_RETENTION_DEFAULT_RECENT_MANUAL_TAG_REVISIONS, OCI_RETENTION_DEFAULT_RETAIN_REFERRERS,
    OCI_RETENTION_DEFAULT_UNTAGGED_GRACE_SECONDS,
};

const DEFAULT_CONTAINER_PAGE_SIZE: u32 = 50;

impl RpcService {
    async fn container_registry_for_read(
        &self,
        auth: Option<&str>,
        identifier: &str,
    ) -> Result<RegistryRecord, RpcError> {
        let registry = self.registry_or_not_found(identifier).await?;
        self.require_read(auth, &registry).await?;
        Ok(registry)
    }

    async fn container_registry_for_mutation(
        &self,
        auth: Option<&str>,
        identifier: &str,
        permission: Permission,
    ) -> Result<(crate::auth::jwt::Claims, RegistryRecord), RpcError> {
        let claims = self.require_claims(auth)?;
        let registry = self.registry_or_not_found(identifier).await?;
        let scope = self.registry_scope(&registry).await?;
        self.require_permission(&claims, permission, &scope).await?;
        Ok((claims, registry))
    }

    /// Authorizes registry-wide publication inspection for a publisher.
    pub(super) async fn container_registry_for_publication_read(
        &self,
        auth: Option<&str>,
        identifier: &str,
    ) -> Result<RegistryRecord, RpcError> {
        let (_, registry) = self
            .container_registry_for_mutation(auth, identifier, Permission::Publish)
            .await?;
        Ok(registry)
    }

    async fn container_distribution_authority(
        &self,
        registry_id: i64,
    ) -> Result<Option<String>, RpcError> {
        let routes = self
            .db
            .list_routes(SurfaceTarget::Registry(registry_id))
            .await
            .map_err(RpcError::internal)?;
        for route in routes {
            if !route.enabled {
                continue;
            }
            let (Some(generation), Some(digest)) = (
                route.configuration_generation,
                route.configuration_digest.as_deref(),
            ) else {
                continue;
            };
            let Some(snapshot) = self
                .db
                .route_snapshot(&route.id)
                .await
                .map_err(RpcError::internal)?
            else {
                continue;
            };
            if !snapshot.spec.enabled || !snapshot.spec.serves_oci {
                continue;
            }
            if !self
                .db
                .hub_route_state_ready(&route.id, generation, digest)
                .await
                .map_err(RpcError::internal)?
            {
                continue;
            }

            return distribution_authority(&snapshot.canonical_url).map(Some);
        }
        Ok(None)
    }
}

fn distribution_authority(canonical_url: &str) -> Result<String, RpcError> {
    let url = url::Url::parse(canonical_url).map_err(RpcError::internal)?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(RpcError::internal(anyhow::anyhow!(
            "ready OCI route has a non-root distribution URL"
        )));
    }
    let host = match url.host() {
        Some(url::Host::Domain(host)) => host.to_string(),
        Some(url::Host::Ipv4(host)) => host.to_string(),
        Some(url::Host::Ipv6(host)) => format!("[{host}]"),
        None => {
            return Err(RpcError::internal(anyhow::anyhow!(
                "ready OCI route has no URL authority"
            )))
        }
    };
    Ok(url
        .port()
        .map_or(host.clone(), |port| format!("{host}:{port}")))
}

fn page_size(value: u32) -> Result<u32, RpcError> {
    let value = if value == 0 {
        DEFAULT_CONTAINER_PAGE_SIZE
    } else {
        value
    };
    if value > OCI_ADMIN_MAX_PAGE_SIZE {
        return Err(RpcError::invalid(format!(
            "pageSize must not exceed {OCI_ADMIN_MAX_PAGE_SIZE}"
        )));
    }
    Ok(value)
}

fn repository_name(value: &str) -> Result<RepositoryName, RpcError> {
    RepositoryName::parse(value).map_err(|error| RpcError::invalid(error.to_string()))
}

fn tag(value: &str) -> Result<Tag, RpcError> {
    Tag::parse(value).map_err(|error| RpcError::invalid(error.to_string()))
}

fn digest(value: &str) -> Result<Sha256Digest, RpcError> {
    Sha256Digest::parse(value).map_err(|error| RpcError::invalid(error.to_string()))
}

fn media_type(value: &str) -> Result<MediaType, RpcError> {
    MediaType::parse(value).map_err(|error| RpcError::invalid(error.to_string()))
}

fn optional_filter(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn resource_version(value: &str, required: bool) -> Result<Option<i64>, RpcError> {
    if value.is_empty() && !required {
        return Ok(None);
    }
    let parsed = value
        .parse::<i64>()
        .map_err(|_| RpcError::invalid("resource version must be a positive integer"))?;
    if parsed < 1 {
        return Err(RpcError::invalid(
            "resource version must be a positive integer",
        ));
    }
    Ok(Some(parsed))
}

fn repository_message(
    registry: &str,
    record: &OciAdminRepositoryRecord,
    distribution_authority: Option<&str>,
) -> pb::ContainerRepository {
    pb::ContainerRepository {
        registry: registry.to_string(),
        repository: record.name.to_string(),
        description: record.description.clone(),
        visibility: record.inherited_visibility.clone(),
        lifecycle_state: record.lifecycle_state.clone(),
        tag_count: record.tag_count,
        manifest_count: record.manifest_count,
        compressed_byte_size: record.compressed_byte_size,
        unique_byte_size: record.unique_byte_size,
        resource_version: record.resource_version.to_string(),
        created_at: record.created_at,
        updated_at: record.updated_at,
        distribution_reference: distribution_authority
            .map(|authority| format!("{authority}/{}", record.name))
            .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::distribution_authority;

    #[test]
    fn distribution_authority_is_a_copyable_registry_reference_authority() {
        assert_eq!(
            distribution_authority("https://containers.example/").unwrap(),
            "containers.example"
        );
        assert_eq!(
            distribution_authority("http://127.0.0.1:8420").unwrap(),
            "127.0.0.1:8420"
        );
        assert_eq!(
            distribution_authority("https://[2001:db8::1]:8443/").unwrap(),
            "[2001:db8::1]:8443"
        );
        assert!(distribution_authority("https://containers.example/control").is_err());
    }
}

fn tag_message(
    registry: &str,
    repository: &RepositoryName,
    record: &OciAdminTagRecord,
) -> pb::ContainerTag {
    pb::ContainerTag {
        registry: registry.to_string(),
        repository: repository.to_string(),
        tag: record.name.to_string(),
        digest: record.digest.to_string(),
        media_type: record.media_type.as_str().to_string(),
        ownership_kind: record.ownership_kind.clone(),
        release: record.release.clone().unwrap_or_default(),
        channel: record.channel.clone().unwrap_or_default(),
        resource_version: record.resource_version.to_string(),
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn history_message(
    registry: &str,
    repository: &RepositoryName,
    record: &OciAdminTagHistoryRecord,
) -> pb::ContainerTagHistoryEntry {
    pb::ContainerTagHistoryEntry {
        registry: registry.to_string(),
        repository: repository.to_string(),
        tag: record.name.to_string(),
        operation: match (&record.prior_digest, &record.next_digest) {
            (None, Some(_)) => "created",
            (Some(_), Some(_)) => "updated",
            (Some(_), None) => "deleted",
            (None, None) => "unknown",
        }
        .to_string(),
        previous_digest: record
            .prior_digest
            .map(|value| value.to_string())
            .unwrap_or_default(),
        digest: record
            .next_digest
            .map(|value| value.to_string())
            .unwrap_or_default(),
        ownership_kind: record.source_kind.clone(),
        actor: record.actor_id.clone(),
        resource_version: record.resource_version.to_string(),
        created_at: record.changed_at,
    }
}

fn manifest_message(
    registry: &str,
    repository: &RepositoryName,
    record: &OciAdminManifestRecord,
) -> Result<pb::ContainerManifest, RpcError> {
    Ok(pb::ContainerManifest {
        registry: registry.to_string(),
        repository: repository.to_string(),
        digest: record.digest.to_string(),
        media_type: record.media_type.as_str().to_string(),
        byte_size: record.byte_size,
        artifact_type: record
            .artifact_type
            .map(MediaType::as_str)
            .unwrap_or_default()
            .to_string(),
        subject_digest: record
            .subject_digest
            .map(|value| value.to_string())
            .unwrap_or_default(),
        config_digest: record
            .config_digest
            .map(|value| value.to_string())
            .unwrap_or_default(),
        layer_count: record.layer_count,
        child_count: record.child_count,
        annotations_json: aos_oci_types::to_canonical_json(&record.annotations)
            .map_err(RpcError::internal)
            .and_then(|bytes| String::from_utf8(bytes).map_err(RpcError::internal))?,
        created_at: record.created_at,
    })
}

fn platform_message(
    registry: &str,
    repository: &RepositoryName,
    record: &OciAdminPlatformRecord,
) -> pb::ContainerPlatform {
    pb::ContainerPlatform {
        registry: registry.to_string(),
        repository: repository.to_string(),
        root_digest: record.root_digest.to_string(),
        manifest_digest: record.manifest_digest.to_string(),
        config_digest: record.config_digest.to_string(),
        operating_system: record.platform.os.clone(),
        architecture: record.platform.architecture.clone(),
        variant: record.platform.variant.clone().unwrap_or_default(),
        aos_system: record.aos_system.clone(),
        compressed_byte_size: record.compressed_byte_size,
        unpacked_byte_size: record.unpacked_byte_size,
        layer_count: record.layer_count,
        config_json: record.config_json.clone(),
        os_version: record.platform.os_version.clone().unwrap_or_default(),
        os_features: record.platform.os_features.clone(),
    }
}

fn platform_selector(
    operating_system: String,
    architecture: String,
    variant: String,
    os_version: String,
    os_features: Vec<String>,
) -> Result<aos_oci_types::Platform, RpcError> {
    let platform = aos_oci_types::Platform {
        os: operating_system,
        architecture,
        variant: optional_filter(&variant).map(str::to_string),
        os_version: optional_filter(&os_version).map(str::to_string),
        os_features,
        features: Vec::new(),
    };
    platform
        .validate()
        .map_err(|error| RpcError::invalid(error.to_string()))?;
    Ok(platform)
}

fn layer_message(
    registry: &str,
    repository: &RepositoryName,
    record: &OciAdminLayerRecord,
) -> pb::ContainerLayer {
    pb::ContainerLayer {
        registry: registry.to_string(),
        repository: repository.to_string(),
        manifest_digest: record.manifest_digest.to_string(),
        ordinal: record.ordinal,
        digest: record.descriptor.digest.to_string(),
        media_type: record.descriptor.media_type.as_str().to_string(),
        compressed_byte_size: record.descriptor.size,
        unpacked_byte_size: record.unpacked_byte_size,
        shared_repository_count: record.shared_repository_count,
        diff_id: record.diff_id.to_string(),
        closure_group: record.closure_group.clone(),
        root_digest: record.root_digest.to_string(),
    }
}

fn referrer_message(
    registry: &str,
    repository: &RepositoryName,
    record: &OciAdminReferrerRecord,
) -> Result<pb::ContainerReferrer, RpcError> {
    Ok(pb::ContainerReferrer {
        registry: registry.to_string(),
        repository: repository.to_string(),
        subject_digest: record.subject_digest.to_string(),
        digest: record.descriptor.digest.to_string(),
        media_type: record.descriptor.media_type.as_str().to_string(),
        byte_size: record.descriptor.size,
        artifact_type: record
            .descriptor
            .artifact_type
            .map(MediaType::as_str)
            .unwrap_or_default()
            .to_string(),
        annotations_json: aos_oci_types::to_canonical_json(&record.descriptor.annotations)
            .map_err(RpcError::internal)
            .and_then(|bytes| String::from_utf8(bytes).map_err(RpcError::internal))?,
        verification: record.verification.clone(),
        created_at: record.created_at,
    })
}

pub(super) fn publication_message(
    registry: &str,
    record: &OciAdminPublicationRecord,
) -> pb::ContainerPublication {
    pb::ContainerPublication {
        publication_id: record.id.clone(),
        registry: registry.to_string(),
        repository: record.repository.to_string(),
        root_digest: record.root_digest.to_string(),
        catalog_digest: record.catalog_digest.to_string(),
        state: record.state.clone(),
        target_tag: record
            .target_tag
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default(),
        resource_version: record.resource_version.to_string(),
        expires_at: record.expires_at,
        created_at: record.created_at,
        committed_at: record.committed_at.unwrap_or_default(),
        confirmation_hash: record.confirmation_hash.to_string(),
        verified_release_root: (record.state == "ready")
            .then(|| record.root_digest.to_string())
            .unwrap_or_default(),
        topology_digest: record.topology_digest.to_string(),
        required_placement_count: i64::from(record.required_placement_count),
        source_kind: record.source_kind.clone(),
    }
}

fn provenance_message(
    registry: &str,
    record: &OciAdminProvenanceRecord,
) -> pb::ContainerProvenance {
    pb::ContainerProvenance {
        registry: registry.to_string(),
        repository: record.repository.to_string(),
        root_digest: record.root_digest.to_string(),
        package: record.package.clone(),
        release: record.release.clone(),
        channel: record.channel.clone().unwrap_or_default(),
        signed_release_root: record.signed_release_root.clone(),
        catalog_digest: record.catalog_digest.to_string(),
        verification: record.verification.clone(),
        closure_members: record
            .closure_members
            .iter()
            .map(|member| pb::ContainerClosureMember {
                store_path: member.store_path.clone(),
                nar_hash: member.nar_hash.clone(),
                nar_size: member.nar_size,
                layer_digest: member.layer_digest.to_string(),
                direct: member.direct,
            })
            .collect(),
        evidence: record
            .evidence
            .iter()
            .map(|evidence| pb::ContainerEvidence {
                kind: evidence.kind.clone(),
                digest: evidence.digest.to_string(),
                media_type: evidence.media_type.as_str().to_string(),
                verification: evidence.verification.clone(),
                referrer_digest: evidence.referrer_digest.to_string(),
            })
            .collect(),
        verified_at: record.verified_at,
    }
}

fn retention_message(
    registry: &str,
    record: &OciRetentionPolicyRecord,
) -> pb::ContainerRetentionPolicy {
    pb::ContainerRetentionPolicy {
        registry: registry.to_string(),
        untagged_grace_period_secs: record.untagged_grace_seconds,
        deleted_tag_history_period_secs: record.deleted_tag_history_seconds,
        recent_manual_tag_revisions: record.recent_manual_tag_revisions,
        retain_referrers: record.retain_referrers,
        resource_version: record.resource_version.to_string(),
        updated_at: record.updated_at,
    }
}

fn default_retention_message(registry: &str) -> pb::ContainerRetentionPolicy {
    pb::ContainerRetentionPolicy {
        registry: registry.to_string(),
        untagged_grace_period_secs: OCI_RETENTION_DEFAULT_UNTAGGED_GRACE_SECONDS,
        deleted_tag_history_period_secs: OCI_RETENTION_DEFAULT_DELETED_TAG_HISTORY_SECONDS,
        recent_manual_tag_revisions: OCI_RETENTION_DEFAULT_RECENT_MANUAL_TAG_REVISIONS,
        retain_referrers: OCI_RETENTION_DEFAULT_RETAIN_REFERRERS,
        resource_version: String::new(),
        updated_at: 0,
    }
}

fn container_gc_unavailable() -> RpcError {
    RpcError::Unavailable(
        "container garbage collection is unavailable until complete inventory and revalidation are enabled"
            .to_string(),
    )
}
