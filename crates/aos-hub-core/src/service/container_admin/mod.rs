//! OCI container administration and inspection control plane.
//!
//! The Distribution endpoints remain the byte-transfer plane. These methods
//! expose registry-bound read models and reviewed metadata mutations through
//! the shared native/Worker [`RpcService`](super::RpcService).

mod mutation;
mod read;

use aos_oci_types::{MediaType, RepositoryName, Sha256Digest, Tag};
use aos_proto_types as pb;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::{Permission, RpcError, RpcService};
use crate::db::{
    OciAdminLayerRecord, OciAdminManifestRecord, OciAdminPlatformRecord, OciAdminProvenanceRecord,
    OciAdminPublicationRecord, OciAdminReferrerRecord, OciAdminRepositoryRecord,
    OciAdminTagHistoryRecord, OciAdminTagRecord, OciGcBlockerRecord, OciGcCandidateRecord,
    OciGcGenerationRecord, OciGcPlacementActionRecord, OciRegistryPurgeFenceAction,
    OciRegistryPurgeFenceStatus, OciRetentionPolicyRecord, OciUntrackedInventoryCursor,
    OciUntrackedInventoryRecord, OciUntrackedRepairOutcome, OciUntrackedRepairPlanRecord,
    RegistryRecord, SurfaceTarget, OCI_ADMIN_MAX_PAGE_SIZE, OCI_GC_MAX_PAGE_SIZE,
    OCI_RETENTION_DEFAULT_DELETED_TAG_HISTORY_SECONDS,
    OCI_RETENTION_DEFAULT_RECENT_MANUAL_TAG_REVISIONS, OCI_RETENTION_DEFAULT_RETAIN_REFERRERS,
    OCI_RETENTION_DEFAULT_UNTAGGED_GRACE_SECONDS,
};

const DEFAULT_CONTAINER_PAGE_SIZE: u32 = 50;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UntrackedInventoryCursorWire {
    generation_id: String,
    object_key: String,
    captured_mutation_epoch: i64,
}

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

fn gc_page_size(value: u32) -> Result<u32, RpcError> {
    let value = if value == 0 {
        DEFAULT_CONTAINER_PAGE_SIZE
    } else {
        value
    };
    if value > OCI_GC_MAX_PAGE_SIZE {
        return Err(RpcError::invalid(format!(
            "pageSize must not exceed {OCI_GC_MAX_PAGE_SIZE}"
        )));
    }
    Ok(value)
}

fn decode_untracked_inventory_cursor(
    value: &str,
) -> Result<Option<OciUntrackedInventoryCursor>, RpcError> {
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 2_048 {
        return Err(RpcError::invalid("pageToken is invalid"));
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| RpcError::invalid("pageToken is invalid"))?;
    if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(RpcError::invalid("pageToken is invalid"));
    }
    let cursor: UntrackedInventoryCursorWire =
        serde_json::from_slice(&bytes).map_err(|_| RpcError::invalid("pageToken is invalid"))?;
    Ok(Some(OciUntrackedInventoryCursor {
        generation_id: cursor.generation_id,
        object_key: cursor.object_key,
        captured_mutation_epoch: cursor.captured_mutation_epoch,
    }))
}

fn encode_untracked_inventory_cursor(
    value: Option<&OciUntrackedInventoryCursor>,
) -> Result<String, RpcError> {
    value.map_or_else(
        || Ok(String::new()),
        |cursor| {
            let bytes = serde_json::to_vec(&UntrackedInventoryCursorWire {
                generation_id: cursor.generation_id.clone(),
                object_key: cursor.object_key.clone(),
                captured_mutation_epoch: cursor.captured_mutation_epoch,
            })
            .map_err(RpcError::internal)?;
            Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
        },
    )
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

fn mutation_epoch(value: &str) -> Result<i64, RpcError> {
    let parsed = value
        .parse::<i64>()
        .map_err(|_| RpcError::invalid("expectedResourceVersion must be a non-negative integer"))?;
    if parsed < 0 {
        return Err(RpcError::invalid(
            "expectedResourceVersion must be a non-negative integer",
        ));
    }
    Ok(parsed)
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
    use aos_oci_types::Sha256Digest;

    use super::{
        decode_untracked_inventory_cursor, distribution_authority,
        encode_untracked_inventory_cursor, gc_placement_action_message, gc_run_message,
        registry_purge_fence_message, untracked_inventory_message, untracked_repair_message,
    };
    use crate::db::{
        OciGcGenerationRecord, OciGcPlacementActionRecord, OciRegistryPurgeBlockers,
        OciRegistryPurgeFenceAction, OciRegistryPurgeFencePlanRecord, OciRegistryPurgeFenceRecord,
        OciRegistryPurgeFenceStatus, OciUntrackedInventoryCursor, OciUntrackedInventoryRecord,
        OciUntrackedRepairKind, OciUntrackedRepairOutcome, OciUntrackedRepairPlanRecord,
    };
    use crate::service::pb;

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

    #[test]
    fn gc_run_projection_preserves_exact_planned_and_finalized_counters() {
        let record = OciGcGenerationRecord {
            id: "gc-run".to_string(),
            registry_id: 1,
            actor_id: "actor".to_string(),
            state: "applying".to_string(),
            captured_mutation_epoch: 7,
            applied_mutation_epoch: Some(8),
            policy_resource_version: 3,
            policy_digest: Sha256Digest::digest(b"policy"),
            root_set_digest: Sha256Digest::digest(b"roots"),
            placement_inventory_digest: Sha256Digest::digest(b"inventory"),
            topology_digest: Sha256Digest::digest(b"topology"),
            plan_digest: Sha256Digest::digest(b"plan"),
            confirmation_hash: Sha256Digest::digest(b"confirmation"),
            inventory_object_count: 23,
            inventory_byte_size: 2_300,
            reachable_object_count: 17,
            planned_bytes: 1_100,
            planned_objects: 11,
            deleted_object_count: 4,
            deleted_byte_size: 400,
            placement_action_count: 15,
            expires_at: 100,
            created_at: 10,
            applied_at: Some(20),
            finished_at: None,
            last_error: None,
            resource_version: 9,
        };

        let message = gc_run_message("andyl/main", &record, &[]);
        assert_eq!(message.inventory_object_count, 23);
        assert_eq!(message.inventory_byte_size, 2_300);
        assert_eq!(message.reachable_object_count, 17);
        assert_eq!(message.candidate_object_count, 11);
        assert_eq!(message.reclaimable_byte_size, 1_100);
        assert_eq!(message.deleted_object_count, 4);
        assert_eq!(message.deleted_byte_size, 400);
    }

    #[test]
    fn gc_action_projection_exposes_the_complete_frozen_non_secret_identity() {
        let record = OciGcPlacementActionRecord {
            id: "gc-action".to_string(),
            generation_id: "gc-run".to_string(),
            registry_id: 1,
            digest: Sha256Digest::digest(b"object"),
            object_key: "oci/blobs/sha256/object".to_string(),
            expected_hash: Sha256Digest::digest(b"expected"),
            expected_size: 41,
            expected_strong_etag: Some("\"strong\"".to_string()),
            inventory_entry_present: true,
            inventory_generation_id: "inventory".to_string(),
            inventory_digest: Sha256Digest::digest(b"inventory"),
            inventory_observed_at: 11,
            placement_id: 2,
            placement_name: "primary".to_string(),
            placement_prefix: "registry".to_string(),
            placement_resource_version: 3,
            placement_write_spec_version: 4,
            placement_observation_version: 5,
            binding_id: 6,
            binding_resource_version: 7,
            binding_write_revision: 8,
            delete_credential_purpose: Some("delete".to_string()),
            delete_credential_generation: Some(9),
            delete_capability_fingerprint: "conditional-delete-v1".to_string(),
            delete_capability_resource_version: 10,
            state: "failed".to_string(),
            attempt_count: 8,
            max_attempts: 8,
            next_attempt_at: 12,
            last_error: Some("precondition failed".to_string()),
            confirmed_at: None,
            resource_version: 13,
        };

        let message = gc_placement_action_message(&record);
        assert_eq!(message.action_id, record.id);
        assert_eq!(message.run_id, record.generation_id);
        assert_eq!(message.digest, record.digest.to_string());
        assert_eq!(message.object_key, record.object_key);
        assert_eq!(message.expected_hash, record.expected_hash.to_string());
        assert_eq!(message.expected_byte_size, record.expected_size);
        assert_eq!(message.expected_strong_etag, "\"strong\"");
        assert!(message.inventory_entry_present);
        assert_eq!(
            message.inventory_generation_id,
            record.inventory_generation_id
        );
        assert_eq!(
            message.inventory_digest,
            record.inventory_digest.to_string()
        );
        assert_eq!(message.inventory_observed_at, record.inventory_observed_at);
        assert_eq!(message.placement_id, record.placement_id);
        assert_eq!(message.placement_name, record.placement_name);
        assert_eq!(message.placement_prefix, record.placement_prefix);
        assert_eq!(message.placement_resource_version, "3");
        assert_eq!(message.placement_write_spec_version, "4");
        assert_eq!(message.placement_observation_version, "5");
        assert_eq!(message.binding_id, record.binding_id);
        assert_eq!(message.binding_resource_version, "7");
        assert_eq!(message.binding_write_revision, "8");
        assert_eq!(message.delete_credential_purpose, "delete");
        assert_eq!(message.delete_credential_generation, "9");
        assert_eq!(
            message.delete_capability_fingerprint,
            record.delete_capability_fingerprint
        );
        assert_eq!(message.delete_capability_resource_version, "10");
        assert_eq!(message.resource_version, "13");
    }

    #[test]
    fn untracked_inventory_projection_and_cursor_preserve_exact_current_head_identity() {
        let record = OciUntrackedInventoryRecord {
            registry_id: 1,
            placement_id: 2,
            inventory_generation_id: "inventory-7".to_string(),
            inventory_digest: Sha256Digest::digest(b"inventory"),
            inventory_observed_at: 11,
            object_key: "oci/blobs/sha256/object".to_string(),
            object_digest: Sha256Digest::digest(b"object"),
            observed_hash: Sha256Digest::digest(b"observed"),
            byte_size: 41,
            strong_etag: "\"strong\"".to_string(),
            placement_resource_version: 3,
            placement_name: "primary".to_string(),
            placement_prefix: "registry".to_string(),
            placement_write_spec_version: 4,
            placement_observation_version: 5,
            binding_id: 6,
            binding_resource_version: 7,
            binding_write_revision: 8,
            delete_credential_purpose: Some("delete".to_string()),
            delete_credential_generation: Some(9),
            delete_capability_fingerprint: Some("conditional-delete-v1".to_string()),
            delete_capability_resource_version: Some(10),
        };

        let message = untracked_inventory_message("andyl/main", &record);
        assert_eq!(message.registry, "andyl/main");
        assert_eq!(
            message.inventory_generation_id,
            record.inventory_generation_id
        );
        assert_eq!(
            message.inventory_digest,
            record.inventory_digest.to_string()
        );
        assert_eq!(message.object_key, record.object_key);
        assert_eq!(message.object_digest, record.object_digest.to_string());
        assert_eq!(message.observed_hash, record.observed_hash.to_string());
        assert_eq!(message.byte_size, 41);
        assert_eq!(message.strong_etag, "\"strong\"");
        assert_eq!(message.placement_resource_version, "3");
        assert_eq!(message.binding_write_revision, "8");
        assert_eq!(message.delete_credential_generation, "9");
        assert_eq!(message.delete_capability_resource_version, "10");

        let cursor = OciUntrackedInventoryCursor {
            generation_id: "inventory-7".to_string(),
            object_key: "oci/blobs/sha256/object".to_string(),
            captured_mutation_epoch: 12,
        };
        let encoded = encode_untracked_inventory_cursor(Some(&cursor)).unwrap();
        assert_eq!(
            decode_untracked_inventory_cursor(&encoded).unwrap(),
            Some(cursor)
        );
        assert!(decode_untracked_inventory_cursor("not+a+cursor").is_err());
    }

    #[test]
    fn untracked_repair_projection_preserves_frozen_identity_and_terminal_evidence() {
        let record = OciUntrackedRepairPlanRecord {
            id: "repair-1".to_string(),
            registry_id: 1,
            placement_id: 2,
            placement_name: "primary".to_string(),
            placement_prefix: "registry".to_string(),
            placement_resource_version: 3,
            placement_write_spec_version: 4,
            placement_observation_version: 5,
            binding_id: 6,
            binding_resource_version: 7,
            binding_write_revision: 8,
            delete_credential_purpose: Some("delete".to_string()),
            delete_credential_generation: Some(9),
            delete_capability_fingerprint: "conditional-delete-v1".to_string(),
            delete_capability_resource_version: 10,
            inventory_generation_id: "inventory-1".to_string(),
            inventory_digest: Sha256Digest::digest(b"inventory"),
            inventory_observed_at: 11,
            object_key: "oci/blobs/sha256/object".to_string(),
            object_digest: Sha256Digest::digest(b"object"),
            observed_hash: Sha256Digest::digest(b"observed"),
            byte_size: 12,
            strong_etag: "\"strong\"".to_string(),
            repair_kind: OciUntrackedRepairKind::Delete,
            adopt_media_type: None,
            actor_id: "actor".to_string(),
            captured_mutation_epoch: 13,
            confirmation_hash: Sha256Digest::digest(b"confirmation"),
            state: "confirmed_absent".to_string(),
            expires_at: 14,
            created_at: 15,
            applied_at: Some(16),
            finished_at: Some(17),
            last_error: None,
            outcome: Some(OciUntrackedRepairOutcome::Deleted),
            provider_request_id: Some("provider-request".to_string()),
            conditional_etag: Some("\"strong\"".to_string()),
            evidence_digest: Some(Sha256Digest::digest(b"evidence")),
            confirmed_at: Some(18),
            resource_version: 19,
        };

        let message = untracked_repair_message("andyl/main", &record).unwrap();
        assert_eq!(message.state, "complete");
        assert_eq!(message.registry, "andyl/main");
        assert_eq!(message.object_key, record.object_key);
        assert_eq!(message.observed_hash, record.observed_hash.to_string());
        assert_eq!(message.binding_write_revision, "8");
        assert_eq!(message.delete_credential_generation, "9");
        assert_eq!(message.resource_version, "19");
        let evidence = message.evidence.unwrap();
        assert_eq!(evidence.outcome, "deleted");
        assert_eq!(evidence.provider_request_id, "provider-request");
        assert_eq!(evidence.conditional_etag, "\"strong\"");
        assert_eq!(
            evidence.evidence_digest,
            record.evidence_digest.as_ref().unwrap().to_string()
        );
        assert_eq!(evidence.confirmed_at, 18);

        let mut malformed = record;
        malformed.evidence_digest = None;
        assert!(untracked_repair_message("andyl/main", &malformed).is_err());
    }

    #[test]
    fn purge_fence_projection_requires_collecting_fence_and_zero_exact_blockers() {
        let plan = OciRegistryPurgeFencePlanRecord {
            id: "purge-plan".to_string(),
            registry_id: 1,
            action: OciRegistryPurgeFenceAction::Begin,
            actor_id: "actor".to_string(),
            expected_resource_version: 2,
            captured_mutation_epoch: 3,
            confirmation_hash: Sha256Digest::digest(b"purge-confirmation"),
            state: "applied".to_string(),
            expires_at: 4,
            created_at: 5,
            applied_at: Some(6),
            finished_at: Some(6),
            last_error: None,
            resource_version: 2,
        };
        let fence = OciRegistryPurgeFenceRecord {
            registry_id: 1,
            actor_id: "actor".to_string(),
            idempotency_key: "apply-key".to_string(),
            registry_resource_version: 2,
            captured_mutation_epoch: 3,
            state: "collecting".to_string(),
            created_at: 6,
            aborted_at: None,
            resource_version: 1,
        };
        let status = OciRegistryPurgeFenceStatus {
            plan,
            fence: Some(fence),
            blockers: OciRegistryPurgeBlockers::default(),
        };

        let ready = registry_purge_fence_message("andyl/main", &status);
        assert!(ready.post_fence_inventory_ready);
        assert_eq!(ready.fence_state, "collecting");
        assert_eq!(ready.fence_resource_version, "1");
        assert_eq!(ready.registry_resource_version, "2");
        assert_eq!(ready.captured_mutation_epoch, "3");
        assert_eq!(
            ready.action,
            pb::ContainerRegistryPurgeFenceAction::Begin as i32
        );

        let mut blocked = status;
        blocked.blockers.untracked_provider_objects = 1;
        let blocked = registry_purge_fence_message("andyl/main", &blocked);
        assert!(!blocked.post_fence_inventory_ready);
        assert_eq!(blocked.blockers.unwrap().untracked_provider_objects, 1);
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

fn gc_run_message(
    registry: &str,
    record: &OciGcGenerationRecord,
    blockers: &[OciGcBlockerRecord],
) -> pb::ContainerGcRun {
    pb::ContainerGcRun {
        run_id: record.id.clone(),
        registry: registry.to_string(),
        state: record.state.clone(),
        mutation_epoch: record.captured_mutation_epoch.to_string(),
        inventory_object_count: record.inventory_object_count,
        reachable_object_count: record.reachable_object_count,
        candidate_object_count: record.planned_objects,
        reclaimable_byte_size: record.planned_bytes,
        deleted_object_count: record.deleted_object_count,
        deleted_byte_size: record.deleted_byte_size,
        blockers: blockers
            .iter()
            .map(|blocker| format!("{}: {}", blocker.kind, blocker.detail))
            .collect(),
        operation_id: record.id.clone(),
        failure: record.last_error.clone().unwrap_or_default(),
        resource_version: record.resource_version.to_string(),
        created_at: record.created_at,
        started_at: record.applied_at.unwrap_or_default(),
        finished_at: record.finished_at.unwrap_or_default(),
        applied_mutation_epoch: record
            .applied_mutation_epoch
            .map(|epoch| epoch.to_string())
            .unwrap_or_default(),
        policy_resource_version: record.policy_resource_version.to_string(),
        root_set_digest: record.root_set_digest.to_string(),
        placement_inventory_digest: record.placement_inventory_digest.to_string(),
        topology_digest: record.topology_digest.to_string(),
        plan_digest: record.plan_digest.to_string(),
        confirmation_hash: record.confirmation_hash.to_string(),
        placement_action_count: record.placement_action_count,
        expires_at: record.expires_at,
        applied_at: record.applied_at.unwrap_or_default(),
        policy_digest: record.policy_digest.to_string(),
        inventory_byte_size: record.inventory_byte_size,
    }
}

fn gc_candidate_message(record: &OciGcCandidateRecord) -> pb::ContainerGcCandidate {
    pb::ContainerGcCandidate {
        digest: record.digest.to_string(),
        media_type: record.media_type.as_str().to_string(),
        byte_size: record.byte_size,
        object_key: record.object_key.clone(),
        repository_count: record.repositories.len() as u64,
        state: record.state.clone(),
        eligible_at: record.eligible_at,
        finalized_at: record.finalized_at.unwrap_or_default(),
        repositories: record
            .repositories
            .iter()
            .map(ToString::to_string)
            .collect(),
        last_error: record.last_error.clone().unwrap_or_default(),
        resource_version: record.resource_version.to_string(),
    }
}

fn gc_blocker_message(record: &OciGcBlockerRecord) -> pb::ContainerGcBlocker {
    pb::ContainerGcBlocker {
        kind: record.kind.clone(),
        digest: record
            .digest
            .map(|digest| digest.to_string())
            .unwrap_or_default(),
        detail: record.detail.clone(),
    }
}

fn gc_placement_action_message(
    record: &OciGcPlacementActionRecord,
) -> pb::ContainerGcPlacementAction {
    pb::ContainerGcPlacementAction {
        action_id: record.id.clone(),
        digest: record.digest.to_string(),
        placement_id: record.placement_id,
        placement_name: record.placement_name.clone(),
        state: record.state.clone(),
        attempt_count: record.attempt_count,
        max_attempts: record.max_attempts,
        last_error: record.last_error.clone().unwrap_or_default(),
        resource_version: record.resource_version.to_string(),
        confirmed_at: record.confirmed_at.unwrap_or_default(),
        next_attempt_at: record.next_attempt_at,
        run_id: record.generation_id.clone(),
        object_key: record.object_key.clone(),
        expected_hash: record.expected_hash.to_string(),
        expected_byte_size: record.expected_size,
        expected_strong_etag: record.expected_strong_etag.clone().unwrap_or_default(),
        inventory_entry_present: record.inventory_entry_present,
        inventory_generation_id: record.inventory_generation_id.clone(),
        inventory_digest: record.inventory_digest.to_string(),
        inventory_observed_at: record.inventory_observed_at,
        placement_prefix: record.placement_prefix.clone(),
        placement_resource_version: record.placement_resource_version.to_string(),
        placement_write_spec_version: record.placement_write_spec_version.to_string(),
        placement_observation_version: record.placement_observation_version.to_string(),
        binding_id: record.binding_id,
        binding_resource_version: record.binding_resource_version.to_string(),
        binding_write_revision: record.binding_write_revision.to_string(),
        delete_credential_purpose: record.delete_credential_purpose.clone().unwrap_or_default(),
        delete_credential_generation: record
            .delete_credential_generation
            .map(|generation| generation.to_string())
            .unwrap_or_default(),
        delete_capability_fingerprint: record.delete_capability_fingerprint.clone(),
        delete_capability_resource_version: record.delete_capability_resource_version.to_string(),
    }
}

fn untracked_inventory_message(
    registry: &str,
    record: &OciUntrackedInventoryRecord,
) -> pb::ContainerUntrackedInventoryObject {
    pb::ContainerUntrackedInventoryObject {
        registry: registry.to_string(),
        placement_id: record.placement_id,
        placement_name: record.placement_name.clone(),
        placement_prefix: record.placement_prefix.clone(),
        inventory_generation_id: record.inventory_generation_id.clone(),
        inventory_digest: record.inventory_digest.to_string(),
        inventory_observed_at: record.inventory_observed_at,
        object_key: record.object_key.clone(),
        object_digest: record.object_digest.to_string(),
        observed_hash: record.observed_hash.to_string(),
        byte_size: record.byte_size,
        strong_etag: record.strong_etag.clone(),
        placement_resource_version: record.placement_resource_version.to_string(),
        placement_write_spec_version: record.placement_write_spec_version.to_string(),
        placement_observation_version: record.placement_observation_version.to_string(),
        binding_id: record.binding_id,
        binding_resource_version: record.binding_resource_version.to_string(),
        binding_write_revision: record.binding_write_revision.to_string(),
        delete_credential_purpose: record.delete_credential_purpose.clone().unwrap_or_default(),
        delete_credential_generation: record
            .delete_credential_generation
            .map(|value| value.to_string())
            .unwrap_or_default(),
        delete_capability_fingerprint: record
            .delete_capability_fingerprint
            .clone()
            .unwrap_or_default(),
        delete_capability_resource_version: record
            .delete_capability_resource_version
            .map(|value| value.to_string())
            .unwrap_or_default(),
    }
}

fn untracked_repair_message(
    registry: &str,
    record: &OciUntrackedRepairPlanRecord,
) -> Result<pb::ContainerUntrackedRepair, RpcError> {
    let state = public_untracked_repair_state(&record.state);
    let evidence = record
        .outcome
        .map(|outcome| {
            let evidence_digest = record.evidence_digest.ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!(
                    "terminal untracked repair evidence omitted its digest"
                ))
            })?;
            let confirmed_at = record.confirmed_at.ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!(
                    "terminal untracked repair evidence omitted its confirmation time"
                ))
            })?;
            let outcome = match outcome {
                OciUntrackedRepairOutcome::Deleted => "deleted",
                OciUntrackedRepairOutcome::AlreadyAbsent => "already_absent",
                OciUntrackedRepairOutcome::Adopted => "adopted",
            };
            Ok(pb::ContainerUntrackedRepairEvidence {
                outcome: outcome.to_string(),
                provider_request_id: record.provider_request_id.clone().unwrap_or_default(),
                conditional_etag: record.conditional_etag.clone().unwrap_or_default(),
                evidence_digest: evidence_digest.to_string(),
                confirmed_at,
            })
        })
        .transpose()?;
    Ok(pb::ContainerUntrackedRepair {
        plan_id: record.id.clone(),
        registry: registry.to_string(),
        state: state.to_string(),
        resource_version: record.resource_version.to_string(),
        placement_id: record.placement_id,
        placement_name: record.placement_name.clone(),
        placement_prefix: record.placement_prefix.clone(),
        placement_resource_version: record.placement_resource_version.to_string(),
        placement_write_spec_version: record.placement_write_spec_version.to_string(),
        placement_observation_version: record.placement_observation_version.to_string(),
        binding_id: record.binding_id,
        binding_resource_version: record.binding_resource_version.to_string(),
        binding_write_revision: record.binding_write_revision.to_string(),
        delete_credential_purpose: record.delete_credential_purpose.clone().unwrap_or_default(),
        delete_credential_generation: record
            .delete_credential_generation
            .map(|value| value.to_string())
            .unwrap_or_default(),
        delete_capability_fingerprint: record.delete_capability_fingerprint.clone(),
        delete_capability_resource_version: record.delete_capability_resource_version.to_string(),
        inventory_generation_id: record.inventory_generation_id.clone(),
        inventory_digest: record.inventory_digest.to_string(),
        inventory_observed_at: record.inventory_observed_at,
        object_key: record.object_key.clone(),
        object_digest: record.object_digest.to_string(),
        observed_hash: record.observed_hash.to_string(),
        byte_size: record.byte_size,
        strong_etag: record.strong_etag.clone(),
        mutation_epoch: record.captured_mutation_epoch.to_string(),
        confirmation_hash: record.confirmation_hash.to_string(),
        expires_at: record.expires_at,
        created_at: record.created_at,
        applied_at: record.applied_at.unwrap_or_default(),
        finished_at: record.finished_at.unwrap_or_default(),
        last_error: record.last_error.clone().unwrap_or_default(),
        evidence,
    })
}

fn public_untracked_repair_state(state: &str) -> &str {
    match state {
        "confirmed_absent" | "adopted" => "complete",
        "aborted" => "failed",
        state => state,
    }
}

fn registry_purge_fence_message(
    registry: &str,
    status: &OciRegistryPurgeFenceStatus,
) -> pb::ContainerRegistryPurgeFence {
    let action = match status.plan.action {
        OciRegistryPurgeFenceAction::Begin => pb::ContainerRegistryPurgeFenceAction::Begin as i32,
        OciRegistryPurgeFenceAction::Abort => pb::ContainerRegistryPurgeFenceAction::Abort as i32,
    };
    let blockers = &status.blockers;
    let post_fence_inventory_ready = status
        .fence
        .as_ref()
        .is_some_and(|fence| fence.state == "collecting")
        && blockers.repositories == 0
        && blockers.catalog_objects == 0
        && blockers.active_sessions == 0
        && blockers.gc_work == 0
        && blockers.tracked_provider_objects == 0
        && blockers.untracked_provider_objects == 0
        && blockers.stale_or_missing_inventories == 0
        && blockers.snapshot_references == 0;
    let (fence_state, fence_resource_version, registry_resource_version, mutation_epoch) = status
        .fence
        .as_ref()
        .map(|fence| {
            (
                fence.state.clone(),
                fence.resource_version.to_string(),
                fence.registry_resource_version.to_string(),
                fence.captured_mutation_epoch.to_string(),
            )
        })
        .unwrap_or_else(|| {
            (
                "absent".to_string(),
                String::new(),
                if status.plan.action == OciRegistryPurgeFenceAction::Begin {
                    status.plan.expected_resource_version.to_string()
                } else {
                    String::new()
                },
                status.plan.captured_mutation_epoch.to_string(),
            )
        });
    pb::ContainerRegistryPurgeFence {
        plan_id: status.plan.id.clone(),
        registry: registry.to_string(),
        action,
        plan_state: status.plan.state.clone(),
        plan_resource_version: status.plan.resource_version.to_string(),
        fence_state,
        fence_resource_version,
        registry_resource_version,
        captured_mutation_epoch: mutation_epoch,
        post_fence_inventory_ready,
        blockers: Some(pb::ContainerRegistryPurgeBlockers {
            repositories: blockers.repositories,
            catalog_objects: blockers.catalog_objects,
            active_sessions: blockers.active_sessions,
            gc_work: blockers.gc_work,
            tracked_provider_objects: blockers.tracked_provider_objects,
            untracked_provider_objects: blockers.untracked_provider_objects,
            stale_or_missing_inventories: blockers.stale_or_missing_inventories,
            snapshot_references: blockers.snapshot_references,
        }),
        confirmation_hash: status.plan.confirmation_hash.to_string(),
        expires_at: status.plan.expires_at,
        created_at: status.plan.created_at,
        applied_at: status.plan.applied_at.unwrap_or_default(),
        finished_at: status.plan.finished_at.unwrap_or_default(),
        last_error: status.plan.last_error.clone().unwrap_or_default(),
    }
}

fn container_gc_rollout_unavailable() -> RpcError {
    RpcError::Unavailable("container garbage-collection rollout is disabled".to_string())
}

fn container_administration_unavailable() -> RpcError {
    RpcError::Unavailable("container administration rollout is disabled".to_string())
}
