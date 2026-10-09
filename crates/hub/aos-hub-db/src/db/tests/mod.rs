//! Shared fixtures and capability regression suites.

use std::sync::Arc;

use super::*;
use rusqlite::Connection;
use uuid::Uuid;

async fn create_test_binding(db: &Database, org_id: i64, name: &str, path: &str) -> i64 {
    let owner = db.org_by_id(org_id).await.unwrap().unwrap();
    db.create_topology_binding(
        Some(org_id),
        &Uuid::new_v4().simple().to_string(),
        &owner.stable_id,
        name,
        "r2",
        None,
        Some("test-bucket"),
        Some(path.trim_start_matches('/')),
        Some("https"),
        Some("dns"),
        Some(b"storage.example.invalid"),
        Some(443),
        Some("auto"),
        Some("private"),
    )
    .await
    .unwrap()
}

async fn create_valid_write_credential(db: &Database, binding_id: i64, secret_ref: &str) -> i64 {
    let expected = db
        .current_binding_credential(binding_id, "write")
        .await
        .unwrap()
        .map_or(0, |revision| revision.generation);
    let revision = db
        .set_binding_credential_revision(
            binding_id,
            "write",
            secret_ref,
            expected,
            &"0".repeat(64),
            "test",
        )
        .await
        .unwrap();
    db.validate_binding_credential_revision(
        binding_id,
        "write",
        revision.generation,
        "valid",
        None,
        revision.head_resource_version,
    )
    .await
    .unwrap()
    .generation
}

fn signed_image_package() -> aos_registry_format::manifest::PackageToml {
    use aos_registry_format::manifest::{
        immutable_image_contract_object_key, immutable_image_object_key,
        ImageArtifactContractDocumentReference, ImageArtifactContractReference, ImageCompression,
        ImageDelivery, ImageTarget,
    };

    #[derive(serde::Serialize)]
    struct DeliveryWrapper<'a> {
        delivery: &'a ImageDelivery,
    }

    let delivery = |format: &str| {
        let (sha256, extension, media_type, compatible_targets, info_sha256) = match format {
            "raw" => (
                "a".repeat(64),
                "img.zst",
                "application/vnd.aos.disk-image.raw+zstd",
                vec![ImageTarget::BareMetal],
                "c".repeat(64),
            ),
            "qcow2" => (
                "b".repeat(64),
                "qcow2",
                "application/vnd.aos.disk-image.qcow2",
                vec![ImageTarget::QemuKvm, ImageTarget::Openstack],
                "d".repeat(64),
            ),
            other => panic!("unsupported image test format {other}"),
        };
        let filename = format!("aos-system.{extension}");
        ImageDelivery {
            schema_version: 1,
            release: "2026.8.0".into(),
            platform: "x86_64-linux".into(),
            architecture: "x86_64".into(),
            logical_image_id: "e".repeat(64),
            logical_disk_sha256: "a".repeat(64),
            filename: filename.clone(),
            object_key: immutable_image_object_key(&sha256, &filename),
            media_type: media_type.into(),
            compression: if format == "raw" {
                ImageCompression::Zstd
            } else {
                ImageCompression::None
            },
            byte_size: 4096,
            sha256: sha256.clone(),
            compatible_targets,
            artifact_contract: ImageArtifactContractReference {
                schema: "aos.test.boot-artifacts/v1".into(),
                document: ImageArtifactContractDocumentReference {
                    filename: "image-info.json".into(),
                    object_key: immutable_image_contract_object_key(
                        &sha256,
                        &info_sha256,
                        "image-info.json",
                    ),
                    store_path: String::new(),
                    nar_hash: String::new(),
                    nar_size: 0,
                    media_type: "application/vnd.aos.image-info+json".into(),
                    byte_size: 512,
                    sha256: info_sha256,
                },
                artifacts: None,
            },
        }
    };
    let mut images = String::new();
    for format in ["raw", "qcow2"] {
        let delivery = delivery(format);
        let store_hash = if format == "raw" {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        } else {
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        };
        let encoded = toml::to_string(&DeliveryWrapper {
            delivery: &delivery,
        })
        .unwrap()
        .replace(
            "[delivery]",
            "[versions.platforms.x86_64-linux.images.delivery]",
        )
        .replace(
            "[delivery.artifact_contract]",
            "[versions.platforms.x86_64-linux.images.delivery.artifact_contract]",
        )
        .replace(
            "[delivery.artifact_contract.document]",
            "[versions.platforms.x86_64-linux.images.delivery.artifact_contract.document]",
        );
        images.push_str(&format!(
            r#"
[[versions.platforms.x86_64-linux.images]]
format = "{format}"
store_path = "/aos/store/{store_hash}-aos-system-{format}"
nar_hash = "sha256:nar"
nar_size = 1
{encoded}
"#,
        ));
    }
    toml::from_str(&format!(
        r#"
[package]
name = "aos-system"
description = "AOS system"
license = "MIT"
maintainer = "aos"
sysroot = true

[[versions]]
version = "2026.8.0"

[versions.platforms.x86_64-linux]
store_path = "/aos/store/aos-system"
closure_size = 1
source_drv = ""
source_nar_hash = ""

[versions.platforms.x86_64-linux.references]
hashes = []
min-format = 1
requires-features = ["image-artifact-contract-v1"]
{images}
"#,
    ))
    .unwrap()
}

fn signed_image_release_snapshot(
    package: &aos_registry_format::manifest::PackageToml,
    release: &str,
    commit: &str,
    tag_oid: &str,
) -> ReleaseImageSnapshot {
    let mut images = Vec::new();
    for version in &package.versions {
        if version.version != release {
            continue;
        }
        for (platform, artifact) in &version.platforms {
            for image in &artifact.images {
                images.push(IndexedSystemImage {
                    package: package.package.name.clone(),
                    release: release.to_string(),
                    platform: platform.clone(),
                    format: image.format.clone(),
                    store_path: image.store_path.clone(),
                    nar_hash: image.nar_hash.clone(),
                    nar_size: image.nar_size,
                    delivery: image.delivery.clone(),
                });
            }
        }
    }
    ReleaseImageSnapshot {
        release_tag: release.to_string(),
        source_commit: commit.to_string(),
        verified_tag_oid: tag_oid.to_string(),
        catalog_digest: "d".repeat(64),
        images,
    }
}

fn store_backed_image_package() -> aos_registry_format::manifest::PackageToml {
    use aos_registry_format::manifest::ImageStoreReference;

    let mut package = signed_image_package();
    for version in &mut package.versions {
        for artifact in version.platforms.values_mut() {
            for image in &mut artifact.images {
                let store_hash = match image.format.as_str() {
                    "raw" => "cccccccccccccccccccccccccccccccc",
                    "qcow2" => "dddddddddddddddddddddddddddddddd",
                    other => panic!("unsupported image test format {other}"),
                };
                image.nar_hash = format!("sha256:{}", "0".repeat(52));
                image.delivery.schema_version = 2;
                image.delivery.object_key.clear();
                image.delivery.artifact_contract.document.object_key.clear();
                image.delivery.artifact_contract.document.store_path =
                    format!("/aos/store/{store_hash}-aos-system-{}-info", image.format);
                image.delivery.artifact_contract.document.nar_hash =
                    format!("sha256:{}", "0".repeat(52));
                image.delivery.artifact_contract.document.nar_size = 1;
                image.delivery.artifact_contract.artifacts = Some(ImageStoreReference {
                    store_path: image.store_path.clone(),
                    nar_hash: image.nar_hash.clone(),
                    nar_size: image.nar_size,
                });
            }
        }
    }
    package
}

/// The central regression guard for the `closed_at`-axis design: closing and
/// reopening a draft must leave `status = 'draft'`, so the indexer's
/// `status='draft'`-guarded auto-merge still fires for a reopened change.

/// M-3: a second approval of an already-approved `user_code` is a no-op —
/// it returns `Ok(false)` and mints no second token. The atomic claim
/// (`UPDATE … WHERE approved_by_user IS NULL`) stamps zero rows on the
/// re-approval, so exactly one token exists per approval and no orphaned,
/// un-pollable token is ever issued.

/// M-3: a denied grant cannot subsequently be approved (the claim's
/// `denied = 0` predicate matches zero rows), so no token is minted.

/// M-2: the transactional owner-safe revoke refuses to remove an org's last
/// owner and rolls the delete back, but happily removes one of several
/// owners.

/// Concurrent revokes serialize through the shared scope guard, so two
/// writers targeting different owner rows cannot both orphan the scope.

/// Caller mutation keys make terminal-operation retries replayable without
/// advancing the resource version twice.

/// M-2: the transactional owner-safe role change refuses to demote an org's
/// last owner; demoting one of several owners is fine. Two sequential
/// demotes still leave at least one owner (the second is rejected).

/// M-2: `delete_user` re-checks sole ownership inside its transaction, so a
/// user who is the only owner of an org cannot be deleted; once another
/// owner exists, the delete succeeds.

/// Count the `owner`-role user grants at `scope`.
async fn owner_count(db: &Database, scope: &str) -> usize {
    db.list_members_of_scope(scope)
        .await
        .unwrap()
        .iter()
        .filter(|(k, _, r)| k == "user" && r == "owner")
        .count()
}

/// Set up an org + binding and return `(db, org_id, binding_id)`.
async fn cache_fixture() -> (Database, i64, i64) {
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    let binding = create_test_binding(&db, org, "primary", "/srv/aos-hub").await;
    (db, org, binding)
}

// -- operations: quotas, usage, signup policy, offboarding (v13) --------

// regression: a restore landing between `list_purgeable_orgs` and
// `hard_purge_org` (the unguarded list+delete race) must not destroy the
// now-active org. `hard_purge_org` re-asserts the soft-deleted/past-grace
// predicate, so the delete is a no-op once the org is restored.

fn topology_placement(
    surface: SurfaceTarget,
    name: &str,
    prefix: &str,
    read_order: i64,
) -> NewSurfacePlacementSpec {
    NewSurfacePlacementSpec {
        surface,
        name: name.to_string(),
        binding_id: 0,
        prefix: prefix.to_string(),
        kind: "complete".to_string(),
        desired_state: "active".to_string(),
        hash_range: None,
        desired_read_enabled: true,
        read_order,
        requires_conditional_writes: false,
    }
}

#[allow(dead_code)]
async fn set_test_placement_watermark(
    db: &Database,
    placement_id: i64,
    registry_id: i64,
    publication_id: Option<&str>,
    observed_at: i64,
) {
    db.backend
        .execute(
            "DELETE FROM registry_placement_publication_watermarks
                 WHERE placement_id = ?1",
            &vals![placement_id],
        )
        .await
        .unwrap();
    db.backend
        .execute(
            "INSERT INTO registry_placement_publication_watermarks
                 (placement_id, registry_id, mutable_publication_id, observed_at)
                 VALUES (?1, ?2, ?3, ?4)",
            &vals![placement_id, registry_id, publication_id, observed_at],
        )
        .await
        .unwrap();
}

/// Test helper: register a managed registry owned by `org` at `slug` with a
/// local_fs binding, so serving queries can exclude it on soft-delete.
impl Database {
    async fn register_owned(&self, org_id: i64, slug: &str) {
        create_test_binding(self, org_id, "primary", "/tmp/aos-hub-test").await;
        // The slug is `org/name`; split off the name for the canonical path.
        let name = slug.rsplit('/').next().unwrap();
        self.create_managed_registry(org_id, "", name, "public", &[], false)
            .await
            .unwrap();
    }
}

mod administration;
mod caches;
mod documentation;
mod identity;
mod registries;
mod releases;
mod runtime;
mod tenancy;
mod topology_1;
mod topology_2;
mod webhooks;
