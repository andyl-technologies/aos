//! Regression tests for metadata preservation and signed draft plan/apply.

use super::*;
use crate::db::{BindingWriteRevisionRecord, IndexSnapshot, SurfacePlacementRecord, TokenAuth};
use crate::domain::{Permission, Principal, Scope};
use crate::fetch::{SurfaceFetch, SurfaceProvider};
use crate::surface_write::{SurfaceWrite, SurfaceWriteProvider};
use aos_registry_surface::object::{encode_loose, encode_tree, hash_object, ObjectKind, TreeEntry};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

const ORIGINAL: &str = r#"# Producer configuration stays intact.
[registry]
name = "original" # Identity comment
description = "Old description"
readme = "Old introduction"
default_release = "2026.9.0"
content_addressed = false
require_signed_ukis = true

[caches]
endpoint = "https://cache.example.test"

[support.default]
kind = "standard"
superseded_after_trains = 2

[producer_extension]
keep = "untouched"
"#;

#[test]
fn metadata_edits_preserve_unselected_fields_comments_and_extensions() {
    let desired = pb::RegistryMetadata {
        name: "New registry".into(),
        ..Default::default()
    };
    let result = edit_metadata(ORIGINAL, &desired, &["name".into()]).unwrap();

    assert!(result.contains("# Producer configuration stays intact."));
    assert!(result.contains("name = \"New registry\" # Identity comment"));
    let mut before: toml::Value = toml::from_str(ORIGINAL).unwrap();
    before["registry"]["name"] = toml::Value::String("New registry".into());
    assert_eq!(toml::from_str::<toml::Value>(&result).unwrap(), before);
}

#[test]
fn optional_metadata_can_be_cleared_without_resetting_producer_flags() {
    let mask = ["description", "readme", "default_release", "support_toml"].map(str::to_string);
    let result = edit_metadata(ORIGINAL, &pb::RegistryMetadata::default(), &mask).unwrap();
    let metadata = metadata_from_toml(&result).unwrap();

    assert_eq!(metadata.name, "original");
    assert!(metadata.description.is_empty());
    assert!(metadata.readme.is_empty());
    assert!(metadata.default_release.is_empty());
    assert!(metadata.support_toml.is_empty());
    let config = parse_metadata(&result).unwrap();
    assert!(!config.registry.content_addressed);
    assert!(config.registry.require_signed_ukis);
    assert!(config.caches.is_some());
}

#[test]
fn invalid_metadata_is_rejected_before_a_plan_is_created() {
    for (field, value) in [
        ("name", ""),
        ("name", "multi\nline"),
        ("default_release", "latest"),
        ("support_toml", "[trains.\"2026.9\"]\nkind = \"lts\""),
        (
            "support_toml",
            "[trains.\"2026.9\"]\nkind = \"lts\"\nsupported_until = \"2028-02-30\"",
        ),
        ("support_toml", "unexpected = true"),
    ] {
        let mut desired = pb::RegistryMetadata::default();
        match field {
            "name" => desired.name = value.into(),
            "default_release" => desired.default_release = value.into(),
            _ => desired.support_toml = value.into(),
        }
        assert!(
            edit_metadata(ORIGINAL, &desired, &[field.into()]).is_err(),
            "{field}: {value}"
        );
    }

    for mask in [
        vec![],
        vec!["name".into(), "name".into()],
        vec!["slug".into()],
        vec!["caches".into()],
    ] {
        assert!(edit_metadata(ORIGINAL, &pb::RegistryMetadata::default(), &mask).is_err());
    }
    assert!(edit_metadata(
        ORIGINAL,
        &metadata_from_toml(ORIGINAL).unwrap(),
        &["name".into()]
    )
    .is_err());
}

#[test]
fn support_policy_round_trips_through_the_editor() {
    let desired = pb::RegistryMetadata {
        support_toml: "[default]\nsuperseded_after_trains = 3\n[trains.\"2026.9\"]\nkind = \"lts\"\nsupported_until = \"2028-09-30\"\n".into(),
        ..Default::default()
    };
    let result = edit_metadata(ORIGINAL, &desired, &["support_toml".into()]).unwrap();
    let returned = metadata_from_toml(&result).unwrap();
    let support: SupportPolicy = toml::from_str(&returned.support_toml).unwrap();

    assert_eq!(support.default.superseded_after_trains, 3);
    assert_eq!(
        support.trains["2026.9"].supported_until.as_deref(),
        Some("2028-09-30")
    );
}

#[derive(Clone, Default)]
struct MemorySurface(Arc<Mutex<BTreeMap<String, Vec<u8>>>>);

impl MemorySurface {
    fn insert_object(&self, kind: ObjectKind, bytes: &[u8]) -> Oid {
        let oid = hash_object(kind, bytes);
        self.0
            .lock()
            .unwrap()
            .insert(oid.loose_path(), encode_loose(kind, bytes).unwrap());
        oid
    }
}

#[async_trait::async_trait]
impl SurfaceFetch for MemorySurface {
    async fn fetch(&self, path: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().get(path).cloned())
    }

    fn describe(&self) -> String {
        "metadata test storage".into()
    }
}

#[async_trait::async_trait]
impl SurfaceProvider for MemorySurface {
    async fn placement_fetcher(
        &self,
        _: &SurfacePlacementRecord,
    ) -> anyhow::Result<Box<dyn SurfaceFetch>> {
        Ok(Box::new(self.clone()))
    }
}

#[async_trait::async_trait]
impl SurfaceWrite for MemorySurface {
    async fn write(&self, path: &str, bytes: &[u8]) -> anyhow::Result<()> {
        self.0.lock().unwrap().insert(path.into(), bytes.to_vec());
        Ok(())
    }

    async fn delete(&self, path: &str) -> anyhow::Result<()> {
        self.0.lock().unwrap().remove(path);
        Ok(())
    }
}

#[async_trait::async_trait]
impl SurfaceWriteProvider for MemorySurface {
    async fn placement_writer(
        &self,
        _: &SurfacePlacementRecord,
    ) -> anyhow::Result<Box<dyn SurfaceWrite>> {
        Ok(Box::new(self.clone()))
    }

    async fn placement_writer_at_revision(
        &self,
        placement: &SurfacePlacementRecord,
        _: &BindingWriteRevisionRecord,
    ) -> anyhow::Result<Box<dyn SurfaceWrite>> {
        self.placement_writer(placement).await
    }

    async fn placement_deleter(
        &self,
        _: &SurfacePlacementRecord,
        _: i64,
        _: i64,
    ) -> anyhow::Result<Box<dyn SurfaceWrite>> {
        anyhow::bail!("metadata edits must not delete published objects")
    }
}

async fn fixture() -> (RpcService, String, MemorySurface, Oid) {
    let (mut service, db) = super::super::cache_upload_tests::delivery_test_service().await;
    let storage = MemorySurface::default();
    let blob = storage.insert_object(ObjectKind::Blob, ORIGINAL.as_bytes());
    let tree = storage.insert_object(
        ObjectKind::Tree,
        &encode_tree(&[TreeEntry {
            mode: "100644".into(),
            name: "registry.toml".into(),
            oid: blob,
        }]),
    );
    let commit = storage.insert_object(ObjectKind::Commit, format!("tree {tree}\nauthor Test <test@example.test> 1 +0000\ncommitter Test <test@example.test> 1 +0000\n\nInitial metadata\n").as_bytes());
    db.apply_snapshot(
        1,
        &IndexSnapshot {
            commit: commit.to_hex(),
            name: "original".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    service.surface = Arc::new(storage.clone());
    service.surface_write = Arc::new(storage.clone());

    let user = db
        .user_by_email("writer@example.test")
        .await
        .unwrap()
        .unwrap();
    let token = service
        .jwt_keys
        .mint(
            &TokenAuth {
                token_id: "metadata-editor".into(),
                owner: Principal::user(user),
                scope: Scope::root(),
                permissions: vec![
                    Permission::Read,
                    Permission::RegistryConfigure,
                    Permission::AuditRead,
                ],
            },
            3600,
        )
        .unwrap();
    (service, format!("Bearer {token}"), storage, commit)
}

fn request(base: Oid) -> pb::PlanUpdateRegistryMetadataRequest {
    pb::PlanUpdateRegistryMetadataRequest {
        slug: "failure/registry".into(),
        desired: Some(pb::RegistryMetadata {
            description: "New description".into(),
            ..Default::default()
        }),
        update_mask: vec!["description".into()],
        expected_resource_version: base.to_hex(),
        idempotency_key: "metadata-plan".into(),
    }
}

#[tokio::test]
async fn metadata_apply_creates_one_reviewed_draft_and_keeps_published_state() {
    let (service, auth, storage, base) = fixture().await;
    let plan = service
        .plan_update_registry_metadata(Some(&auth), request(base))
        .await
        .unwrap()
        .plan
        .unwrap();
    let replayed_plan = service
        .plan_update_registry_metadata(Some(&auth), request(base))
        .await
        .unwrap()
        .plan
        .unwrap();
    assert_eq!(plan, replayed_plan);
    assert!(plan.effects.join("\n").contains("New description"));
    let apply = pb::ApplyRegistryMutationRequest {
        plan_id: plan.plan_id,
        confirmation_hash: plan.confirmation_hash,
        idempotency_key: "metadata-plan".into(),
    };

    let response = service
        .update_registry_metadata(Some(&auth), apply.clone())
        .await
        .unwrap();
    let replay = service
        .update_registry_metadata(Some(&auth), apply)
        .await
        .unwrap();

    assert_eq!(response, replay);
    assert!(response.merge_command.contains(&response.change_id));
    let draft = storage
        .fetch(&format!("refs/hub/changes/{}", response.change_id))
        .await
        .unwrap()
        .unwrap();
    let draft_oid = Oid::from_hex(std::str::from_utf8(&draft).unwrap().trim()).unwrap();
    let draft_contents = crate::git::load_committed_file(&storage, draft_oid, "registry.toml")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        metadata_from_toml(&draft_contents).unwrap().description,
        "New description"
    );
    let commit = crate::git::ObjectReader::new(&storage)
        .read_commit(draft_oid)
        .await
        .unwrap();
    assert_eq!(commit.parents, vec![base]);
    assert!(commit.signature.is_some());
    let read = service
        .get_registry_metadata(
            Some(&auth),
            pb::GetRegistryRequest {
                slug: "failure/registry".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(read.resource_version, base.to_hex());
    assert_eq!(read.metadata.unwrap().description, "Old description");
}

#[tokio::test]
async fn metadata_plans_reject_missing_authority_and_stale_commits() {
    let (service, auth, _, base) = fixture().await;
    assert!(matches!(
        service
            .plan_update_registry_metadata(None, request(base))
            .await,
        Err(RpcError::Unauthenticated(_))
    ));

    let mut stale = request(base);
    stale.expected_resource_version = "0".repeat(64);
    assert!(matches!(
        service
            .plan_update_registry_metadata(Some(&auth), stale)
            .await,
        Err(RpcError::FailedPrecondition(_))
    ));

    let plan = service
        .plan_update_registry_metadata(Some(&auth), request(base))
        .await
        .unwrap()
        .plan
        .unwrap();
    service
        .db
        .apply_snapshot(
            1,
            &IndexSnapshot {
                commit: "1".repeat(64),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let result = service
        .update_registry_metadata(
            Some(&auth),
            pb::ApplyRegistryMutationRequest {
                plan_id: plan.plan_id,
                confirmation_hash: plan.confirmation_hash,
                idempotency_key: "metadata-plan".into(),
            },
        )
        .await;
    assert!(matches!(result, Err(RpcError::FailedPrecondition(_))));
}

#[tokio::test]
async fn metadata_apply_checks_confirmation_and_current_permission_before_writing() {
    let (service, auth, storage, base) = fixture().await;
    let plan = service
        .plan_update_registry_metadata(Some(&auth), request(base))
        .await
        .unwrap()
        .plan
        .unwrap();
    let mut apply = pb::ApplyRegistryMutationRequest {
        plan_id: plan.plan_id.clone(),
        confirmation_hash: "wrong".into(),
        idempotency_key: "metadata-plan".into(),
    };
    assert!(matches!(
        service
            .update_registry_metadata(Some(&auth), apply.clone())
            .await,
        Err(RpcError::FailedPrecondition(_))
    ));

    let user = service
        .db
        .user_by_email("writer@example.test")
        .await
        .unwrap()
        .unwrap();
    let read_token = service
        .jwt_keys
        .mint(
            &TokenAuth {
                token_id: "metadata-read-only".into(),
                owner: Principal::user(user),
                scope: Scope::root(),
                permissions: vec![Permission::Read],
            },
            3600,
        )
        .unwrap();
    let read_auth = format!("Bearer {read_token}");
    apply.confirmation_hash = plan.confirmation_hash;
    assert!(matches!(
        service
            .update_registry_metadata(Some(&read_auth), apply.clone())
            .await,
        Err(RpcError::PermissionDenied(_))
    ));
    assert!(storage
        .fetch(&format!("refs/hub/changes/{}", plan.plan_id))
        .await
        .unwrap()
        .is_none());

    service
        .update_registry_metadata(Some(&auth), apply.clone())
        .await
        .unwrap();
    assert!(matches!(
        service
            .update_registry_metadata(Some(&read_auth), apply)
            .await,
        Err(RpcError::PermissionDenied(_))
    ));
}
