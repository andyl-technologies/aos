//! Manifest reservation, byte verification, quota and interrupted-write recovery.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Result};
use aos_oci_types::RepositoryName;

use super::*;
use crate::auth::jwt::JwtKeys;
use crate::coordinator::InMemoryCoordinator;
use crate::db::{
    BindingWriteRevisionRecord, Database, NewSurfacePlacementSpec, OciSha256State, OrgQuota,
};
use crate::fetch::{SurfaceFetch, SurfaceObjectEvidence, SurfaceProvider};
use crate::jobs::InMemoryQueue;
use crate::lease::InMemoryLease;
use crate::ratelimit::CoordinatorRateLimiter;
use crate::reindex::QueuedReindexer;
use crate::surface_write::{SurfaceWrite, SurfaceWriteProvider};
use crate::topology_probe::DatabaseTopologyProbeScheduler;

#[derive(Clone, Default)]
struct Storage(Arc<Mutex<BTreeMap<String, Vec<u8>>>>);

#[async_trait::async_trait]
impl SurfaceFetch for Storage {
    async fn fetch(&self, _: &str) -> Result<Option<Vec<u8>>> {
        bail!("manifest verification must not fetch object bodies")
    }

    async fn inventory_evidence_bounded(
        &self,
        path: &str,
        maximum_bytes: u64,
    ) -> Result<Option<SurfaceObjectEvidence>> {
        let objects = self.0.lock().unwrap();
        let Some(bytes) = objects.get(path) else {
            return Ok(None);
        };
        assert!(bytes.len() as u64 <= maximum_bytes);
        Ok(Some(SurfaceObjectEvidence {
            provider_version: None,
            sha256: *Sha256Digest::digest(bytes).as_bytes(),
            size: bytes.len() as i64,
            strong_etag: Some("\"stored-version\"".into()),
        }))
    }

    fn describe(&self) -> String {
        "manifest storage-local evidence fixture".into()
    }
}

#[async_trait::async_trait]
impl SurfaceProvider for Storage {
    async fn placement_fetcher(&self, _: &SurfacePlacementRecord) -> Result<Box<dyn SurfaceFetch>> {
        Ok(Box::new(self.clone()))
    }
}

#[async_trait::async_trait]
impl SurfaceWriteProvider for Storage {
    async fn placement_writer(&self, _: &SurfacePlacementRecord) -> Result<Box<dyn SurfaceWrite>> {
        bail!("Native cannot stage manifest bodies")
    }

    async fn placement_writer_at_revision(
        &self,
        _: &SurfacePlacementRecord,
        _: &BindingWriteRevisionRecord,
    ) -> Result<Box<dyn SurfaceWrite>> {
        bail!("Native cannot stage manifest bodies")
    }

    async fn placement_deleter(
        &self,
        _: &SurfacePlacementRecord,
        _: i64,
        _: i64,
    ) -> Result<Box<dyn SurfaceWrite>> {
        bail!("manifest fixture does not execute physical cleanup")
    }
}

async fn fixture() -> (RpcService, RegistryRecord, OciRepositoryRecord, Storage) {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org_id = db.create_org("manifest", "Manifest").await.unwrap();
    let org = db.org_by_id(org_id).await.unwrap().unwrap();
    let binding = db
        .ensure_instance_default_binding("deployment_r2", None, Some("REGISTRY_BUCKET"))
        .await
        .unwrap();
    db.grant_consumer_scope(
        crate::db::GrantResource::Binding {
            id: binding.id,
            stable_id: &binding.stable_id,
        },
        &org.stable_id,
        "explicit",
        "test",
        "manifest-binding-grant",
    )
    .await
    .unwrap();
    let registry_id = db
        .create_managed_registry(org_id, "", "main", "private", &[], false)
        .await
        .unwrap();
    let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();
    let repository = db
        .ensure_oci_repository(registry_id, &RepositoryName::parse("aos").unwrap(), now())
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "primary".into(),
            binding_id: binding.id,
            prefix: "manifest/main".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await
        .unwrap();
    db.observe_surface_placement(placement.id, "ready", "complete", 1)
        .await
        .unwrap();
    db.bind_surface_placement_write_capability(placement.id, 1)
        .await
        .unwrap();
    db.create_surface_write_authority(
        SurfaceTarget::Registry(registry_id),
        "manifest-authority",
        placement.id,
        placement.resource_version,
        placement.write_spec_version,
        1,
    )
    .await
    .unwrap();

    let storage = Storage::default();
    let service = RpcService::new(
        db.clone(),
        JwtKeys::from_secret(b"manifest-test-key"),
        "https://hub.example.test".into(),
        Arc::new(CoordinatorRateLimiter::new(Arc::new(
            InMemoryCoordinator::new(),
        ))),
        Arc::new(storage.clone()),
        Arc::new(storage.clone()),
        Arc::new(InMemoryLease::new()),
        Arc::new(QueuedReindexer::new(Arc::new(InMemoryQueue::new()))),
        Arc::new(DatabaseTopologyProbeScheduler::new(db)),
        None,
    )
    .with_hybrid_delivery();
    (service, registry, repository, storage)
}

fn preflight(bytes: &[u8]) -> HybridOciManifestPreflight {
    let mut sha256_state = OciSha256State::initial();
    sha256_state.update(bytes).unwrap();
    HybridOciManifestPreflight { sha256_state }
}

async fn reserve(
    service: &RpcService,
    registry: &RegistryRecord,
    repository: &OciRepositoryRecord,
    bytes: &[u8],
) -> HybridOciManifestAdmission {
    service
        .reserve_hybrid_manifest(
            registry,
            repository,
            "writer",
            &ManifestReference::Digest(Sha256Digest::digest(bytes)),
            preflight(bytes),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn manifest_preflight_reserves_quota_and_cleanup_before_any_storage_write() {
    let (service, registry, repository, storage) = fixture().await;
    let bytes = vec![42; MAX_MANIFEST_BYTES];
    let admission = reserve(&service, &registry, &repository, &bytes).await;

    assert!(storage.0.lock().unwrap().is_empty());
    let upload = service
        .db
        .hybrid_oci_manifest_upload(&admission.upload_id, "writer", now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(upload.expected_size, Some(MAX_MANIFEST_BYTES as u64));
    assert!(upload.staging_binding_write_revision.is_some());
    let chunks = service.db.oci_upload_chunks(&upload.id).await.unwrap();
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].staging_object_key, admission.staging_object_key);
    assert_eq!(chunks[0].digest, Sha256Digest::digest(&bytes));

    service
        .db
        .expire_oci_upload(&upload.id, upload.expires_at)
        .await
        .unwrap();
    let cleanup = service.db.oci_upload_cleanup_candidates(10).await.unwrap();
    assert_eq!(cleanup.len(), 1);
    assert_eq!(cleanup[0].chunks, chunks);
    assert_eq!(
        cleanup[0].upload.staging_binding_write_revision,
        upload.staging_binding_write_revision
    );
}

#[tokio::test]
async fn manifest_completion_requires_exact_owner_body_and_storage_evidence() {
    let (service, registry, repository, storage) = fixture().await;
    let bytes = b"exact manifest document";
    let admission = reserve(&service, &registry, &repository, bytes).await;
    let digest = Sha256Digest::digest(bytes);

    assert!(service
        .verified_hybrid_manifest_staging(
            &repository,
            "writer",
            &admission.upload_id,
            digest,
            bytes.len()
        )
        .await
        .is_err());
    storage.0.lock().unwrap().insert(
        admission.staging_object_key.clone(),
        b"other manifest document".to_vec(),
    );
    assert!(service
        .verified_hybrid_manifest_staging(
            &repository,
            "writer",
            &admission.upload_id,
            digest,
            bytes.len()
        )
        .await
        .is_err());

    storage
        .0
        .lock()
        .unwrap()
        .insert(admission.staging_object_key.clone(), bytes.to_vec());
    assert!(service
        .verified_hybrid_manifest_staging(
            &repository,
            "another-writer",
            &admission.upload_id,
            digest,
            bytes.len()
        )
        .await
        .is_err());
    assert!(service
        .verified_hybrid_manifest_staging(
            &repository,
            "writer",
            &admission.upload_id,
            Sha256Digest::digest(b"different"),
            bytes.len()
        )
        .await
        .is_err());
    assert!(service
        .verified_hybrid_manifest_staging(
            &repository,
            "writer",
            &admission.upload_id,
            digest,
            bytes.len() - 1
        )
        .await
        .is_err());
    let (_, upload, chunks) = service
        .verified_hybrid_manifest_staging(
            &repository,
            "writer",
            &admission.upload_id,
            digest,
            bytes.len(),
        )
        .await
        .unwrap();
    assert_eq!(upload.state, "active");
    assert_eq!(chunks[0].digest, digest);
}

#[tokio::test]
async fn manifest_preflight_rejects_size_and_quota_before_worker_put() {
    let (service, registry, repository, storage) = fixture().await;
    let bytes = b"manifest";
    let reference = ManifestReference::Digest(Sha256Digest::digest(bytes));
    for invalid in [preflight(b""), preflight(&vec![42; MAX_MANIFEST_BYTES + 1])] {
        assert!(service
            .reserve_hybrid_manifest(&registry, &repository, "writer", &reference, invalid)
            .await
            .is_err());
    }
    service
        .db
        .set_org_quota(
            registry.org_id.unwrap(),
            &OrgQuota {
                max_bytes: Some(1),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(service
        .reserve_hybrid_manifest(
            &registry,
            &repository,
            "writer",
            &reference,
            preflight(bytes)
        )
        .await
        .is_err());
    assert!(storage.0.lock().unwrap().is_empty());
}

#[test]
fn manifest_completion_query_rejects_duplicate_and_unsafe_identities() {
    let id = "a".repeat(32);
    assert_eq!(
        private_manifest_upload(Some(&format!("{HYBRID_OCI_MANIFEST_UPLOAD_QUERY}={id}"))).unwrap(),
        Some(id.clone())
    );
    assert!(private_manifest_upload(Some(&format!(
        "{HYBRID_OCI_MANIFEST_UPLOAD_QUERY}={id}&{HYBRID_OCI_MANIFEST_UPLOAD_QUERY}={id}"
    )))
    .is_err());
    for value in ["../path", "", "short", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"] {
        assert!(private_manifest_upload(Some(&format!(
            "{HYBRID_OCI_MANIFEST_UPLOAD_QUERY}={value}"
        )))
        .is_err());
    }
}
