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
struct Storage {
    objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    owner: String,
    authorization: String,
    revoke_after_projection: Arc<Mutex<Option<(Arc<Database>, String)>>>,
    compositions: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait::async_trait]
impl SurfaceFetch for Storage {
    async fn fetch(&self, _: &str) -> Result<Option<Vec<u8>>> {
        bail!("manifest verification must not fetch object bodies")
    }

    async fn oci_document_projection(
        &self,
        path: &str,
        descriptor: &aos_oci_types::Descriptor,
        admission: Option<&HybridOciManifestAdmission>,
    ) -> Result<Option<crate::oci_projection::guard::VerifiedOciProjection>> {
        use crate::mirror_guard::MirrorGuardIssuer;
        use crate::oci_projection::{guard::*, OciDocumentProjection};
        use crate::storage_work::{StorageObjectIdentity, StorageWorkKey};
        let proof = {
            let objects = self.objects.lock().unwrap();
            let Some(bytes) = objects.get(path) else {
                return Ok(None);
            };
            let projection = OciDocumentProjection::from_stored_bytes(descriptor, bytes)?;
            let current = now() as u64;
            let key = crate::keymap::r2_key("manifest/main", path);
            let request = OciProjectionLookup {
                version: 1,
                protected_profile_digest: "c".repeat(64),
                deployment_id: "controlled-fixture".into(),
                issuer: MirrorGuardIssuer {
                    source_digest: "a".repeat(64),
                    script_version: "controlled-parser".into(),
                },
                clock_uncertainty_seconds: 2,
                key: key.clone(),
                descriptor: descriptor.clone(),
                admission: admission.cloned(),
                nonce: "b".repeat(64),
                issued_at: current,
                expires_at: current + 30,
            };
            let reply = OciProjectionReply {
                request: request.clone(),
                projection,
                observed_at: current + 2,
                object: StorageObjectIdentity {
                    key,
                    size: bytes.len() as u64,
                    etag: "\"actual-fixture-etag\"".into(),
                    provider_version: Some("actual-fixture-incarnation".into()),
                },
            };
            let guard = StorageWorkKey::new([7; 32])?;
            let signed = sign_oci_projection_reply(&guard, &reply)?;
            verify_oci_projection_reply(
                &guard,
                &signed.signature,
                &signed.body,
                &request,
                current + 2,
            )?
        };
        let mutation = self.revoke_after_projection.lock().unwrap().take();
        if let Some((db, token)) = mutation {
            db.revoke_token(&token).await?;
        }
        Ok(Some(proof))
    }

    async fn inventory_evidence_bounded(
        &self,
        path: &str,
        maximum_bytes: u64,
    ) -> Result<Option<SurfaceObjectEvidence>> {
        let objects = self.objects.lock().unwrap();
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
    async fn compose_oci_blob(
        &self,
        _: &SurfacePlacementRecord,
        _: &BindingWriteRevisionRecord,
        _: Option<&SurfacePlacementRecord>,
        path: &str,
        chunks: &[OciUploadChunkRecord],
        digest: Sha256Digest,
        size: u64,
    ) -> Result<Option<SurfaceObjectEvidence>> {
        self.compositions
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut objects = self.objects.lock().unwrap();
        let mut bytes = Vec::new();
        for chunk in chunks {
            let stored = objects.get(&chunk.staging_object_key).unwrap();
            assert_eq!(Sha256Digest::digest(stored), chunk.digest);
            assert_eq!(stored.len() as u64, chunk.byte_size);
            bytes.extend_from_slice(stored);
        }
        assert_eq!(Sha256Digest::digest(&bytes), digest);
        assert_eq!(bytes.len() as u64, size);
        objects.insert(path.into(), bytes);
        Ok(Some(SurfaceObjectEvidence {
            provider_version: Some("fixture-version".into()),
            sha256: *digest.as_bytes(),
            size: size as i64,
            strong_etag: Some("\"actual-fixture-etag\"".into()),
        }))
    }

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
    fixture_with_database(Arc::new(Database::open_in_memory().await.unwrap())).await
}

async fn fixture_with_database(
    db: Arc<Database>,
) -> (RpcService, RegistryRecord, OciRepositoryRecord, Storage) {
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

    let user = db
        .create_user("manifest-writer@example.test", None)
        .await
        .unwrap();
    db.grant_membership("user", user, "instance", "owner")
        .await
        .unwrap();
    let (token_id, _) = db
        .create_token(
            crate::domain::Principal::user(user),
            "instance",
            &[crate::domain::Permission::Publish],
            None,
            None,
        )
        .await
        .unwrap();
    let auth = db
        .current_token_authority(&token_id)
        .await
        .unwrap()
        .unwrap();
    let owner = format!("token:{token_id}");
    let jwt = JwtKeys::from_secret(b"manifest-test-key");
    let token = jwt
        .mint_oci(
            &crate::auth::jwt::OciTokenGrant {
                subject: owner.clone(),
                owner_kind: Some("user".into()),
                owner_incarnation: auth.owner_incarnation,
                authority: "hub.example.test".into(),
                registry_stable_id: registry.stable_id.clone(),
                grants: vec![crate::auth::jwt::OciRepositoryGrant {
                    repository: repository.name.clone(),
                    actions: vec!["push".into()],
                }],
            },
            900,
        )
        .unwrap();
    let storage = Storage {
        objects: Arc::default(),
        owner,
        authorization: format!("Bearer {token}"),
        revoke_after_projection: Arc::default(),
        compositions: Arc::default(),
    };
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
    HybridOciManifestPreflight {
        media_type: MediaType::OciImageIndex,
        sha256_state,
    }
}

async fn reserve(
    service: &RpcService,
    registry: &RegistryRecord,
    repository: &OciRepositoryRecord,
    bytes: &[u8],
    storage: &Storage,
) -> HybridOciManifestAdmission {
    service
        .reserve_hybrid_manifest(
            registry,
            repository,
            &storage.owner,
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
    let admission = reserve(&service, &registry, &repository, &bytes, &storage).await;

    assert!(storage.objects.lock().unwrap().is_empty());
    let upload = service
        .db
        .hybrid_oci_manifest_upload(&admission.upload_id, &storage.owner, now())
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
    let admission = reserve(&service, &registry, &repository, bytes, &storage).await;
    let digest = Sha256Digest::digest(bytes);

    assert!(service
        .verified_hybrid_manifest_staging(
            &repository,
            &storage.owner,
            &admission.upload_id,
            digest,
            bytes.len()
        )
        .await
        .is_err());
    storage.objects.lock().unwrap().insert(
        admission.staging_object_key.clone(),
        b"other manifest document".to_vec(),
    );
    assert!(service
        .verified_hybrid_manifest_staging(
            &repository,
            &storage.owner,
            &admission.upload_id,
            digest,
            bytes.len()
        )
        .await
        .is_err());

    storage
        .objects
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
            &storage.owner,
            &admission.upload_id,
            Sha256Digest::digest(b"different"),
            bytes.len()
        )
        .await
        .is_err());
    assert!(service
        .verified_hybrid_manifest_staging(
            &repository,
            &storage.owner,
            &admission.upload_id,
            digest,
            bytes.len() - 1
        )
        .await
        .is_err());
    let (_, upload, chunks) = service
        .verified_hybrid_manifest_staging(
            &repository,
            &storage.owner,
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
            .reserve_hybrid_manifest(&registry, &repository, &storage.owner, &reference, invalid)
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
            &storage.owner,
            &reference,
            preflight(bytes)
        )
        .await
        .is_err());
    assert!(storage.objects.lock().unwrap().is_empty());
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

fn index_headers(storage: &Storage) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/vnd.oci.image.index.v1+json"),
    );
    headers.insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_str(&storage.authorization).unwrap(),
    );
    headers
}

// Dependency setup uses the real retained upload/claim/completion APIs. The
// fixture's storage adapter supplies bytes and observations; it is not a live
// provider qualification.
async fn upload_dependency(
    service: &RpcService,
    repository: &OciRepositoryRecord,
    storage: &Storage,
    bytes: &[u8],
) -> aos_oci_types::Descriptor {
    use crate::db::{AppendOciUploadChunk, BeginOciUpload, ClaimOciUpload, CompleteOciUpload};
    let current = now();
    let digest = Sha256Digest::digest(bytes);
    let placement = service
        .effective_surface_writer(SurfaceTarget::Registry(repository.registry_id))
        .await
        .unwrap();
    let revision = service
        .db
        .placement_publication_write_revision(placement.id)
        .await
        .unwrap()
        .unwrap();
    let upload = service
        .db
        .begin_oci_upload(&BeginOciUpload {
            registry_id: repository.registry_id,
            repository_id: repository.id,
            publication_id: None,
            writer_id: storage.owner.clone(),
            token_id: storage.owner.clone(),
            idempotency_key: digest.to_string(),
            expected_digest: Some(digest),
            expected_size: Some(bytes.len() as u64),
            maximum_size: MAX_MANIFEST_BYTES as u64,
            now: current,
            expires_at: current + 60,
        })
        .await
        .unwrap();
    let mut hash = OciSha256State::initial();
    hash.update(bytes).unwrap();
    let upload = service
        .db
        .append_oci_upload_chunk(&AppendOciUploadChunk {
            upload_id: upload.id.clone(),
            writer_id: storage.owner.clone(),
            token_id: storage.owner.clone(),
            expected_resource_version: upload.resource_version,
            staging_placement_id: placement.id,
            staging_placement_resource_version: placement.resource_version,
            staging_binding_id: placement.binding_id,
            staging_binding_write_revision: revision.revision,
            chunk: OciUploadChunkRecord {
                ordinal: 0,
                byte_offset: 0,
                byte_size: bytes.len() as u64,
                digest,
                staging_object_key: format!("oci/uploads/{}/chunk", upload.id),
                created_at: current,
            },
            next_sha256: hash,
            now: current,
        })
        .await
        .unwrap();
    let evidence = service
        .db
        .record_oci_uploaded_object(
            repository.registry_id,
            placement.id,
            digest,
            bytes.len() as u64,
            "\"actual-fixture-etag\"",
            current,
        )
        .await
        .unwrap();
    service
        .db
        .claim_oci_upload(&ClaimOciUpload {
            upload_id: upload.id.clone(),
            writer_id: storage.owner.clone(),
            token_id: storage.owner.clone(),
            expected_resource_version: upload.resource_version,
            materialization_placement_id: placement.id,
            materialization_placement_resource_version: placement.resource_version,
            materialization_binding_id: placement.binding_id,
            materialization_binding_write_revision: revision.revision,
            digest,
            now: current,
            lease_expires_at: current + 60,
        })
        .await
        .unwrap();
    let claimed = service
        .db
        .oci_upload(&upload.id, &storage.owner, &storage.owner, current)
        .await
        .unwrap()
        .unwrap();
    service
        .db
        .complete_oci_upload(&CompleteOciUpload {
            upload_id: upload.id,
            writer_id: storage.owner.clone(),
            token_id: storage.owner.clone(),
            expected_resource_version: claimed.resource_version,
            digest,
            byte_size: bytes.len() as u64,
            surface_object_id: evidence.surface_object_id,
            placement_id: placement.id,
            now: current,
        })
        .await
        .unwrap();
    storage
        .objects
        .lock()
        .unwrap()
        .insert(crate::db::oci_blob_object_key(digest), bytes.to_vec());
    aos_oci_types::Descriptor {
        media_type: MediaType::OctetStream,
        digest,
        size: bytes.len() as u64,
        urls: Vec::new(),
        annotations: aos_oci_types::Annotations::new(),
        data: None,
        artifact_type: None,
        platform: None,
    }
}

async fn runnable_manifest(
    service: &RpcService,
    repository: &OciRepositoryRecord,
    storage: &Storage,
) -> Vec<u8> {
    let mut layer = upload_dependency(
        &service,
        &repository,
        &storage,
        b"actual uncompressed layer",
    )
    .await;
    layer.media_type = MediaType::OciLayerTar;
    let config_bytes = format!("{{ \"os\": \"linux\", \"architecture\": \"amd64\", \"rootfs\": {{\"type\":\"layers\",\"diff_ids\":[\"{}\"]}} }}\n", layer.digest);
    let mut config =
        upload_dependency(&service, &repository, &storage, config_bytes.as_bytes()).await;
    config.media_type = MediaType::OciImageConfig;
    let manifest = aos_oci_types::ImageManifest {
        schema_version: 2,
        media_type: None,
        artifact_type: None,
        config,
        layers: vec![layer],
        subject: None,
        annotations: aos_oci_types::Annotations::new(),
    };
    let mut bytes = aos_oci_types::to_canonical_json(&manifest).unwrap();
    bytes.insert(0, b' ');
    bytes.push(b'\n');
    bytes
}

#[tokio::test]
async fn closed_completion_preserves_noncanonical_bytes_and_terminal_quota_replay() {
    completion_contract(fixture().await).await;
}

async fn completion_contract(
    (service, registry, repository, storage): (
        RpcService,
        RegistryRecord,
        OciRepositoryRecord,
        Storage,
    ),
) {
    let bytes = runnable_manifest(&service, &repository, &storage).await;
    let digest = Sha256Digest::digest(&bytes);
    let mut request = preflight(&bytes);
    request.media_type = MediaType::OciImageManifest;
    let preflight_response = service
        .serve_hybrid_manifest(
            &registry,
            &repository,
            storage.owner.clone(),
            "hub.example.test",
            ManifestReference::Digest(digest),
            index_headers(&storage),
            None,
            Body::from(serde_json::to_vec(&request).unwrap()),
            "preflight",
        )
        .await;
    assert_eq!(preflight_response.status(), StatusCode::OK);
    let admission: HybridOciManifestAdmission = serde_json::from_slice(
        &to_bytes(preflight_response.into_body(), 4096)
            .await
            .unwrap(),
    )
    .unwrap();
    storage
        .objects
        .lock()
        .unwrap()
        .insert(admission.staging_object_key.clone(), bytes.clone());
    let query = format!("{HYBRID_OCI_MANIFEST_UPLOAD_QUERY}={}", admission.upload_id);
    let mut headers = index_headers(&storage);
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/vnd.oci.image.manifest.v1+json"),
    );

    let response = service
        .serve_hybrid_manifest(
            &registry,
            &repository,
            storage.owner.clone(),
            "hub.example.test",
            ManifestReference::Digest(digest),
            headers.clone(),
            Some(&query),
            Body::from("{}"),
            "complete",
        )
        .await;
    let status = response.status();
    let body = to_bytes(response.into_body(), 65536).await.unwrap();
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(
        storage
            .objects
            .lock()
            .unwrap()
            .get(&crate::db::oci_blob_object_key(digest))
            .unwrap(),
        &bytes
    );
    let completed = service
        .db
        .hybrid_oci_manifest_upload(&admission.upload_id, &storage.owner, now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(completed.state, "complete");
    let baseline = service
        .db
        .org_usage(registry.org_id.unwrap())
        .await
        .unwrap();

    // Canonical metadata is not a replacement for the original config bytes
    // on the ordinary API. Only the opaque independent proof admits it.
    let root_descriptor = super::super::document_descriptor(
        MediaType::OciImageManifest,
        digest,
        bytes.len() as u64,
        &crate::oci_projection::OciDocumentProjection::from_stored_bytes(
            &aos_oci_types::Descriptor {
                media_type: MediaType::OciImageManifest,
                digest,
                size: bytes.len() as u64,
                urls: Vec::new(),
                annotations: aos_oci_types::Annotations::new(),
                data: None,
                artifact_type: None,
                platform: None,
            },
            &bytes,
        )
        .unwrap(),
    );
    let mut objects = service
        .db
        .oci_repository_closed_graph(repository.id, &[root_descriptor])
        .await
        .unwrap();
    for object in &mut objects {
        if let Some(crate::db::OciCatalogProjection::Manifest {
            document,
            image_config,
            ..
        }) = &mut object.projection
        {
            let config_bytes = storage
                .objects
                .lock()
                .unwrap()
                .get(&crate::db::oci_blob_object_key(document.config.digest))
                .unwrap()
                .clone();
            let config = aos_oci_types::ImageConfig::from_json(&config_bytes).unwrap();
            let canonical = aos_oci_types::to_canonical_json(&config).unwrap();
            assert_ne!(Sha256Digest::digest(&canonical), document.config.digest);
            *image_config = Some(crate::db::OciImageConfigProjection {
                config_json: String::from_utf8(canonical).unwrap(),
                aos_system: "x86_64-linux".into(),
                layers: vec![crate::db::OciLayerProjection {
                    unpacked_byte_size: document.layers[0].size,
                    diff_id: config.rootfs.diff_ids[0],
                    closure_group: String::new(),
                }],
            });
        }
    }
    assert!(service
        .db
        .index_oci_repository_catalog(&crate::db::IndexOciRepositoryCatalog {
            registry_id: registry.id,
            placement_id: completed.materialization_placement_id.unwrap(),
            repository: repository.name.clone(),
            objects,
            root_digest: digest,
            tag: None,
            source_kind: "manual".into(),
            actor_id: storage.owner.clone(),
            observed_at: now(),
        })
        .await
        .is_err());

    // Delete only fixture staging: lost completion ACK recovers the exact
    // canonical incarnation, without staging or another quota transfer.
    storage
        .objects
        .lock()
        .unwrap()
        .remove(&admission.staging_object_key);
    let replay = service
        .serve_hybrid_manifest(
            &registry,
            &repository,
            storage.owner.clone(),
            "hub.example.test",
            ManifestReference::Digest(digest),
            headers,
            Some(&query),
            Body::from("{}"),
            "complete",
        )
        .await;
    assert_eq!(replay.status(), StatusCode::CREATED);
    let retained = service
        .db
        .hybrid_oci_manifest_upload(&admission.upload_id, &storage.owner, now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retained, completed);
    assert_eq!(
        storage
            .compositions
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        service
            .db
            .org_usage(registry.org_id.unwrap())
            .await
            .unwrap(),
        baseline
    );
}

#[tokio::test]
async fn completion_refuses_raw_body_changed_reference_and_invalid_stored_graph() {
    let (service, registry, repository, storage) = fixture().await;
    let bytes = b"{\"schemaVersion\":2,\"manifests\":[]}";
    let digest = Sha256Digest::digest(bytes);
    let admission = reserve(&service, &registry, &repository, bytes, &storage).await;
    storage
        .objects
        .lock()
        .unwrap()
        .insert(admission.staging_object_key.clone(), bytes.to_vec());
    let query = format!("{HYBRID_OCI_MANIFEST_UPLOAD_QUERY}={}", admission.upload_id);
    let raw = service
        .serve_hybrid_manifest(
            &registry,
            &repository,
            storage.owner.clone(),
            "hub.example.test",
            ManifestReference::Digest(digest),
            index_headers(&storage),
            Some(&query),
            Body::from(bytes.as_slice()),
            "complete",
        )
        .await;
    assert_eq!(raw.status(), StatusCode::BAD_REQUEST);
    let changed = service
        .serve_hybrid_manifest(
            &registry,
            &repository,
            storage.owner.clone(),
            "hub.example.test",
            ManifestReference::parse("changed").unwrap(),
            index_headers(&storage),
            Some(&query),
            Body::from("{}"),
            "complete",
        )
        .await;
    assert_eq!(changed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        service
            .db
            .hybrid_oci_manifest_upload(&admission.upload_id, &storage.owner, now())
            .await
            .unwrap()
            .unwrap()
            .state,
        "active"
    );
    assert!(!storage
        .objects
        .lock()
        .unwrap()
        .contains_key(&crate::db::oci_blob_object_key(digest)));

    // An exact byte hash alone cannot admit malformed or incomplete metadata.
    let malformed = b"exact invalid OCI bytes";
    let invalid = reserve(&service, &registry, &repository, malformed, &storage).await;
    storage
        .objects
        .lock()
        .unwrap()
        .insert(invalid.staging_object_key.clone(), malformed.to_vec());
    let response = service
        .serve_hybrid_manifest(
            &registry,
            &repository,
            storage.owner.clone(),
            "hub.example.test",
            ManifestReference::Digest(Sha256Digest::digest(malformed)),
            index_headers(&storage),
            Some(&format!(
                "{HYBRID_OCI_MANIFEST_UPLOAD_QUERY}={}",
                invalid.upload_id
            )),
            Body::from("{}"),
            "complete",
        )
        .await;
    assert_ne!(response.status(), StatusCode::CREATED);
    assert!(!storage
        .objects
        .lock()
        .unwrap()
        .contains_key(&crate::db::oci_blob_object_key(Sha256Digest::digest(
            malformed
        ))));
}

#[tokio::test]
async fn current_credential_revocation_after_guard_readback_refuses_materialization() {
    let (service, registry, repository, storage) = fixture().await;
    let bytes = runnable_manifest(&service, &repository, &storage).await;
    let digest = Sha256Digest::digest(&bytes);
    let mut request = preflight(&bytes);
    request.media_type = MediaType::OciImageManifest;
    let admission = service
        .reserve_hybrid_manifest(
            &registry,
            &repository,
            &storage.owner,
            &ManifestReference::Digest(digest),
            request,
        )
        .await
        .unwrap();
    storage
        .objects
        .lock()
        .unwrap()
        .insert(admission.staging_object_key.clone(), bytes);
    let token = storage.owner.strip_prefix("token:").unwrap().to_owned();
    *storage.revoke_after_projection.lock().unwrap() = Some((service.db.clone(), token));
    let mut headers = index_headers(&storage);
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/vnd.oci.image.manifest.v1+json"),
    );
    let baseline = service
        .db
        .org_usage(registry.org_id.unwrap())
        .await
        .unwrap();

    let response = service
        .serve_hybrid_manifest(
            &registry,
            &repository,
            storage.owner.clone(),
            "hub.example.test",
            ManifestReference::Digest(digest),
            headers.clone(),
            Some(&format!(
                "{HYBRID_OCI_MANIFEST_UPLOAD_QUERY}={}",
                admission.upload_id
            )),
            Body::from("{}"),
            "complete",
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        storage
            .compositions
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert!(!storage
        .objects
        .lock()
        .unwrap()
        .contains_key(&crate::db::oci_blob_object_key(digest)));
    assert_eq!(
        service
            .db
            .org_usage(registry.org_id.unwrap())
            .await
            .unwrap(),
        baseline
    );

    // The same revoked request is rejected before its body is polled.
    let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let endpoint_polls = polls.clone();
    let body = Body::from_stream(futures_util::stream::poll_fn(move |_| {
        endpoint_polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::task::Poll::Ready(Some(Err::<axum::body::Bytes, _>(std::io::Error::other(
            "body trap",
        ))))
    }));
    let denied = service
        .serve_hybrid_manifest(
            &registry,
            &repository,
            storage.owner.clone(),
            "hub.example.test",
            ManifestReference::Digest(digest),
            headers,
            None,
            body,
            "preflight",
        )
        .await;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(polls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires a disposable AOS_HUB_TEST_PG_URL database"]
async fn guarded_managed_completion_postgres_exact_graph_and_replay() {
    let url = std::env::var("AOS_HUB_TEST_PG_URL").expect("disposable PostgreSQL DSN is required");
    let backend = crate::backend::SqlxBackend::connect_postgres(&url)
        .await
        .unwrap();
    let db = Arc::new(Database::with_backend(Box::new(backend)).await.unwrap());
    completion_contract(fixture_with_database(db).await).await;
}

#[path = "../../../../../../aos-hub-worker/src/oci_manifest_ingress.rs"]
mod body_authorization;

#[tokio::test]
async fn current_bodyless_authorization_precedes_real_incoming_body_poll_and_reservation() {
    let (service, registry, repository, storage) = fixture().await;
    let response = service
        .serve_hybrid_manifest(
            &registry,
            &repository,
            storage.owner.clone(),
            "hub.example.test",
            ManifestReference::Tag(aos_oci_types::Tag::parse("latest").unwrap()),
            index_headers(&storage),
            None,
            Body::empty(),
            "authorize",
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(storage.objects.lock().unwrap().is_empty());
    assert_eq!(
        storage
            .compositions
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );

    service
        .db
        .revoke_token(storage.owner.strip_prefix("token:").unwrap())
        .await
        .unwrap();
    let unread = Body::from_stream(futures_util::stream::poll_fn(
        |_| -> std::task::Poll<Option<Result<axum::body::Bytes, std::io::Error>>> {
            panic!("denied incoming Worker OCI body was polled")
        },
    ));
    let origin = async {
        Ok::<_, anyhow::Error>(
            service
                .serve_hybrid_manifest(
                    &registry,
                    &repository,
                    storage.owner.clone(),
                    "hub.example.test",
                    ManifestReference::Tag(aos_oci_types::Tag::parse("latest").unwrap()),
                    index_headers(&storage),
                    None,
                    Body::empty(),
                    "authorize",
                )
                .await,
        )
    };
    let result = body_authorization::read_authorized(
        origin,
        |response| response.status() == StatusCode::NO_CONTENT,
        || async { Ok::<_, anyhow::Error>(to_bytes(unread, MAX_MANIFEST_BYTES).await?) },
    )
    .await
    .unwrap();
    let body_authorization::AuthorizedBody::Denied(response) = result else {
        panic!("revoked original actor admitted a body");
    };
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(storage.objects.lock().unwrap().is_empty());
    assert_eq!(
        storage
            .compositions
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    let rows = service
        .db
        .backend
        .query("SELECT COUNT(*) FROM oci_upload_sessions", &[])
        .await
        .unwrap();
    assert_eq!(rows[0].get::<i64>(0).unwrap(), 0);
}
