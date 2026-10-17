//! Service regressions for private draft progress and signed publication.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use aos_registry_surface::object::{ObjectKind, TreeEntry, encode_loose, encode_tree, hash_object};
use aos_registry_surface::sshsig::trusted_key_line;
use aos_registry_surface::staging::{
    STAGE_SCHEMA, StageObject, StagePointer, StageRevision, inventory_digest,
};
use sha2::{Digest as _, Sha256};

use crate::db::{
    BindingWriteRevisionRecord, NewRegistryPublication, NewSurfacePlacementSpec,
    RegistryPublicationManifestObject, SetRegistryPublicationObject,
    SetRegistryPublicationPlacement, SurfacePlacementRecord, SurfaceTarget, TokenAuth,
};
use crate::domain::{Permission, Principal, Scope};
use crate::fetch::{SurfaceFetch, SurfaceProvider};
use crate::reindex::Reindexer;
use crate::surface_write::{SurfaceWrite, SurfaceWriteProvider};

use super::{Database, RpcError, RpcService, pb};

#[derive(Clone, Default)]
struct MemorySurface(
    Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    Arc<WriteObservations>,
);

#[derive(Default)]
struct WriteObservations {
    delay_millis: AtomicUsize,
    active: AtomicUsize,
    peak: AtomicUsize,
    completed: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl SurfaceFetch for MemorySurface {
    async fn fetch(&self, path: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().get(path).cloned())
    }

    fn describe(&self) -> String {
        "staged release fixture".into()
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
        let delay = self.1.delay_millis.load(Ordering::SeqCst);
        if delay != 0 {
            let active = self.1.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.1.peak.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(delay as u64)).await;
            self.1.active.fetch_sub(1, Ordering::SeqCst);
            self.1.completed.lock().unwrap().push(path.to_owned());
        }
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
        Ok(Box::new(self.clone()))
    }
}

struct InlineIndex {
    db: Arc<Database>,
    storage: MemorySurface,
    placement_id: i64,
}

struct DeferredIndex;

#[async_trait::async_trait]
impl Reindexer for DeferredIndex {
    async fn reindex(&self, _: &crate::db::RegistryRecord) -> anyhow::Result<Option<String>> {
        Ok(None)
    }
}

#[async_trait::async_trait]
impl Reindexer for InlineIndex {
    async fn reindex(
        &self,
        registry: &crate::db::RegistryRecord,
    ) -> anyhow::Result<Option<String>> {
        let outcome = crate::indexer::index_and_record_from_placement(
            &self.db,
            &self.storage,
            registry,
            Some(self.placement_id),
        )
        .await
        .map_err(|error| {
            // Production keeps a committed publication resumable when its
            // index refresh fails. Surface that retained error in this fixture.
            eprintln!("staged release fixture index failed: {error:#}");
            error
        })?;
        Ok(Some(outcome.commit))
    }
}

struct Fixture {
    service: RpcService,
    auth: String,
    read_auth: String,
    storage: MemorySurface,
    revision: StageRevision,
    immutable: BTreeMap<String, Vec<u8>>,
    publication_id: String,
    registry_id: i64,
}

fn object(kind: ObjectKind, payload: &[u8]) -> (String, Vec<u8>) {
    (
        hash_object(kind, payload).loose_path(),
        encode_loose(kind, payload).unwrap(),
    )
}

async fn fixture() -> Fixture {
    let (mut service, db, auth) = super::cache_upload_tests::release_test_service().await;
    let storage = MemorySurface::default();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
    let trust = vec![trusted_key_line("test", &signing_key.verifying_key())];
    let org_id = db.create_org("stage-tests", "Stage tests").await.unwrap();
    let registry_id = db
        .create_managed_registry(org_id, "", "main", "public", &trust, false)
        .await
        .unwrap();
    let org = db.org_by_id(org_id).await.unwrap().unwrap();
    let binding_id = db
        .create_topology_binding(
            Some(org_id),
            "stage-tests-binding",
            &org.stable_id,
            "registry",
            "r2",
            None,
            Some("stage-tests"),
            Some("registry"),
            Some("https"),
            Some("dns"),
            Some(b"storage.example.invalid"),
            Some(443),
            Some("auto"),
            Some("private"),
        )
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "primary".into(),
            binding_id,
            prefix: "main".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await
        .unwrap();
    let placement = db
        .observe_surface_placement(placement.id, "ready", "complete", 1)
        .await
        .unwrap();

    let root = b"[registry]\nname = \"Stage catalog\"\n";
    let blob_oid = hash_object(ObjectKind::Blob, root);
    let tree_payload = encode_tree(&[TreeEntry {
        mode: "100644".into(),
        name: "registry.toml".into(),
        oid: blob_oid,
    }]);
    let tree_oid = hash_object(ObjectKind::Tree, &tree_payload);
    let commit_payload = format!(
        "tree {tree_oid}\nauthor Test <test@example.test> 1 +0000\ncommitter Test <test@example.test> 1 +0000\n\nCandidate\n"
    );
    let commit = hash_object(ObjectKind::Commit, commit_payload.as_bytes());
    let tag =
        crate::signing::sign_release_tag(&signing_key, "2026.10.0", &commit.to_hex(), 1).unwrap();
    let initial_refs = format!("{commit}\trefs/heads/stable\n").into_bytes();
    storage
        .0
        .lock()
        .unwrap()
        .insert("HEAD".into(), b"ref: refs/heads/stable\n".to_vec());
    storage
        .0
        .lock()
        .unwrap()
        .insert("info/refs".into(), initial_refs.clone());

    let mut publication = Vec::new();
    for (path, bytes) in [
        object(ObjectKind::Blob, root),
        object(ObjectKind::Tree, &tree_payload),
        object(ObjectKind::Commit, commit_payload.as_bytes()),
        (tag.oid.loose_path(), tag.loose_bytes),
    ] {
        publication.push(StagePointer {
            path,
            bytes,
            expected_sha256: None,
        });
    }
    publication.push(StagePointer {
        path: "info/refs".into(),
        bytes: format!(
            "{commit}\trefs/heads/stable\n{}\trefs/tags/2026.10.0\n",
            tag.oid
        )
        .into_bytes(),
        expected_sha256: Some(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(&initial_refs))
        )),
    });

    let mut pack = b"PACK\x00\x00\x00\x02\x00\x00\x00\x00".to_vec();
    let pack_hash = hex::encode(Sha256::digest(&pack));
    pack.extend_from_slice(&Sha256::digest(&pack));
    let pack_path = format!("releases/2026/10/0/objects/pack/pack-{pack_hash}.pack");
    publication.push(StagePointer {
        path: "releases/2026/10/0/objects/info/packs".into(),
        bytes: format!("P pack-{pack_hash}.pack\n").into_bytes(),
        expected_sha256: None,
    });
    publication.sort_by(|left, right| left.path.cmp(&right.path));

    let artifact = b"exact staged artifact".to_vec();
    let artifact_hash = hex::encode(Sha256::digest(&artifact));
    let immutable = BTreeMap::from([
        (pack_path, pack),
        (format!("nar/{artifact_hash}.nar.xz"), artifact),
    ]);
    let inventory: Vec<_> = immutable
        .iter()
        .map(|(path, bytes)| StageObject {
            path: path.clone(),
            sha256: format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
            byte_size: bytes.len() as u64,
            kind: "registry".into(),
            media_type: super::publication_media_type(path).into(),
        })
        .collect();
    let revision = StageRevision {
        schema: STAGE_SCHEMA.into(),
        id: "candidate".into(),
        registry: "stage-tests/main".into(),
        revision: 1,
        release_id: "2026.10.0".into(),
        source_branch: "dplecki/candidate".into(),
        commit: commit.to_hex(),
        inventory_digest: inventory_digest(&inventory).unwrap(),
        inventory,
        publication,
        container: None,
        store_roots: Vec::new(),
    };
    revision.validate().unwrap();
    let publication_id = "stage-tests-publication".to_string();
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: publication_id.clone(),
        registry_id,
        generation: "candidate".into(),
        manifest_digest: "a".repeat(64),
        refs_digest: hex::encode(Sha256::digest(
            &revision
                .publication
                .iter()
                .find(|pointer| pointer.path == "info/refs")
                .unwrap()
                .bytes,
        )),
        default_commit: Some(commit.to_hex()),
        parent_publication_id: None,
    })
    .await
    .unwrap();
    db.set_registry_publication_placement(&SetRegistryPublicationPlacement {
        publication_id: publication_id.clone(),
        placement_id: placement.id,
        required: true,
        state: "preparing".into(),
        observed_at: 1,
    })
    .await
    .unwrap();
    // Admit fresh placeholders through the publication path that records their
    // accounting origin; generic catalogue insertion preserves unknown origins.
    let manifest = immutable
        .iter()
        .map(|(path, bytes)| (path, bytes, "immutable"))
        .chain(
            revision
                .publication
                .iter()
                .map(|pointer| (&pointer.path, &pointer.bytes, "mutable_pointer")),
        )
        .map(|(path, bytes, kind)| RegistryPublicationManifestObject {
            object_key: path.clone(),
            expected_hash: hex::encode(Sha256::digest(bytes)),
            expected_size: bytes.len() as i64,
            object_kind: kind.into(),
        })
        .collect::<Vec<_>>();
    db.admit_registry_publication_manifest_objects(registry_id, &publication_id, &manifest)
        .await
        .unwrap();

    let user = db
        .user_by_email("writer@example.test")
        .await
        .unwrap()
        .unwrap();
    let owner = Principal::user(user);
    let owner_incarnation = db.principal_incarnation(owner).await.unwrap();
    let read_token = service
        .jwt_keys
        .mint(
            &TokenAuth {
                token_id: "stage-read-only".into(),
                owner,
                owner_incarnation,
                browser_session_id_hash: None,
                scope: Scope::root(),
                permissions: vec![Permission::Read],
            },
            3600,
        )
        .unwrap();
    service.surface = Arc::new(storage.clone());
    service.surface_write = Arc::new(storage.clone());
    service.reindexer = Arc::new(InlineIndex {
        db,
        storage: storage.clone(),
        placement_id: placement.id,
    });
    Fixture {
        service,
        auth,
        read_auth: format!("Bearer {read_token}"),
        storage,
        revision,
        immutable,
        publication_id,
        registry_id,
    }
}

impl Fixture {
    async fn admit(&self) -> pb::StagedRelease {
        self.service
            .upsert_staged_release(
                Some(&self.auth),
                pb::UpsertStagedReleaseRequest {
                    registry: self.revision.registry.clone(),
                    revision_json: serde_json::to_string(&self.revision).unwrap(),
                    expected_revision: 0,
                    publication_id: self.publication_id.clone(),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
    }

    async fn upload(&self, path: &str) {
        let object = self
            .service
            .db
            .registry_publication_upload_objects(&self.publication_id)
            .await
            .unwrap()
            .into_iter()
            .find(|object| object.object_key == path)
            .unwrap();
        self.service
            .upload_registry_publication_object(
                Some(&self.auth),
                &self.publication_id,
                object.surface_object_id,
                axum::body::Body::from(self.immutable[path].clone()),
            )
            .await
            .unwrap();
    }

    fn finalize_request(&self) -> pb::FinalizeStagedReleaseRequest {
        pb::FinalizeStagedReleaseRequest {
            registry: self.revision.registry.clone(),
            stage_id: self.revision.id.clone(),
            expected_revision: 1,
            release_id: self.revision.release_id.clone(),
        }
    }
}

#[tokio::test]
async fn staged_releases_private_progress_and_signed_finalize_end_to_end() {
    let fixture = fixture().await;
    let admitted = fixture.admit().await;
    assert_eq!(admitted.state, "draft");
    assert_eq!(admitted.missing_paths.len(), 2);
    assert_eq!(admitted.uploaded_bytes, 0);
    assert!(
        fixture
            .service
            .db
            .release_record(fixture.registry_id, &fixture.revision.release_id)
            .await
            .unwrap()
            .is_none()
    );

    let paths: Vec<_> = fixture.immutable.keys().cloned().collect();
    fixture.upload(&paths[0]).await;
    let partial = fixture
        .service
        .get_staged_release(
            Some(&fixture.auth),
            pb::GetStagedReleaseRequest {
                registry: fixture.revision.registry.clone(),
                stage_id: fixture.revision.id.clone(),
            },
        )
        .await
        .unwrap();
    assert_eq!(partial.state, "draft");
    assert_eq!(partial.missing_paths, vec![paths[1].clone()]);
    assert!(partial.uploaded_bytes > 0 && partial.uploaded_bytes < partial.total_bytes);
    assert!(
        fixture
            .service
            .finalize_staged_release(Some(&fixture.auth), fixture.finalize_request())
            .await
            .is_err()
    );
    assert!(
        !String::from_utf8(fixture.storage.fetch("info/refs").await.unwrap().unwrap())
            .unwrap()
            .contains("refs/tags/")
    );
    assert!(
        fixture
            .service
            .commit_registry_publication(
                Some(&fixture.auth),
                pb::CommitRegistryPublicationRequest {
                    publication_id: fixture.publication_id.clone(),
                }
            )
            .await
            .is_err()
    );

    fixture.upload(&paths[1]).await;
    let ready = fixture
        .service
        .get_staged_release(
            Some(&fixture.auth),
            pb::GetStagedReleaseRequest {
                registry: fixture.revision.registry.clone(),
                stage_id: fixture.revision.id.clone(),
            },
        )
        .await
        .unwrap();
    assert_eq!(ready.state, "ready");
    assert_eq!(ready.uploaded_bytes, ready.total_bytes);
    fixture.storage.1.delay_millis.store(20, Ordering::SeqCst);

    let released = fixture
        .service
        .finalize_staged_release(Some(&fixture.auth), fixture.finalize_request())
        .await;
    let released = released.unwrap();
    assert_eq!(released.state, "released");
    assert_eq!(released.released_version, fixture.revision.release_id);
    let writes = &fixture.storage.1;
    assert!(writes.peak.load(Ordering::SeqCst) >= 2);
    assert!(writes.peak.load(Ordering::SeqCst) <= 8);
    assert_eq!(writes.active.load(Ordering::SeqCst), 0);
    let completed = writes.completed.lock().unwrap().clone();
    assert_eq!(completed.len(), fixture.revision.publication.len());
    assert_eq!(completed.last().map(String::as_str), Some("info/refs"));

    assert!(
        String::from_utf8(fixture.storage.fetch("info/refs").await.unwrap().unwrap())
            .unwrap()
            .contains("refs/tags/2026.10.0")
    );
    assert_eq!(
        fixture
            .service
            .finalize_staged_release(Some(&fixture.auth), fixture.finalize_request())
            .await
            .unwrap()
            .state,
        "released"
    );
}

#[tokio::test]
async fn staged_releases_committed_retry_preserves_a_later_publication() {
    let mut fixture = fixture().await;
    fixture.service.reindexer = Arc::new(DeferredIndex);
    fixture.admit().await;
    for path in fixture.immutable.keys() {
        fixture.upload(path).await;
    }
    let pending = fixture
        .service
        .finalize_staged_release(Some(&fixture.auth), fixture.finalize_request())
        .await
        .unwrap();
    assert_eq!(pending.state, "releasing");
    assert_eq!(
        fixture
            .service
            .db
            .registry_publication(&fixture.publication_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        "ready"
    );

    let placement_id = fixture
        .service
        .db
        .registry_publication_placement_records(&fixture.publication_id)
        .await
        .unwrap()[0]
        .placement_id;
    let previous_refs = fixture.storage.fetch("info/refs").await.unwrap().unwrap();
    let later_refs = [
        format!("{}\trefs/heads/dplecki/later\n", fixture.revision.commit).into_bytes(),
        previous_refs,
    ]
    .concat();
    let later_id = "stage-tests-later-publication";
    fixture
        .service
        .db
        .create_registry_publication(&NewRegistryPublication {
            publication_id: later_id.into(),
            registry_id: fixture.registry_id,
            generation: "later".into(),
            manifest_digest: "c".repeat(64),
            refs_digest: hex::encode(Sha256::digest(&later_refs)),
            default_commit: Some(fixture.revision.commit.clone()),
            parent_publication_id: Some(fixture.publication_id.clone()),
        })
        .await
        .unwrap();
    fixture
        .service
        .db
        .set_registry_publication_placement(&SetRegistryPublicationPlacement {
            publication_id: later_id.into(),
            placement_id,
            required: true,
            state: "preparing".into(),
            observed_at: 2,
        })
        .await
        .unwrap();
    let declared = fixture
        .service
        .db
        .registry_publication_upload_objects(&fixture.publication_id)
        .await
        .unwrap();
    let refs_id = declared
        .iter()
        .find(|object| object.object_key == "info/refs")
        .unwrap()
        .surface_object_id;
    for object in declared {
        let changed = object.object_key == "info/refs";
        fixture
            .service
            .db
            .set_registry_publication_object(&SetRegistryPublicationObject {
                publication_id: later_id.into(),
                surface_object_id: object.surface_object_id,
                object_kind: object.object_kind,
                expected_hash: if changed {
                    hex::encode(Sha256::digest(&later_refs))
                } else {
                    object.expected_hash
                },
                expected_size: if changed {
                    later_refs.len() as i64
                } else {
                    object.expected_size
                },
            })
            .await
            .unwrap();
    }
    fixture.service.reindexer = Arc::new(InlineIndex {
        db: Arc::clone(&fixture.service.db),
        storage: fixture.storage.clone(),
        placement_id,
    });
    fixture
        .service
        .upload_registry_publication_object(
            Some(&fixture.auth),
            later_id,
            refs_id,
            axum::body::Body::from(later_refs.clone()),
        )
        .await
        .unwrap();
    fixture
        .service
        .commit_registry_publication(
            Some(&fixture.auth),
            pb::CommitRegistryPublicationRequest {
                publication_id: later_id.into(),
            },
        )
        .await
        .unwrap();

    let released = fixture
        .service
        .finalize_staged_release(Some(&fixture.auth), fixture.finalize_request())
        .await
        .unwrap();
    assert_eq!(released.state, "released");
    assert_eq!(
        fixture.storage.fetch("info/refs").await.unwrap().unwrap(),
        later_refs
    );
    assert_eq!(
        fixture
            .service
            .db
            .surface_placement(placement_id)
            .await
            .unwrap()
            .unwrap()
            .mutable_publication_id
            .as_deref(),
        Some(later_id)
    );
}

#[tokio::test]
async fn staged_releases_discovery_requires_publish_even_on_public_registry() {
    let fixture = fixture().await;
    fixture.admit().await;
    for auth in [None, Some(fixture.read_auth.as_str())] {
        assert!(
            fixture
                .service
                .list_staged_releases(
                    auth,
                    pb::ListStagedReleasesRequest {
                        registry: fixture.revision.registry.clone(),
                        ..Default::default()
                    }
                )
                .await
                .is_err()
        );
        assert!(
            fixture
                .service
                .get_staged_release(
                    auth,
                    pb::GetStagedReleaseRequest {
                        registry: fixture.revision.registry.clone(),
                        stage_id: fixture.revision.id.clone(),
                    }
                )
                .await
                .is_err()
        );
        assert!(
            fixture
                .service
                .finalize_staged_release(auth, fixture.finalize_request())
                .await
                .is_err()
        );
    }
    let stages = fixture
        .service
        .list_staged_releases(
            Some(&fixture.auth),
            pb::ListStagedReleasesRequest {
                registry: fixture.revision.registry.clone(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(stages.stages.len(), 1);
    assert!(stages.stages[0].revision_json.is_empty());
    assert_eq!(stages.stages[0].missing_object_count, 2);
}

#[tokio::test]
async fn staged_releases_discard_is_idempotent_and_closes_upload_and_pointer_admission() {
    let fixture = fixture().await;
    fixture.admit().await;
    let request = pb::DiscardStagedReleaseRequest {
        registry: fixture.revision.registry.clone(),
        stage_id: fixture.revision.id.clone(),
        expected_revision: 1,
    };
    assert_eq!(
        fixture
            .service
            .discard_staged_release(Some(&fixture.auth), request.clone())
            .await
            .unwrap()
            .state,
        "discarded"
    );
    assert_eq!(
        fixture
            .service
            .discard_staged_release(Some(&fixture.auth), request)
            .await
            .unwrap()
            .state,
        "discarded"
    );
    assert_eq!(
        fixture
            .service
            .db
            .registry_publication(&fixture.publication_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        "failed"
    );
    assert!(matches!(
        fixture
            .service
            .finalize_staged_release(Some(&fixture.auth), fixture.finalize_request())
            .await,
        Err(RpcError::FailedPrecondition(_))
    ));
    assert!(
        !String::from_utf8(fixture.storage.fetch("info/refs").await.unwrap().unwrap())
            .unwrap()
            .contains("refs/tags/")
    );
}

#[tokio::test]
async fn staged_releases_shared_client_rpc_revision_cas_and_finalization() {
    use aos_package::registry::hub_stage::HubStageClient;
    use aos_registry_surface::staging::StageState;

    let fixture = fixture().await;
    let mut revision = fixture.revision.clone();
    let paths: Vec<_> = fixture.immutable.keys().cloned().collect();
    let auth_token = fixture.auth.strip_prefix("Bearer ").unwrap().to_string();
    let registry = revision.registry.clone();
    let publication_id = fixture.publication_id.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let service = Arc::new(fixture.service);
    let router = crate::connect::rpc_router(Arc::clone(&service));
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = HubStageClient::connect(&origin, &registry, Some(&auth_token))
        .await
        .unwrap();

    let admitted = client.upsert(&revision, 0, None).await.unwrap();
    assert_eq!(admitted.record.state, StageState::Draft);
    assert_eq!(client.list().await.unwrap()[0].missing_object_count, 2);
    assert_eq!(
        client.show(&revision.id).await.unwrap().record.revision,
        revision
    );

    let previous = revision.clone();
    revision.revision = 2;
    revision.source_branch = "dplecki/revised-candidate".into();
    let updated = client
        .upsert(&revision, 1, Some(&publication_id))
        .await
        .unwrap();
    assert_eq!(updated.record.revision.revision, 2);
    assert!(client.upsert(&previous, 0, None).await.is_err());
    assert!(client.finalize(&previous).await.is_err());

    for path in paths {
        let object = service
            .db
            .registry_publication_upload_objects(&publication_id)
            .await
            .unwrap()
            .into_iter()
            .find(|object| object.object_key == path)
            .unwrap();
        service
            .upload_registry_publication_object(
                Some(&fixture.auth),
                &publication_id,
                object.surface_object_id,
                axum::body::Body::from(fixture.immutable[&path].clone()),
            )
            .await
            .unwrap();
    }
    assert_eq!(
        client.show(&revision.id).await.unwrap().record.state,
        StageState::Ready
    );
    assert_eq!(
        client.finalize(&revision).await.unwrap().record.state,
        StageState::Released
    );
    assert_eq!(
        client.finalize(&revision).await.unwrap().record.state,
        StageState::Released
    );
    assert!(client.discard(&revision.id, 2).await.is_err());
    let mut third = revision.clone();
    third.revision = 3;
    assert!(client.upsert(&third, 2, None).await.is_err());
    server.abort();
}
