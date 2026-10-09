//! Shared fixtures and capability regression suites.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Result};
use base64::Engine as _;
use sha2::{Digest as _, Sha256};

use super::{
    collect_plan_pin_impacts, multipart_completion_matches, narinfo_store_hash,
    parse_cache_narinfo, pb, render_nix_cache_info, validate_signing_key_consumer_compatibility,
    RpcError, RpcService,
};
use crate::auth::jwt::JwtKeys;
use crate::auth::seal::SecretSealer;
use crate::coordinator::InMemoryCoordinator;
use crate::db::{
    ChannelSummary, Database, IndexSnapshot, IndexedSystemImage, NewRegistryPublication,
    NewSurfacePlacementSpec, RegistryRecord, ReleaseImageSnapshot, ReleaseRow,
    SetRegistryPublicationObject, SetRegistryPublicationPlacement, SetSurfaceObject,
    SurfacePlacementBlockers, SurfaceTarget, TokenAuth, VerifiedRegistryImageObject,
    WriteTicketPartRecord,
};
use crate::domain::{Permission, Principal, Role, Scope};
use crate::fetch::{StreamedRead, SurfaceFetch, SurfaceObjectEvidence, SurfaceProvider};
use crate::lease::InMemoryLease;
use crate::ratelimit::CoordinatorRateLimiter;
use crate::reindex::Reindexer;
use crate::surface_write::{
    MultipartAbortOutcome, PartTag, SurfaceDeleteOutcome, SurfaceDeletePrecondition, SurfaceWrite,
    SurfaceWriteProvider,
};
use crate::topology_probe::DatabaseTopologyProbeScheduler;

#[allow(dead_code)]
#[derive(Clone)]
enum FetchBehavior {
    Missing,
    Failure,
    ProviderFailure,
    Evidence { bytes: Vec<u8>, strong_etag: String },
}

struct InjectedFetch {
    behavior: FetchBehavior,
}

#[async_trait::async_trait]
impl SurfaceFetch for InjectedFetch {
    async fn fetch(&self, _path: &str) -> Result<Option<Vec<u8>>> {
        match &self.behavior {
            FetchBehavior::Missing => Ok(None),
            FetchBehavior::Failure => bail!("injected inventory failure"),
            FetchBehavior::ProviderFailure => {
                bail!("provider failure reached an injected fetcher")
            }
            FetchBehavior::Evidence { bytes, .. } => Ok(Some(bytes.clone())),
        }
    }

    async fn inventory_evidence(&self, _path: &str) -> Result<Option<SurfaceObjectEvidence>> {
        match &self.behavior {
            FetchBehavior::Missing => Ok(None),
            FetchBehavior::Failure => bail!("injected inventory failure"),
            FetchBehavior::ProviderFailure => {
                bail!("provider failure reached an injected fetcher")
            }
            FetchBehavior::Evidence { bytes, strong_etag } => Ok(Some(SurfaceObjectEvidence {
                sha256: Sha256::digest(bytes).into(),
                size: i64::try_from(bytes.len()).unwrap(),
                strong_etag: Some(strong_etag.clone()),
            })),
        }
    }

    fn describe(&self) -> String {
        "injected-test".into()
    }
}

struct InjectedSurfaceProvider {
    behaviors: Mutex<VecDeque<FetchBehavior>>,
}

struct CountingRejectingSurfaceProvider {
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl SurfaceProvider for CountingRejectingSurfaceProvider {
    async fn placement_fetcher(
        &self,
        _placement: &crate::db::SurfacePlacementRecord,
    ) -> Result<Box<dyn SurfaceFetch>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        bail!("image metadata-only response reached the placement backend")
    }
}

#[async_trait::async_trait]
impl SurfaceProvider for InjectedSurfaceProvider {
    async fn placement_fetcher(
        &self,
        _placement: &crate::db::SurfacePlacementRecord,
    ) -> Result<Box<dyn SurfaceFetch>> {
        let behavior = self
            .behaviors
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(FetchBehavior::Missing);
        if matches!(behavior, FetchBehavior::ProviderFailure) {
            bail!("injected placement fetcher resolution failure");
        }
        Ok(Box::new(InjectedFetch { behavior }))
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
enum WriteBehavior {
    Success,
    PutFailure,
    CreateFailure,
    ProviderFailure,
    MultipartUnsupported,
}

struct InjectedWriter {
    behavior: WriteBehavior,
}

#[async_trait::async_trait]
impl SurfaceWrite for InjectedWriter {
    fn multipart_protocol_version(&self) -> Option<u32> {
        if matches!(self.behavior, WriteBehavior::MultipartUnsupported) {
            None
        } else {
            Some(1)
        }
    }

    async fn write(&self, _path: &str, _bytes: &[u8]) -> Result<()> {
        if matches!(self.behavior, WriteBehavior::PutFailure) {
            bail!("injected PUT failure");
        }
        Ok(())
    }

    async fn delete(&self, _path: &str) -> Result<()> {
        Ok(())
    }

    async fn delete_if_matches(
        &self,
        _path: &str,
        _expected: &SurfaceDeletePrecondition,
    ) -> Result<SurfaceDeleteOutcome> {
        Ok(SurfaceDeleteOutcome::NotFound)
    }

    async fn create_multipart(&self, _path: &str) -> Result<String> {
        if matches!(self.behavior, WriteBehavior::CreateFailure) {
            bail!("injected multipart creation failure");
        }
        Ok("backend-upload".into())
    }

    async fn abort_multipart(
        &self,
        _path: &str,
        _upload_id: &str,
    ) -> Result<MultipartAbortOutcome> {
        Ok(MultipartAbortOutcome::Aborted)
    }
}

struct InjectedWriteProvider {
    behaviors: Mutex<VecDeque<WriteBehavior>>,
}

#[async_trait::async_trait]
impl SurfaceWriteProvider for InjectedWriteProvider {
    async fn placement_writer(
        &self,
        _placement: &crate::db::SurfacePlacementRecord,
    ) -> Result<Box<dyn SurfaceWrite>> {
        let behavior = self
            .behaviors
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(WriteBehavior::Success);
        if matches!(behavior, WriteBehavior::ProviderFailure) {
            bail!("injected placement writer resolution failure");
        }
        Ok(Box::new(InjectedWriter { behavior }))
    }

    async fn placement_writer_at_revision(
        &self,
        placement: &crate::db::SurfacePlacementRecord,
        _revision: &crate::db::BindingWriteRevisionRecord,
    ) -> Result<Box<dyn SurfaceWrite>> {
        self.placement_writer(placement).await
    }

    async fn placement_deleter(
        &self,
        _placement: &crate::db::SurfacePlacementRecord,
        _expected_binding_resource_version: i64,
        _delete_credential_generation: i64,
    ) -> Result<Box<dyn SurfaceWrite>> {
        Ok(Box::new(InjectedWriter {
            behavior: WriteBehavior::Success,
        }))
    }
}

struct InjectedReindexer {
    calls: Option<Arc<AtomicUsize>>,
}

#[async_trait::async_trait]
impl Reindexer for InjectedReindexer {
    async fn reindex(&self, _registry: &RegistryRecord) -> Result<Option<String>> {
        if let Some(calls) = &self.calls {
            calls.fetch_add(1, Ordering::SeqCst);
        }
        Ok(None)
    }
}

#[derive(Clone, Copy)]
enum SealerBehavior {
    Credential,
    Failure,
}

struct InjectedSealer {
    behaviors: Mutex<VecDeque<SealerBehavior>>,
}

impl SecretSealer for InjectedSealer {
    fn seal(&self, plaintext: &str) -> Result<String> {
        Ok(format!("sealed:{plaintext}"))
    }

    fn unseal(&self, sealed: &str) -> Result<String> {
        if let Some(plaintext) = sealed.strip_prefix("sealed:") {
            return Ok(plaintext.to_string());
        }
        match self
            .behaviors
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(SealerBehavior::Credential)
        {
            SealerBehavior::Credential => Ok("access:secret:us-test-1".into()),
            SealerBehavior::Failure => bail!("injected secret resolution failure"),
        }
    }
}

struct PublishedIdentityDomain;

#[async_trait::async_trait]
impl crate::topology_probe::IdentityDomainVerifier for PublishedIdentityDomain {
    async fn challenge_is_published(&self, _domain: &str, _challenge: &str) -> Result<bool> {
        Ok(true)
    }
}

struct UnavailableIdentityDomain;

#[async_trait::async_trait]
impl crate::topology_probe::IdentityDomainVerifier for UnavailableIdentityDomain {
    async fn challenge_is_published(&self, _domain: &str, _challenge: &str) -> Result<bool> {
        bail!("injected DNS transport failure")
    }
}

async fn injected_service(
    fetch_behaviors: Vec<FetchBehavior>,
    write_behaviors: Vec<WriteBehavior>,
) -> (RpcService, Arc<Database>, Arc<InMemoryLease>, String) {
    injected_service_with_sealer(fetch_behaviors, write_behaviors, vec![]).await
}

pub(crate) async fn delivery_test_service() -> (RpcService, Arc<Database>) {
    let (service, database, _, _) = injected_service(vec![], vec![]).await;
    (service, database)
}

/// Builds a service and a bearer token holding instance-wide `publish`.
pub(super) async fn release_test_service() -> (RpcService, Arc<Database>, String) {
    let (service, database, _, auth) = injected_service(vec![], vec![]).await;
    (service, database, auth)
}

async fn injected_service_with_sealer(
    fetch_behaviors: Vec<FetchBehavior>,
    write_behaviors: Vec<WriteBehavior>,
    sealer_behaviors: Vec<SealerBehavior>,
) -> (RpcService, Arc<Database>, Arc<InMemoryLease>, String) {
    injected_service_with_dependencies(
        fetch_behaviors,
        write_behaviors,
        sealer_behaviors,
        Arc::new(InjectedReindexer { calls: None }),
    )
    .await
}

async fn injected_service_with_reindexer(
    reindexer: Arc<dyn Reindexer>,
) -> (RpcService, Arc<Database>, Arc<InMemoryLease>, String) {
    injected_service_with_dependencies(vec![], vec![], vec![], reindexer).await
}

async fn injected_service_with_dependencies(
    fetch_behaviors: Vec<FetchBehavior>,
    write_behaviors: Vec<WriteBehavior>,
    sealer_behaviors: Vec<SealerBehavior>,
    reindexer: Arc<dyn Reindexer>,
) -> (RpcService, Arc<Database>, Arc<InMemoryLease>, String) {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.install_write_failure_test_tickets().await.unwrap();
    let user_id = db.create_user("writer@example.test", None).await.unwrap();
    db.grant_membership("user", user_id, "instance", Role::Owner.as_str())
        .await
        .unwrap();
    let jwt_keys = JwtKeys::from_secret(b"injected-write-flow-test-key");
    let user_id = db
        .user_by_email("writer@example.test")
        .await
        .unwrap()
        .unwrap();
    let token = jwt_keys
        .mint(
            &TokenAuth {
                token_id: "holder".into(),
                owner: Principal::user(user_id),
                scope: Scope::root(),
                permissions: vec![
                    Permission::RegistryConfigure,
                    Permission::Publish,
                    Permission::TokensManage,
                    Permission::IamAdmin,
                    Permission::MembersManage,
                ],
            },
            3600,
        )
        .unwrap();
    let coordinator = Arc::new(InMemoryCoordinator::new());
    let lease = Arc::new(InMemoryLease::new());
    let service = RpcService::new(
        Arc::clone(&db),
        jwt_keys,
        "https://hub.example.test".into(),
        Arc::new(CoordinatorRateLimiter::new(coordinator)),
        Arc::new(InjectedSurfaceProvider {
            behaviors: Mutex::new(fetch_behaviors.into()),
        }),
        Arc::new(InjectedWriteProvider {
            behaviors: Mutex::new(write_behaviors.into()),
        }),
        lease.clone(),
        reindexer,
        Arc::new(DatabaseTopologyProbeScheduler::new(Arc::clone(&db))),
        Some(Arc::new(InjectedSealer {
            behaviors: Mutex::new(sealer_behaviors.into()),
        })),
    )
    .with_container_rollout(crate::container_rollout::ContainerRollout::all_enabled())
    .with_identity_domain_verifier(Arc::new(PublishedIdentityDomain));
    (service, db, lease, format!("Bearer {token}"))
}

fn one_signed_raw_image_package() -> aos_registry_format::manifest::PackageToml {
    use aos_registry_format::manifest::{
        immutable_image_contract_object_key, immutable_image_object_key,
        ImageArtifactContractDocumentReference, ImageArtifactContractReference, ImageCompression,
        ImageDelivery, ImageEntry, ImageTarget,
    };

    let image_sha256 = "a".repeat(64);
    let info_sha256 = "b".repeat(64);
    let filename = "aos-system.img.zst";
    let image = ImageEntry {
        format: "raw".into(),
        store_path: "/aos/store/aos-system-raw".into(),
        nar_hash: "sha256:nar".into(),
        nar_size: 1,
        delivery: ImageDelivery {
            schema_version: 1,
            release: "2026.8.0".into(),
            platform: "x86_64-linux".into(),
            architecture: "x86_64".into(),
            logical_image_id: "c".repeat(64),
            logical_disk_sha256: image_sha256.clone(),
            filename: filename.into(),
            object_key: immutable_image_object_key(&image_sha256, filename),
            media_type: "application/vnd.aos.disk-image.raw+zstd".into(),
            compression: ImageCompression::Zstd,
            byte_size: 16,
            sha256: image_sha256.clone(),
            compatible_targets: vec![ImageTarget::BareMetal],
            artifact_contract: ImageArtifactContractReference {
                schema: "aos.test.boot-artifacts/v1".into(),
                document: ImageArtifactContractDocumentReference {
                    filename: "image-info.json".into(),
                    object_key: immutable_image_contract_object_key(
                        &image_sha256,
                        &info_sha256,
                        "image-info.json",
                    ),
                    store_path: String::new(),
                    nar_hash: String::new(),
                    nar_size: 0,
                    media_type: "application/vnd.aos.image-info+json".into(),
                    byte_size: 8,
                    sha256: info_sha256,
                },
                artifacts: None,
            },
        },
    };
    let mut package: toml::Value = toml::from_str(
            "[package]\nname = \"aos-system\"\ndescription = \"AOS system\"\nlicense = \"MIT\"\nmaintainer = \"aos\"\nsysroot = true\n\n[[versions]]\nversion = \"2026.8.0\"\n\n[versions.platforms.x86_64-linux]\nstore_path = \"/aos/store/aos-system\"\nclosure_size = 1\nsource_drv = \"\"\nsource_nar_hash = \"\"\n",
        )
        .unwrap();
    package
        .get_mut("versions")
        .and_then(toml::Value::as_array_mut)
        .unwrap()[0]
        .get_mut("platforms")
        .and_then(toml::Value::as_table_mut)
        .unwrap()
        .get_mut("x86_64-linux")
        .and_then(toml::Value::as_table_mut)
        .unwrap()
        .insert("images".into(), toml::Value::try_from(vec![image]).unwrap());
    toml::from_str(&toml::to_string(&package).unwrap()).unwrap()
}

fn one_signed_raw_image_release(
    package: &aos_registry_format::manifest::PackageToml,
) -> ReleaseImageSnapshot {
    let version = &package.versions[0];
    let (platform, artifact) = version.platforms.iter().next().unwrap();
    let image = &artifact.images[0];
    ReleaseImageSnapshot {
        release_tag: version.version.clone(),
        source_commit: "f".repeat(64),
        verified_tag_oid: "1".repeat(64),
        catalog_digest: "2".repeat(64),
        images: vec![IndexedSystemImage {
            package: package.package.name.clone(),
            release: version.version.clone(),
            platform: platform.clone(),
            format: image.format.clone(),
            store_path: image.store_path.clone(),
            nar_hash: image.nar_hash.clone(),
            nar_size: image.nar_size,
            delivery: image.delivery.clone(),
        }],
    }
}

async fn image_metadata_service(
    visibility: &str,
) -> (RpcService, RegistryRecord, String, Arc<AtomicUsize>) {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org_id = db.create_org("image-http", "Image HTTP").await.unwrap();
    let registry_id = db
        .create_managed_registry(org_id, "", "system", visibility, &[], false)
        .await
        .unwrap();
    let org = db.org_by_id(org_id).await.unwrap().unwrap();
    let binding_id = db
        .create_topology_binding(
            Some(org_id),
            "binding-image-http",
            &org.stable_id,
            "images",
            "r2",
            None,
            Some("image-http"),
            Some("images"),
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
            binding_id: binding_id,
            prefix: "system".into(),
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
    let package = one_signed_raw_image_package();
    let snapshot = IndexSnapshot {
        commit: "f".repeat(64),
        name: "AOS system".into(),
        packages: vec![package.clone()],
        releases: vec![ReleaseRow {
            semver: "2026.8.0".into(),
            tag_oid: "1".repeat(64),
            commit_oid: "f".repeat(64),
            signer: Some("test".into()),
            tagged_at: Some(1),
            pack_present: true,
        }],
        release_images: vec![one_signed_raw_image_release(&package)],
        channels: vec![ChannelSummary {
            name: "stable".into(),
            frontier: Some("2026.8.0".into()),
            partitions: vec![Some("2026.8.0".into()); 256],
        }],
        ..Default::default()
    };
    let identities = snapshot.release_images[0]
        .images
        .iter()
        .flat_map(|image| {
            [
                VerifiedRegistryImageObject {
                    object_key: image.delivery.object_key.clone(),
                    sha256: image.delivery.sha256.clone(),
                    byte_size: i64::try_from(image.delivery.byte_size).unwrap(),
                    strong_etag: "test-version".into(),
                },
                VerifiedRegistryImageObject {
                    object_key: image.delivery.artifact_contract.document.object_key.clone(),
                    sha256: image.delivery.artifact_contract.document.sha256.clone(),
                    byte_size: i64::try_from(image.delivery.artifact_contract.document.byte_size)
                        .unwrap(),
                    strong_etag: "test-version".into(),
                },
            ]
        })
        .collect::<Vec<_>>();
    db.apply_snapshot_with_image_presence(registry_id, &snapshot, placement.id, &identities, 1)
        .await
        .unwrap();
    let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();
    let object_key = db.list_system_image_root_keys(registry_id).await.unwrap()[0].clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let coordinator = Arc::new(InMemoryCoordinator::new());
    let service = RpcService::new(
        Arc::clone(&db),
        JwtKeys::from_secret(b"image-http-metadata-test-key"),
        "https://hub.example.test".into(),
        Arc::new(CoordinatorRateLimiter::new(coordinator)),
        Arc::new(CountingRejectingSurfaceProvider {
            calls: Arc::clone(&calls),
        }),
        Arc::new(InjectedWriteProvider {
            behaviors: Mutex::new(VecDeque::new()),
        }),
        Arc::new(InMemoryLease::new()),
        Arc::new(InjectedReindexer { calls: None }),
        Arc::new(DatabaseTopologyProbeScheduler::new(db)),
        None,
    );
    (service, registry, object_key, calls)
}

fn image_http_request(
    method: crate::delivery_http::DeliveryMethod,
    range: Option<&[u8]>,
) -> crate::image_http::ImageHttpRequest<'_> {
    crate::image_http::ImageHttpRequest {
        method,
        range,
        if_match: None,
        if_unmodified_since: None,
        if_none_match: None,
        if_modified_since: None,
        if_range: None,
        now: crate::delivery_http::HttpTimestamp::from_unix_seconds(1_700_000_000).unwrap(),
    }
}

mod caches;
mod documentation;
mod identity;
mod registries;
mod releases;
mod runtime;
mod tenancy;
mod topology;
