//! Native Hub OCI Distribution delivery over a real TCP listener.
//!
//! These tests admit exact verified object bytes into the relational OCI
//! catalog, route a root-mounted registry through the native Axum shell, and
//! then exercise both raw Distribution requests and the production OCI client.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aos_hub::auth::extract::AuthState;
use aos_hub::auth::jwt::{
    JwtKeys, OciClaims, OciRepositoryGrant, OciTokenGrant, OCI_AUTHORIZATION_CLAIMS_VERSION,
};
use aos_hub::db::{
    Database, EndpointHostInput, EndpointRevisionSpec, NewTopologyOperation,
    NewTopologyOperationTarget, NewTopologyOperationTargetRef, RouteSpec, SetSurfaceObject,
    SurfaceTarget, TokenAuth,
};
use aos_hub::domain::{Permission, Principal, Scope};
use aos_hub::server::{router, AppState};
use aos_hub_core::db::{
    oci_blob_object_key, ClaimOciUpload, IndexOciRepositoryCatalog, OciBlobClaimOutcome,
    OciCatalogObject, OciCatalogProjection,
};
use aos_oci::{
    PlatformSelector, PullOptions, PushOptions, RegistryClient, RegistryReference, TransferEvent,
};
use aos_oci_types::{
    to_canonical_json, Annotations, Descriptor, HistoryEntry, ImageConfig, ImageIndex,
    ImageManifest, ImageRuntimeConfig, MediaType, Platform, RepositoryName, RootFs, RootFsType,
    Sha256Digest, Tag,
};
use base64::Engine as _;
use hmac::{Hmac, Mac as _};
use reqwest::header::{
    ACCEPT, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, IF_NONE_MATCH, LINK,
    LOCATION, RANGE, VARY, WWW_AUTHENTICATE,
};
use reqwest::StatusCode;
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const TEST_JWT_SECRET: &[u8] = b"native-oci-distribution-test-secret";
const OCI_JWS_HEADER: &[u8] = br#"{"alg":"HS256","typ":"application/vnd.aos.oci-token+jwt"}"#;

#[derive(Clone)]
struct GraphObject {
    descriptor: Descriptor,
    bytes: Vec<u8>,
    projection: Option<OciCatalogProjection>,
}

#[derive(Clone)]
struct ImageGraph {
    root: Descriptor,
    manifest: Descriptor,
    layer: Descriptor,
    objects: Vec<GraphObject>,
}

struct RunningRegistry {
    _temporary: tempfile::TempDir,
    _server: tokio::task::JoinHandle<()>,
    db: Arc<Database>,
    org_id: i64,
    http: reqwest::Client,
    keys: JwtKeys,
    registry_id: i64,
    registry_stable_id: String,
    surface_root: PathBuf,
    authority: String,
    origin: String,
    image: ImageGraph,
    hub_bearer: Option<String>,
}

impl Drop for RunningRegistry {
    fn drop(&mut self) {
        self._server.abort();
    }
}

fn descriptor(media_type: MediaType, bytes: &[u8], platform: Option<Platform>) -> Descriptor {
    Descriptor {
        media_type,
        digest: Sha256Digest::digest(bytes),
        size: u64::try_from(bytes.len()).unwrap(),
        urls: Vec::new(),
        annotations: Annotations::new(),
        data: None,
        artifact_type: None,
        platform,
    }
}

fn image_graph(marker: &str) -> ImageGraph {
    image_graph_for(
        marker,
        Platform::linux_amd64(),
        format!("fixture layer for {marker}\n").into_bytes(),
        false,
    )
}

fn image_graph_for(
    marker: &str,
    platform: Platform,
    layer: Vec<u8>,
    pretty_manifest: bool,
) -> ImageGraph {
    let diff_id = Sha256Digest::digest(&layer);
    let layer_descriptor = descriptor(MediaType::OciLayerTar, &layer, None);

    let config = ImageConfig {
        created: Some("1970-01-01T00:00:01Z".to_string()),
        author: None,
        architecture: platform.architecture.clone(),
        os: platform.os.clone(),
        os_version: None,
        os_features: Vec::new(),
        variant: platform.variant.clone(),
        config: Some(ImageRuntimeConfig {
            entrypoint: vec!["/usr/bin/aos".to_string()],
            cmd: vec!["--help".to_string()],
            ..ImageRuntimeConfig::default()
        }),
        rootfs: RootFs {
            rootfs_type: RootFsType::Layers,
            diff_ids: vec![diff_id],
        },
        history: vec![HistoryEntry {
            created_by: Some(marker.to_string()),
            ..HistoryEntry::default()
        }],
    };
    config.validate().unwrap();
    let config = to_canonical_json(&config).unwrap();
    let config_descriptor = descriptor(MediaType::OciImageConfig, &config, None);

    let manifest = ImageManifest {
        schema_version: 2,
        media_type: Some(MediaType::OciImageManifest),
        artifact_type: None,
        config: config_descriptor.clone(),
        layers: vec![layer_descriptor.clone()],
        subject: None,
        annotations: Annotations::new(),
    };
    manifest.validate().unwrap();
    let manifest_bytes = if pretty_manifest {
        serde_json::to_vec_pretty(&manifest).unwrap()
    } else {
        to_canonical_json(&manifest).unwrap()
    };
    let manifest_descriptor = descriptor(
        MediaType::OciImageManifest,
        &manifest_bytes,
        Some(platform.clone()),
    );

    let index = ImageIndex {
        schema_version: 2,
        media_type: Some(MediaType::OciImageIndex),
        artifact_type: None,
        manifests: vec![manifest_descriptor.clone()],
        subject: None,
        annotations: Annotations::new(),
    };
    index.validate().unwrap();
    let index_bytes = to_canonical_json(&index).unwrap();
    let index_descriptor = descriptor(MediaType::OciImageIndex, &index_bytes, None);

    ImageGraph {
        root: index_descriptor.clone(),
        manifest: manifest_descriptor.clone(),
        layer: layer_descriptor.clone(),
        objects: vec![
            GraphObject {
                descriptor: index_descriptor,
                bytes: index_bytes,
                projection: Some(OciCatalogProjection::Index(index)),
            },
            GraphObject {
                descriptor: manifest_descriptor,
                bytes: manifest_bytes,
                projection: Some(OciCatalogProjection::Manifest {
                    document: manifest,
                    platform: Some(platform),
                }),
            },
            GraphObject {
                descriptor: config_descriptor,
                bytes: config,
                projection: None,
            },
            GraphObject {
                descriptor: layer_descriptor,
                bytes: layer,
                projection: None,
            },
        ],
    }
}

fn write_layout(root: &Path, index_bytes: &[u8], objects: &[GraphObject]) {
    fs::create_dir_all(root.join("blobs/sha256")).unwrap();
    fs::write(
        root.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    fs::write(root.join("index.json"), index_bytes).unwrap();
    for object in objects {
        fs::write(
            root.join("blobs/sha256")
                .join(object.descriptor.digest.encoded()),
            &object.bytes,
        )
        .unwrap();
    }
}

fn write_graph_layout(root: &Path, graph: &ImageGraph) {
    let index = graph
        .objects
        .iter()
        .find(|object| object.descriptor.digest == graph.root.digest)
        .unwrap();
    write_layout(root, &index.bytes, &graph.objects);
}

fn write_multi_platform_layout(root: &Path, platforms: &[ImageGraph]) -> (Descriptor, Vec<u8>) {
    let index = ImageIndex {
        schema_version: 2,
        media_type: Some(MediaType::OciImageIndex),
        artifact_type: None,
        manifests: platforms
            .iter()
            .map(|graph| graph.manifest.clone())
            .collect(),
        subject: None,
        annotations: Annotations::new(),
    };
    index.validate().unwrap();
    let index_bytes = to_canonical_json(&index).unwrap();
    let index_descriptor = descriptor(MediaType::OciImageIndex, &index_bytes, None);
    let objects = platforms
        .iter()
        .flat_map(|graph| {
            graph
                .objects
                .iter()
                .filter(|object| object.descriptor.digest != graph.root.digest)
                .cloned()
        })
        .collect::<Vec<_>>();
    write_layout(root, &index_bytes, &objects);
    (index_descriptor, index_bytes)
}

fn artifact_graph(subject: &ImageGraph) -> (Descriptor, Vec<GraphObject>) {
    let config = b"{}".to_vec();
    let config_descriptor = Descriptor::canonical_empty();
    let payload = br#"{"spdxVersion":"SPDX-2.3"}"#.to_vec();
    let payload_descriptor = descriptor(MediaType::SpdxJson, &payload, None);
    let manifest = ImageManifest {
        schema_version: 2,
        media_type: Some(MediaType::OciImageManifest),
        artifact_type: Some(MediaType::SpdxJson),
        config: config_descriptor.clone(),
        layers: vec![payload_descriptor.clone()],
        subject: Some(subject.root.clone()),
        annotations: Annotations::new(),
    };
    manifest.validate().unwrap();
    let bytes = to_canonical_json(&manifest).unwrap();
    let mut manifest_descriptor = descriptor(MediaType::OciImageManifest, &bytes, None);
    manifest_descriptor.artifact_type = Some(MediaType::SpdxJson);

    let mut objects = subject.objects.clone();
    objects.extend([
        GraphObject {
            descriptor: manifest_descriptor.clone(),
            bytes,
            projection: Some(OciCatalogProjection::Manifest {
                document: manifest,
                platform: None,
            }),
        },
        GraphObject {
            descriptor: config_descriptor,
            bytes: config,
            projection: None,
        },
        GraphObject {
            descriptor: payload_descriptor,
            bytes: payload,
            projection: None,
        },
    ]);
    (manifest_descriptor, objects)
}

fn catalog(
    registry_id: i64,
    placement_id: i64,
    repository: &str,
    objects: &[GraphObject],
    root: &Descriptor,
    tag: &str,
    observed_at: i64,
) -> IndexOciRepositoryCatalog {
    IndexOciRepositoryCatalog {
        registry_id,
        placement_id,
        repository: RepositoryName::parse(repository).unwrap(),
        objects: objects
            .iter()
            .map(|object| OciCatalogObject {
                descriptor: object.descriptor.clone(),
                projection: object.projection.clone(),
            })
            .collect(),
        root_digest: root.digest,
        tag: Some(Tag::parse(tag).unwrap()),
        source_kind: "release".to_string(),
        actor_id: "test:native-oci".to_string(),
        observed_at,
    }
}

async fn configure_oci_route(
    db: &Database,
    registry_id: i64,
    placement_id: i64,
    owner_scope: &str,
    port: u16,
    access_policy_kind: &str,
) {
    let boundary = aos_hub::db::GrantResource::NetworkPolicy {
        id: "instance:public",
    };
    let grants = db.list_consumer_scope_grants(boundary).await.unwrap();
    if !grants
        .iter()
        .any(|grant| grant.consumer_scope_key == owner_scope && grant.state == "active")
    {
        db.grant_consumer_scope(
            boundary,
            owner_scope,
            "explicit",
            "test",
            "request:native-oci-boundary-grant",
        )
        .await
        .unwrap();
    }
    db.create_endpoint(
        "endpoint:native-oci",
        owner_scope,
        Some(db.registry_by_id(registry_id).await.unwrap().unwrap().org_id.unwrap()),
        "http",
        &EndpointHostInput::Ipv4([127, 0, 0, 1]),
        port,
        "instance:public",
        &EndpointRevisionSpec {
            boundary_revision: 1,
            ingress_kind: "hub".to_string(),
            listener_configuration: "listener:native-oci".to_string(),
            tls_configuration: "{}".to_string(),
            probe_configuration: "{\"provider\":\"native_file\",\"signerSecretRef\":\"test-probe-key\",\"publicKey\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}".to_string(),
        },
        Some(1),
        "test",
        "request:native-oci-endpoint",
    )
    .await
    .unwrap();
    db.reconcile_endpoint("endpoint:native-oci", 1, 1, "healthy", true, false, None, 1)
        .await
        .unwrap();

    let access_policy_json = "{}".to_string();
    let access_policy_digest = hex::encode(Sha256::digest(access_policy_json.as_bytes()));
    let canonical_url = format!("http://127.0.0.1:{port}");
    let endpoint = db.endpoint("endpoint:native-oci").await.unwrap().unwrap();
    let endpoint_digest = hex::decode(&endpoint.endpoint_identity_digest).unwrap();
    let reservation_digest =
        Database::route_reservation_digest(&[17_u8; 32], &endpoint_digest, "", &canonical_url)
            .unwrap();
    let route = db
        .create_route(
            "route:native-oci",
            SurfaceTarget::Registry(registry_id),
            &RouteSpec {
                consumer_scope_key: owner_scope.to_string(),
                endpoint_id: "endpoint:native-oci".to_string(),
                endpoint_generation: 1,
                endpoint_ingress_kind: "hub".to_string(),
                base_path: String::new(),
                mode: "hub_proxy".to_string(),
                access_policy_kind: access_policy_kind.to_string(),
                access_policy_json,
                access_policy_digest: access_policy_digest.clone(),
                access_boundary_id: None,
                access_boundary_revision: None,
                external_provider_kind: None,
                external_provider_resource_id: None,
                external_provider_revision: None,
                gateway_id: None,
                gateway_generation: None,
                target_binding_id: None,
                gateway_client_base_path: None,
                target_placement_prefix: None,
                placement_id: Some(placement_id),
                placement_policy_revision_id: None,
                serves_git: false,
                serves_cache: false,
                serves_web: false,
                serves_oci: true,
                enabled: true,
            },
            &canonical_url,
            1,
            &reservation_digest,
            &[(1, reservation_digest.to_vec())],
            None,
            "test",
        )
        .await
        .unwrap();
    db.reconcile_route(
        &route.id,
        route.configuration_generation.unwrap(),
        route.configuration_digest.as_deref().unwrap(),
        &access_policy_digest,
        "healthy",
        "verified",
        None,
        None,
        1,
    )
    .await
    .unwrap();
}

async fn spawn_registry(
    visibility: &str,
    auxiliary_repository: bool,
    access_policy_kind: &str,
) -> RunningRegistry {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let authority = format!("127.0.0.1:{port}");
    let origin = format!("http://{authority}/");

    let temporary = tempfile::tempdir().unwrap();
    let image_snapshots =
        aos_hub::image_snapshot::ImageSnapshotStore::open(temporary.path()).unwrap();
    let surface_root = temporary.path().join("surface");
    fs::create_dir_all(surface_root.join("objects")).unwrap();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org_id = db.create_org("oci-native", "Native OCI").await.unwrap();
    let org = db.org_by_id(org_id).await.unwrap().unwrap();
    let registry_id = db
        .create_managed_registry(org_id, "", "containers", visibility, &[], false)
        .await
        .unwrap();
    let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();
    let binding_id =
        common::create_local_binding(&db, org_id, "native-oci", surface_root.to_str().unwrap())
            .await;
    let placement = db
        .create_surface_placement(&aos_hub::db::NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "native-oci".to_string(),
            binding_id,
            prefix: "objects".to_string(),
            kind: "complete".to_string(),
            desired_state: "active".to_string(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await
        .unwrap();

    let image = image_graph("aos");
    let (artifact_root, artifact_objects) = artifact_graph(&image);
    let auxiliary = auxiliary_repository.then(|| image_graph("other"));
    let mut physical_objects = BTreeMap::<Sha256Digest, GraphObject>::new();
    for object in image
        .objects
        .iter()
        .chain(&artifact_objects)
        .chain(auxiliary.iter().flat_map(|graph| graph.objects.iter()))
    {
        physical_objects
            .entry(object.descriptor.digest)
            .or_insert_with(|| object.clone());
    }
    for object in physical_objects.values() {
        let key = oci_blob_object_key(object.descriptor.digest);
        let path = surface_root.join("objects").join(&key);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, &object.bytes).unwrap();
        db.create_surface_object(&SetSurfaceObject {
            surface: SurfaceTarget::Registry(registry_id),
            object_key: key,
            content_hash: Some(object.descriptor.digest.encoded()),
            size: Some(i64::try_from(object.descriptor.size).unwrap()),
            object_kind: "immutable".to_string(),
            mutable_publication_id: None,
        })
        .await
        .unwrap();
    }

    db.create_topology_operation(&NewTopologyOperation {
        operation_id: "scan-native-oci".to_string(),
        operation_kind: "scan_placement".to_string(),
        control_permission: Permission::StorageManage,
        targets: vec![NewTopologyOperationTarget {
            role: "primary".to_string(),
            target: NewTopologyOperationTargetRef::Placement(placement.id),
            generation_key: placement.resource_version,
            configuration_digest: String::new(),
        }],
        detail_json: serde_json::json!({"phase":"pending"}).to_string(),
        progress_total: None,
    })
    .await
    .unwrap();
    let surfaces = Arc::new(
        aos_hub::coreports::HubSurfaceProvider::new(
            Arc::clone(&db),
            aos_hub::fetch::hardened_client().await,
            Some(Arc::clone(&image_snapshots)),
        )
        .for_image_indexing(),
    );
    let scanner =
        aos_hub_core::placement_scan::PlacementScanController::new(Arc::clone(&db), surfaces);
    assert_eq!(scanner.run_due(1).await.unwrap(), 1);
    let placement = db.surface_placement(placement.id).await.unwrap().unwrap();
    assert_eq!(placement.state, "ready");
    assert_eq!(placement.completeness, "complete");
    common::configure_write_authority(
        &db,
        SurfaceTarget::Registry(registry_id),
        binding_id,
        &placement,
        "native-oci-writer",
    )
    .await;

    db.index_oci_repository_catalog(&catalog(
        registry_id,
        placement.id,
        "aos",
        &image.objects,
        &image.root,
        "latest",
        1_800_000_000,
    ))
    .await
    .unwrap();
    db.index_oci_repository_catalog(&catalog(
        registry_id,
        placement.id,
        "aos",
        &artifact_objects,
        &artifact_root,
        "sbom",
        1_800_000_001,
    ))
    .await
    .unwrap();
    if let Some(auxiliary) = &auxiliary {
        db.index_oci_repository_catalog(&catalog(
            registry_id,
            placement.id,
            "other",
            &auxiliary.objects,
            &auxiliary.root,
            "latest",
            1_800_000_002,
        ))
        .await
        .unwrap();
    }

    configure_oci_route(
        &db,
        registry_id,
        placement.id,
        &org.stable_id,
        port,
        access_policy_kind,
    )
    .await;

    let keys = JwtKeys::from_secret(TEST_JWT_SECRET);
    let hub_bearer = if visibility == "public" && access_policy_kind != "hub_auth" {
        None
    } else {
        let user_id = db
            .create_user("puller@oci.example", Some("OCI puller"))
            .await
            .unwrap();
        db.grant_membership("user", user_id, &org.stable_id, "maintainer")
            .await
            .unwrap();
        let scope = db.registry_authorization_scope(registry_id).await.unwrap();
        Some(
            keys.mint(
                &TokenAuth {
                    token_id: "native-oci-hub-token".to_string(),
                    owner: Principal::user(user_id),
                    scope: Scope::parse(&scope),
                    permissions: vec![Permission::Read, Permission::Publish],
                },
                900,
            )
            .unwrap(),
        )
    };
    let ratelimit = Arc::new(aos_hub::ratelimit::RateLimiter::new());
    let auth = Arc::new(AuthState {
        db: Arc::clone(&db),
        jwt_keys: keys.clone(),
        access_token_ttl: 900,
        ratelimit: Arc::clone(&ratelimit),
        trusted_proxy: false,
    });
    let state = Arc::new(AppState {
        db: Arc::clone(&db),
        external_url: origin.trim_end_matches('/').to_string(),
        auth,
        leases: Arc::new(aos_hub_core::lease::InMemoryLease::new()),
        mailer: Arc::new(aos_hub::auth::magic::LogMailer),
        dev: false,
        sealer: aos_hub::auth::oidc::dev_sealer(),
        secret_versions: aos_hub_core::secret_version::EmptySecretVersionResolver::shared(),
        http: aos_hub::fetch::hardened_client().await,
        image_snapshots: Some(image_snapshots),
        ratelimit,
        trusted_proxy: false,
        delivery_attestation_verifier: None,
        domain_probe_terminator: None,
        identity_domain_verifier: None,
        route_reservation_keyring: None,
    });
    let app = router(state).await;
    let server = tokio::spawn(async move {
        let result = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
        assert!(result.is_ok(), "native OCI test server failed: {result:?}");
    });

    RunningRegistry {
        _temporary: temporary,
        _server: server,
        db,
        org_id,
        http: reqwest::Client::new(),
        keys,
        registry_id,
        registry_stable_id: registry.stable_id,
        surface_root,
        authority,
        origin,
        image,
        hub_bearer,
    }
}

async fn error_code(response: reqwest::Response) -> String {
    let envelope: serde_json::Value = response.json().await.unwrap();
    envelope["errors"][0]["code"].as_str().unwrap().to_string()
}

fn forged_action_token(registry: &RunningRegistry, repository: &str, action: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = OciClaims {
        oci_version: OCI_AUTHORIZATION_CLAIMS_VERSION.to_string(),
        sub: "test:wrong-action".to_string(),
        aud: registry.authority.clone(),
        registry: registry.registry_stable_id.clone(),
        grants: vec![OciRepositoryGrant {
            repository: RepositoryName::parse(repository).unwrap(),
            actions: vec![action.to_string()],
        }],
        iat: now,
        exp: now + 300,
    };
    let encoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = encoder.encode(OCI_JWS_HEADER);
    let body = encoder.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header}.{body}");
    let mut mac = Hmac::<Sha256>::new_from_slice(TEST_JWT_SECRET).unwrap();
    mac.update(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        encoder.encode(mac.finalize().into_bytes())
    )
}

async fn exchange_oci_token(registry: &RunningRegistry, scopes: &[&str]) -> String {
    let mut query = vec![("service", registry.authority.as_str())];
    query.extend(scopes.iter().copied().map(|scope| ("scope", scope)));
    let response = registry
        .http
        .get(format!("{}v2/token", registry.origin))
        .query(&query)
        .bearer_auth(registry.hub_bearer.as_deref().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response: serde_json::Value = response.json().await.unwrap();
    response["token"].as_str().unwrap().to_string()
}

fn resolved_location(registry: &RunningRegistry, location: &str) -> String {
    url::Url::parse(&registry.origin)
        .unwrap()
        .join(location)
        .unwrap()
        .to_string()
}

async fn put_manifest_bytes(
    registry: &RunningRegistry,
    token: &str,
    repository: &str,
    reference: &str,
    media_type: MediaType,
    bytes: &[u8],
) -> reqwest::Response {
    registry
        .http
        .put(format!(
            "{}v2/{repository}/manifests/{reference}",
            registry.origin
        ))
        .bearer_auth(token)
        .header(CONTENT_TYPE, media_type.as_str())
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap()
}

fn count_regular_files(path: &Path) -> usize {
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| {
            if entry.path().is_dir() {
                count_regular_files(&entry.path())
            } else {
                usize::from(entry.path().is_file())
            }
        })
        .sum()
}

fn novel_manifest(registry: &RunningRegistry, marker: &str) -> (ImageManifest, Vec<u8>) {
    let mut manifest = registry
        .image
        .objects
        .iter()
        .find(|object| object.descriptor.digest == registry.image.manifest.digest)
        .and_then(|object| ImageManifest::from_json(&object.bytes).ok())
        .unwrap();
    manifest
        .annotations
        .insert(
            "org.opencontainers.image.revision".to_string(),
            marker.to_string(),
        )
        .unwrap();
    let bytes = to_canonical_json(&manifest).unwrap();
    (manifest, bytes)
}

#[tokio::test]
async fn manifest_admission_stages_before_validation_and_claims_each_digest_once() {
    let registry = spawn_registry("private", true, "hub_auth").await;
    let token = exchange_oci_token(&registry, &["repository:aos:pull,push"]).await;
    let repository = registry
        .db
        .oci_repository(registry.registry_id, &RepositoryName::parse("aos").unwrap())
        .await
        .unwrap()
        .unwrap();
    let staging_root = registry.surface_root.join("objects/oci/uploads");

    let (mut missing, _) = novel_manifest(&registry, "missing-dependency");
    missing.config = descriptor(MediaType::OciImageConfig, b"absent-config", None);
    let missing_bytes = to_canonical_json(&missing).unwrap();
    let missing_digest = Sha256Digest::digest(&missing_bytes);
    let usage_before_missing = registry.db.org_usage(registry.org_id).await.unwrap();
    let rejected = put_manifest_bytes(
        &registry,
        &token,
        "aos",
        "missing-dependency",
        MediaType::OciImageManifest,
        &missing_bytes,
    )
    .await;
    let rejected_status = rejected.status();
    let rejected_body = rejected.text().await.unwrap();
    assert_eq!(rejected_status, StatusCode::BAD_REQUEST, "{rejected_body}");
    assert!(rejected_body.contains("MANIFEST_BLOB_UNKNOWN"));
    assert!(!registry
        .surface_root
        .join("objects")
        .join(oci_blob_object_key(missing_digest))
        .exists());
    assert!(registry
        .db
        .oci_manifest_for_repository(
            repository.id,
            &aos_oci_types::ManifestReference::Digest(missing_digest),
        )
        .await
        .unwrap()
        .is_none());
    let usage_after_missing = registry.db.org_usage(registry.org_id).await.unwrap();
    assert_eq!(
        usage_after_missing.used_bytes,
        usage_before_missing.used_bytes
    );
    assert_eq!(
        usage_after_missing.object_count,
        usage_before_missing.object_count
    );
    assert_eq!(count_regular_files(&staging_root), 0);

    let (_, race_bytes) = novel_manifest(&registry, "concurrent-identical-manifest");
    let race_digest = Sha256Digest::digest(&race_bytes);
    assert!(!registry
        .surface_root
        .join("objects")
        .join(oci_blob_object_key(race_digest))
        .exists());
    let usage_before_race = registry.db.org_usage(registry.org_id).await.unwrap();
    let first = put_manifest_bytes(
        &registry,
        &token,
        "aos",
        "race-one",
        MediaType::OciImageManifest,
        &race_bytes,
    );
    let second = put_manifest_bytes(
        &registry,
        &token,
        "aos",
        "race-two",
        MediaType::OciImageManifest,
        &race_bytes,
    );
    let (first, second) = tokio::join!(first, second);
    let first_status = first.status();
    let second_status = second.status();
    let first_body = first.text().await.unwrap();
    let second_body = second.text().await.unwrap();
    let physical = registry
        .surface_root
        .join("objects")
        .join(oci_blob_object_key(race_digest));
    let physical_detail = fs::read(&physical)
        .map(|bytes| format!("{}:{}", bytes.len(), Sha256Digest::digest(&bytes)))
        .unwrap_or_else(|error| format!("absent:{error}"));
    assert_eq!(
        (first_status, second_status),
        (StatusCode::CREATED, StatusCode::CREATED),
        "first={first_body}; second={second_body}; physical={physical_detail}"
    );
    assert_eq!(fs::read(physical).unwrap(), race_bytes);
    assert_eq!(count_regular_files(&staging_root), 0);
    let usage_after_race = registry.db.org_usage(registry.org_id).await.unwrap();
    assert_eq!(
        usage_after_race.used_bytes - usage_before_race.used_bytes,
        race_bytes.len() as i64
    );
    assert_eq!(
        usage_after_race.object_count - usage_before_race.object_count,
        1
    );

    let (_, over_quota_bytes) = novel_manifest(&registry, "over-quota-manifest");
    let over_quota_digest = Sha256Digest::digest(&over_quota_bytes);
    registry
        .db
        .set_org_quota(
            registry.org_id,
            &aos_hub::db::OrgQuota {
                max_bytes: Some(usage_after_race.used_bytes + over_quota_bytes.len() as i64 - 1),
                max_objects: None,
                max_registries: None,
                max_tokens: None,
            },
        )
        .await
        .unwrap();
    let rejected = put_manifest_bytes(
        &registry,
        &token,
        "aos",
        "over-quota",
        MediaType::OciImageManifest,
        &over_quota_bytes,
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!registry
        .surface_root
        .join("objects")
        .join(oci_blob_object_key(over_quota_digest))
        .exists());
    assert!(registry
        .db
        .oci_manifest_for_repository(
            repository.id,
            &aos_oci_types::ManifestReference::Digest(over_quota_digest),
        )
        .await
        .unwrap()
        .is_none());
    let usage_after_rejection = registry.db.org_usage(registry.org_id).await.unwrap();
    assert_eq!(
        usage_after_rejection.used_bytes,
        usage_after_race.used_bytes
    );
    assert_eq!(
        usage_after_rejection.object_count,
        usage_after_race.object_count
    );
    assert_eq!(count_regular_files(&staging_root), 0);
}

#[tokio::test]
async fn manifest_readback_failure_preserves_a_prior_shared_cas_object() {
    let registry = spawn_registry("private", true, "hub_auth").await;
    let token = exchange_oci_token(&registry, &["repository:aos:pull,push"]).await;
    let (_, bytes) = novel_manifest(&registry, "preserve-prior-cas");
    let digest = Sha256Digest::digest(&bytes);
    let canonical = registry
        .surface_root
        .join("objects")
        .join(oci_blob_object_key(digest));
    fs::create_dir_all(canonical.parent().unwrap()).unwrap();
    let prior = b"prior shared bytes with broken readback";
    fs::write(&canonical, prior).unwrap();

    let response = put_manifest_bytes(
        &registry,
        &token,
        "aos",
        "preserve-prior-cas",
        MediaType::OciImageManifest,
        &bytes,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(fs::read(canonical).unwrap(), prior);
}

#[tokio::test]
async fn authenticated_upload_lifecycle_and_real_client_preserve_exact_bytes() {
    let registry = spawn_registry("private", true, "hub_auth").await;
    let token = exchange_oci_token(&registry, &["repository:aos:pull,push"]).await;

    let raw_blob = b"native standard upload body";
    let raw_digest = Sha256Digest::digest(raw_blob);
    let start = registry
        .http
        .post(format!("{}v2/aos/blobs/uploads/", registry.origin))
        .query(&[
            ("digest", raw_digest.to_string()),
            ("size", raw_blob.len().to_string()),
        ])
        .bearer_auth(&token)
        .body(Vec::new())
        .send()
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::ACCEPTED);
    let upload = resolved_location(&registry, start.headers()[LOCATION].to_str().unwrap());

    let split = 9_usize;
    let patch = registry
        .http
        .patch(&upload)
        .bearer_auth(&token)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_RANGE, format!("0-{}", split - 1))
        .body(raw_blob[..split].to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(patch.status(), StatusCode::ACCEPTED);
    assert_eq!(patch.headers()[RANGE], format!("0-{}", split - 1));

    let status = registry
        .http
        .get(&upload)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::NO_CONTENT);
    assert_eq!(status.headers()[RANGE], format!("0-{}", split - 1));

    let finish = registry
        .http
        .put(&upload)
        .query(&[("digest", raw_digest.to_string())])
        .bearer_auth(&token)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_RANGE, format!("{split}-{}", raw_blob.len() - 1))
        .body(raw_blob[split..].to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(finish.status(), StatusCode::CREATED);
    assert_eq!(
        finish.headers()["docker-content-digest"],
        raw_digest.to_string()
    );

    let blob_url = format!("{}v2/aos/blobs/{raw_digest}", registry.origin);
    let head = registry
        .http
        .head(&blob_url)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(head.headers()[CONTENT_LENGTH], raw_blob.len().to_string());
    assert_eq!(
        head.headers()["docker-content-digest"],
        raw_digest.to_string()
    );
    assert!(head.bytes().await.unwrap().is_empty());
    let exact_blob = registry
        .http
        .get(&blob_url)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(exact_blob.bytes().await.unwrap().as_ref(), raw_blob);

    let graph = image_graph_for(
        "noncanonical-manifest",
        Platform::linux_amd64(),
        b"exact noncanonical manifest layer\n".to_vec(),
        true,
    );
    let source = tempfile::tempdir().unwrap();
    write_graph_layout(source.path(), &graph);
    let reference =
        RegistryReference::parse(&format!("{}/aos:uploaded", registry.authority)).unwrap();
    let client =
        RegistryClient::new(&reference, Some(&registry.origin), Some(token.clone())).unwrap();
    let state = tempfile::tempdir().unwrap();
    let options = PushOptions {
        source: source.path().to_path_buf(),
        platform: PlatformSelector::parse("linux/amd64").unwrap(),
        state_directory: state.path().join("uploads"),
        chunk_bytes: 11,
        cancellation: CancellationToken::new(),
        events: None,
    };
    let pushed = client.push(&reference, &options).await.unwrap();
    assert_eq!(pushed.image.manifest.digest, graph.manifest.digest);

    let manifest = graph
        .objects
        .iter()
        .find(|object| object.descriptor.digest == graph.manifest.digest)
        .unwrap();
    assert!(manifest.bytes.contains(&b'\n'));
    let stored = registry
        .http
        .get(format!(
            "{}v2/aos/manifests/{}",
            registry.origin, graph.manifest.digest
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(stored.status(), StatusCode::OK);
    assert_eq!(stored.bytes().await.unwrap().as_ref(), manifest.bytes);

    let destination = tempfile::tempdir().unwrap();
    let pulled = client
        .pull(
            &reference,
            &PullOptions {
                destination: destination.path().join("layout"),
                platform: PlatformSelector::parse("linux/amd64").unwrap(),
                cancellation: CancellationToken::new(),
                events: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(pulled.manifest.digest, graph.manifest.digest);
    assert_eq!(pulled.layers, vec![graph.layer]);

    let (artifact, artifact_objects) = artifact_graph(&registry.image);
    let artifact_bytes = artifact_objects
        .iter()
        .find(|object| object.descriptor.digest == artifact.digest)
        .unwrap()
        .bytes
        .clone();
    let tagged_artifact = put_manifest_bytes(
        &registry,
        &token,
        "aos",
        "uploaded-sbom",
        MediaType::OciImageManifest,
        &artifact_bytes,
    )
    .await;
    assert_eq!(tagged_artifact.status(), StatusCode::CREATED);
    let artifact_url = format!("{}v2/aos/manifests/uploaded-sbom", registry.origin);
    let artifact_get = registry
        .http
        .get(&artifact_url)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(artifact_get.status(), StatusCode::OK);
    assert_eq!(
        artifact_get.headers()["docker-content-digest"],
        artifact.digest.to_string()
    );
    assert_eq!(artifact_get.bytes().await.unwrap().as_ref(), artifact_bytes);
    let artifact_head = registry
        .http
        .head(&artifact_url)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(artifact_head.status(), StatusCode::OK);
    assert_eq!(
        artifact_head.headers()["docker-content-digest"],
        artifact.digest.to_string()
    );
    let referrers = registry
        .http
        .get(format!(
            "{}v2/aos/referrers/{}",
            registry.origin, registry.image.root.digest
        ))
        .query(&[("artifactType", MediaType::SpdxJson.as_str())])
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(referrers.status(), StatusCode::OK);
    let referrers = ImageIndex::from_json(&referrers.bytes().await.unwrap()).unwrap();
    assert!(referrers
        .manifests
        .iter()
        .any(|descriptor| descriptor.digest == artifact.digest));
}

#[tokio::test]
async fn real_client_mounts_cancels_and_roundtrips_a_complete_multi_platform_graph() {
    let registry = spawn_registry("private", true, "hub_auth").await;
    let aos_token = exchange_oci_token(&registry, &["repository:aos:pull,push"]).await;
    let mount_token = exchange_oci_token(
        &registry,
        &["repository:aos:pull", "repository:other:pull,push"],
    )
    .await;

    let mount_source = tempfile::tempdir().unwrap();
    write_graph_layout(mount_source.path(), &registry.image);
    let mounted_reference =
        RegistryReference::parse(&format!("{}/other:mounted", registry.authority)).unwrap();
    let mounted_client = RegistryClient::new(
        &mounted_reference,
        Some(&registry.origin),
        Some(mount_token),
    )
    .unwrap();
    let mount_state = tempfile::tempdir().unwrap();
    let mounted = mounted_client
        .push_with_mounts(
            &mounted_reference,
            &PushOptions {
                source: mount_source.path().to_path_buf(),
                platform: PlatformSelector::parse("linux/amd64").unwrap(),
                state_directory: mount_state.path().join("uploads"),
                chunk_bytes: 13,
                cancellation: CancellationToken::new(),
                events: None,
            },
            &[RepositoryName::parse("aos").unwrap()],
        )
        .await
        .unwrap();
    assert_eq!(mounted.image.layers, vec![registry.image.layer.clone()]);
    let mounted_destination = tempfile::tempdir().unwrap();
    let mounted_pull = mounted_client
        .pull(
            &mounted_reference,
            &PullOptions {
                destination: mounted_destination.path().join("layout"),
                platform: PlatformSelector::parse("linux/amd64").unwrap(),
                cancellation: CancellationToken::new(),
                events: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(mounted_pull.manifest.digest, registry.image.manifest.digest);

    let large_graph = image_graph_for(
        "cancelled-upload",
        Platform::linux_amd64(),
        vec![b'x'; 512 * 1024],
        false,
    );
    let cancel_source = tempfile::tempdir().unwrap();
    write_graph_layout(cancel_source.path(), &large_graph);
    let cancel_reference =
        RegistryReference::parse(&format!("{}/aos:cancelled", registry.authority)).unwrap();
    let cancel_client = RegistryClient::new(
        &cancel_reference,
        Some(&registry.origin),
        Some(aos_token.clone()),
    )
    .unwrap();
    let cancel_state = tempfile::tempdir().unwrap();
    let cancellation = CancellationToken::new();
    let cancel = cancellation.clone();
    let target_digest = large_graph.layer.digest.to_string();
    let (events, mut received) = mpsc::unbounded_channel();
    let observer = tokio::spawn(async move {
        while let Some(event) = received.recv().await {
            if matches!(event, TransferEvent::Uploading { ref digest, .. } if digest == &target_digest)
            {
                cancel.cancel();
                return;
            }
        }
    });
    let cancelled_options = PushOptions {
        source: cancel_source.path().to_path_buf(),
        platform: PlatformSelector::parse("linux/amd64").unwrap(),
        state_directory: cancel_state.path().join("uploads"),
        chunk_bytes: 4096,
        cancellation,
        events: Some(events),
    };
    let error = cancel_client
        .push(&cancel_reference, &cancelled_options)
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("cancelled"));
    observer.await.unwrap();
    drop(cancelled_options);
    let cancelled = cancel_client
        .cancel_uploads(
            &cancel_reference,
            &cancel_state.path().join("uploads"),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(cancelled, 1);

    let amd64 = image_graph_for(
        "multi-amd64",
        Platform::linux_amd64(),
        b"amd64 multi-platform layer\n".to_vec(),
        true,
    );
    let arm64 = image_graph_for(
        "multi-arm64",
        Platform::linux_arm64(),
        b"arm64 multi-platform layer\n".to_vec(),
        true,
    );
    let multi_source = tempfile::tempdir().unwrap();
    let (multi_root, multi_bytes) =
        write_multi_platform_layout(multi_source.path(), &[amd64.clone(), arm64.clone()]);
    let multi_client =
        RegistryClient::new(&cancel_reference, Some(&registry.origin), Some(aos_token)).unwrap();
    for (tag, platform) in [
        ("stage-amd64", "linux/amd64"),
        ("stage-arm64", "linux/arm64"),
    ] {
        let reference =
            RegistryReference::parse(&format!("{}/aos:{tag}", registry.authority)).unwrap();
        let state = tempfile::tempdir().unwrap();
        multi_client
            .push(
                &reference,
                &PushOptions {
                    source: multi_source.path().to_path_buf(),
                    platform: PlatformSelector::parse(platform).unwrap(),
                    state_directory: state.path().join("uploads"),
                    chunk_bytes: 17,
                    cancellation: CancellationToken::new(),
                    events: None,
                },
            )
            .await
            .unwrap();
    }

    let repository = registry
        .db
        .oci_repository(registry.registry_id, &RepositoryName::parse("aos").unwrap())
        .await
        .unwrap()
        .unwrap();
    for (graph, expected) in [
        (&amd64, Platform::linux_amd64()),
        (&arm64, Platform::linux_arm64()),
    ] {
        let stored = registry
            .db
            .oci_manifest_for_repository(
                repository.id,
                &aos_oci_types::ManifestReference::Digest(graph.manifest.digest),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.platform, Some(expected));
    }

    let token = exchange_oci_token(&registry, &["repository:aos:pull,push"]).await;
    let admitted_index = ImageIndex::from_json(&multi_bytes).unwrap();
    let mut wrong_os = admitted_index.clone();
    wrong_os.manifests[0].platform.as_mut().unwrap().os = "windows".to_string();
    let mut wrong_architecture = admitted_index.clone();
    wrong_architecture.manifests[0]
        .platform
        .as_mut()
        .unwrap()
        .architecture = "arm64".to_string();
    let mut wrong_variant = admitted_index.clone();
    wrong_variant.manifests[0]
        .platform
        .as_mut()
        .unwrap()
        .variant = Some("v8".to_string());
    for (tag, index) in [
        ("wrong-os", wrong_os),
        ("wrong-architecture", wrong_architecture),
        ("wrong-variant", wrong_variant),
    ] {
        let bytes = to_canonical_json(&index).unwrap();
        let rejected = put_manifest_bytes(
            &registry,
            &token,
            "aos",
            tag,
            MediaType::OciImageIndex,
            &bytes,
        )
        .await;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        assert_eq!(error_code(rejected).await, "MANIFEST_INVALID");
    }
    let by_digest = put_manifest_bytes(
        &registry,
        &token,
        "aos",
        &multi_root.digest.to_string(),
        MediaType::OciImageIndex,
        &multi_bytes,
    )
    .await;
    assert_eq!(by_digest.status(), StatusCode::CREATED);
    let tagged = put_manifest_bytes(
        &registry,
        &token,
        "aos",
        "multi",
        MediaType::OciImageIndex,
        &multi_bytes,
    )
    .await;
    assert_eq!(tagged.status(), StatusCode::CREATED);

    let multi_reference =
        RegistryReference::parse(&format!("{}/aos:multi", registry.authority)).unwrap();
    let destination = tempfile::tempdir().unwrap();
    let pulled = multi_client
        .pull(
            &multi_reference,
            &PullOptions {
                destination: destination.path().join("layout"),
                platform: PlatformSelector::parse("linux/arm64").unwrap(),
                cancellation: CancellationToken::new(),
                events: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(pulled.platform, Platform::linux_arm64());
    assert_eq!(pulled.manifest.digest, arm64.manifest.digest);
    assert_eq!(pulled.layers, vec![arm64.layer]);
}

#[tokio::test]
async fn public_native_distribution_serves_exact_objects_and_the_real_client_pulls() {
    let registry = spawn_registry("public", true, "public").await;
    let ping = registry
        .http
        .get(format!("{}v2/", registry.origin))
        .send()
        .await
        .unwrap();
    assert_eq!(ping.status(), StatusCode::OK);
    assert_eq!(
        ping.headers()["docker-distribution-api-version"],
        "registry/2.0"
    );

    let manifest_url = format!("{}v2/aos/manifests/latest", registry.origin);
    let manifest = registry.http.get(&manifest_url).send().await.unwrap();
    assert_eq!(manifest.status(), StatusCode::OK);
    assert_eq!(
        manifest.headers()[CONTENT_TYPE],
        MediaType::OciImageIndex.as_str()
    );
    assert_eq!(
        manifest.headers()["docker-content-digest"],
        registry.image.root.digest.to_string()
    );
    let manifest_etag = manifest.headers()[ETAG].to_str().unwrap().to_string();
    assert_eq!(
        manifest.bytes().await.unwrap().as_ref(),
        registry.image.objects[0].bytes.as_slice()
    );

    let head = registry.http.head(&manifest_url).send().await.unwrap();
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(
        head.headers()[CONTENT_LENGTH],
        registry.image.root.size.to_string()
    );
    assert_eq!(head.headers()[ETAG], manifest_etag);
    assert!(head.bytes().await.unwrap().is_empty());

    let unacceptable = registry
        .http
        .get(&manifest_url)
        .header(ACCEPT, MediaType::SpdxJson.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(unacceptable.status(), StatusCode::NOT_ACCEPTABLE);
    assert_eq!(error_code(unacceptable).await, "UNSUPPORTED");
    let explicitly_rejected = registry
        .http
        .get(&manifest_url)
        .header(ACCEPT, format!("{};q=0", MediaType::OciImageIndex.as_str()))
        .send()
        .await
        .unwrap();
    assert_eq!(explicitly_rejected.status(), StatusCode::NOT_ACCEPTABLE);

    let blob_url = format!(
        "{}v2/aos/blobs/{}",
        registry.origin, registry.image.layer.digest
    );
    let ranged = registry
        .http
        .get(&blob_url)
        .header(RANGE, "bytes=2-7")
        .send()
        .await
        .unwrap();
    assert_eq!(ranged.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        ranged.headers()[CONTENT_RANGE],
        format!("bytes 2-7/{}", registry.image.layer.size)
    );
    let expected_layer = registry
        .image
        .objects
        .iter()
        .find(|object| object.descriptor.digest == registry.image.layer.digest)
        .unwrap();
    assert_eq!(
        &ranged.bytes().await.unwrap()[..],
        &expected_layer.bytes[2..=7]
    );

    let not_modified = registry
        .http
        .get(&blob_url)
        .header(
            IF_NONE_MATCH,
            format!("\"{}\"", registry.image.layer.digest),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
    assert!(not_modified.bytes().await.unwrap().is_empty());

    let first_tags = registry
        .http
        .get(format!("{}v2/aos/tags/list?n=1", registry.origin))
        .send()
        .await
        .unwrap();
    assert_eq!(first_tags.status(), StatusCode::OK);
    assert_eq!(first_tags.headers()[CACHE_CONTROL], "public, no-cache");
    assert_eq!(
        first_tags.headers()[LINK],
        "</v2/aos/tags/list?n=1&last=latest>; rel=\"next\""
    );
    let first_tags: serde_json::Value = first_tags.json().await.unwrap();
    assert_eq!(first_tags["name"], "aos");
    assert_eq!(first_tags["tags"], serde_json::json!(["latest"]));
    let final_tags = registry
        .http
        .get(format!(
            "{}v2/aos/tags/list?n=1&last=latest",
            registry.origin
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(final_tags.status(), StatusCode::OK);
    assert!(final_tags.headers().get(LINK).is_none());
    let final_tags: serde_json::Value = final_tags.json().await.unwrap();
    assert_eq!(final_tags["tags"], serde_json::json!(["sbom"]));

    let referrers = registry
        .http
        .get(format!(
            "{}v2/aos/referrers/{}",
            registry.origin, registry.image.root.digest
        ))
        .query(&[("artifactType", MediaType::SpdxJson.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(referrers.status(), StatusCode::OK);
    assert_eq!(referrers.headers()[CACHE_CONTROL], "public, no-cache");
    assert_eq!(
        referrers.headers()[CONTENT_TYPE],
        MediaType::OciImageIndex.as_str()
    );
    let referrers = ImageIndex::from_json(&referrers.bytes().await.unwrap()).unwrap();
    assert_eq!(referrers.manifests.len(), 1);
    assert_eq!(
        referrers.manifests[0].artifact_type,
        Some(MediaType::SpdxJson)
    );

    let isolated = registry
        .http
        .get(format!(
            "{}v2/other/blobs/{}",
            registry.origin, registry.image.layer.digest
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(isolated.status(), StatusCode::NOT_FOUND);
    assert_eq!(error_code(isolated).await, "BLOB_UNKNOWN");

    let reference =
        RegistryReference::parse(&format!("{}/aos:latest", registry.authority)).unwrap();
    let client = RegistryClient::new(&reference, Some(&registry.origin), None).unwrap();
    let output = tempfile::tempdir().unwrap();
    let verified = client
        .pull(
            &reference,
            &PullOptions::native(output.path().join("layout")),
        )
        .await
        .unwrap();
    assert_eq!(verified.manifest.digest, registry.image.manifest.digest);
    assert_eq!(verified.layers, vec![registry.image.layer.clone()]);

    let root_path = registry
        ._temporary
        .path()
        .join("surface/objects")
        .join(oci_blob_object_key(registry.image.root.digest));
    let corrupt = vec![b'x'; registry.image.root.size as usize];
    fs::write(&root_path, corrupt).unwrap();
    let retained = registry.http.get(&manifest_url).send().await.unwrap();
    assert_eq!(retained.status(), StatusCode::OK);
    assert_eq!(retained.headers()[ETAG], manifest_etag);
    assert_eq!(
        retained.bytes().await.unwrap().as_ref(),
        registry.image.objects[0].bytes.as_slice()
    );
    fs::remove_file(root_path).unwrap();
    let retained_head = registry.http.head(&manifest_url).send().await.unwrap();
    assert_eq!(retained_head.status(), StatusCode::OK);
    assert!(retained_head.bytes().await.unwrap().is_empty());
}

#[tokio::test]
async fn private_native_distribution_binds_tokens_and_authenticates_before_lookup() {
    let registry = spawn_registry("private", false, "hub_auth").await;
    let manifest_url = format!("{}v2/aos/manifests/latest", registry.origin);
    let anonymous = registry.http.get(&manifest_url).send().await.unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        anonymous.headers()[WWW_AUTHENTICATE],
        format!(
            "Bearer realm=\"{}v2/token\",service=\"{}\",scope=\"repository:aos:pull\"",
            registry.origin, registry.authority
        )
    );
    assert_eq!(error_code(anonymous).await, "UNAUTHORIZED");

    let hub_bearer = registry.hub_bearer.as_deref().unwrap();
    let token_response: serde_json::Value = registry
        .http
        .get(format!("{}v2/token", registry.origin))
        .query(&[
            ("service", registry.authority.as_str()),
            ("scope", "repository:aos:pull"),
        ])
        .bearer_auth(hub_bearer)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let pull_token = token_response["token"].as_str().unwrap();
    assert_eq!(token_response["access_token"], pull_token);
    assert!(token_response["expires_in"].as_i64().unwrap() <= 300);
    let authorized = registry
        .http
        .get(&manifest_url)
        .bearer_auth(pull_token)
        .send()
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);

    for protected_catalog in [
        format!("{}v2/aos/tags/list", registry.origin),
        format!(
            "{}v2/aos/referrers/{}",
            registry.origin, registry.image.root.digest
        ),
    ] {
        let response = registry
            .http
            .get(protected_catalog)
            .bearer_auth(pull_token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CACHE_CONTROL], "private, no-store");
        assert_eq!(response.headers()[VARY], "Authorization");
    }

    for wrong in [
        registry
            .keys
            .mint_oci(
                &OciTokenGrant {
                    subject: "test:wrong-audience".to_string(),
                    authority: "127.0.0.1:1".to_string(),
                    registry_stable_id: registry.registry_stable_id.clone(),
                    grants: vec![OciRepositoryGrant {
                        repository: RepositoryName::parse("aos").unwrap(),
                        actions: vec!["pull".to_string()],
                    }],
                },
                300,
            )
            .unwrap(),
        registry
            .keys
            .mint_oci(
                &OciTokenGrant {
                    subject: "test:wrong-repository".to_string(),
                    authority: registry.authority.clone(),
                    registry_stable_id: registry.registry_stable_id.clone(),
                    grants: vec![OciRepositoryGrant {
                        repository: RepositoryName::parse("other").unwrap(),
                        actions: vec!["pull".to_string()],
                    }],
                },
                300,
            )
            .unwrap(),
    ] {
        let denied = registry
            .http
            .get(&manifest_url)
            .bearer_auth(wrong)
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        assert_eq!(error_code(denied).await, "DENIED");
    }
    let wrong_action = registry
        .http
        .get(&manifest_url)
        .bearer_auth(forged_action_token(&registry, "aos", "push"))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_action.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_code(wrong_action).await, "DENIED");

    let unknown_repository_url = format!("{}v2/unknown/manifests/latest", registry.origin);
    let unauthenticated_unknown = registry
        .http
        .get(&unknown_repository_url)
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated_unknown.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(unauthenticated_unknown).await, "UNAUTHORIZED");
    let unknown_token = registry
        .keys
        .mint_oci(
            &OciTokenGrant {
                subject: "test:unknown-repository".to_string(),
                authority: registry.authority.clone(),
                registry_stable_id: registry.registry_stable_id.clone(),
                grants: vec![OciRepositoryGrant {
                    repository: RepositoryName::parse("unknown").unwrap(),
                    actions: vec!["pull".to_string()],
                }],
            },
            300,
        )
        .unwrap();
    let authenticated_unknown = registry
        .http
        .get(&unknown_repository_url)
        .bearer_auth(unknown_token)
        .send()
        .await
        .unwrap();
    assert_eq!(authenticated_unknown.status(), StatusCode::NOT_FOUND);
    assert_eq!(error_code(authenticated_unknown).await, "NAME_UNKNOWN");

    let unknown_blob_url = format!("{}v2/aos/blobs/sha256:{}", registry.origin, "0".repeat(64));
    let unauthenticated_blob = registry.http.get(&unknown_blob_url).send().await.unwrap();
    assert_eq!(unauthenticated_blob.status(), StatusCode::UNAUTHORIZED);
    let authenticated_blob = registry
        .http
        .get(&unknown_blob_url)
        .bearer_auth(pull_token)
        .send()
        .await
        .unwrap();
    assert_eq!(authenticated_blob.status(), StatusCode::NOT_FOUND);
    assert_eq!(error_code(authenticated_blob).await, "BLOB_UNKNOWN");

    let reference =
        RegistryReference::parse(&format!("{}/aos:latest", registry.authority)).unwrap();
    let client = RegistryClient::new(
        &reference,
        Some(&registry.origin),
        Some(hub_bearer.to_string()),
    )
    .unwrap();
    let output = tempfile::tempdir().unwrap();
    let verified = client
        .pull(
            &reference,
            &PullOptions::native(output.path().join("layout")),
        )
        .await
        .unwrap();
    assert_eq!(verified.manifest.digest, registry.image.manifest.digest);
}

#[tokio::test]
async fn public_registry_behind_hub_auth_requires_exchange_and_pull_tokens() {
    let registry = spawn_registry("public", false, "hub_auth").await;
    let manifest_url = format!("{}v2/aos/manifests/latest", registry.origin);
    let anonymous = registry.http.get(&manifest_url).send().await.unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(anonymous).await, "UNAUTHORIZED");

    let token_url = format!("{}v2/token", registry.origin);
    let anonymous_exchange = registry
        .http
        .get(&token_url)
        .query(&[
            ("service", registry.authority.as_str()),
            ("scope", "repository:aos:pull"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous_exchange.status(), StatusCode::UNAUTHORIZED);

    let hub_bearer = registry.hub_bearer.as_deref().unwrap();
    let exchange = registry
        .http
        .get(&token_url)
        .query(&[
            ("service", registry.authority.as_str()),
            ("scope", "repository:aos:pull"),
        ])
        .bearer_auth(hub_bearer)
        .send()
        .await
        .unwrap();
    assert_eq!(exchange.status(), StatusCode::OK);
    let token: serde_json::Value = exchange.json().await.unwrap();
    let authorized = registry
        .http
        .get(&manifest_url)
        .bearer_auth(token["token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);
    assert_eq!(authorized.headers()[CACHE_CONTROL], "private, no-store");
    assert_eq!(authorized.headers()[VARY], "Authorization");
}

#[tokio::test]
async fn soft_deleted_registry_owner_stops_every_distribution_endpoint_immediately() {
    let registry = spawn_registry("private", false, "hub_auth").await;
    let hub_bearer = registry.hub_bearer.as_deref().unwrap();
    let token_url = format!("{}v2/token", registry.origin);
    let exchange = registry
        .http
        .get(&token_url)
        .query(&[
            ("service", registry.authority.as_str()),
            ("scope", "repository:aos:pull"),
        ])
        .bearer_auth(hub_bearer)
        .send()
        .await
        .unwrap();
    assert_eq!(exchange.status(), StatusCode::OK);
    let token: serde_json::Value = exchange.json().await.unwrap();
    let pull_token = token["token"].as_str().unwrap().to_string();

    assert!(registry
        .db
        .soft_delete_org(registry.org_id, 86_400)
        .await
        .unwrap());
    let requests = [
        registry.http.get(format!("{}v2/", registry.origin)),
        registry
            .http
            .get(&token_url)
            .query(&[
                ("service", registry.authority.as_str()),
                ("scope", "repository:aos:pull"),
            ])
            .bearer_auth(hub_bearer),
        registry
            .http
            .get(format!("{}v2/aos/manifests/latest", registry.origin))
            .bearer_auth(&pull_token),
    ];
    for request in requests {
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(error_code(response).await, "NAME_UNKNOWN");
    }
}

#[tokio::test]
async fn upload_resumes_after_materialization_before_evidence_and_rejects_wrong_terminal_digest() {
    let registry = spawn_registry("private", true, "hub_auth").await;
    let token = exchange_oci_token(&registry, &["repository:aos:pull,push"]).await;
    let owner = registry.keys.verify_oci_claims(&token).unwrap().sub;
    let bytes = b"materialized before crash evidence";
    let digest = Sha256Digest::digest(bytes);

    let start = registry
        .http
        .post(format!("{}v2/aos/blobs/uploads/", registry.origin))
        .query(&[
            ("digest", digest.to_string()),
            ("size", bytes.len().to_string()),
        ])
        .bearer_auth(&token)
        .body(Vec::new())
        .send()
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::ACCEPTED);
    let upload_url = resolved_location(&registry, start.headers()[LOCATION].to_str().unwrap());
    let upload_id = url::Url::parse(&upload_url)
        .unwrap()
        .path_segments()
        .unwrap()
        .next_back()
        .unwrap()
        .to_string();

    let patch = registry
        .http
        .patch(&upload_url)
        .bearer_auth(&token)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_RANGE, format!("0-{}", bytes.len() - 1))
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(patch.status(), StatusCode::ACCEPTED);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let staged = registry
        .db
        .oci_upload(&upload_id, &owner, &owner, now)
        .await
        .unwrap()
        .unwrap();
    let placement_id = staged.staging_placement_id.unwrap();
    let placement_version = staged.staging_placement_resource_version.unwrap();
    assert_eq!(
        registry
            .db
            .claim_oci_upload(&ClaimOciUpload {
                upload_id: upload_id.clone(),
                writer_id: owner.clone(),
                token_id: owner.clone(),
                expected_resource_version: staged.resource_version,
                materialization_placement_id: placement_id,
                materialization_placement_resource_version: placement_version,
                materialization_binding_id: staged.staging_binding_id.unwrap(),
                materialization_binding_write_revision: staged
                    .staging_binding_write_revision
                    .unwrap(),
                digest,
                now,
                lease_expires_at: now + 900,
            })
            .await
            .unwrap(),
        OciBlobClaimOutcome::Claimed
    );

    // Models a process crash after the provider made the canonical object
    // visible but before the Hub recorded immutable placement evidence.
    let canonical = registry
        .surface_root
        .join("objects")
        .join(oci_blob_object_key(digest));
    fs::create_dir_all(canonical.parent().unwrap()).unwrap();
    fs::write(&canonical, bytes).unwrap();

    let resumable = registry
        .http
        .get(&upload_url)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resumable.status(), StatusCode::NO_CONTENT);
    let rejected_cancel = registry
        .http
        .delete(&upload_url)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(rejected_cancel.status(), StatusCode::CONFLICT);
    assert_eq!(fs::read(&canonical).unwrap(), bytes);

    let completed = registry
        .http
        .put(&upload_url)
        .query(&[("digest", digest.to_string())])
        .bearer_auth(&token)
        .body(Vec::new())
        .send()
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::CREATED);
    assert_eq!(fs::read(&canonical).unwrap(), bytes);

    let wrong_digest = Sha256Digest::digest(b"wrong terminal digest");
    let wrong_replay = registry
        .http
        .put(&upload_url)
        .query(&[("digest", wrong_digest.to_string())])
        .bearer_auth(&token)
        .body(Vec::new())
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_replay.status(), StatusCode::BAD_REQUEST);
    assert_eq!(error_code(wrong_replay).await, "DIGEST_INVALID");
    assert_eq!(
        count_regular_files(&registry.surface_root.join("objects/oci/uploads")),
        0
    );
}
