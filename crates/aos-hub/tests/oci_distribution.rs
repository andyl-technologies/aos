//! Native Hub OCI Distribution delivery over a real TCP listener.
//!
//! These tests admit exact verified object bytes into the relational OCI
//! catalog, route a root-mounted registry through the native Axum shell, and
//! then exercise both raw Distribution requests and the production OCI client.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;

use aos_hub::auth::extract::AuthState;
use aos_hub::auth::jwt::{JwtKeys, OciClaims, OciTokenGrant, OCI_AUTHORIZATION_CLAIMS_VERSION};
use aos_hub::db::{
    Database, EndpointHostInput, EndpointRevisionSpec, NewTopologyOperation,
    NewTopologyOperationTarget, NewTopologyOperationTargetRef, RouteSpec, SetSurfaceObject,
    SurfaceTarget, TokenAuth,
};
use aos_hub::domain::{Permission, Principal, Scope};
use aos_hub::server::{router, AppState};
use aos_hub_core::db::{
    oci_blob_object_key, IndexOciRepositoryCatalog, OciCatalogObject, OciCatalogProjection,
};
use aos_oci::{PullOptions, RegistryClient, RegistryReference};
use aos_oci_types::{
    to_canonical_json, Annotations, Descriptor, HistoryEntry, ImageConfig, ImageIndex,
    ImageManifest, ImageRuntimeConfig, MediaType, Platform, RepositoryName, RootFs, RootFsType,
    Sha256Digest, Tag,
};
use base64::Engine as _;
use hmac::{Hmac, Mac as _};
use reqwest::header::{
    ACCEPT, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, IF_NONE_MATCH, LINK,
    RANGE, VARY, WWW_AUTHENTICATE,
};
use reqwest::StatusCode;
use sha2::{Digest as _, Sha256};

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
    registry_stable_id: String,
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
    let layer = format!("fixture layer for {marker}\n").into_bytes();
    let diff_id = Sha256Digest::digest(&layer);
    let layer_descriptor = descriptor(MediaType::OciLayerTar, &layer, None);

    let config = ImageConfig {
        created: Some("1970-01-01T00:00:01Z".to_string()),
        author: None,
        architecture: "amd64".to_string(),
        os: "linux".to_string(),
        os_version: None,
        os_features: Vec::new(),
        variant: None,
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
    let manifest_bytes = to_canonical_json(&manifest).unwrap();
    let manifest_descriptor = descriptor(
        MediaType::OciImageManifest,
        &manifest_bytes,
        Some(Platform::linux_amd64()),
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
                projection: Some(OciCatalogProjection::Manifest(manifest)),
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
            projection: Some(OciCatalogProjection::Manifest(manifest)),
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
    let (_artifact_root, artifact_objects) = artifact_graph(&image);
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
        &image.root,
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
        db.grant_membership("user", user_id, &org.stable_id, "viewer")
            .await
            .unwrap();
        let scope = db.registry_authorization_scope(registry_id).await.unwrap();
        Some(
            keys.mint(
                &TokenAuth {
                    token_id: "native-oci-hub-token".to_string(),
                    owner: Principal::user(user_id),
                    scope: Scope::parse(&scope),
                    permissions: vec![Permission::Read],
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
        registry_stable_id: registry.stable_id,
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
        repository: RepositoryName::parse(repository).unwrap(),
        actions: vec![action.to_string()],
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
                    repository: RepositoryName::parse("aos").unwrap(),
                    actions: vec!["pull".to_string()],
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
                    repository: RepositoryName::parse("other").unwrap(),
                    actions: vec!["pull".to_string()],
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
    assert_eq!(wrong_action.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(wrong_action).await, "UNAUTHORIZED");

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
                repository: RepositoryName::parse("unknown").unwrap(),
                actions: vec!["pull".to_string()],
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
