//! Native end-to-end coverage for signed AOS container publication.
//!
//! This test crosses the real process, Connect, Distribution, filesystem
//! placement, signed APR release, Hub indexer, and production pull boundaries.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "../../aos-oci/tests/support/mod.rs"]
mod oci_support;

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result, bail};
use aos_hub::auth::extract::AuthState;
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::db::{
    Database, EndpointHostInput, EndpointRevisionSpec, NewBindingWriteRevision,
    NewSurfacePlacementSpec, RegistryRecord, RouteSpec, SurfacePlacementRecord, SurfaceTarget,
    TokenAuth,
};
use aos_hub::domain::{Permission, Principal, Scope};
use aos_hub::fetch::LocalFsFetch;
use aos_hub::server::{AppState, router};
use aos_hub_core::db::oci_blob_object_key;
use aos_oci::{PullOptions, RegistryClient, RegistryReference};
use aos_oci_types::{
    CONTAINER_DSSE_SIGNATURE_NAMESPACE, CONTAINER_SIGNATURE_INPUT_MEDIA_TYPE,
    CONTAINER_SIGNATURE_INPUT_SCHEMA, ContainerDsseEnvelope, ContainerDsseSignature,
    ContainerEvidenceQualificationCheck, ContainerEvidenceUnknownPath, ContainerRelease,
    ContainerSignatureInput, ContainerSignatureInputEvidence, MediaType, RepositoryName,
    Sha256Digest, Tag, to_canonical_json,
};
use aos_package::security::parse_signing_key;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const APR_REGISTRY: &str = "native-container-publication";
const RELEASE: &str = "1.0.0";
const TARGET_TAG: &str = "stable";
const TEST_JWT_SECRET: &[u8] = b"native-container-publication-secret";

#[derive(Clone, Debug, PartialEq, Eq)]
struct ControlObservation {
    method: String,
    status: StatusCode,
    tag_digest: Option<Sha256Digest>,
}

#[derive(Clone)]
struct ObserverState {
    db: Arc<Database>,
    registry_id: i64,
    observations: Arc<Mutex<Vec<ControlObservation>>>,
}

struct RunningHub {
    db: Arc<Database>,
    image_snapshots: Arc<aos_hub::image_snapshot::ImageSnapshotStore>,
    registry: RegistryRecord,
    placement_id: i64,
    surface: PathBuf,
    replica_placement_id: i64,
    replica_surface: PathBuf,
    authority: String,
    origin: String,
    bearer: String,
    observations: Arc<Mutex<Vec<ControlObservation>>>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for RunningHub {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_apr_release_admits_and_publishes_the_staged_graph() -> Result<()> {
    let workspace = tempfile::tempdir()?;
    let home = workspace.path().join("home");
    fs::create_dir_all(&home)?;
    let (trust_key, key_path, authoring_registry) = create_authoring_registry(&home)?;
    let hub = spawn_hub(workspace.path(), &trust_key).await?;

    let fixture = oci_support::fixture();
    let mut release = oci_support::add_signed_release_graph(&fixture);
    let signature_input = signature_input(&release);
    let envelope = signed_container_envelope(&signature_input, &key_path, &trust_key)?;
    oci_support::replace_signature_artifact(&fixture, &mut release, &envelope);
    let release_bytes = to_canonical_json(&release)?;
    let release_path = workspace.path().join("container-release.json");
    fs::write(&release_path, &release_bytes)?;
    let signature_input_path = workspace.path().join("signature-input.json");
    fs::write(&signature_input_path, to_canonical_json(&signature_input)?)?;

    assert_local_publication_rejections(
        &hub,
        workspace.path(),
        fixture.root(),
        &release,
        &release_path,
        &signature_input,
    )
    .await?;

    let reference = format!("{}/aos:{TARGET_TAG}", hub.authority);
    let staged = run_publish(
        &hub,
        workspace.path(),
        fixture.root(),
        &release_path,
        &signature_input_path,
        &reference,
        "native-release-1",
        true,
    )?;
    assert_eq!(staged["schema"], "aos.container.cli/v1");
    assert_eq!(staged["operation"], "publish");
    assert_eq!(staged["state"], "staged");
    assert_eq!(staged["object_count"], 18);
    assert_eq!(staged["index_digest"], release.oci.index.digest.to_string());
    assert_eq!(staged["tag_updated"], false);
    assert_eq!(staged["verification"], "pending-control-plane-commit");
    assert!(hub.observations.lock().unwrap().is_empty());

    let repository_name = RepositoryName::parse("aos")?;
    let repository = hub
        .db
        .oci_repository(hub.registry.id, &repository_name)
        .await?
        .context("stage-only upload did not create the OCI repository")?;
    let roots = release_roots(&release);
    let graph = hub
        .db
        .oci_repository_closed_graph(repository.id, &roots)
        .await?;
    assert_eq!(graph.len(), 18, "complete staged release graph");
    for object in &graph {
        let path = hub
            .surface
            .join(oci_blob_object_key(object.descriptor.digest));
        let bytes =
            fs::read(&path).with_context(|| format!("reading staged object {}", path.display()))?;
        assert_eq!(Sha256Digest::digest(&bytes), object.descriptor.digest);
        assert_eq!(bytes.len() as u64, object.descriptor.size);

        let replica_path = hub
            .replica_surface
            .join(oci_blob_object_key(object.descriptor.digest));
        fs::create_dir_all(replica_path.parent().context("replica object parent")?)?;
        fs::write(&replica_path, &bytes)?;
        let evidence = hub
            .db
            .record_oci_uploaded_object(
                hub.registry.id,
                hub.replica_placement_id,
                object.descriptor.digest,
                object.descriptor.size,
                &format!("native-replica-{}", object.descriptor.digest.encoded()),
                aos_hub_core::clock::now_unix_secs(),
            )
            .await?;
        assert_eq!(evidence.placement_id, hub.replica_placement_id);
    }
    assert_tag(&hub.db, repository.id, None).await?;

    assert_apr_attachment_rejections(
        &home,
        &key_path,
        &release_path,
        &signature_input_path,
        &authoring_registry,
    )?;
    run_apr(
        &home,
        &[
            "release",
            RELEASE,
            "--registry",
            APR_REGISTRY,
            "--key",
            path_str(&key_path)?,
            "--container-release",
            path_str(&release_path)?,
            "--container-signature-input",
            path_str(&signature_input_path)?,
        ],
    )?;
    run_apr(
        &home,
        &[
            "channel",
            "init",
            TARGET_TAG,
            RELEASE,
            "--registry",
            APR_REGISTRY,
            "--key",
            path_str(&key_path)?,
        ],
    )?;
    let committed_sidecar = git_output(
        &authoring_registry,
        &["show", "1.0.0:containers/v1/index.json"],
    )?;
    assert_eq!(committed_sidecar, release_bytes);

    run_apr(
        &home,
        &[
            "origin",
            "upload",
            "--registry",
            APR_REGISTRY,
            "--upload-url",
            &format!("file://{}", hub.surface.display()),
        ],
    )?;
    let fetch = LocalFsFetch::new(&hub.surface)
        .with_image_snapshots(Arc::clone(&hub.image_snapshots))
        .with_image_snapshot_db(Arc::clone(&hub.db))
        .with_image_snapshot_indexing();
    aos_hub::indexer::index_and_record_from_placement(
        &hub.db,
        &fetch,
        &hub.registry,
        Some(hub.placement_id),
    )
    .await?;
    let sidecar_sha256 = Sha256Digest::digest(&committed_sidecar).encoded();
    assert!(
        hub.db
            .oci_signed_release_root_exists(
                hub.registry.id,
                repository.id,
                RELEASE,
                release.oci.index.digest,
                &sidecar_sha256,
            )
            .await?,
        "signed APR release did not admit the exact container root"
    );
    let channels = hub.db.list_channels(hub.registry.id).await?;
    let stable = channels
        .iter()
        .find(|channel| channel.name == TARGET_TAG)
        .context("indexed APR channel disappeared")?;
    assert_eq!(stable.frontier.as_deref(), Some(RELEASE));
    assert_eq!(stable.partitions.len(), 256);
    assert!(
        stable
            .partitions
            .iter()
            .all(|partition| partition.as_deref() == Some(RELEASE)),
        "signed APR channel did not converge all 256 partitions"
    );

    let published = run_publish(
        &hub,
        workspace.path(),
        fixture.root(),
        &release_path,
        &signature_input_path,
        &reference,
        "native-release-1",
        false,
    )?;
    assert_eq!(published["verification"], "verified");
    assert_eq!(
        published["verified_release_root"],
        release.oci.index.digest.to_string()
    );
    assert_eq!(published["target_tag"], TARGET_TAG);
    assert_eq!(published["source_kind"], "channel");
    assert_eq!(published["required_placement_count"], 2);
    assert!(
        published["topology_digest"]
            .as_str()
            .is_some_and(|value| { Sha256Digest::parse(value).is_ok() })
    );
    assert_control_sequence(&hub, None, release.oci.index.digest);
    assert_tag(&hub.db, repository.id, Some(release.oci.index.digest)).await?;

    let referrers = hub
        .db
        .oci_referrers(repository.id, release.oci.index.digest, None)
        .await?;
    assert_eq!(referrers.len(), 6);
    let mut artifact_types = referrers
        .iter()
        .filter_map(|descriptor| descriptor.artifact_type.as_ref())
        .map(|media_type| media_type.as_str())
        .collect::<Vec<_>>();
    artifact_types.sort();
    let mut expected_types = vec![
        MediaType::AosNixClosure.as_str(),
        MediaType::SpdxJson.as_str(),
        MediaType::AosSourceClosure.as_str(),
        MediaType::AosLicenseReport.as_str(),
        MediaType::InTotoJson.as_str(),
        MediaType::DsseEnvelope.as_str(),
    ];
    expected_types.sort();
    assert_eq!(artifact_types, expected_types);

    hub.observations.lock().unwrap().clear();
    let retried = run_publish(
        &hub,
        workspace.path(),
        fixture.root(),
        &release_path,
        &signature_input_path,
        &reference,
        "native-release-1",
        false,
    )?;
    assert_eq!(retried["publication_id"], published["publication_id"]);
    assert_eq!(retried["resource_version"], published["resource_version"]);
    assert_eq!(
        retried["verified_release_root"],
        published["verified_release_root"]
    );
    assert_control_sequence(
        &hub,
        Some(release.oci.index.digest),
        release.oci.index.digest,
    );
    let tags = hub.db.oci_tags(repository.id, 10, None).await?;
    assert_eq!(tags.len(), 1);
    assert_eq!(tags[0].name.as_str(), TARGET_TAG);
    assert_eq!(tags[0].digest, release.oci.index.digest);
    assert_eq!(tags[0].source_kind, "channel");
    assert_eq!(tags[0].resource_version, 1, "retry must not move the tag");

    let pull_reference = RegistryReference::parse(&reference)?;
    let client = RegistryClient::new(&pull_reference, Some(&hub.origin), Some(hub.bearer.clone()))?;
    let pull_destination = workspace.path().join("pulled-layout");
    let pulled = client
        .pull(
            &pull_reference,
            &PullOptions::native(pull_destination.clone()),
        )
        .await?;
    assert_eq!(
        pulled.index_digest,
        Sha256Digest::digest(&fs::read(pull_destination.join("index.json"))?)
    );
    assert_eq!(pulled.manifest.digest, fixture.manifest_descriptor.digest);
    assert_eq!(pulled.layers, vec![fixture.layer_descriptor.clone()]);

    Ok(())
}

fn signature_input(release: &ContainerRelease) -> ContainerSignatureInput {
    ContainerSignatureInput {
        schema: CONTAINER_SIGNATURE_INPUT_SCHEMA.to_string(),
        identity: release.identity.clone(),
        oci: release.oci.clone(),
        nix: release.nix.clone(),
        evidence: ContainerSignatureInputEvidence {
            sbom: release.evidence.sbom.clone(),
            source: release.evidence.source.clone(),
            license: release.evidence.license.clone(),
            provenance: release.evidence.provenance.clone(),
        },
        qualification: release.qualification.clone(),
    }
}

fn signed_container_envelope(
    input: &ContainerSignatureInput,
    key_path: &Path,
    trust_key: &str,
) -> Result<Vec<u8>> {
    let payload = to_canonical_json(input)?;
    let (_, _, keyid) = parse_signing_key(trust_key)?;
    let mut envelope = ContainerDsseEnvelope {
        payload_type: CONTAINER_SIGNATURE_INPUT_MEDIA_TYPE.to_string(),
        payload: base64::engine::general_purpose::STANDARD.encode(payload),
        signatures: vec![ContainerDsseSignature {
            keyid,
            sig: base64::engine::general_purpose::STANDARD.encode(b"pending"),
        }],
    };
    let pae = envelope.pae()?;
    let armor = aos_package::security::sign_payload_signature(
        key_path,
        CONTAINER_DSSE_SIGNATURE_NAMESPACE,
        &pae,
    )?;
    envelope.signatures[0].sig = base64::engine::general_purpose::STANDARD.encode(armor.as_bytes());
    to_canonical_json(&envelope).map_err(Into::into)
}

fn release_roots(release: &ContainerRelease) -> Vec<aos_oci_types::Descriptor> {
    vec![
        release.oci.index.clone(),
        release.nix.closure.clone(),
        release.evidence.sbom.clone(),
        release.evidence.source.clone(),
        release.evidence.license.clone(),
        release.evidence.provenance.clone(),
        release.evidence.signature.clone(),
    ]
}

async fn assert_local_publication_rejections(
    hub: &RunningHub,
    workspace: &Path,
    layout: &Path,
    release: &ContainerRelease,
    release_path: &Path,
    signature_input: &ContainerSignatureInput,
) -> Result<()> {
    let noncanonical = workspace.join("noncanonical-release.json");
    fs::write(&noncanonical, serde_json::to_vec_pretty(release)?)?;
    let ready_input = workspace.join("ready-signature-input.json");
    fs::write(&ready_input, to_canonical_json(signature_input)?)?;
    let reference = format!("{}/aos:{TARGET_TAG}", hub.authority);
    let rejected = publish_output(
        hub,
        workspace,
        layout,
        &noncanonical,
        &ready_input,
        &reference,
        "reject-noncanonical",
        true,
    )?;
    assert_failure_contains(&rejected, "document must use canonical JSON");

    let mut unqualified = signature_input.clone();
    unqualified.qualification.corresponding_source = ContainerEvidenceQualificationCheck {
        complete: false,
        unknown_paths: vec![ContainerEvidenceUnknownPath {
            path: "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-unqualified".to_string(),
            reason: "missing corresponding source".to_string(),
        }],
    };
    unqualified.qualification.ready_for_verified_publication = false;
    let unqualified_path = workspace.join("unqualified-signature-input.json");
    fs::write(&unqualified_path, to_canonical_json(&unqualified)?)?;
    let rejected = publish_output(
        hub,
        workspace,
        layout,
        release_path,
        &unqualified_path,
        &reference,
        "reject-unqualified",
        true,
    )?;
    assert_failure_contains(&rejected, "readyForVerifiedPublication must be true");
    assert!(hub.observations.lock().unwrap().is_empty());
    assert!(
        hub.db
            .oci_repository(hub.registry.id, &RepositoryName::parse("aos")?)
            .await?
            .is_none(),
        "local validation failures must precede Distribution effects"
    );
    Ok(())
}

fn assert_apr_attachment_rejections(
    home: &Path,
    key_path: &Path,
    release_path: &Path,
    signature_input_path: &Path,
    registry: &Path,
) -> Result<()> {
    let missing_input = run_apr_output(
        home,
        &[
            "release",
            RELEASE,
            "--registry",
            APR_REGISTRY,
            "--key",
            path_str(key_path)?,
            "--container-release",
            path_str(release_path)?,
        ],
    )?;
    assert_failure_contains(
        &missing_input,
        "--container-release requires the paired --container-signature-input",
    );
    let missing_release = run_apr_output(
        home,
        &[
            "release",
            RELEASE,
            "--registry",
            APR_REGISTRY,
            "--key",
            path_str(key_path)?,
            "--container-signature-input",
            path_str(signature_input_path)?,
        ],
    )?;
    assert_failure_contains(
        &missing_release,
        "--container-signature-input requires the paired --container-release",
    );
    let wrong_release = run_apr_output(
        home,
        &[
            "release",
            "1.0.1",
            "--registry",
            APR_REGISTRY,
            "--key",
            path_str(key_path)?,
            "--container-release",
            path_str(release_path)?,
            "--container-signature-input",
            path_str(signature_input_path)?,
        ],
    )?;
    assert_failure_contains(&wrong_release, "does not match apr release semver '1.0.1'");
    let tag_probe = Command::new("git")
        .args(["rev-parse", "--verify", "refs/tags/1.0.1"])
        .current_dir(registry)
        .output()?;
    assert!(
        !tag_probe.status.success(),
        "rejected APR release created a tag"
    );
    Ok(())
}

fn create_authoring_registry(home: &Path) -> Result<(String, PathBuf, PathBuf)> {
    let generated = run_apr(
        home,
        &["keys", "generate", "initial", "--registry", APR_REGISTRY],
    )?;
    let trust_key = generated
        .lines()
        .filter_map(|line| {
            let value = line.split_whitespace().last()?;
            parse_signing_key(value).ok().map(|_| value.to_string())
        })
        .next()
        .with_context(|| format!("APR key output omitted the trust key:\n{generated}"))?;
    let key_path = home.join(format!(".config/apm/keys/{APR_REGISTRY}-initial.key"));
    run_apr(
        home,
        &[
            "create",
            APR_REGISTRY,
            "--trust-key",
            &trust_key,
            "--key",
            path_str(&key_path)?,
        ],
    )?;
    let registry = home.join(".local/share/apm/registries").join(APR_REGISTRY);
    let package = registry.join("packages/a/aos.toml");
    fs::create_dir_all(package.parent().context("package parent")?)?;
    fs::write(
        &package,
        r#"[package]
name = "aos"
description = "Native container publication fixture"
license = "Apache-2.0"
maintainer = "registry@example.com"

[[versions]]
version = "0.1.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-0.1.0"
nar_hash = "sha256:placeholder"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
references = []
"#,
    )?;
    run_apr(
        home,
        &[
            "commit",
            "packages/a/aos.toml",
            "--message",
            "publish aos package metadata",
            "--registry",
            APR_REGISTRY,
            "--key",
            path_str(&key_path)?,
        ],
    )?;
    Ok((trust_key, key_path, registry))
}

async fn spawn_hub(workspace: &Path, trust_key: &str) -> Result<RunningHub> {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let authority = address.to_string();
    let origin = format!("http://{authority}/");
    let storage = workspace.join("hub-storage");
    let surface = storage.join("surface");
    let replica_surface = storage.join("replica");
    fs::create_dir_all(&surface)?;
    fs::create_dir_all(&replica_surface)?;

    let db = Arc::new(Database::open_in_memory().await?);
    let org_id = db.create_org("native", "Native publication").await?;
    let registry_id = db
        .create_managed_registry(
            org_id,
            "",
            "containers",
            "private",
            &[trust_key.to_string()],
            true,
        )
        .await?;
    let registry = db
        .registry_by_id(registry_id)
        .await?
        .context("created registry disappeared")?;
    let binding = create_local_binding(
        &db,
        org_id,
        "native-container-publication",
        path_str(&storage)?,
    )
    .await?;
    let placement = create_ready_placement(
        &db,
        SurfaceTarget::Registry(registry.id),
        binding,
        "native-container-publication",
        "surface",
    )
    .await?;
    let replica = create_ready_placement(
        &db,
        SurfaceTarget::Registry(registry.id),
        binding,
        "native-container-publication-replica",
        "replica",
    )
    .await?;
    let write_revision = configure_write_authority(
        &db,
        SurfaceTarget::Registry(registry.id),
        binding,
        &placement,
        "native-container-publication-writer",
    )
    .await?;
    db.bind_surface_placement_write_capability(replica.id, write_revision)
        .await?;
    configure_oci_route(&db, &registry, placement.id, address.port()).await?;

    let user_id = db
        .create_user("publisher@native.example", Some("Native publisher"))
        .await?;
    db.grant_membership("user", user_id, &registry.owner_scope_key, "maintainer")
        .await?;
    let keys = JwtKeys::from_secret(TEST_JWT_SECRET);
    let bearer = keys.mint(
        &TokenAuth {
            token_id: "native-container-publisher".to_string(),
            owner: Principal::user(user_id),
            scope: Scope::parse(&db.registry_authorization_scope(registry.id).await?),
            permissions: vec![Permission::Read, Permission::Publish],
        },
        900,
    )?;
    let ratelimit = Arc::new(aos_hub::ratelimit::RateLimiter::new());
    let auth = Arc::new(AuthState {
        db: Arc::clone(&db),
        jwt_keys: keys,
        access_token_ttl: 900,
        ratelimit: Arc::clone(&ratelimit),
        trusted_proxy: false,
    });
    let snapshots = aos_hub::image_snapshot::ImageSnapshotStore::open(workspace)?;
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
        image_snapshots: Some(Arc::clone(&snapshots)),
        ratelimit,
        trusted_proxy: false,
        delivery_attestation_verifier: None,
        domain_probe_terminator: None,
        identity_domain_verifier: None,
        route_reservation_keyring: None,
        container_rollout: aos_hub_core::container_rollout::ContainerRollout::all_enabled(),
    });
    let observations = Arc::new(Mutex::new(Vec::new()));
    let app = router(state)
        .await
        .layer(axum::middleware::from_fn_with_state(
            ObserverState {
                db: Arc::clone(&db),
                registry_id: registry.id,
                observations: Arc::clone(&observations),
            },
            observe_control,
        ));
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("native publication Hub server");
    });
    Ok(RunningHub {
        db,
        image_snapshots: snapshots,
        registry,
        placement_id: placement.id,
        surface,
        replica_placement_id: replica.id,
        replica_surface,
        authority,
        origin,
        bearer,
        observations,
        server,
    })
}

async fn create_local_binding(db: &Database, org_id: i64, name: &str, path: &str) -> Result<i64> {
    db.org_by_id(org_id)
        .await?
        .context("binding owner organization disappeared")?;
    db.create_topology_binding(
        None,
        &uuid::Uuid::new_v4().simple().to_string(),
        "instance",
        name,
        "local_fs",
        Some(path),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
}

async fn create_ready_placement(
    db: &Database,
    surface: SurfaceTarget,
    binding_id: i64,
    name: &str,
    prefix: &str,
) -> Result<SurfacePlacementRecord> {
    let consumer_scope = match surface {
        SurfaceTarget::Registry(id) => {
            db.registry_by_id(id)
                .await?
                .context("placement registry disappeared")?
                .owner_scope_key
        }
        SurfaceTarget::BinaryCache(id) => {
            db.binary_cache_by_id(id)
                .await?
                .context("placement cache disappeared")?
                .owner_scope_key
        }
    };
    let binding = db
        .binding(binding_id)
        .await?
        .context("placement binding disappeared")?;
    let resource = aos_hub::db::GrantResource::Binding {
        id: binding_id,
        stable_id: &binding.stable_id,
    };
    if !db
        .list_consumer_scope_grants(resource)
        .await?
        .iter()
        .any(|grant| grant.consumer_scope_key == consumer_scope && grant.state == "active")
    {
        db.grant_consumer_scope(
            resource,
            &consumer_scope,
            "explicit",
            "test",
            &format!("test-placement-grant-{binding_id}-{name}"),
        )
        .await?;
    }
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface,
            name: name.to_string(),
            binding_id,
            prefix: prefix.to_string(),
            kind: "complete".to_string(),
            desired_state: "active".to_string(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await?;
    Ok(db
        .observe_surface_placement(placement.id, "ready", "complete", 1)
        .await?)
}

async fn configure_write_authority(
    db: &Database,
    surface: SurfaceTarget,
    binding_id: i64,
    placement: &SurfacePlacementRecord,
    incarnation_id: &str,
) -> Result<i64> {
    let expected = db
        .current_binding_credential(binding_id, "write")
        .await?
        .map_or(0, |revision| revision.generation);
    let credential = db
        .set_binding_credential_revision(
            binding_id,
            "write",
            "secret://test/write/v1",
            expected,
            &"0".repeat(64),
            "test",
        )
        .await?;
    let credential_generation = db
        .validate_binding_credential_revision(
            binding_id,
            "write",
            credential.generation,
            "valid",
            None,
            credential.head_resource_version,
        )
        .await?
        .generation;
    let revision = db
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id,
            write_credential_generation: credential_generation,
            writes_supported: true,
            conditional_writes_supported: true,
            revision_fingerprint: format!("test-write-revision-{binding_id}"),
            capability_fingerprint: "test-writes-and-conditional-writes".to_string(),
        })
        .await?;
    db.observe_binding_write_revision(binding_id, revision.revision, "valid", None, None)
        .await?;
    let state = db
        .binding_write_state(binding_id)
        .await?
        .context("binding write state disappeared")?;
    db.set_current_binding_write_revision(binding_id, revision.revision, state.resource_version)
        .await?;
    db.bind_surface_placement_write_capability(placement.id, revision.revision)
        .await?;
    db.create_surface_write_authority(
        surface,
        incarnation_id,
        placement.id,
        placement.resource_version,
        placement.write_spec_version,
        revision.revision,
    )
    .await?;
    Ok(revision.revision)
}

async fn configure_oci_route(
    db: &Database,
    registry: &RegistryRecord,
    placement_id: i64,
    port: u16,
) -> Result<()> {
    let boundary = aos_hub::db::GrantResource::NetworkPolicy {
        id: "instance:public",
    };
    let grants = db.list_consumer_scope_grants(boundary).await?;
    if !grants.iter().any(|grant| {
        grant.consumer_scope_key == registry.owner_scope_key && grant.state == "active"
    }) {
        db.grant_consumer_scope(
            boundary,
            &registry.owner_scope_key,
            "explicit",
            "test",
            "request:native-container-boundary",
        )
        .await?;
    }
    db.create_endpoint(
        "endpoint:native-container",
        &registry.owner_scope_key,
        registry.org_id,
        "http",
        &EndpointHostInput::Ipv4([127, 0, 0, 1]),
        port,
        "instance:public",
        &EndpointRevisionSpec {
            boundary_revision: 1,
            ingress_kind: "hub".to_string(),
            listener_configuration: "listener:native-container".to_string(),
            tls_configuration: "{}".to_string(),
            probe_configuration: "{\"provider\":\"native_file\",\"signerSecretRef\":\"test-probe-key\",\"publicKey\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}".to_string(),
        },
        Some(1),
        "test",
        "request:native-container-endpoint",
    )
    .await?;
    db.reconcile_endpoint(
        "endpoint:native-container",
        1,
        1,
        "healthy",
        true,
        false,
        None,
        1,
    )
    .await?;

    let access_policy_json = "{}".to_string();
    let access_policy_digest = hex::encode(Sha256::digest(access_policy_json.as_bytes()));
    let canonical_url = format!("http://127.0.0.1:{port}");
    let endpoint = db
        .endpoint("endpoint:native-container")
        .await?
        .context("created endpoint disappeared")?;
    let endpoint_digest = hex::decode(&endpoint.endpoint_identity_digest)?;
    let reservation_digest =
        Database::route_reservation_digest(&[31_u8; 32], &endpoint_digest, "", &canonical_url)?;
    let route = db
        .create_route(
            "route:native-container",
            SurfaceTarget::Registry(registry.id),
            &RouteSpec {
                consumer_scope_key: registry.owner_scope_key.clone(),
                endpoint_id: "endpoint:native-container".to_string(),
                endpoint_generation: 1,
                endpoint_ingress_kind: "hub".to_string(),
                base_path: String::new(),
                mode: "hub_proxy".to_string(),
                access_policy_kind: "hub_auth".to_string(),
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
        .await?;
    db.reconcile_route(
        &route.id,
        route.configuration_generation.context("route generation")?,
        route
            .configuration_digest
            .as_deref()
            .context("route digest")?,
        &access_policy_digest,
        "healthy",
        "verified",
        None,
        None,
        1,
    )
    .await?;
    Ok(())
}

async fn observe_control(
    State(state): State<ObserverState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    let response = next.run(request).await;
    let Some(method) = path
        .strip_prefix("/aos.hub.v1.ContainerService/")
        .map(ToString::to_string)
    else {
        return response;
    };
    let tag_digest = match state
        .db
        .oci_repository(
            state.registry_id,
            &RepositoryName::parse("aos").expect("fixture repository"),
        )
        .await
        .expect("observer repository lookup")
    {
        Some(repository) => state
            .db
            .oci_tags(repository.id, 10, None)
            .await
            .expect("observer tag lookup")
            .into_iter()
            .find(|tag| tag.name.as_str() == TARGET_TAG)
            .map(|tag| tag.digest),
        None => None,
    };
    state.observations.lock().unwrap().push(ControlObservation {
        method,
        status: response.status(),
        tag_digest,
    });
    response
}

fn assert_control_sequence(
    hub: &RunningHub,
    before_commit: Option<Sha256Digest>,
    root: Sha256Digest,
) {
    assert_eq!(
        *hub.observations.lock().unwrap(),
        [
            ControlObservation {
                method: "BeginContainerPublication".to_string(),
                status: StatusCode::OK,
                tag_digest: before_commit,
            },
            ControlObservation {
                method: "GetContainerPublication".to_string(),
                status: StatusCode::OK,
                tag_digest: before_commit,
            },
            ControlObservation {
                method: "CommitContainerPublication".to_string(),
                status: StatusCode::OK,
                tag_digest: Some(root),
            },
        ]
    );
}

async fn assert_tag(
    db: &Database,
    repository_id: i64,
    expected: Option<Sha256Digest>,
) -> Result<()> {
    let tags = db.oci_tags(repository_id, 10, None).await?;
    let actual = tags
        .iter()
        .find(|tag| tag.name == Tag::parse(TARGET_TAG).expect("fixture tag"))
        .map(|tag| tag.digest);
    assert_eq!(actual, expected);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_publish(
    hub: &RunningHub,
    workspace: &Path,
    layout: &Path,
    release: &Path,
    signature_input: &Path,
    reference: &str,
    idempotency_key: &str,
    stage_only: bool,
) -> Result<Value> {
    let output = publish_output(
        hub,
        workspace,
        layout,
        release,
        signature_input,
        reference,
        idempotency_key,
        stage_only,
    )?;
    if !output.status.success() {
        bail!(
            "aos container publish failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    serde_json::from_slice(&output.stdout).context("parsing aos container publish JSON")
}

#[allow(clippy::too_many_arguments)]
fn publish_output(
    hub: &RunningHub,
    workspace: &Path,
    layout: &Path,
    release: &Path,
    signature_input: &Path,
    reference: &str,
    idempotency_key: &str,
    stage_only: bool,
) -> Result<Output> {
    let home = workspace.join("publisher-home");
    fs::create_dir_all(&home)?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_aos"));
    command
        .current_dir(workspace)
        .env("HOME", &home)
        .env("XDG_STATE_HOME", home.join(".local/state"))
        .args(["--json", "--progress", "off", "--color", "never"])
        .args(["container", "publish", "aos", reference])
        .arg("--release")
        .arg(release)
        .arg("--release-layout")
        .arg(layout)
        .arg("--signature-input")
        .arg(signature_input)
        .args(["--registry", &hub.registry.slug])
        .args(["--idempotency-key", idempotency_key])
        .args(["--registry-origin", &hub.origin])
        .args(["--registry-token", &hub.bearer]);
    if stage_only {
        command.arg("--stage-only");
    } else {
        command
            .args(["--hub", &hub.origin])
            .args(["--token", &hub.bearer]);
    }
    command.output().context("running aos container publish")
}

fn run_apr(home: &Path, arguments: &[&str]) -> Result<String> {
    let output = run_apr_output(home, arguments)?;
    if !output.status.success() {
        bail!(
            "apr {} failed:\nstdout:\n{}\nstderr:\n{}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn run_apr_output(home: &Path, arguments: &[&str]) -> Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_apr"))
        .env("HOME", home)
        .env("USER", "registry-test")
        .env("LOGNAME", "registry-test")
        .env("GIT_AUTHOR_NAME", "Registry Test")
        .env("GIT_AUTHOR_EMAIL", "registry@example.com")
        .env("GIT_COMMITTER_NAME", "Registry Test")
        .env("GIT_COMMITTER_EMAIL", "registry@example.com")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .args(arguments)
        .output()
        .with_context(|| format!("running apr {}", arguments.join(" ")))
}

fn assert_failure_contains(output: &Output, needle: &str) {
    assert!(!output.status.success(), "command unexpectedly succeeded");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
}

fn git_output(registry: &Path, arguments: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(registry)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(output.stdout)
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not UTF-8: {}", path.display()))
}
