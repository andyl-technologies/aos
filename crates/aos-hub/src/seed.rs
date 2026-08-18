//! Dev seed: populate a fresh hub with a browsable, signed demo registry.
//!
//! `aos-hub serve --dev` boots zero-config but empty, which makes a
//! local instance hard to demo or develop against — there is nothing to
//! browse, no account to log in with. [`seed_dev`] fills that gap: it writes a
//! complete, **correctly signed** registry surface to disk and registers it,
//! plus a demo org, a demo user with a known password, and a sample publish
//! token, then indexes the registry so its browse pages show real packages and
//! channels the instant the server comes up.
//!
//! # What it creates
//!
//! ```text
//! instance:   signup_policy = open
//! user:       demo@example.com  /  password "demo"   (Argon2id-hashed)
//! org:        demo  ("Demo Org")        ─ user is Owner
//! project:    demo/  (org root)
//! binding:    instance/default → deployment-owned local storage
//! registry:   demo/cdn  (canonical)  placed on `default`, signatures required
//! registry:   demo/private-images  authenticated twin for consumer testing
//! surface:    curl 8.5.0, openssl 3.2.1, jq 1.7.1    (x86_64-linux each)
//!             aos-system 1.0.0 as exact raw + QCOW2 disk downloads
//!             release 1.0.0, channel `stable` 100% rolled out
//!             registry.toml + keys.toml + signed HEAD commit + signed tag +
//!             256 signed partitions
//! token:      an org-scoped read/publish token (secret printed once)
//! ```
//!
//! # Signed surface
//!
//! The generated surface **is signed**. A deterministic maintainer Ed25519 key
//! (a fixed seed — fine for a throwaway dev instance) signs the HEAD commit,
//! the `1.0.0` release tag, and all 256 `stable` partitions, exactly as
//! [`crate::signing`] and the test fixtures do. The registry's pinned
//! `trust_keys` is that maintainer's trusted-key line and `require_signatures`
//! is left **on**, so the index verifies cleanly and the in-browser
//! verification badge is genuine.
//!
//! # Idempotency
//!
//! Seeding detects a prior run by the presence of the `demo` org and returns
//! early with [`SeedOutcome::AlreadySeeded`] rather than duplicating rows, so
//! `serve --dev --seed` is safe to leave on across restarts.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

use crate::db::{
    Database, DeliveryEndpointHostInput, DeliveryEndpointRevisionSpec, DeliveryRouteSpec,
    GrantResource, NewSurfacePlacementSpec, SignupPolicy, SurfaceTarget,
};
use crate::domain::{Permission, Principal, Role, Scope};
use crate::fetch::LocalFsFetch;
use crate::surface::object::{encode_loose, encode_tree, hash_object, ObjectKind, Oid, TreeEntry};
use crate::surface::sshsig;
use aos_hub_core::service::RouteReservationKey;

/// The demo user's email address.
pub const DEMO_EMAIL: &str = "demo@example.com";

/// The demo user's password (printed in the report; dev-only).
pub const DEMO_PASSWORD: &str = "demo";

/// The demo org slug.
pub const DEMO_ORG: &str = "demo";

/// The demo registry name (its canonical path is `demo/cdn`).
pub const DEMO_REGISTRY: &str = "cdn";

/// The private image-registry name used by the authenticated dev fixture.
pub const DEMO_PRIVATE_REGISTRY: &str = "private-images";

/// Runtime-owned network identity and reservation keys for seeded routes.
pub struct SeedRouteConfig<'a> {
    /// Bound native listener represented by the seeded Hub endpoint.
    pub listen_addr: SocketAddr,
    /// Externally reachable origin used to render immutable consumer URLs.
    pub external_url: &'a str,
    /// Active and retained URL-reservation keys configured for this deployment.
    pub reservation_keys: &'a [RouteReservationKey],
}

/// The demo release semver and channel.
const DEMO_SEMVER: &str = "1.0.0";
const DEMO_CHANNEL: &str = "stable";

/// A fixed Unix timestamp for the seeded commit/tag/partitions (deterministic).
const SEED_WHEN: i64 = 1_770_000_000;

/// The outcome of a [`seed_dev`] run.
#[derive(Debug, Clone)]
pub enum SeedOutcome {
    /// The hub was empty and was seeded; carries the [`SeedReport`].
    Seeded(SeedReport),
    /// The hub already had the demo org, so seeding was skipped.
    AlreadySeeded,
}

/// A summary of what [`seed_dev`] created, for printing to an operator.
#[derive(Debug, Clone)]
pub struct SeedReport {
    /// The registry's canonical path (`demo/cdn`).
    pub canonical: String,
    /// The browse URL path for the registry (`/demo/cdn/`).
    pub browse_url: String,
    /// The demo login email.
    pub login_email: String,
    /// The demo login password (plaintext; dev-only).
    pub login_password: String,
    /// The sample publish token's id.
    pub token_id: String,
    /// The sample publish token's secret (printed once).
    pub token_secret: String,
}

impl SeedReport {
    /// Print the report to stdout in a human-readable block.
    pub fn print(&self) {
        println!("seeded demo data:");
        println!("  registry:  {}", self.canonical);
        println!("  browse:    {}", self.browse_url);
        println!(
            "  login:     {}  /  {}",
            self.login_email, self.login_password
        );
        println!("  token id:  {}", self.token_id);
        println!("  token:     {}", self.token_secret);
    }
}

/// Seed a fresh hub with a browsable, signed demo registry and a demo login.
///
/// Idempotent: if the `demo` org already exists this returns
/// [`SeedOutcome::AlreadySeeded`] without touching the database. Otherwise it
/// creates the instance/user/org/project/binding/registry described in the
/// [module docs](self), generates and writes a correctly signed registry
/// surface under the deployment's default storage binding, indexes it so it is immediately
/// browsable, mints a sample publish token, and returns the
/// [`SeedReport`].
///
/// `root` is the hub state directory (the same `--root` the server uses) and
/// owns the retained image-snapshot store.
///
/// # Errors
///
/// Returns an error on any database failure, if the surface cannot be written
/// under `root`, or if the post-seed index fails (which would mean the
/// generated surface did not verify — a bug, surfaced loudly).
pub async fn seed_dev(
    db: &Database,
    root: &Path,
    route: &SeedRouteConfig<'_>,
) -> Result<SeedOutcome> {
    let storage_root = root.join("storage");
    std::fs::create_dir_all(&storage_root)
        .with_context(|| format!("creating development storage {}", storage_root.display()))?;
    let storage_root = storage_root
        .to_str()
        .context("development storage root is not valid UTF-8")?;
    db.ensure_instance_default_binding("local_fs", Some(storage_root), None)
        .await?;
    let snapshots = crate::image_snapshot::ImageSnapshotStore::open(root)?;
    seed_dev_with_snapshots(db, root, snapshots, route).await
}

/// Seeds a development instance using the runtime's retained image store.
///
/// # Errors
///
/// Returns an error when seed state cannot be written, signed, or indexed.
pub async fn seed_dev_with_snapshots(
    db: &Database,
    _root: &Path,
    image_snapshots: Arc<crate::image_snapshot::ImageSnapshotStore>,
    route: &SeedRouteConfig<'_>,
) -> Result<SeedOutcome> {
    // Idempotency gate: a prior run leaves the `demo` org behind.
    if db.org_by_slug(DEMO_ORG).await?.is_some() {
        return Ok(SeedOutcome::AlreadySeeded);
    }

    // Open signups so the demo user can create orgs from the console.
    db.set_signup_policy(SignupPolicy::Open).await?;

    // Demo user with a known (hashed) password.
    let user_id = db.find_or_create_user(DEMO_EMAIL).await?;
    let hash = crate::auth::password::hash_password(DEMO_PASSWORD)?;
    db.set_user_password(user_id, &hash).await?;

    // Org + org-root project, with the demo user as Owner.
    let org_id = db.create_org(DEMO_ORG, "Demo Org").await?;
    db.create_project(org_id, "", "Demo Org root").await?;
    let principal = Principal::user(user_id);
    let org_scope = db
        .org_by_id(org_id)
        .await?
        .context("seed organization disappeared")?
        .stable_id;
    db.grant_membership(
        principal.kind.as_str(),
        principal.id,
        Scope::parse(&org_scope).as_str(),
        Role::Owner.as_str(),
    )
    .await?;

    // Development storage uses the deployment-owned default local binding.
    // Seeding must not redefine that binding to point at a seed-only root;
    // ordinary placements remain explicit through the grant below.
    let binding = db
        .instance_default_binding()
        .await?
        .context("deployment default storage binding is not provisioned")?;
    anyhow::ensure!(
        binding.kind == "local_fs",
        "development seed requires a local deployment storage binding"
    );
    let bucket = std::path::PathBuf::from(
        binding
            .local_root_path
            .as_deref()
            .context("local deployment storage binding has no root path")?,
    );
    std::fs::create_dir_all(&bucket)
        .with_context(|| format!("creating seed bucket {}", bucket.display()))?;
    let binding_id = binding.id;

    // The live E2E launchers inject the output of the real `apr release`
    // producer here. Ordinary dev seeding retains the small in-process demo.
    // Both public and private placements receive independent copies so neither
    // registry depends on the other's availability.
    let producer_fixture =
        std::env::var_os("AOS_HUB_E2E_IMAGE_FIXTURE").map(std::path::PathBuf::from);
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let trust_key = if let Some(fixture) = &producer_fixture {
        std::fs::read_to_string(fixture.join("trust-key"))
            .context("reading producer fixture trust key")?
            .trim()
            .to_string()
    } else {
        sshsig::trusted_key_line("maintainer", &key.verifying_key())
    };
    let surface_root = bucket.join(DEMO_REGISTRY);
    let private_surface_root = bucket.join(DEMO_PRIVATE_REGISTRY);
    if let Some(fixture) = &producer_fixture {
        let source = fixture.join("surface");
        copy_surface_tree(&source, &surface_root, false)?;
        copy_surface_tree(&source, &private_surface_root, false)?;
    } else {
        write_signed_surface(&surface_root, &key, &trust_key)
            .with_context(|| format!("writing seed surface to {}", surface_root.display()))?;
        write_signed_surface(&private_surface_root, &key, &trust_key).with_context(|| {
            format!(
                "writing private seed surface to {}",
                private_surface_root.display()
            )
        })?;
    }

    // Register the managed registry, pinning the maintainer trust key with
    // signature verification on, then index it from the binding root.
    let registry_id = db
        .create_managed_registry(
            org_id,
            "",
            DEMO_REGISTRY,
            "public",
            std::slice::from_ref(&trust_key),
            true,
        )
        .await?;
    let private_registry_id = db
        .create_managed_registry(
            org_id,
            "",
            DEMO_PRIVATE_REGISTRY,
            "private",
            std::slice::from_ref(&trust_key),
            true,
        )
        .await?;
    let (registry, public_placement_id) = seed_placement_and_index(
        db,
        binding_id,
        registry_id,
        DEMO_REGISTRY,
        &surface_root,
        &image_snapshots,
    )
    .await
    .context("indexing public seeded registry")?;
    let (_, private_placement_id) = seed_placement_and_index(
        db,
        binding_id,
        private_registry_id,
        DEMO_PRIVATE_REGISTRY,
        &private_surface_root,
        &image_snapshots,
    )
    .await
    .context("indexing private seeded registry")?;
    seed_hub_delivery_routes(
        db,
        org_id,
        &org_scope,
        registry_id,
        public_placement_id,
        private_registry_id,
        private_placement_id,
        route,
    )
    .await
    .context("configuring seeded delivery topology")?;
    if let Some(fixture) = &producer_fixture {
        anyhow::ensure!(
            db.list_system_images(registry_id).await?.is_empty()
                && db.list_system_images(private_registry_id).await?.is_empty(),
            "producer image became discoverable before release/channel publication"
        );
        let source = fixture.join("surface");
        copy_surface_tree(&source, &surface_root, true)?;
        copy_surface_tree(&source, &private_surface_root, true)?;
        for (registry_id, placement_id, surface_root) in [
            (registry_id, public_placement_id, surface_root.as_path()),
            (
                private_registry_id,
                private_placement_id,
                private_surface_root.as_path(),
            ),
        ] {
            let registry = db
                .registry_by_id(registry_id)
                .await?
                .context("seeded producer registry disappeared")?;
            crate::indexer::index_and_record_from_placement(
                db,
                &LocalFsFetch::new(surface_root).with_image_snapshots(Arc::clone(&image_snapshots)),
                &registry,
                Some(placement_id),
            )
            .await?;
        }
    }
    anyhow::ensure!(
        db.list_system_image_root_keys(registry_id).await?.len() == 4
            && db
                .list_system_image_root_keys(private_registry_id)
                .await?
                .len()
                == 4,
        "seeded image publication did not become exact release GC roots"
    );

    // Mint one org-scoped token so the fixture can prove both anonymous public
    // access and authenticated private access through the same consumer CLI.
    let (token_id, token_secret) = db
        .create_token(
            principal,
            &org_scope,
            &[Permission::Read, Permission::Publish],
            Some("seed demo publish token"),
            None,
        )
        .await?;

    let report = SeedReport {
        browse_url: format!("/{}/", registry.slug),
        canonical: registry.slug.clone(),
        login_email: DEMO_EMAIL.to_string(),
        login_password: DEMO_PASSWORD.to_string(),
        token_id,
        token_secret,
    };
    Ok(SeedOutcome::Seeded(report))
}

/// Copies a producer-created static origin without interpreting its contents.
fn copy_surface_tree(source: &Path, destination: &Path, pointers_only: bool) -> Result<()> {
    copy_surface_tree_inner(source, source, destination, pointers_only)
}

fn copy_surface_tree_inner(
    root: &Path,
    source: &Path,
    destination: &Path,
    pointers_only: bool,
) -> Result<()> {
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)
        .with_context(|| format!("reading producer surface {}", source.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_surface_tree_inner(root, &entry.path(), &target, pointers_only)?;
        } else if file_type.is_file() {
            let entry_path = entry.path();
            let relative = entry_path
                .strip_prefix(root)
                .unwrap_or(entry_path.as_path())
                .to_string_lossy()
                .replace('\\', "/");
            let pointer =
                relative == "HEAD" || relative == "info/refs" || relative.starts_with("channels/");
            if pointer == pointers_only {
                std::fs::copy(entry.path(), &target)?;
            }
        } else {
            anyhow::bail!("producer surface contains a non-file entry");
        }
    }
    Ok(())
}

async fn seed_placement_and_index(
    db: &Database,
    binding_id: i64,
    registry_id: i64,
    prefix: &str,
    surface_root: &Path,
    image_snapshots: &Arc<crate::image_snapshot::ImageSnapshotStore>,
) -> Result<(crate::db::RegistryRecord, i64)> {
    let registry = db
        .registry_by_id(registry_id)
        .await?
        .context("seeded registry disappeared")?;
    let consumer_scope = registry.owner_scope_key.clone();
    let binding = db
        .storage_binding(binding_id)
        .await?
        .context("seed storage binding disappeared")?;
    let binding_resource = GrantResource::StorageBinding {
        id: binding_id,
        stable_id: &binding.stable_id,
    };
    let binding_grants = db.list_consumer_scope_grants(binding_resource).await?;
    if !binding_grants
        .iter()
        .any(|grant| grant.consumer_scope_key == consumer_scope && grant.state == "active")
    {
        db.grant_consumer_scope(
            binding_resource,
            &consumer_scope,
            "explicit",
            "seed",
            &format!("seed-placement-grant-{registry_id}"),
        )
        .await?;
    }
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "primary".to_string(),
            storage_binding_id: binding_id,
            prefix: prefix.to_string(),
            kind: "complete".to_string(),
            desired_state: "active".to_string(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await?;
    db.observe_surface_placement(placement.id, "ready", "complete", 1)
        .await?;
    crate::indexer::index_and_record_from_placement(
        db,
        &LocalFsFetch::new(surface_root).with_image_snapshots(Arc::clone(image_snapshots)),
        &registry,
        Some(placement.id),
    )
    .await?;
    Ok((registry, placement.id))
}

#[allow(clippy::too_many_arguments)]
async fn seed_hub_delivery_routes(
    db: &Database,
    org_id: i64,
    org_scope: &str,
    public_registry_id: i64,
    public_placement_id: i64,
    private_registry_id: i64,
    private_placement_id: i64,
    config: &SeedRouteConfig<'_>,
) -> Result<()> {
    const ENDPOINT_ID: &str = "seed-hub";
    let boundary = GrantResource::NetworkBoundary {
        id: "instance:public",
    };
    if !db
        .list_consumer_scope_grants(boundary)
        .await?
        .iter()
        .any(|grant| grant.consumer_scope_key == org_scope && grant.state == "active")
    {
        db.grant_consumer_scope(
            boundary,
            org_scope,
            "explicit",
            "seed",
            "seed-hub-boundary-grant",
        )
        .await?;
    }

    let (host, port) = match config.listen_addr {
        SocketAddr::V4(address) => (
            DeliveryEndpointHostInput::Ipv4(address.ip().octets()),
            address.port(),
        ),
        SocketAddr::V6(address) => (
            DeliveryEndpointHostInput::Ipv6(address.ip().octets()),
            address.port(),
        ),
    };
    let scheme = url::Url::parse(config.external_url)
        .context("parsing seeded external URL")?
        .scheme()
        .to_string();
    anyhow::ensure!(
        matches!(scheme.as_str(), "http" | "https"),
        "seeded external URL must use HTTP or HTTPS"
    );
    db.create_delivery_endpoint(
        ENDPOINT_ID,
        org_scope,
        Some(org_id),
        &scheme,
        &host,
        port,
        "instance:public",
        &DeliveryEndpointRevisionSpec {
            boundary_revision: 1,
            ingress_kind: "hub".to_string(),
            listener_configuration: format!("native:{}", config.listen_addr),
            tls_configuration: if scheme == "https" {
                "{\"termination\":\"external\"}".to_string()
            } else {
                "{}".to_string()
            },
            probe_configuration: "{\"provider\":\"native_file\",\"signerSecretRef\":\"seed-probe-key\",\"publicKey\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}".to_string(),
        },
        (scheme == "http").then_some(1),
        "seed",
        "seed-hub-endpoint",
    )
    .await?;
    db.reconcile_delivery_endpoint(
        ENDPOINT_ID,
        1,
        1,
        "healthy",
        true,
        scheme == "https",
        None,
        1,
    )
    .await?;

    for (registry_id, placement_id, name, visibility) in [
        (
            public_registry_id,
            public_placement_id,
            DEMO_REGISTRY,
            "public",
        ),
        (
            private_registry_id,
            private_placement_id,
            DEMO_PRIVATE_REGISTRY,
            "private",
        ),
    ] {
        seed_hub_delivery_route(
            db,
            org_scope,
            registry_id,
            placement_id,
            name,
            visibility,
            config,
            ENDPOINT_ID,
        )
        .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn seed_hub_delivery_route(
    db: &Database,
    org_scope: &str,
    registry_id: i64,
    placement_id: i64,
    registry_name: &str,
    visibility: &str,
    config: &SeedRouteConfig<'_>,
    endpoint_id: &str,
) -> Result<()> {
    let base_path = format!("/{DEMO_ORG}/{registry_name}");
    let canonical_url = format!("{}{}", config.external_url.trim_end_matches('/'), base_path);
    let endpoint = db
        .delivery_endpoint(endpoint_id)
        .await?
        .context("seeded delivery endpoint disappeared")?;
    let endpoint_digest = hex::decode(&endpoint.endpoint_identity_digest)
        .context("decoding seeded endpoint identity digest")?;
    let active = config
        .reservation_keys
        .iter()
        .find(|key| key.active)
        .context("seed route configuration has no active reservation key")?;
    anyhow::ensure!(
        config
            .reservation_keys
            .iter()
            .filter(|key| key.active)
            .count()
            == 1,
        "seed route configuration must have exactly one active reservation key"
    );
    let mut candidates = Vec::with_capacity(config.reservation_keys.len());
    for key in config.reservation_keys {
        candidates.push((
            key.version,
            Database::route_reservation_digest(
                &key.secret,
                &endpoint_digest,
                &base_path,
                &canonical_url,
            )?
            .to_vec(),
        ));
    }
    let reservation_digest = candidates
        .iter()
        .find_map(|(version, digest)| (*version == active.version).then_some(digest.as_slice()))
        .context("active reservation digest was not computed")?;
    let access_policy_json = "{}".to_string();
    let access_policy_digest = hex::encode(Sha256::digest(access_policy_json.as_bytes()));
    let route_id = format!("seed-{registry_name}");
    let route = db
        .create_delivery_route(
            &route_id,
            SurfaceTarget::Registry(registry_id),
            &DeliveryRouteSpec {
                consumer_scope_key: org_scope.to_string(),
                endpoint_id: endpoint_id.to_string(),
                endpoint_generation: 1,
                endpoint_ingress_kind: "hub".to_string(),
                base_path,
                mode: "hub_proxy".to_string(),
                access_policy_kind: if visibility == "public" {
                    "public".to_string()
                } else {
                    "hub_auth".to_string()
                },
                access_policy_json,
                access_policy_digest: access_policy_digest.clone(),
                access_boundary_id: None,
                access_boundary_revision: None,
                external_provider_kind: None,
                external_provider_resource_id: None,
                external_provider_revision: None,
                storage_gateway_id: None,
                gateway_generation: None,
                target_storage_binding_id: None,
                gateway_client_base_path: None,
                target_placement_prefix: None,
                placement_id: Some(placement_id),
                placement_policy_revision_id: None,
                serves_git: true,
                serves_cache: false,
                serves_web: true,
                enabled: true,
            },
            &canonical_url,
            active.version,
            reservation_digest,
            &candidates,
            None,
            "seed",
        )
        .await?;
    db.reconcile_delivery_route(
        &route_id,
        route
            .configuration_generation
            .context("seeded route has no selected generation")?,
        route
            .configuration_digest
            .as_deref()
            .context("seeded route has no configuration digest")?,
        &access_policy_digest,
        "healthy",
        "verified",
        None,
        None,
        1,
    )
    .await?;
    for audience in ["git", "web"] {
        db.set_canonical_route(
            SurfaceTarget::Registry(registry_id),
            audience,
            &route_id,
            None,
        )
        .await?;
    }
    Ok(())
}

/// A package to seed: name, description, version, and one platform's store
/// path. Kept tiny — the seed is for browsing, not for real installs.
struct SeedPackage {
    name: &'static str,
    description: &'static str,
    version: &'static str,
    store_hash: &'static str,
}

/// The handful of demo packages the seed surface carries.
const SEED_PACKAGES: &[SeedPackage] = &[
    SeedPackage {
        name: "curl",
        description: "Command-line URL transfers",
        version: "8.5.0",
        store_hash: "h7j3k8l2m9n4",
    },
    SeedPackage {
        name: "openssl",
        description: "TLS/SSL and crypto toolkit",
        version: "3.2.1",
        store_hash: "p2q4r6s8t0u1",
    },
    SeedPackage {
        name: "jq",
        description: "Command-line JSON processor",
        version: "1.7.1",
        store_hash: "v3w5x7y9z1a2",
    },
];

/// Write a complete, correctly signed registry surface to `root`.
///
/// Mirrors the test fixture (`tests/common::standard_registry`) and
/// [`crate::signing`]: it builds the committed tree (`registry.toml`,
/// `keys.toml`, `packages/<x>/<name>.toml`, `closures/<hash>`) as loose git
/// objects, wraps it in a maintainer-signed commit, signs the `1.0.0` release
/// tag and all 256 `stable` partitions, and writes `HEAD`, `info/refs`, and the
/// static nix-cache files. The result verifies under `trust_key`.
fn write_signed_surface(root: &Path, key: &SigningKey, trust_key: &str) -> Result<()> {
    let put_object = |kind: ObjectKind, content: &[u8]| -> Result<Oid> {
        let oid = hash_object(kind, content);
        let path = root.join(oid.loose_path());
        std::fs::create_dir_all(path.parent().context("loose path has parent")?)?;
        std::fs::write(&path, encode_loose(kind, content)?)?;
        Ok(oid)
    };
    let put_blob =
        |content: &str| -> Result<Oid> { put_object(ObjectKind::Blob, content.as_bytes()) };
    let put_tree = |entries: &[(&str, &str, Oid)]| -> Result<Oid> {
        let entries: Vec<TreeEntry> = entries
            .iter()
            .map(|(mode, name, oid)| TreeEntry {
                mode: (*mode).to_string(),
                name: (*name).to_string(),
                oid: *oid,
            })
            .collect();
        put_object(ObjectKind::Tree, &encode_tree(&entries))
    };

    // Committed config blobs.
    let registry_toml = put_blob(
        "[registry]\nname = \"demo\"\ndescription = \"Demo registry (aos-hub seed)\"\n\
         readme = \"\"\"\n\
         The demo registry is a small, signed example surface seeded by \
         aos-hub for local development. It carries a handful of \
         packages (curl, jq, openssl) on a single stable channel.\n\n\
         Use it to explore the browse UI, the package filter, and the producer \
         console without standing up a real registry. Everything here is \
         regenerated on each seed, so feel free to publish, roll out, and \
         delete at will.\n\"\"\"\n\n\
         [caches]\nendpoint = \"https://cache.example.com/\"\n",
    )?;
    let keys_toml = put_blob(&format!(
        "schema = 1\n\n[[keys]]\nid = \"maintainer\"\nkey = \"{trust_key}\"\n",
    ))?;

    // One package TOML + one closure blob per demo package. Packages are
    // bucketed by their first letter, matching the surface layout the indexer
    // and `apr` use (`packages/<first-letter>/<name>.toml`).
    let mut package_buckets: std::collections::BTreeMap<char, Vec<(String, Oid)>> =
        std::collections::BTreeMap::new();
    let mut closure_entries: Vec<(String, Oid)> = Vec::new();
    for pkg in SEED_PACKAGES {
        let toml = format!(
            "[package]\nname = \"{name}\"\ndescription = \"{desc}\"\nlicense = \"MIT\"\n\
             maintainer = \"aos\"\n\n[[versions]]\nversion = \"{ver}\"\n\n\
             [versions.platforms.x86_64-linux]\n\
             store_path = \"/var/lib/store/{hash}-{name}-{ver}\"\n\
             nar_hash = \"sha256:aa\"\nnar_size = 10\nclosure_size = 20\n\
             source_drv = \"/var/lib/store/{hash}-{name}-{ver}.drv\"\n\
             source_nar_hash = \"sha256:bb\"\nreferences = []\n",
            name = pkg.name,
            desc = pkg.description,
            ver = pkg.version,
            hash = pkg.store_hash,
        );
        let toml_oid = put_blob(&toml)?;
        let first = pkg
            .name
            .chars()
            .next()
            .context("package name is non-empty")?;
        package_buckets
            .entry(first)
            .or_default()
            .push((format!("{}.toml", pkg.name), toml_oid));

        let closure_oid = put_blob(&format!("{}\n", pkg.store_hash))?;
        closure_entries.push((pkg.store_hash.to_string(), closure_oid));
    }

    // One logical AOS system release with two end-user encodings. The image
    // catalog is embedded in the signed package metadata; direct disk bytes
    // and per-format image-info documents are written separately below.
    let images = seed_system_images()?;
    let mut system_package: toml::Value = toml::from_str(
        "[package]\nname = \"aos-system\"\ndescription = \"AOS system image\"\nlicense = \"MIT\"\nmaintainer = \"aos\"\nsysroot = true\n\n[[versions]]\nversion = \"1.0.0\"\n\n[versions.platforms.x86_64-linux]\nstore_path = \"/var/lib/store/aos-system-1.0.0\"\nnar_hash = \"sha256:aa\"\nnar_size = 10\nclosure_size = 20\nsource_drv = \"/var/lib/store/aos-system-1.0.0.drv\"\nsource_nar_hash = \"sha256:bb\"\nreferences = []\n",
    )?;
    system_package
        .get_mut("versions")
        .and_then(toml::Value::as_array_mut)
        .and_then(|versions| versions.first_mut())
        .and_then(|version| version.get_mut("platforms"))
        .and_then(|platforms| platforms.get_mut("x86_64-linux"))
        .and_then(toml::Value::as_table_mut)
        .context("seed system package is missing its x86_64-linux artifact")?
        .insert("images".to_string(), toml::Value::try_from(&images)?);
    let system_oid = put_blob(&toml::to_string(&system_package)?)?;
    package_buckets
        .entry('a')
        .or_default()
        .push(("aos-system.toml".to_string(), system_oid));
    closure_entries.push(("aossystemhash".to_string(), put_blob("aossystemhash\n")?));

    // Build the `packages/` tree of per-letter bucket subtrees.
    let mut packages_entries: Vec<(String, Oid)> = Vec::new();
    for (letter, mut files) in package_buckets {
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let bucket_refs: Vec<(&str, &str, Oid)> = files
            .iter()
            .map(|(name, oid)| ("100644", name.as_str(), *oid))
            .collect();
        let bucket_tree = put_tree(&bucket_refs)?;
        packages_entries.push((letter.to_string(), bucket_tree));
    }
    packages_entries.sort_by(|a, b| a.0.cmp(&b.0));
    let packages_refs: Vec<(&str, &str, Oid)> = packages_entries
        .iter()
        .map(|(name, oid)| ("40000", name.as_str(), *oid))
        .collect();
    let packages = put_tree(&packages_refs)?;

    // Build the `closures/` tree.
    closure_entries.sort_by(|a, b| a.0.cmp(&b.0));
    let closure_refs: Vec<(&str, &str, Oid)> = closure_entries
        .iter()
        .map(|(name, oid)| ("100644", name.as_str(), *oid))
        .collect();
    let closures = put_tree(&closure_refs)?;

    // Root tree, sorted by git's name ordering (lexicographic here suffices).
    let root_tree = put_tree(&[
        ("40000", "closures", closures),
        ("100644", "keys.toml", keys_toml),
        ("40000", "packages", packages),
        ("100644", "registry.toml", registry_toml),
    ])?;

    // Signed HEAD commit over the root tree (mirror the fixture's SHA-256
    // gpgsig-sha256 header construction so the indexer's verifier accepts it).
    let commit = put_signed_commit(root, key, root_tree, &format!("release {DEMO_SEMVER}"))?;

    // Signed release tag + 256 signed partitions, via the hub's own signer.
    let signed_tag =
        crate::signing::sign_release_tag(key, DEMO_SEMVER, &commit.to_hex(), SEED_WHEN)?;
    let tag_path = root.join(signed_tag.oid.loose_path());
    std::fs::create_dir_all(tag_path.parent().context("tag loose path has parent")?)?;
    std::fs::write(&tag_path, &signed_tag.loose_bytes)?;

    let partition =
        crate::signing::sign_partition(key, DEMO_CHANNEL, &signed_tag.oid.to_hex(), SEED_WHEN)?;
    let chan_dir = root.join("channels").join(DEMO_CHANNEL);
    std::fs::create_dir_all(&chan_dir)?;
    for bucket in 0u16..=255 {
        std::fs::write(chan_dir.join(format!("{bucket:02x}")), &partition)?;
    }

    // HEAD + info/refs.
    std::fs::write(
        root.join("HEAD"),
        format!("ref: refs/heads/{DEMO_CHANNEL}\n"),
    )?;
    let mut refs = String::new();
    refs.push_str(&format!("{}\trefs/heads/{DEMO_CHANNEL}\n", commit.to_hex()));
    refs.push_str(&format!(
        "{}\trefs/tags/{DEMO_SEMVER}\n",
        signed_tag.oid.to_hex()
    ));
    refs.push_str(&format!(
        "{}\trefs/tags/{DEMO_SEMVER}^{{}}\n",
        commit.to_hex()
    ));
    std::fs::create_dir_all(root.join("info"))?;
    std::fs::write(root.join("info/refs"), refs)?;

    write_seed_image_objects(root, commit, &images)?;

    // Static nix-cache surface (one narinfo + one placeholder NAR).
    std::fs::write(
        root.join("nix-cache-info"),
        "StoreDir: /var/lib/store\nPriority: 40\n",
    )?;
    std::fs::write(
        root.join("h7j3k8l2m9n4.narinfo"),
        "StorePath: /var/lib/store/h7j3k8l2m9n4-curl-8.5.0\nURL: nar/h7j3k8l2m9n4.nar.zst\n\
         Compression: zstd\nNarHash: sha256:aa\nNarSize: 10\nReferences: \n",
    )?;
    std::fs::create_dir_all(root.join("nar"))?;
    std::fs::write(root.join("nar/h7j3k8l2m9n4.nar.zst"), b"not-a-real-nar")?;

    Ok(())
}

fn seed_system_images() -> Result<Vec<aos_registry_surface::manifest::ImageEntry>> {
    use aos_registry_surface::manifest::{
        immutable_image_info_object_key, immutable_image_object_key, ImageCompression,
        ImageDelivery, ImageEntry, ImageInfoReference, ImageTarget, ImageUkiIdentity,
        ImageVerificationState,
    };
    use sha2::{Digest as _, Sha256};

    let raw = b"AOS demo raw disk image bytes\n";
    let qcow2 = b"QFI\xfbAOS demo qcow2 disk image bytes\n";
    let raw_info = br#"{"schemaVersion":1,"format":"raw","target":"bare-metal"}"#;
    let qcow2_info = br#"{"schemaVersion":1,"format":"qcow2","targets":["qemu-kvm","openstack"]}"#;
    let raw_sha = hex::encode(Sha256::digest(raw));
    let uki = ImageUkiIdentity {
        filename: "aos.efi".to_string(),
        esp_path: "EFI/Linux/aos.efi".to_string(),
        byte_size: 8,
        sha256: "e".repeat(64),
        verification: ImageVerificationState::Unsigned,
        signer_cert_sha256: None,
        sbat: Vec::new(),
        measured: false,
        expected_pcr11: None,
    };
    let make = |format: &str,
                filename: &str,
                bytes: &[u8],
                info: &[u8],
                media_type: &str,
                compatible_targets: Vec<ImageTarget>| {
        let sha256 = hex::encode(Sha256::digest(bytes));
        let info_sha256 = hex::encode(Sha256::digest(info));
        ImageEntry {
            format: format.to_string(),
            store_path: format!("/var/lib/store/{}-image-{format}", &sha256[..32]),
            nar_hash: format!("sha256:{sha256}"),
            nar_size: bytes.len() as u64,
            delivery: ImageDelivery {
                schema_version: 1,
                release: DEMO_SEMVER.to_string(),
                platform: "x86_64-linux".to_string(),
                architecture: "x86_64".to_string(),
                logical_image_id: "d".repeat(64),
                logical_disk_sha256: raw_sha.clone(),
                rootfs_sha256: "f".repeat(64),
                filename: filename.to_string(),
                object_key: immutable_image_object_key(&sha256, filename),
                media_type: media_type.to_string(),
                compression: ImageCompression::None,
                byte_size: bytes.len() as u64,
                sha256: sha256.clone(),
                compatible_targets,
                uki: uki.clone(),
                image_info: ImageInfoReference {
                    filename: "image-info.json".to_string(),
                    object_key: immutable_image_info_object_key(&sha256, &info_sha256),
                    media_type: "application/vnd.aos.image-info+json".to_string(),
                    byte_size: info.len() as u64,
                    sha256: info_sha256,
                },
            },
            sb_signer_cert_sha256: None,
            sbat: Vec::new(),
            expected_pcr11: None,
            ukis: Vec::new(),
            recovery_ukis: Vec::new(),
            recovery_bundle: None,
            root_image: None,
            root_verity: None,
            root_hash: None,
            root_hash_sig: None,
        }
    };
    let images = vec![
        make(
            "raw",
            "aos-demo-1.0.0-x86_64.img",
            raw,
            raw_info,
            "application/vnd.aos.disk-image.raw",
            vec![ImageTarget::BareMetal],
        ),
        make(
            "qcow2",
            "aos-demo-1.0.0-x86_64.qcow2",
            qcow2,
            qcow2_info,
            "application/vnd.aos.disk-image.qcow2",
            vec![ImageTarget::QemuKvm, ImageTarget::Openstack],
        ),
    ];
    for image in &images {
        image.validate_delivery(DEMO_SEMVER, "x86_64-linux")?;
    }
    Ok(images)
}

fn write_seed_image_objects(
    root: &Path,
    commit: Oid,
    images: &[aos_registry_surface::manifest::ImageEntry],
) -> Result<()> {
    let objects = images
        .iter()
        .flat_map(|image| {
            [
                serde_json::json!({
                    "key": image.delivery.object_key,
                    "role": "disk",
                    "byteSize": image.delivery.byte_size,
                    "sha256": image.delivery.sha256,
                }),
                serde_json::json!({
                    "key": image.delivery.image_info.object_key,
                    "role": "image-info",
                    "byteSize": image.delivery.image_info.byte_size,
                    "sha256": image.delivery.image_info.sha256,
                }),
            ]
        })
        .collect::<Vec<_>>();
    for image in images {
        let (disk, info): (&[u8], &[u8]) = match image.format.as_str() {
            "raw" => (
                b"AOS demo raw disk image bytes\n",
                br#"{"schemaVersion":1,"format":"raw","target":"bare-metal"}"#,
            ),
            "qcow2" => (
                b"QFI\xfbAOS demo qcow2 disk image bytes\n",
                br#"{"schemaVersion":1,"format":"qcow2","targets":["qemu-kvm","openstack"]}"#,
            ),
            other => anyhow::bail!("unsupported seeded image format {other}"),
        };
        for (key, bytes) in [
            (image.delivery.object_key.as_str(), disk),
            (image.delivery.image_info.object_key.as_str(), info),
        ] {
            let path = root.join(key);
            std::fs::create_dir_all(path.parent().context("image object path has a parent")?)?;
            std::fs::write(path, bytes)?;
        }
    }
    let catalog_digest = aos_registry_surface::manifest::image_catalog_digest(
        "demo",
        images.iter().flat_map(|image| {
            [
                (
                    image.delivery.object_key.as_str(),
                    "disk",
                    image.delivery.byte_size,
                    image.delivery.sha256.as_str(),
                ),
                (
                    image.delivery.image_info.object_key.as_str(),
                    "image-info",
                    image.delivery.image_info.byte_size,
                    image.delivery.image_info.sha256.as_str(),
                ),
            ]
        }),
    );
    let receipt = root.join(format!("publication-receipts/{}.json", commit.to_hex()));
    std::fs::create_dir_all(receipt.parent().context("receipt path has a parent")?)?;
    std::fs::write(
        receipt,
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "commit": commit.to_hex(),
            "registry": "demo",
            "catalogDigest": catalog_digest,
            "objects": objects,
        }))?,
    )?;
    Ok(())
}

/// Write a maintainer-signed commit over `tree`, returning its oid.
///
/// The armored SSH signature is embedded as a multi-line `gpgsig-sha256` header
/// (the SHA-256-repo form git writes), with continuation lines prefixed by one
/// space — the exact shape the indexer's commit verifier parses.
fn put_signed_commit(root: &Path, key: &SigningKey, tree: Oid, message: &str) -> Result<Oid> {
    let ident = format!("AOS Seed <seed@aos> {SEED_WHEN} +0000");
    let unsigned = format!(
        "tree {tree}\nauthor {ident}\ncommitter {ident}\n\n{message}\n",
        tree = tree.to_hex(),
    );
    let armor = sshsig::sign_armored(unsigned.as_bytes(), key);
    let mut armor_lines = armor.lines();
    let first = armor_lines.next().context("armor has at least one line")?;
    let mut gpgsig = format!("gpgsig-sha256 {first}\n");
    for line in armor_lines {
        gpgsig.push(' ');
        gpgsig.push_str(line);
        gpgsig.push('\n');
    }
    let signed = format!(
        "tree {tree}\nauthor {ident}\ncommitter {ident}\n{gpgsig}\n{message}\n",
        tree = tree.to_hex(),
    );
    let oid = hash_object(ObjectKind::Commit, signed.as_bytes());
    let path = root.join(oid.loose_path());
    std::fs::create_dir_all(path.parent().context("commit loose path has parent")?)?;
    std::fs::write(&path, encode_loose(ObjectKind::Commit, signed.as_bytes())?)?;
    Ok(oid)
}
