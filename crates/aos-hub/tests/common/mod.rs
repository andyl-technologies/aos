//! Fixture registry surfaces for integration tests.
//!
//! Builds a complete, *correctly signed* registry surface on disk — loose
//! objects, refs, channel partitions, and nix-cache files — using only the
//! hub's own primitives plus `ed25519-dalek`. This is the seed of the
//! parser-divergence fixture set from RFC-0004's testing story: the same
//! directories are valid input for `apm` (they are exactly what
//! `apr origin upload` would have written).

use std::fs;
use std::path::{Path, PathBuf};

use aos_hub::surface::object::{
    encode_loose, encode_tree, hash_object, ObjectKind, Oid, TreeEntry,
};
use aos_hub::surface::sshsig;
use aos_hub::surface::tag::render_tag_payload;
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

/// Creates a final-topology instance-owned local binding for integration tests.
pub async fn create_instance_local_binding(
    db: &aos_hub::db::Database,
    name: &str,
    path: &str,
) -> i64 {
    db.create_topology_storage_binding(
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
    .unwrap()
}

/// Creates a final-topology local binding for integration-test setup.
pub async fn create_local_binding(
    db: &aos_hub::db::Database,
    org_id: i64,
    name: &str,
    path: &str,
) -> i64 {
    // Local filesystem bindings are instance-owned: accepting an
    // organization-controlled host path would cross the tenancy boundary.
    // Creating the instance binding eagerly materializes a grant for every
    // existing organization, including this fixture's owner.
    db.org_by_id(org_id).await.unwrap().unwrap();
    db.create_topology_storage_binding(
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
    .unwrap()
}

/// Creates and reconciles one native Hub delivery endpoint and route.
pub async fn configure_hub_delivery_route(
    db: &aos_hub::db::Database,
    surface: aos_hub::db::SurfaceTarget,
    placement_id: i64,
    owner_scope: &str,
    endpoint_id: &str,
    route_id: &str,
    base_path: &str,
    audience: &str,
) {
    use aos_hub::db::{DeliveryEndpointHostInput, DeliveryEndpointRevisionSpec, DeliveryRouteSpec};

    let (org_id, visibility) = match surface {
        aos_hub::db::SurfaceTarget::Registry(id) => {
            let registry = db.registry_by_id(id).await.unwrap().unwrap();
            (registry.org_id, registry.visibility)
        }
        aos_hub::db::SurfaceTarget::BinaryCache(id) => {
            let cache = db.binary_cache_by_id(id).await.unwrap().unwrap();
            (cache.org_id, cache.visibility)
        }
    };
    if db.delivery_endpoint(endpoint_id).await.unwrap().is_none() {
        db.create_delivery_endpoint(
            endpoint_id,
            owner_scope,
            org_id,
            "http",
            &DeliveryEndpointHostInput::Ipv4([127, 0, 0, 1]),
            8420,
            "instance:public",
            &DeliveryEndpointRevisionSpec {
                boundary_revision: 1,
                ingress_kind: "hub".to_string(),
                listener_configuration: format!("listener:{endpoint_id}"),
                tls_configuration: "{}".to_string(),
                probe_configuration: "{\"provider\":\"native_file\",\"signerSecretRef\":\"test-probe-key\",\"publicKey\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}".to_string(),
            },
            Some(1),
            "test",
            &format!("request:{endpoint_id}"),
        )
        .await
        .unwrap();
        db.reconcile_delivery_endpoint(endpoint_id, 1, 1, "healthy", true, false, None, 1)
            .await
            .unwrap();
    }

    let access_policy_json = "{}".to_string();
    let access_policy_digest = hex::encode(Sha256::digest(access_policy_json.as_bytes()));
    let canonical_url = format!("http://127.0.0.1:8420{base_path}");
    let endpoint = db.delivery_endpoint(endpoint_id).await.unwrap().unwrap();
    let endpoint_digest = hex::decode(&endpoint.endpoint_identity_digest).unwrap();
    let reservation_digest = aos_hub::db::Database::route_reservation_digest(
        &[9_u8; 32],
        &endpoint_digest,
        base_path,
        &canonical_url,
    )
    .unwrap();
    let (serves_git, serves_cache, serves_web) = match surface {
        aos_hub::db::SurfaceTarget::Registry(_) => (true, false, true),
        aos_hub::db::SurfaceTarget::BinaryCache(_) => (false, true, true),
    };
    let route = db
        .create_delivery_route(
            route_id,
            surface,
            &DeliveryRouteSpec {
                consumer_scope_key: owner_scope.to_string(),
                endpoint_id: endpoint_id.to_string(),
                endpoint_generation: 1,
                endpoint_ingress_kind: "hub".to_string(),
                base_path: base_path.to_string(),
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
                serves_git,
                serves_cache,
                serves_web,
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
    db.reconcile_delivery_route(
        route_id,
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
    db.set_canonical_route(surface, audience, route_id, None)
        .await
        .unwrap();
}

/// Creates and validates the next immutable write-credential generation.
pub async fn create_valid_write_credential(
    db: &aos_hub::db::Database,
    binding_id: i64,
    secret_ref: &str,
) -> i64 {
    let expected = db
        .current_storage_binding_credential(binding_id, "write")
        .await
        .unwrap()
        .map_or(0, |revision| revision.generation);
    let revision = db
        .set_storage_binding_credential_revision(
            binding_id,
            "write",
            secret_ref,
            expected,
            &"0".repeat(64),
            "test",
        )
        .await
        .unwrap();
    db.validate_storage_binding_credential_revision(
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

/// Creates and observes one complete, read-enabled placement.
pub async fn create_ready_placement(
    db: &aos_hub::db::Database,
    surface: aos_hub::db::SurfaceTarget,
    binding_id: i64,
    name: &str,
    prefix: &str,
) -> aos_hub::db::SurfacePlacementRecord {
    let consumer_scope = match surface {
        aos_hub::db::SurfaceTarget::Registry(id) => {
            db.registry_by_id(id)
                .await
                .unwrap()
                .unwrap()
                .owner_scope_key
        }
        aos_hub::db::SurfaceTarget::BinaryCache(id) => {
            db.binary_cache_by_id(id)
                .await
                .unwrap()
                .unwrap()
                .owner_scope_key
        }
    };
    let binding = db.storage_binding(binding_id).await.unwrap().unwrap();
    let resource = aos_hub::db::GrantResource::StorageBinding {
        id: binding_id,
        stable_id: &binding.stable_id,
    };
    let grants = db.list_consumer_scope_grants(resource).await.unwrap();
    if !grants
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
        .await
        .unwrap();
    }
    let placement = db
        .create_surface_placement(&aos_hub::db::NewSurfacePlacementSpec {
            surface,
            name: name.to_string(),
            storage_binding_id: binding_id,
            prefix: prefix.to_string(),
            kind: "complete".to_string(),
            desired_state: "active".to_string(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await
        .unwrap();
    db.observe_surface_placement(placement.id, "ready", "complete", 1)
        .await
        .unwrap()
}

/// Configures a ready placement as the reconciled writer for its surface.
pub async fn configure_write_authority(
    db: &aos_hub::db::Database,
    surface: aos_hub::db::SurfaceTarget,
    binding_id: i64,
    placement: &aos_hub::db::SurfacePlacementRecord,
    incarnation_id: &str,
) {
    let credential_generation =
        create_valid_write_credential(db, binding_id, "secret://test/write/v1").await;
    let revision = db
        .create_storage_binding_write_revision(&aos_hub::db::NewStorageBindingWriteRevision {
            storage_binding_id: binding_id,
            write_credential_generation: credential_generation,
            writes_supported: true,
            conditional_writes_supported: true,
            revision_fingerprint: format!("test-write-revision-{binding_id}"),
            capability_fingerprint: "test-writes-and-conditional-writes".to_string(),
        })
        .await
        .unwrap();
    db.observe_storage_binding_write_revision(binding_id, revision.revision, "valid", None, None)
        .await
        .unwrap();
    let state = db
        .storage_binding_write_state(binding_id)
        .await
        .unwrap()
        .unwrap();
    db.set_current_storage_binding_write_revision(
        binding_id,
        revision.revision,
        state.resource_version,
    )
    .await
    .unwrap();
    db.bind_surface_placement_write_capability(placement.id, revision.revision)
        .await
        .unwrap();
    db.create_surface_write_authority(
        surface,
        incarnation_id,
        placement.id,
        placement.resource_version,
        placement.write_spec_version,
        revision.revision,
    )
    .await
    .unwrap();
}

/// Resolve an organization slug to its canonical stable authorization scope.
///
/// Human-readable slugs are resource locators, not authorization scopes. Test
/// setup should therefore resolve the stable scope exactly as production code
/// does instead of coupling grants and tokens to a mutable slug.
pub async fn org_scope(db: &aos_hub::db::Database, slug: &str) -> String {
    db.org_by_slug(slug)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("test organization {slug:?} must exist"))
        .stable_id
}

/// Resolve a project path to its canonical stable authorization scope.
pub async fn project_scope(db: &aos_hub::db::Database, org_slug: &str, path: &str) -> String {
    let org = db
        .org_by_slug(org_slug)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("test organization {org_slug:?} must exist"));
    db.list_projects(org.id)
        .await
        .unwrap()
        .into_iter()
        .find(|project| project.path == path)
        .unwrap_or_else(|| panic!("test project {org_slug:?}/{path} must exist"))
        .scope_key
}

/// Resolve a registry slug to the exact stable scope which authorizes it.
pub async fn registry_scope(db: &aos_hub::db::Database, slug: &str) -> String {
    let registry = db
        .registry_by_slug(slug)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("test registry {slug:?} must exist"));
    db.registry_authorization_scope(registry.id).await.unwrap()
}

/// A registry fixture being assembled on disk.
pub struct Fixture {
    /// Surface root directory.
    pub root: PathBuf,
    /// The maintainer signing key.
    pub key: SigningKey,
    /// The trust anchor line for the key.
    pub trust_key: String,
}

/// Complete signed system-image fixture with two direct encodings.
pub struct SystemImageFixture {
    /// Signed registry fixture and trust anchor.
    pub registry: Fixture,
    /// Canonical raw disk bytes.
    pub raw: Vec<u8>,
    /// QCOW2 encoding bytes.
    pub qcow2: Vec<u8>,
    /// Raw image object key.
    pub raw_key: String,
    /// QCOW2 image object key.
    pub qcow2_key: String,
    /// Raw per-format metadata object key.
    pub raw_info_key: String,
    /// QCOW2 per-format metadata object key.
    pub qcow2_info_key: String,
    /// Commit authenticated by the signed release tag.
    pub release_commit: Oid,
    /// Signed release tag object advertised in `info/refs`.
    pub release_tag: Oid,
}

impl Fixture {
    /// Create an empty fixture rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let trust_key = sshsig::trusted_key_line("demo", &key.verifying_key());
        Self {
            root: root.into(),
            key,
            trust_key,
        }
    }

    /// Write one loose object and return its oid.
    pub fn put_object(&self, kind: ObjectKind, content: &[u8]) -> Oid {
        let oid = hash_object(kind, content);
        let path = self.root.join(oid.loose_path());
        fs::create_dir_all(path.parent().expect("loose path has parent")).unwrap();
        fs::write(path, encode_loose(kind, content).unwrap()).unwrap();
        oid
    }

    /// Write a blob and return its oid.
    pub fn put_blob(&self, content: &str) -> Oid {
        self.put_object(ObjectKind::Blob, content.as_bytes())
    }

    /// Write a tree from `(mode, name, oid)` entries and return its oid.
    pub fn put_tree(&self, entries: &[(&str, &str, Oid)]) -> Oid {
        let entries: Vec<TreeEntry> = entries
            .iter()
            .map(|(mode, name, oid)| TreeEntry {
                mode: (*mode).to_string(),
                name: (*name).to_string(),
                oid: *oid,
            })
            .collect();
        self.put_object(ObjectKind::Tree, &encode_tree(&entries))
    }

    /// Write a signed commit over `tree` and return its oid.
    pub fn put_signed_commit(&self, tree: Oid, message: &str) -> Oid {
        let ident = "AOS Test <test@aos> 1770000000 +0000";
        let unsigned = format!("tree {tree}\nauthor {ident}\ncommitter {ident}\n\n{message}\n");
        let armor = sshsig::sign_armored(unsigned.as_bytes(), &self.key);
        // The armored signature becomes a multi-line gpgsig-sha256 header
        // (the SHA-256-repo form real git writes) with
        // continuation lines prefixed by one space.
        let mut armor_lines = armor.lines();
        let first = armor_lines.next().expect("armor has lines");
        let mut gpgsig = format!("gpgsig-sha256 {first}\n");
        for line in armor_lines {
            gpgsig.push(' ');
            gpgsig.push_str(line);
            gpgsig.push('\n');
        }
        let signed =
            format!("tree {tree}\nauthor {ident}\ncommitter {ident}\n{gpgsig}\n{message}\n");
        self.put_object(ObjectKind::Commit, signed.as_bytes())
    }

    /// Render and sign a tag payload; returns the raw payload bytes.
    pub fn signed_tag_payload(&self, name: &str, target: Oid, target_type: &str) -> Vec<u8> {
        let body =
            render_tag_payload(name, &target.to_hex(), target_type, "fixture", 1770000000).unwrap();
        let armor = sshsig::sign_armored(body.as_bytes(), &self.key);
        format!("{body}{armor}\n").into_bytes()
    }

    /// Write a signed release tag as a loose tag object; returns its oid.
    pub fn put_release_tag(&self, semver: &str, commit: Oid) -> Oid {
        let payload = self.signed_tag_payload(semver, commit, "commit");
        self.put_object(ObjectKind::Tag, &payload)
    }

    /// Write all 256 channel partition payloads pointing at one release tag.
    pub fn put_channel(&self, channel: &str, release_tag: Oid) {
        let payload = self.signed_tag_payload(channel, release_tag, "tag");
        let dir = self.root.join("channels").join(channel);
        fs::create_dir_all(&dir).unwrap();
        for bucket in 0u16..=255 {
            fs::write(dir.join(format!("{bucket:02x}")), &payload).unwrap();
        }
    }

    /// Write `HEAD` and `info/refs` for the given branches and tags.
    pub fn put_refs(
        &self,
        default_branch: &str,
        branches: &[(&str, Oid)],
        tags: &[(&str, Oid, Oid)],
    ) {
        fs::write(
            self.root.join("HEAD"),
            format!("ref: refs/heads/{default_branch}\n"),
        )
        .unwrap();
        let mut refs = String::new();
        for (name, oid) in branches {
            refs.push_str(&format!("{oid}\trefs/heads/{name}\n"));
        }
        for (name, tag_oid, peeled) in tags {
            refs.push_str(&format!("{tag_oid}\trefs/tags/{name}\n"));
            refs.push_str(&format!("{peeled}\trefs/tags/{name}^{{}}\n"));
        }
        fs::create_dir_all(self.root.join("info")).unwrap();
        fs::write(self.root.join("info/refs"), refs).unwrap();
    }

    /// Write the static nix-cache surface (`nix-cache-info`, one narinfo,
    /// one NAR file).
    ///
    /// The narinfo is **correctly Ed25519-signed** by the fixture's key under
    /// the registry name `demo` (the same key the roster pins), and the NAR is
    /// an uncompressed payload whose `FileHash`/`NarHash` match its bytes — so
    /// the mirror's mandatory narinfo-signature + NAR-hash verification accepts
    /// it. The `Sig:` is over the Nix narinfo fingerprint, matching
    /// `aos_core`'s narinfo signer.
    pub fn put_nix_cache(&self) {
        fs::write(
            self.root.join("nix-cache-info"),
            "StoreDir: /var/lib/store\nPriority: 40\n",
        )
        .unwrap();

        // A real (tiny) uncompressed NAR payload; FileHash == NarHash over
        // these exact bytes, so the hash check passes.
        use sha2::Digest as _;
        let nar_bytes = b"fixture-nar-bytes-for-curl-8.5.0";
        let digest = sha2::Sha256::digest(nar_bytes);
        let hash = format!("sha256:{}", hex::encode(digest));
        let store_path = "/var/lib/store/h7j3k8l2m9n4-curl-8.5.0";
        // The conventional `nar/<store-hash>-<nar-hash>.<ext>` layout, so the
        // pull-through can derive the narinfo path from the NAR path.
        let nar_url = "nar/h7j3k8l2m9n4-fixturehash.nar";

        let body = self.signed_narinfo(store_path, nar_url, &hash, nar_bytes.len() as u64, &[]);
        fs::write(self.root.join("h7j3k8l2m9n4.narinfo"), body).unwrap();

        fs::create_dir_all(self.root.join("nar")).unwrap();
        fs::write(self.root.join(nar_url), nar_bytes).unwrap();
    }

    /// Write a *zstd-compressed* nix-cache entry: a signed narinfo declaring
    /// `Compression: zstd` whose signed `NarHash` is over the **uncompressed**
    /// NAR, plus the compressed NAR file on disk.
    ///
    /// `tamper_compressed` injects the CR-1 attack: when set, the on-disk NAR is
    /// replaced with `tampered_plain` compressed with zstd, and the narinfo's
    /// (unsigned) `FileHash` is set to match those malicious *compressed* bytes —
    /// so a verifier that trusted `FileHash` would accept it, but the decompressed
    /// bytes do not match the signed `NarHash`. The signed fields (`NarHash`,
    /// `StorePath`, `NarSize`, `Sig:`) are unchanged, exactly as a MITM upstream
    /// would keep them.
    ///
    /// Returns `(narinfo_relative_path, nar_relative_path)`.
    ///
    /// The store hash is unique per `tag` so multiple entries can coexist.
    // Not every test binary that compiles this shared module calls this builder
    // (the same pre-existing pattern as the other fixture helpers).
    #[allow(dead_code)]
    pub fn put_zstd_nix_entry(
        &self,
        tag: &str,
        plain: &[u8],
        tamper_compressed: Option<&[u8]>,
    ) -> (String, String) {
        use base64::Engine as _;
        use sha2::Digest as _;

        let store_hash = format!("zstdhash{tag}");
        let store_path = format!("/var/lib/store/{store_hash}-pkg-1.0");
        let nar_url = format!("nar/{store_hash}-fixturehash.nar.zst");

        // The signed NarHash is over the UNCOMPRESSED bytes.
        let nar_hash = format!("sha256:{}", hex::encode(sha2::Sha256::digest(plain)));
        let nar_size = plain.len() as u64;

        // The bytes actually written to disk (and the compressed bytes FileHash
        // is computed over): the honest compression of `plain`, unless tampering.
        let honest_compressed = zstd::encode_all(plain, 0).unwrap();
        let (on_disk, file_source): (Vec<u8>, Vec<u8>) = match tamper_compressed {
            Some(evil_plain) => {
                let evil = zstd::encode_all(evil_plain, 0).unwrap();
                (evil.clone(), evil)
            }
            None => (honest_compressed.clone(), honest_compressed),
        };
        let file_hash = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&file_source)));
        let file_size = on_disk.len() as u64;

        // Sign the fingerprint over the (uncompressed) NarHash, as a real signer
        // would — the signature is independent of the compressed payload.
        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(&self.key.to_bytes());
        secret.extend_from_slice(self.key.verifying_key().as_bytes());
        let secret_b64 = base64::engine::general_purpose::STANDARD.encode(&secret);
        let signer =
            aos_core::nar::cache::NarInfoSigner::from_key_content(&format!("demo:{secret_b64}"))
                .unwrap();
        let fingerprint = aos_core::nar::cache::NarInfoSigner::fingerprint(
            &store_path,
            &nar_hash,
            nar_size as i64,
            &[],
        );
        let sig = signer.sign(&fingerprint).unwrap();

        let narinfo = format!(
            "StorePath: {store_path}\nURL: {nar_url}\nCompression: zstd\n\
             FileHash: {file_hash}\nFileSize: {file_size}\nNarHash: {nar_hash}\nNarSize: {nar_size}\n\
             References: \nSig: {sig}\n",
        );
        let narinfo_path = format!("{store_hash}.narinfo");
        fs::write(self.root.join(&narinfo_path), narinfo).unwrap();
        fs::create_dir_all(self.root.join("nar")).unwrap();
        fs::write(self.root.join(&nar_url), &on_disk).unwrap();
        (narinfo_path, nar_url)
    }

    /// Render a narinfo for an *uncompressed* NAR and sign it with the
    /// fixture's key under the registry name (so its `Sig:` verifies against
    /// the roster).
    ///
    /// `hash` is the `sha256:<hex>` digest of the NAR bytes, used for both
    /// `NarHash` and `FileHash` (uncompressed, so they coincide). `refs` are
    /// full store paths referenced by this path.
    pub fn signed_narinfo(
        &self,
        store_path: &str,
        nar_url: &str,
        hash: &str,
        size: u64,
        refs: &[String],
    ) -> String {
        use base64::Engine as _;

        // The Nix narinfo signing key is name:base64(seed||pubkey); the signer
        // uses the first 32 bytes (the seed) to reproduce the Ed25519 key.
        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(&self.key.to_bytes());
        secret.extend_from_slice(self.key.verifying_key().as_bytes());
        let secret_b64 = base64::engine::general_purpose::STANDARD.encode(&secret);
        let signer =
            aos_core::nar::cache::NarInfoSigner::from_key_content(&format!("demo:{secret_b64}"))
                .unwrap();

        let fingerprint =
            aos_core::nar::cache::NarInfoSigner::fingerprint(store_path, hash, size as i64, refs);
        let sig = signer.sign(&fingerprint).unwrap();

        let refs_basenames: Vec<&str> = refs
            .iter()
            .map(|r| r.rsplit('/').next().unwrap_or(r))
            .collect();
        format!(
            "StorePath: {store_path}\nURL: {nar_url}\nCompression: none\n\
             FileHash: {hash}\nFileSize: {size}\nNarHash: {hash}\nNarSize: {size}\n\
             References: {}\nSig: {sig}\n",
            refs_basenames.join(" "),
        )
    }
}

/// Build a complete single-package, single-channel registry fixture.
///
/// Layout: `curl 8.5.0` for `x86_64-linux`, release `1.0.0`, channel
/// `stable` fully rolled out, roster with one active key, one committed
/// cache, plus the nix-cache files.
// Not every test binary that compiles this shared module calls this builder
// (the same pre-existing pattern as `standard_registry_versioned`).
#[allow(dead_code)]
pub fn standard_registry(root: &Path) -> Fixture {
    standard_registry_versioned(root, "1.0.0")
}

/// [`standard_registry`] with a configurable release semver, so tests can
/// build surfaces at different (e.g. older) release versions.
// Not every test crate that compiles this module uses the fixture
// builders (the same pre-existing pattern as the rest of this file).
#[allow(dead_code)]
pub fn standard_registry_versioned(root: &Path, semver: &str) -> Fixture {
    standard_registry_with_commit_message(root, semver, &format!("release {semver}"))
}

/// [`standard_registry_versioned`] with an explicit HEAD commit message, so a
/// test can embed an `AOS-Change-Id` trailer (for the indexer's change-request
/// cross-referencing) or otherwise control the committed message.
#[allow(dead_code)]
pub fn standard_registry_with_commit_message(
    root: &Path,
    semver: &str,
    commit_message: &str,
) -> Fixture {
    let fixture = Fixture::new(root);

    let registry_toml = fixture.put_blob(
        "[registry]\nname = \"demo\"\ndescription = \"Fixture registry\"\n\n\
         [caches]\nendpoint = \"https://cache.example.com/\"\n",
    );
    let keys_toml = fixture.put_blob(&format!(
        "schema = 1\n\n[[keys]]\nid = \"maintainer\"\nkey = \"{}\"\n",
        fixture.trust_key,
    ));
    let curl_toml = fixture.put_blob(
        "[package]\nname = \"curl\"\ndescription = \"URL transfers\"\nlicense = \"MIT\"\n\
         maintainer = \"aos\"\n\n[[versions]]\nversion = \"8.5.0\"\n\n\
         [versions.platforms.x86_64-linux]\nstore_path = \"/var/lib/store/h7j3k8l2m9n4-curl-8.5.0\"\n\
         nar_hash = \"sha256:aa\"\nnar_size = 10\nclosure_size = 20\n\
         source_drv = \"/var/lib/store/h7j3k8l2m9n4-curl-8.5.0.drv\"\n\
         source_nar_hash = \"sha256:bb\"\nreferences = []\n",
    );
    let closure_blob = fixture.put_blob("h7j3k8l2m9n4\n");

    let bucket_c = fixture.put_tree(&[("100644", "curl.toml", curl_toml)]);
    let packages = fixture.put_tree(&[("40000", "c", bucket_c)]);
    let closures = fixture.put_tree(&[("100644", "h7j3k8l2m9n4", closure_blob)]);
    let root_tree = fixture.put_tree(&[
        ("100644", "keys.toml", keys_toml),
        ("100644", "registry.toml", registry_toml),
        ("40000", "closures", closures),
        ("40000", "packages", packages),
    ]);

    let commit = fixture.put_signed_commit(root_tree, commit_message);
    let release_tag = fixture.put_release_tag(semver, commit);
    fixture.put_channel("stable", release_tag);
    fixture.put_refs(
        "stable",
        &[("stable", commit)],
        &[(semver, release_tag, commit)],
    );
    fixture.put_nix_cache();
    fixture
}

/// Builds a signed sysroot catalog with exact raw and QCOW2 delivery objects.
#[allow(dead_code)]
pub fn system_image_registry(root: &Path) -> SystemImageFixture {
    use aos_registry_surface::manifest::{
        immutable_image_info_object_key, immutable_image_object_key, ImageCompression,
        ImageDelivery, ImageEntry, ImageInfoReference, ImageTarget, ImageUkiIdentity,
        ImageVerificationState,
    };
    use sha2::Digest as _;

    let fixture = Fixture::new(root);
    let release = "1.0.0";
    let platform = "x86_64-linux";
    let raw = b"AOS fake raw disk image bytes\n".to_vec();
    let qcow2 = b"QFI\xfbAOS fake qcow2 disk image bytes\n".to_vec();
    let raw_info = br#"{"schemaVersion":1,"format":"raw","target":"bare-metal"}"#.to_vec();
    let qcow2_info =
        br#"{"schemaVersion":1,"format":"qcow2","targets":["qemu-kvm","openstack"]}"#.to_vec();
    let raw_sha = hex::encode(sha2::Sha256::digest(&raw));
    let qcow2_sha = hex::encode(sha2::Sha256::digest(&qcow2));
    let raw_info_sha = hex::encode(sha2::Sha256::digest(&raw_info));
    let qcow2_info_sha = hex::encode(sha2::Sha256::digest(&qcow2_info));
    let raw_key = immutable_image_object_key(&raw_sha, "aos-1.0.0-x86_64.img");
    let qcow2_key = immutable_image_object_key(&qcow2_sha, "aos-1.0.0-x86_64.qcow2");
    let raw_info_key = immutable_image_info_object_key(&raw_sha, &raw_info_sha);
    let qcow2_info_key = immutable_image_info_object_key(&qcow2_sha, &qcow2_info_sha);
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
    let make_image = |format: &str,
                      filename: &str,
                      bytes: &[u8],
                      sha256: &str,
                      object_key: &str,
                      info: &[u8],
                      info_sha256: &str,
                      info_key: &str,
                      media_type: &str,
                      targets: Vec<ImageTarget>| {
        ImageEntry {
            format: format.to_string(),
            store_path: format!("/var/lib/store/{}-image-{format}", &sha256[..32]),
            nar_hash: format!("sha256:{sha256}"),
            nar_size: bytes.len() as u64,
            delivery: ImageDelivery {
                schema_version: 1,
                release: release.to_string(),
                platform: platform.to_string(),
                architecture: "x86_64".to_string(),
                logical_image_id: "d".repeat(64),
                logical_disk_sha256: raw_sha.clone(),
                rootfs_sha256: "f".repeat(64),
                filename: filename.to_string(),
                object_key: object_key.to_string(),
                media_type: media_type.to_string(),
                compression: ImageCompression::None,
                byte_size: bytes.len() as u64,
                sha256: sha256.to_string(),
                compatible_targets: targets,
                uki: uki.clone(),
                image_info: ImageInfoReference {
                    filename: "image-info.json".to_string(),
                    object_key: info_key.to_string(),
                    media_type: "application/vnd.aos.image-info+json".to_string(),
                    byte_size: info.len() as u64,
                    sha256: info_sha256.to_string(),
                },
            },
            sb_signer_cert_sha256: None,
            sbat: Vec::new(),
            expected_pcr11: None,
            root_image: None,
            root_verity: None,
            root_hash: None,
            root_hash_sig: None,
        }
    };
    let images = vec![
        make_image(
            "raw",
            "aos-1.0.0-x86_64.img",
            &raw,
            &raw_sha,
            &raw_key,
            &raw_info,
            &raw_info_sha,
            &raw_info_key,
            "application/vnd.aos.disk-image.raw",
            vec![ImageTarget::BareMetal],
        ),
        make_image(
            "qcow2",
            "aos-1.0.0-x86_64.qcow2",
            &qcow2,
            &qcow2_sha,
            &qcow2_key,
            &qcow2_info,
            &qcow2_info_sha,
            &qcow2_info_key,
            "application/vnd.aos.disk-image.qcow2",
            vec![ImageTarget::QemuKvm, ImageTarget::Openstack],
        ),
    ];
    for image in &images {
        image.validate_delivery(release, platform).unwrap();
    }

    let registry_toml =
        fixture.put_blob("[registry]\nname = \"demo\"\ndescription = \"Signed system images\"\n");
    let keys_toml = fixture.put_blob(&format!(
        "schema = 1\n\n[[keys]]\nid = \"maintainer\"\nkey = \"{}\"\n",
        fixture.trust_key,
    ));
    let mut package: toml::Value = toml::from_str(
        "[package]\nname = \"aos-system\"\ndescription = \"AOS system image\"\nlicense = \"MIT\"\nmaintainer = \"aos\"\nsysroot = true\n\n[[versions]]\nversion = \"1.0.0\"\n\n[versions.platforms.x86_64-linux]\nstore_path = \"/var/lib/store/aos-system-1.0.0\"\nnar_hash = \"sha256:aa\"\nnar_size = 10\nclosure_size = 20\nsource_drv = \"/var/lib/store/aos-system-1.0.0.drv\"\nsource_nar_hash = \"sha256:bb\"\nreferences = []\n",
    )
    .unwrap();
    package["versions"][0]["platforms"][platform]
        .as_table_mut()
        .unwrap()
        .insert(
            "images".to_string(),
            toml::Value::try_from(&images).unwrap(),
        );
    let package_toml = fixture.put_blob(&toml::to_string(&package).unwrap());
    let closure_blob = fixture.put_blob("aossystemhash\n");
    let bucket = fixture.put_tree(&[("100644", "aos-system.toml", package_toml)]);
    let packages = fixture.put_tree(&[("40000", "a", bucket)]);
    let closures = fixture.put_tree(&[("100644", "aossystemhash", closure_blob)]);
    let root_tree = fixture.put_tree(&[
        ("100644", "keys.toml", keys_toml),
        ("100644", "registry.toml", registry_toml),
        ("40000", "closures", closures),
        ("40000", "packages", packages),
    ]);
    let commit = fixture.put_signed_commit(root_tree, "release system images");
    let release_tag = fixture.put_release_tag(release, commit);
    fixture.put_channel("stable", release_tag);
    fixture.put_refs(
        "stable",
        &[("stable", commit)],
        &[(release, release_tag, commit)],
    );

    for (key, bytes) in [
        (&raw_key, raw.as_slice()),
        (&qcow2_key, qcow2.as_slice()),
        (&raw_info_key, raw_info.as_slice()),
        (&qcow2_info_key, qcow2_info.as_slice()),
    ] {
        let path = root.join(key);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    let receipt_objects = images
        .iter()
        .flat_map(|image| {
            [
                serde_json::json!({
                    "key": image.delivery.object_key.as_str(),
                    "role": "disk",
                    "byteSize": image.delivery.byte_size,
                    "sha256": image.delivery.sha256.as_str(),
                }),
                serde_json::json!({
                    "key": image.delivery.image_info.object_key.as_str(),
                    "role": "image-info",
                    "byteSize": image.delivery.image_info.byte_size,
                    "sha256": image.delivery.image_info.sha256.as_str(),
                }),
            ]
        })
        .collect::<Vec<_>>();
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
    let receipt_path = root.join(format!("publication-receipts/{}.json", commit.to_hex()));
    fs::create_dir_all(receipt_path.parent().unwrap()).unwrap();
    fs::write(
        receipt_path,
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "commit": commit.to_hex(),
            "registry": "demo",
            "catalogDigest": catalog_digest,
            "objects": receipt_objects,
        }))
        .unwrap(),
    )
    .unwrap();

    SystemImageFixture {
        registry: fixture,
        raw,
        qcow2,
        raw_key,
        qcow2_key,
        raw_info_key,
        qcow2_info_key,
        release_commit: commit,
        release_tag,
    }
}
