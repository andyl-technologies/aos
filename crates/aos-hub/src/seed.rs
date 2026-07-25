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
//! binding:    local  →  {root}/seed-bucket           (local_fs)
//! registry:   demo/cdn  (canonical)  bound to `local`, require_signatures=on
//! surface:    curl 8.5.0, openssl 3.2.1, jq 1.7.1    (x86_64-linux each)
//!             release 1.0.0, channel `stable` 100% rolled out
//!             registry.toml + keys.toml + signed HEAD commit + signed tag +
//!             256 signed partitions
//! token:      a publish token for demo/cdn (secret printed once)
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

use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;

use crate::db::{Database, SignupPolicy};
use crate::domain::{Permission, Principal, Role, Scope};
use crate::fetch::LocalFsFetch;
use crate::surface::object::{encode_loose, encode_tree, hash_object, ObjectKind, Oid, TreeEntry};
use crate::surface::sshsig;

/// The demo user's email address.
pub const DEMO_EMAIL: &str = "demo@example.com";

/// The demo user's password (printed in the report; dev-only).
pub const DEMO_PASSWORD: &str = "demo";

/// The demo org slug.
pub const DEMO_ORG: &str = "demo";

/// The demo registry name (its canonical path is `demo/cdn`).
pub const DEMO_REGISTRY: &str = "cdn";

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
/// surface under `{root}/seed-bucket`, indexes it so it is immediately
/// browsable, mints a sample publish token, and returns the
/// [`SeedReport`].
///
/// `root` is the hub state directory (the same `--root` the server uses); the
/// seeded surface lives at `{root}/seed-bucket/cdn`.
///
/// # Errors
///
/// Returns an error on any database failure, if the surface cannot be written
/// under `root`, or if the post-seed index fails (which would mean the
/// generated surface did not verify — a bug, surfaced loudly).
pub async fn seed_dev(db: &Database, root: &Path) -> Result<SeedOutcome> {
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
    // The org scope is just the org slug (see Scope::parse).
    db.grant_membership(
        principal.kind.as_str(),
        principal.id,
        Scope::parse(DEMO_ORG).as_str(),
        Role::Owner.as_str(),
    )
    .await?;

    // local_fs storage binding rooted under the hub state dir.
    let bucket = root.join("seed-bucket");
    std::fs::create_dir_all(&bucket)
        .with_context(|| format!("creating seed bucket {}", bucket.display()))?;
    let binding_id = db
        .create_storage_binding(org_id, "local", "local_fs", &bucket.to_string_lossy())
        .await?;

    // Generate the maintainer key + write the signed surface into the binding
    // root under the registry's prefix (`cdn`).
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let trust_key = sshsig::trusted_key_line("maintainer", &key.verifying_key());
    let surface_root = bucket.join(DEMO_REGISTRY);
    write_signed_surface(&surface_root, &key, &trust_key)
        .with_context(|| format!("writing seed surface to {}", surface_root.display()))?;

    // Register the managed registry, pinning the maintainer trust key with
    // signature verification on, then index it from the binding root.
    let registry_id = db
        .create_managed_registry(
            org_id,
            "",
            DEMO_REGISTRY,
            "public",
            Some(binding_id),
            DEMO_REGISTRY,
            std::slice::from_ref(&trust_key),
            true,
        )
        .await?;
    let registry = db
        .registry_by_id(registry_id)
        .await?
        .context("loading seeded registry after creation")?;
    let fetch = LocalFsFetch::new(&surface_root);
    crate::indexer::index_and_record(db, &fetch, &registry)
        .await
        .context("indexing seeded registry (the generated surface must verify)")?;

    // Mint a sample publish token scoped to the registry.
    let (token_id, token_secret) = db
        .create_token(
            principal,
            &registry.slug,
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
         [[caches]]\nurl = \"https://cache.example.com/\"\npriority = 40\n",
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
