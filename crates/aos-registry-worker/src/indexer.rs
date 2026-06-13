//! The Cron-triggered indexer over R2 surfaces, writing the D1 index
//! (wasm32-only).
//!
//! RFC-0004 drives the Worker's indexer from a **Cron Trigger** ("Cron
//! Triggers/Queues drive the indexer, validator, and mirror jobs"). The
//! `scheduled` handler walks every public registry's surface — read from the
//! R2 bucket rather than over HTTP — and replaces its D1 index, reusing the
//! exact pure verifier the native hub indexer and `apm` run
//! ([`aos_registry_surface`]). One parser, three runtimes: the Worker's read
//! of the surface cannot drift from the native hub's.
//!
//! # Scope (mirrors the native flow, minus the tree walk)
//!
//! The native indexer ([`aos_registry_hub`]'s `indexer`) additionally walks the
//! committed tree to parse `registry.toml` and the package TOMLs into the
//! `packages`/`version_platforms` tables — that step depends on `aos-package`'s
//! committed-file parsers, which are not part of the wasm-clean surface core.
//! This Worker indexer implements the **cryptographically verified, surface-
//! derivable core**: it
//!
//! 1. fetches `HEAD` + `info/refs` from R2 and selects the default branch's
//!    commit;
//! 2. reads the commit loose object and, when `require_signatures`, verifies
//!    its `gpgsig` SSH signature against the registry's pinned trust anchors
//!    (fail closed — an unverifiable surface is never recorded fresh);
//! 3. verifies every semver release tag (signature + name binding) and writes
//!    the `releases` rows;
//! 4. resolves each channel by verifying its 256 partition payloads (signature
//!    + name binding) and writes the `channels`/`channel_partitions` rows.
//!
//! Populating `packages`/`version_platforms` from the committed tree is the
//! one deferred step; it is noted in the crate README. The roster used to
//! verify is the registry's pinned trust anchors only (the in-band roster
//! rotation that extends trust from the committed `keys.toml` is part of the
//! tree walk and is deferred with it).

use anyhow::{anyhow, Context as _, Result};
use worker::{Bucket, D1Database};

use aos_registry_surface::object::{decode_loose, parse_commit, ObjectKind, Oid};
use aos_registry_surface::refs::{parse_head, parse_info_refs, Refs};
use aos_registry_surface::tag::verify_signed_tag;
use aos_registry_surface::tagobject::TagTarget;

use crate::keymap;
use crate::model::Registry;

/// Number of channel partition buckets (the registry channel model).
const PARTITIONS: usize = 256;

/// Index every public registry from R2 into D1.
///
/// Called from the `scheduled` handler. Each registry is indexed independently;
/// one registry's failure is logged and does not abort the rest.
///
/// # Errors
///
/// Returns an error only if the registry list cannot be read from D1.
pub async fn index_all(db: &D1Database, bucket: &Bucket) -> Result<()> {
    let registries = list_public_registries(db).await?;
    for registry in registries {
        if let Err(err) = index_one(db, bucket, &registry).await {
            worker::console_log!("index {} failed: {err:#}", registry.slug);
            let _ = mark_state(db, registry.id, "failed", Some(&format!("{err:#}"))).await;
        }
    }
    Ok(())
}

/// Index one registry's surface from R2 into D1.
///
/// # Errors
///
/// Returns an error on a verification failure or an R2/D1 access failure; the
/// caller records it as the registry's `failed` index state.
pub async fn index_one(db: &D1Database, bucket: &Bucket, registry: &Registry) -> Result<()> {
    let trust_keys = parse_trust_keys(&registry.trust_keys)?;

    // 1. HEAD + info/refs -> the default branch commit.
    let head = fetch_text(bucket, registry, "HEAD")
        .await?
        .ok_or_else(|| anyhow!("missing HEAD"))?;
    let info_refs = fetch_text(bucket, registry, "info/refs")
        .await?
        .ok_or_else(|| anyhow!("missing info/refs"))?;
    let refs = parse_info_refs(&info_refs).context("parsing info/refs")?;
    let default_branch = parse_head(&head).ok_or_else(|| anyhow!("detached HEAD"))?;
    let head_commit = refs
        .branches
        .get(&default_branch)
        .ok_or_else(|| anyhow!("HEAD branch '{default_branch}' not advertised"))?
        .to_hex();

    // 2. Verify the commit signature (fail closed under require_signatures).
    let commit_bytes = read_loose(bucket, registry, &head_commit, ObjectKind::Commit).await?;
    let commit = parse_commit(&commit_bytes).context("parsing HEAD commit")?;
    if registry.require_signatures != 0 {
        let sig = commit
            .signature
            .as_ref()
            .ok_or_else(|| anyhow!("HEAD commit is unsigned"))?;
        aos_registry_surface::sshsig::verify_armored(sig, &commit.signed_payload, &trust_keys)
            .context("verifying HEAD commit signature")?;
    }

    // 3. Verify and record release tags.
    let releases = index_releases(db, bucket, registry, &refs, &trust_keys).await?;

    // 4. Resolve and record channels (the branch heads).
    index_channels(db, bucket, registry, &refs, &trust_keys, &releases).await?;

    // 5. Record the fresh index head.
    record_index(db, registry.id, &head_commit).await?;
    Ok(())
}

/// Verify every semver release tag and write the `releases` rows.
///
/// Returns a map of verified tag-object oid -> semver, used to resolve channel
/// partitions (which point at tag objects) to releases.
async fn index_releases(
    db: &D1Database,
    bucket: &Bucket,
    registry: &Registry,
    refs: &Refs,
    trust_keys: &[String],
) -> Result<std::collections::BTreeMap<String, String>> {
    clear_table(db, "releases", registry.id).await?;
    let mut by_oid = std::collections::BTreeMap::new();
    for (name, oid) in &refs.tags {
        // Only semver tags are releases; others are ignored (mirrors native).
        if semver::Version::parse(name).is_err() {
            continue;
        }
        let payload = read_loose(bucket, registry, &oid.to_hex(), ObjectKind::Tag).await?;
        let signed = verify_signed_tag(&payload, name, trust_keys)
            .with_context(|| format!("verifying release tag '{name}'"))?;
        if signed.tag.target_type != TagTarget::Commit {
            continue;
        }
        let commit_oid = signed.tag.object.clone();
        write_release(db, registry.id, name, &oid.to_hex(), &commit_oid).await?;
        by_oid.insert(oid.to_hex(), name.clone());
    }
    Ok(by_oid)
}

/// Resolve each channel's 256 partitions and write the channel rows.
async fn index_channels(
    db: &D1Database,
    bucket: &Bucket,
    registry: &Registry,
    refs: &Refs,
    trust_keys: &[String],
    releases: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    clear_table(db, "channels", registry.id).await?;
    for name in refs.branches.keys() {
        let channel_id = write_channel(db, registry.id, name).await?;
        let mut frontier: Option<String> = None;
        for bucket_idx in 0..PARTITIONS {
            let path = format!("channels/{name}/{bucket_idx:02x}");
            let Some(payload) = fetch_bytes(bucket, registry, &path).await? else {
                continue;
            };
            let signed = verify_signed_tag(&payload, name, trust_keys)
                .with_context(|| format!("verifying partition {path}"))?;
            // The partition points at a release tag object; map it to a semver.
            let target = signed.tag.object.clone();
            if let Some(release) = releases.get(&target) {
                write_partition(db, channel_id, bucket_idx, release).await?;
                // The frontier is the highest semver mapped on the channel.
                let higher = frontier
                    .as_ref()
                    .and_then(|f| semver::Version::parse(f).ok())
                    .zip(semver::Version::parse(release).ok())
                    .map(|(cur, new)| new > cur)
                    .unwrap_or(true);
                if higher {
                    frontier = Some(release.clone());
                }
            }
        }
        if let Some(frontier) = frontier {
            set_channel_frontier(db, channel_id, &frontier).await?;
        }
    }
    Ok(())
}

// -- R2 surface reads -------------------------------------------------------

/// Fetch a machine path's raw bytes from R2, mapping the prefix in.
async fn fetch_bytes(bucket: &Bucket, registry: &Registry, path: &str) -> Result<Option<Vec<u8>>> {
    let key = keymap::r2_key(&registry.prefix, path);
    let object = bucket
        .get(&key)
        .execute()
        .await
        .map_err(|e| anyhow!("R2 get {key}: {e}"))?;
    let Some(object) = object else {
        return Ok(None);
    };
    let Some(body) = object.body() else {
        return Ok(Some(Vec::new()));
    };
    let bytes = body
        .bytes()
        .await
        .map_err(|e| anyhow!("R2 body {key}: {e}"))?;
    Ok(Some(bytes))
}

/// Fetch a machine path's bytes as UTF-8 text.
async fn fetch_text(bucket: &Bucket, registry: &Registry, path: &str) -> Result<Option<String>> {
    match fetch_bytes(bucket, registry, path).await? {
        Some(bytes) => Ok(Some(
            String::from_utf8(bytes).context("surface text not UTF-8")?,
        )),
        None => Ok(None),
    }
}

/// Read a loose object by oid from R2, inflate it, and check its kind + hash.
async fn read_loose(
    bucket: &Bucket,
    registry: &Registry,
    oid_hex: &str,
    expect: ObjectKind,
) -> Result<Vec<u8>> {
    let oid = Oid::from_hex(oid_hex)?;
    let path = format!("objects/{}", oid.loose_path());
    let compressed = fetch_bytes(bucket, registry, &path)
        .await?
        .ok_or_else(|| anyhow!("missing object {oid_hex}"))?;
    let (kind, content) = decode_loose(&compressed, Some(oid))
        .with_context(|| format!("decoding object {oid_hex}"))?;
    if kind != expect {
        return Err(anyhow!(
            "object {oid_hex} is {} not {}",
            kind.as_str(),
            expect.as_str()
        ));
    }
    Ok(content)
}

/// Parse the registry's stored trust-anchor JSON array into key lines.
fn parse_trust_keys(json: &str) -> Result<Vec<String>> {
    serde_json::from_str(json).context("parsing trust_keys JSON")
}

// -- D1 writes --------------------------------------------------------------
//
// The write side of the index. Each helper runs one D1 prepared statement. D1
// is sqlite, so these are the sqlite-flavored DML the native indexer would run.

async fn list_public_registries(db: &D1Database) -> Result<Vec<Registry>> {
    let rows = db
        .prepare(crate::sql::LIST_PUBLIC_REGISTRIES)
        .all()
        .await
        .map_err(|e| anyhow!("listing registries: {e}"))?;
    // Deserialize via the d1 layer's row mapping by going through serde_json
    // values would be redundant; reuse the typed results() path.
    rows.results::<RegistryRow>()
        .map(|rows| rows.into_iter().map(Registry::from).collect())
        .map_err(|e| anyhow!("decoding registries: {e}"))
}

#[derive(serde::Deserialize)]
struct RegistryRow {
    id: i64,
    slug: String,
    source_url: String,
    trust_keys: String,
    require_signatures: i64,
    visibility: String,
    prefix: String,
}

impl From<RegistryRow> for Registry {
    fn from(r: RegistryRow) -> Self {
        Registry {
            id: r.id,
            slug: r.slug,
            source_url: r.source_url,
            trust_keys: r.trust_keys,
            require_signatures: r.require_signatures,
            visibility: r.visibility,
            prefix: r.prefix,
        }
    }
}

async fn run(db: &D1Database, sql: &str, binds: &[worker::wasm_bindgen::JsValue]) -> Result<()> {
    db.prepare(sql)
        .bind(binds)
        .map_err(|e| anyhow!("bind {sql}: {e}"))?
        .run()
        .await
        .map_err(|e| anyhow!("run {sql}: {e}"))?;
    Ok(())
}

async fn clear_table(db: &D1Database, table: &str, registry_id: i64) -> Result<()> {
    // `table` is a fixed internal literal, never user input.
    let sql = format!("DELETE FROM {table} WHERE registry_id = ?1");
    run(db, &sql, &[registry_id.into()]).await
}

async fn write_release(
    db: &D1Database,
    registry_id: i64,
    semver: &str,
    tag_oid: &str,
    commit_oid: &str,
) -> Result<()> {
    run(
        db,
        "INSERT INTO releases (registry_id, semver, tag_oid, commit_oid, pack_present) \
         VALUES (?1, ?2, ?3, ?4, 0)",
        &[
            registry_id.into(),
            semver.into(),
            tag_oid.into(),
            commit_oid.into(),
        ],
    )
    .await
}

async fn write_channel(db: &D1Database, registry_id: i64, name: &str) -> Result<i64> {
    run(
        db,
        "INSERT INTO channels (registry_id, name) VALUES (?1, ?2)",
        &[registry_id.into(), name.into()],
    )
    .await?;
    let id: Option<i64> = db
        .prepare("SELECT id FROM channels WHERE registry_id = ?1 AND name = ?2")
        .bind(&[registry_id.into(), name.into()])
        .map_err(|e| anyhow!("bind channel id: {e}"))?
        .first(Some("id"))
        .await
        .map_err(|e| anyhow!("channel id: {e}"))?;
    id.ok_or_else(|| anyhow!("channel id not found after insert"))
}

async fn write_partition(
    db: &D1Database,
    channel_id: i64,
    bucket: usize,
    release: &str,
) -> Result<()> {
    run(
        db,
        "INSERT INTO channel_partitions (channel_id, bucket, release) VALUES (?1, ?2, ?3)",
        &[channel_id.into(), (bucket as i64).into(), release.into()],
    )
    .await
}

async fn set_channel_frontier(db: &D1Database, channel_id: i64, frontier: &str) -> Result<()> {
    run(
        db,
        "UPDATE channels SET frontier = ?2 WHERE id = ?1",
        &[channel_id.into(), frontier.into()],
    )
    .await
}

async fn record_index(db: &D1Database, registry_id: i64, commit: &str) -> Result<()> {
    let now = worker::Date::now().as_millis() as i64 / 1000;
    run(
        db,
        "INSERT INTO registry_index (registry_id, state, last_indexed_commit, indexed_at) \
         VALUES (?1, 'fresh', ?2, ?3) \
         ON CONFLICT(registry_id) DO UPDATE SET \
           state = 'fresh', last_indexed_commit = excluded.last_indexed_commit, \
           indexed_at = excluded.indexed_at, error = NULL",
        &[registry_id.into(), commit.into(), now.into()],
    )
    .await
}

async fn mark_state(
    db: &D1Database,
    registry_id: i64,
    state: &str,
    error: Option<&str>,
) -> Result<()> {
    let err_val: worker::wasm_bindgen::JsValue = match error {
        Some(e) => e.into(),
        None => worker::wasm_bindgen::JsValue::NULL,
    };
    run(
        db,
        "INSERT INTO registry_index (registry_id, state, error) VALUES (?1, ?2, ?3) \
         ON CONFLICT(registry_id) DO UPDATE SET state = excluded.state, error = excluded.error",
        &[registry_id.into(), state.into(), err_val],
    )
    .await
}
