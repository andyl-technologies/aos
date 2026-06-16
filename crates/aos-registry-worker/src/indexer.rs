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
//!
//! # D1 access
//!
//! All D1 reads and writes go through the shared
//! [`Backend`](aos_registry_core::backend::Backend) over the
//! [`D1Backend`](crate::d1backend::D1Backend), exactly as the read path does
//! ([`crate::reads`]). This is deliberate: the backend binds integers as JS
//! numbers (not the `worker` crate's BigInt, which the pinned 2024-09-09 workerd
//! D1 rejects) and reads NULL columns cleanly, so the indexer's writes and
//! floor reads run on the same engine the hub's `Database` uses. The indexer
//! keeps its own SQL (the deferred-package scope writes only `releases` /
//! `channels` / `channel_partitions` and the index head, never the whole-index
//! `apply_snapshot`, which would clear the separately-populated `packages`).

use anyhow::{anyhow, Context as _, Result};
use worker::Bucket;

use aos_registry_core::backend::Backend;
use aos_registry_core::value::Value;
use aos_registry_surface::object::{decode_loose, parse_commit, ObjectKind, Oid};
use aos_registry_surface::refs::{parse_head, parse_info_refs, Refs};
use aos_registry_surface::tag::verify_signed_tag;
use aos_registry_surface::tagobject::TagTarget;

use crate::d1backend::D1Backend;
use crate::indexlogic::{
    advance_frontier, floor_decision, resolve_partition_release, should_raise_floor, FloorDecision,
};
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
pub async fn index_all(backend: &D1Backend, bucket: &Bucket) -> Result<()> {
    let registries = list_public_registries(backend).await?;
    for registry in registries {
        if let Err(err) = index_one(backend, bucket, &registry).await {
            worker::console_log!("index {} failed: {err:#}", registry.slug);
            let _ = mark_state(backend, registry.id, "failed", Some(&format!("{err:#}"))).await;
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
pub async fn index_one(backend: &D1Backend, bucket: &Bucket, registry: &Registry) -> Result<()> {
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
    let releases = index_releases(backend, bucket, registry, &refs, &trust_keys).await?;

    // 4. Resolve and record channels (the branch heads).
    index_channels(backend, bucket, registry, &refs, &trust_keys, &releases).await?;

    // 5. Record the fresh index head.
    record_index(backend, registry.id, &head_commit).await?;
    Ok(())
}

/// Verify every semver release tag and write the `releases` rows.
///
/// Returns a map of verified tag-object oid -> semver, used to resolve channel
/// partitions (which point at tag objects) to releases.
async fn index_releases(
    backend: &D1Backend,
    bucket: &Bucket,
    registry: &Registry,
    refs: &Refs,
    trust_keys: &[String],
) -> Result<std::collections::BTreeMap<String, String>> {
    clear_table(backend, "releases", registry.id).await?;
    let mut by_oid = std::collections::BTreeMap::new();
    for (name, oid) in &refs.tags {
        // Only semver tags are releases; others are ignored (mirrors native).
        if semver::Version::parse(name).is_err() {
            continue;
        }
        let payload = read_loose(bucket, registry, &oid.to_hex(), ObjectKind::Tag).await?;
        let signed = verify_signed_tag(&payload, name, trust_keys)
            .with_context(|| format!("verifying release tag '{name}'"))?;
        // A release tag must target a commit (mirrors the native indexer); a
        // release pointing elsewhere is a hard failure, not a silent skip.
        if signed.tag.target_type != TagTarget::Commit {
            return Err(anyhow!("release tag '{name}' does not target a commit"));
        }
        let commit_oid = signed.tag.object.clone();
        write_release(backend, registry.id, name, &oid.to_hex(), &commit_oid).await?;
        by_oid.insert(oid.to_hex(), name.clone());
    }
    Ok(by_oid)
}

/// Resolve each channel's 256 partitions and write the channel rows.
///
/// Mirrors the native hub's `resolve_channels` + `enforce_floors` +
/// `raise_floors`: every partition's signed tag is verified, then required to
/// (1) target a release **tag object** and (2) name a known verified release
/// (an unknown or non-tag target is a hard failure, never a silent skip), and
/// the channel's new frontier is checked against the recorded anti-rollback
/// floor before any rows are written. A channel whose frontier dropped below
/// its floor fails the index (fail closed); after a clean write the floor is
/// raised (only ever upward) to the new frontier.
async fn index_channels(
    backend: &D1Backend,
    bucket: &Bucket,
    registry: &Registry,
    refs: &Refs,
    trust_keys: &[String],
    releases: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    clear_table(backend, "channels", registry.id).await?;
    for name in refs.branches.keys() {
        // Resolve and verify the channel fully in memory first, so the
        // anti-rollback floor is enforced *before* any row is written.
        let mut buckets: Vec<(usize, String)> = Vec::new();
        let mut frontier: Option<semver::Version> = None;
        for bucket_idx in 0..PARTITIONS {
            let path = format!("channels/{name}/{bucket_idx:02x}");
            let Some(payload) = fetch_bytes(bucket, registry, &path).await? else {
                continue;
            };
            let signed = verify_signed_tag(&payload, name, trust_keys)
                .with_context(|| format!("verifying partition {path}"))?;
            // Enforce the native hub's two target checks: the partition must
            // point at a *known* release *tag object*. A forged or dangling
            // pointer fails the whole index for this registry.
            let release = resolve_partition_release(&path, &signed, releases)?;
            advance_frontier(&mut frontier, release);
            buckets.push((bucket_idx, release.clone()));
        }
        let frontier = frontier.map(|v| v.to_string());

        // Anti-rollback floor: reject a channel whose frontier fell below the
        // recorded floor before touching the index (fail closed).
        let floor = channel_floor(backend, registry.id, name).await?;
        if floor_decision(frontier.as_deref(), floor.as_deref()) == FloorDecision::Rollback {
            // Both are Some here (Rollback requires it), but format defensively.
            return Err(anyhow!(
                "channel '{name}' frontier {} is below the recorded floor {}: refusing rollback",
                frontier.as_deref().unwrap_or("?"),
                floor.as_deref().unwrap_or("?"),
            ));
        }

        // Write the verified channel, its partitions, and its frontier.
        let channel_id = write_channel(backend, registry.id, name).await?;
        for (bucket_idx, release) in &buckets {
            write_partition(backend, channel_id, *bucket_idx, release).await?;
        }
        if let Some(frontier) = &frontier {
            set_channel_frontier(backend, channel_id, frontier).await?;
            // Raise (never lower) the floor to the new frontier.
            if should_raise_floor(frontier, floor.as_deref()) {
                set_channel_floor(backend, registry.id, name, frontier).await?;
            }
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
    // `loose_path()` already yields `objects/ab/cdef…` — do not re-prefix.
    let path = oid.loose_path();
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
// The write side of the index, issued through the shared D1Backend (sqlite
// dialect; integers bind as JS numbers, NULL columns read cleanly). The SQL is
// the sqlite-flavored DML the native indexer's writes reduce to, scoped to the
// surface-derivable tables (releases / channels / channel_partitions / the
// index head) — never the whole-index snapshot.

/// List every public registry, mapped to the worker's [`Registry`].
async fn list_public_registries(backend: &D1Backend) -> Result<Vec<Registry>> {
    let rows = backend
        .query(crate::sql::LIST_PUBLIC_REGISTRIES, &[])
        .await
        .context("listing registries")?;
    rows.into_iter()
        .map(|row| {
            Ok(Registry {
                id: row.get(0)?,
                slug: row.get(1)?,
                source_url: row.get(2)?,
                trust_keys: row.get(3)?,
                require_signatures: row.get(4)?,
                visibility: row.get(5)?,
                prefix: row.get(6)?,
            })
        })
        .collect()
}

async fn clear_table(backend: &D1Backend, table: &str, registry_id: i64) -> Result<()> {
    // `table` is a fixed internal literal, never user input.
    let sql = format!("DELETE FROM {table} WHERE registry_id = ?1");
    backend.execute(&sql, &[Value::Int(registry_id)]).await?;
    Ok(())
}

async fn write_release(
    backend: &D1Backend,
    registry_id: i64,
    semver: &str,
    tag_oid: &str,
    commit_oid: &str,
) -> Result<()> {
    backend
        .execute(
            "INSERT INTO releases (registry_id, semver, tag_oid, commit_oid, pack_present) \
             VALUES (?1, ?2, ?3, ?4, 0)",
            &[
                Value::Int(registry_id),
                Value::Text(semver.to_string()),
                Value::Text(tag_oid.to_string()),
                Value::Text(commit_oid.to_string()),
            ],
        )
        .await?;
    Ok(())
}

/// Insert a channel row and return its new id (D1's `last_row_id`).
async fn write_channel(backend: &D1Backend, registry_id: i64, name: &str) -> Result<i64> {
    backend
        .execute_insert(
            "INSERT INTO channels (registry_id, name) VALUES (?1, ?2)",
            &[Value::Int(registry_id), Value::Text(name.to_string())],
        )
        .await
        .context("inserting channel")
}

async fn write_partition(
    backend: &D1Backend,
    channel_id: i64,
    bucket: usize,
    release: &str,
) -> Result<()> {
    backend
        .execute(
            "INSERT INTO channel_partitions (channel_id, bucket, release) VALUES (?1, ?2, ?3)",
            &[
                Value::Int(channel_id),
                Value::Int(bucket as i64),
                Value::Text(release.to_string()),
            ],
        )
        .await?;
    Ok(())
}

async fn set_channel_frontier(backend: &D1Backend, channel_id: i64, frontier: &str) -> Result<()> {
    backend
        .execute(
            "UPDATE channels SET frontier = ?2 WHERE id = ?1",
            &[Value::Int(channel_id), Value::Text(frontier.to_string())],
        )
        .await?;
    Ok(())
}

/// Read a channel's recorded anti-rollback floor (the highest frontier ever
/// indexed for it), or `None` if it has never been indexed.
async fn channel_floor(
    backend: &D1Backend,
    registry_id: i64,
    channel: &str,
) -> Result<Option<String>> {
    let row = backend
        .query_opt(
            "SELECT floor FROM channel_floors WHERE registry_id = ?1 AND channel = ?2",
            &[Value::Int(registry_id), Value::Text(channel.to_string())],
        )
        .await
        .context("reading channel floor")?;
    row.map(|r| r.get::<String>(0)).transpose()
}

/// Raise (overwrite) a channel's anti-rollback floor.
///
/// The caller only ever passes a frontier that is strictly greater than the
/// recorded floor (see [`should_raise_floor`]); the floor only moves upward.
async fn set_channel_floor(
    backend: &D1Backend,
    registry_id: i64,
    channel: &str,
    floor: &str,
) -> Result<()> {
    backend
        .execute(
            "INSERT INTO channel_floors (registry_id, channel, floor) VALUES (?1, ?2, ?3) \
             ON CONFLICT(registry_id, channel) DO UPDATE SET floor = excluded.floor",
            &[
                Value::Int(registry_id),
                Value::Text(channel.to_string()),
                Value::Text(floor.to_string()),
            ],
        )
        .await?;
    Ok(())
}

async fn record_index(backend: &D1Backend, registry_id: i64, commit: &str) -> Result<()> {
    let now = worker::Date::now().as_millis() as i64 / 1000;
    backend
        .execute(
            "INSERT INTO registry_index (registry_id, state, last_indexed_commit, indexed_at) \
             VALUES (?1, 'fresh', ?2, ?3) \
             ON CONFLICT(registry_id) DO UPDATE SET \
               state = 'fresh', last_indexed_commit = excluded.last_indexed_commit, \
               indexed_at = excluded.indexed_at, error = NULL",
            &[
                Value::Int(registry_id),
                Value::Text(commit.to_string()),
                Value::Int(now),
            ],
        )
        .await?;
    Ok(())
}

async fn mark_state(
    backend: &D1Backend,
    registry_id: i64,
    state: &str,
    error: Option<&str>,
) -> Result<()> {
    let error = error.map_or(Value::Null, |e| Value::Text(e.to_string()));
    backend
        .execute(
            "INSERT INTO registry_index (registry_id, state, error) VALUES (?1, ?2, ?3) \
             ON CONFLICT(registry_id) DO UPDATE SET state = excluded.state, error = excluded.error",
            &[Value::Int(registry_id), Value::Text(state.to_string()), error],
        )
        .await?;
    Ok(())
}
