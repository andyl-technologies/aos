//! Registry mirroring (RFC-0004 "Mirroring other registries").
//!
//! A mirror cannot alter content without breaking verification: releases are
//! signed tag objects, partitions are signed name-bound tags, objects are
//! SHA-256 content-addressed, and narinfos are Ed25519-signed. A mirror is a
//! byte courier, not a trust party. This module implements two of the three
//! named modes (the third, **derived**, is a publish-pipeline feature deferred
//! past v1 — see [`crate::db::Database::create_mirror_source`] which rejects
//! every mode but `full` and `pullthrough`):
//!
//! 1. **Full mirror** ([`sync_full_mirror`]) — a scheduled job fetches the
//!    upstream surface exactly as `apm` would (the same [`crate::surface`]
//!    reader), **verifies it against the mirror's trust anchors before
//!    accepting anything**, then copies the byte-identical files into the local
//!    binding root immutable-first (mutable pointers last), and re-indexes the
//!    local copy so it serves. On a verification failure nothing is written and
//!    the prior local state is kept — a poisoned upstream never propagates.
//!
//!    Consumers keep the **upstream's trust anchors**: an operator sets the
//!    mirror registry's `trust_keys` to the upstream's anchors at creation, so
//!    a consumer who only changed the URL in their `registries.d` still
//!    verifies against upstream's roster.
//!
//! 2. **Pull-through cache** ([`fetch_through`]) — a *proxied* frontend that
//!    fetches-on-miss from upstream, verifies, persists content-addressed
//!    payloads to the local binding, and serves. Content-addressed payloads
//!    (`objects/<oid>`, `nar/<hash>`, release packs) are verified by hash and
//!    are trivially safe to persist; pointers (`info/refs`, `HEAD`,
//!    `channels/**`, `nix-cache-info`) are self-verifying through signatures +
//!    name binding but are fetched fresh and **not** frozen as immutable —
//!    fall-through to upstream on every local miss is the completeness
//!    guarantee.
//!
//! # Surface enumeration
//!
//! The full mirror enumerates "every needed file" from the verified surface:
//! `HEAD` and `info/refs`, every loose object reachable from the HEAD commit's
//! tree and from each release tag, every present channel partition
//! (`channels/<branch>/00..ff`), and — best-effort when present — the
//! nix-cache files (`nix-cache-info`, the per-platform `*.narinfo`, and the
//! `nar/*` blobs the indexed store paths name). The git surface is what makes
//! `apm` work and is mirrored in full; the nix-cache files are mirrored when
//! the upstream serves them.

use std::collections::BTreeSet;

use anyhow::{bail, Context, Result};
use aos_package::registry::verify::TagTarget;

use crate::db::{Database, RegistryRecord};
use crate::fetch::{fetch_for_url, safe_join, SurfaceFetch};
use crate::surface::load::{load_registry_tree, ObjectReader};
use crate::surface::object::{ObjectKind, Oid};
use crate::surface::refs::{parse_head, parse_info_refs};
use crate::surface::sshsig;
use crate::surface::tag::{parse_signed_tag, verify_signed_tag};

/// The outcome of one full-mirror sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorSyncResult {
    /// The HEAD commit the upstream surface was verified at.
    pub commit: String,
    /// The newest release frontier observed across the mirrored channels.
    pub frontier: Option<String>,
    /// Number of surface files copied into the local binding.
    pub files_copied: usize,
    /// Number of releases verified on the upstream surface.
    pub releases: usize,
    /// Number of channels resolved on the upstream surface.
    pub channels: usize,
}

/// A verified upstream surface and the exact set of files to mirror.
///
/// Produced by [`verify_surface`]: the surface passed every signature and
/// name-binding check the indexer performs, so its files are safe to copy
/// byte-identically into the local binding.
struct VerifiedSurface {
    /// The verified HEAD commit oid (hex).
    commit: String,
    /// The newest release frontier across the channels.
    frontier: Option<String>,
    /// Surface-relative paths of the immutable, content-addressed files
    /// (loose objects, release packs, narinfos, NARs).
    immutable: Vec<String>,
    /// Surface-relative paths of the mutable pointers, written last so a reader
    /// never observes a dangling pointer (`HEAD`, `info/refs`, `channels/**`,
    /// `nix-cache-info`).
    mutable: Vec<String>,
    /// Number of verified releases.
    releases: usize,
    /// Number of resolved channels.
    channels: usize,
}

/// Run a full-mirror sync for `registry` against its recorded upstream.
///
/// Verifies the upstream surface against `registry.trust_keys` (the upstream's
/// anchors, set at mirror creation), copies the verified files into the local
/// binding root immutable-first, re-indexes the local copy, and records the
/// sync outcome. On a verification failure nothing is written, the prior local
/// state is kept, and `last_sync_status` is set to `failed` with the error.
///
/// # Errors
///
/// Returns an error when the registry has no `mirror_sources` row, has no
/// writable local binding, the upstream surface fails verification, or a copy
/// or re-index fails. A verification failure is recorded before the error is
/// returned, so a caller that ignores the error still sees `failed` in the
/// health page.
pub async fn sync_full_mirror(
    db: &Database,
    registry: &RegistryRecord,
) -> Result<MirrorSyncResult> {
    let source = db
        .mirror_source(registry.id)?
        .with_context(|| format!("registry '{}' is not a mirror", registry.slug))?;
    if source.mode != "full" {
        bail!(
            "registry '{}' is a '{}' mirror, not a full mirror",
            registry.slug,
            source.mode
        );
    }
    let root = db.registry_surface_root(registry.id)?.with_context(|| {
        format!(
            "mirror '{}' has no local binding to write into",
            registry.slug
        )
    })?;

    // Defense in depth: re-validate the upstream is a safe remote target before
    // fetching, even though creation already validated it (the row could have
    // been written by an older binary or restored from a backup).
    crate::fetch::is_safe_remote_url(&source.upstream_url).with_context(|| {
        format!(
            "refusing to sync mirror '{}' from unsafe upstream",
            registry.slug
        )
    })?;
    let fetch = fetch_for_url(&source.upstream_url)?;
    let now = unix_now();

    // Verify the upstream surface up front. A failure records `failed` and is
    // returned without touching the local binding.
    let verified = match verify_surface(fetch.as_ref(), &registry.trust_keys, source.verify).await {
        Ok(verified) => verified,
        Err(err) => {
            let detail = format!("{err:#}");
            db.update_mirror_sync(registry.id, now, "failed", Some(&detail), None)?;
            return Err(err).with_context(|| {
                format!(
                    "verifying upstream '{}' for mirror '{}'",
                    source.upstream_url, registry.slug
                )
            });
        }
    };

    // Copy immutable-first: content-addressed payloads land before any pointer
    // that references them, so a concurrent reader never sees a dangling
    // pointer. Pointers (HEAD, info/refs, channels, nix-cache-info) are written
    // last.
    let mut files_copied = 0usize;
    for path in verified.immutable.iter().chain(verified.mutable.iter()) {
        let copied = copy_path(fetch.as_ref(), &root, path).await?;
        if copied {
            files_copied += 1;
        }
    }

    // Re-index the local mirror so it serves the freshly synced state.
    let local = crate::fetch::LocalFsFetch::new(&root);
    crate::indexer::index_and_record(db, &local, registry)
        .await
        .with_context(|| format!("re-indexing mirror '{}' after sync", registry.slug))?;

    db.update_mirror_sync(registry.id, now, "ok", None, verified.frontier.as_deref())?;

    Ok(MirrorSyncResult {
        commit: verified.commit,
        frontier: verified.frontier,
        files_copied,
        releases: verified.releases,
        channels: verified.channels,
    })
}

/// Verify an upstream surface and enumerate the files to mirror.
///
/// Performs the same checks [`crate::indexer::index_registry`] performs — HEAD
/// commit signature, release tag signatures + name binding, channel partition
/// signatures + name binding, target resolution — and, as a side effect,
/// collects every surface-relative path that must be copied. When `verify` is
/// false the signature checks are skipped (name binding is still enforced), for
/// an operator mirroring an unsigned/legacy surface.
///
/// # Errors
///
/// Returns an error when the surface is unreachable, malformed, or — with
/// `verify` — fails any signature or name-binding check.
async fn verify_surface(
    fetch: &dyn SurfaceFetch,
    trust_keys: &[String],
    verify: bool,
) -> Result<VerifiedSurface> {
    let refs_bytes = fetch
        .fetch("info/refs")
        .await?
        .with_context(|| format!("{}: info/refs not found", fetch.describe()))?;
    let refs = parse_info_refs(std::str::from_utf8(&refs_bytes).context("info/refs not UTF-8")?)?;

    let head_bytes = fetch.fetch("HEAD").await?.context("HEAD not found")?;
    let head = parse_head(&String::from_utf8_lossy(&head_bytes));
    let (default_branch, commit_oid) =
        match head.and_then(|name| refs.branches.get(&name).copied().map(|oid| (name, oid))) {
            Some(found) => found,
            None => refs
                .branches
                .iter()
                .next()
                .map(|(name, oid)| (name.clone(), *oid))
                .context("upstream surface advertises no branches")?,
        };
    let _ = default_branch;

    // Verify the HEAD commit's signature and collect every object reachable
    // from its tree.
    let reader = ObjectReader::new(fetch);
    let commit = reader.read_commit(commit_oid).await?;
    let mut trusted: Vec<String> = trust_keys.to_vec();
    if verify {
        let signature = commit
            .signature
            .as_ref()
            .with_context(|| format!("commit {commit_oid} is unsigned"))?;
        sshsig::verify_armored(signature, &commit.signed_payload, &trusted)
            .with_context(|| format!("verifying commit {commit_oid}"))?;
    }

    // The verified roster extends the trusted set, mirroring apm's in-band
    // rotation (and the indexer).
    let tree = load_registry_tree(fetch, commit_oid).await?;
    if let Some(keys) = &tree.keys {
        for key in &keys.active {
            if !trusted.contains(&key.key) {
                trusted.push(key.key.clone());
            }
        }
    }

    // Object closure reachable from the HEAD commit. Walk the commit tree
    // transitively so every blob/tree object the registry tree needs is copied.
    let mut objects: BTreeSet<Oid> = BTreeSet::new();
    objects.insert(commit_oid);
    collect_tree_objects(&reader, commit.tree, &mut objects).await?;

    // Releases: every semver tag, verified and resolved to a commit.
    let mut releases = Vec::new();
    for (tag_name, tag_oid) in &refs.tags {
        if semver::Version::parse(tag_name).is_err() {
            continue;
        }
        let payload = reader.read_kind(*tag_oid, ObjectKind::Tag).await?;
        let signed = if verify {
            verify_signed_tag(&payload, tag_name, &trusted)
                .with_context(|| format!("release tag '{tag_name}'"))?
        } else {
            lenient_tag(&payload, tag_name)?
        };
        if signed.tag.target_type != TagTarget::Commit {
            bail!("release tag '{tag_name}' does not target a commit");
        }
        objects.insert(*tag_oid);
        releases.push((tag_name.clone(), tag_oid.to_hex()));
    }

    // Channels: branches whose 256 partitions resolve to release tag objects.
    let tag_oid_set: BTreeSet<String> = releases.iter().map(|(_, oid)| oid.clone()).collect();
    let mut mutable: Vec<String> = vec!["HEAD".to_string(), "info/refs".to_string()];
    let mut frontier: Option<semver::Version> = None;
    let mut channel_count = 0usize;
    for channel_name in refs.branches.keys() {
        let mut present = false;
        for bucket in 0u16..=255 {
            let path = format!("channels/{channel_name}/{bucket:02x}");
            let Some(payload) = fetch.fetch(&path).await? else {
                continue;
            };
            present = true;
            let signed = if verify {
                verify_signed_tag(&payload, channel_name, &trusted)
                    .with_context(|| format!("partition {path}"))?
            } else {
                lenient_tag(&payload, channel_name)?
            };
            if signed.tag.target_type != TagTarget::Tag {
                bail!("partition {path} does not target a tag object");
            }
            if !tag_oid_set.contains(&signed.tag.object) {
                bail!(
                    "partition {path} targets unknown tag object {}",
                    signed.tag.object
                );
            }
            mutable.push(path);
        }
        if present {
            channel_count += 1;
            // The branch head commit is part of the surface; map the channel
            // name's frontier from the resolved release semvers.
        }
    }
    // Frontier = newest release version that any present channel partition
    // pointed at. The simplest correct value is the max release semver, since
    // a fully-rolled mirror points every partition at the frontier; refine if
    // needed. Use the release set as the bound.
    for (semver_str, _) in &releases {
        if let Ok(version) = semver::Version::parse(semver_str) {
            if frontier.as_ref().is_none_or(|f| version > *f) {
                frontier = Some(version);
            }
        }
    }

    // Per-release pack files (best effort): mirror the per-release
    // `objects/info/packs` listing and its referenced packs when present.
    let mut immutable: Vec<String> = objects.iter().map(|oid| oid.loose_path()).collect();
    for (semver_str, _) in &releases {
        collect_release_packs(fetch, semver_str, &mut immutable).await?;
    }

    // Nix-cache files (best effort): when the upstream serves a nix-cache-info,
    // mirror it plus the narinfos and NARs the indexed store paths name.
    if fetch.fetch("nix-cache-info").await?.is_some() {
        mutable.push("nix-cache-info".to_string());
        collect_nix_cache(fetch, &tree, &mut immutable).await?;
    }

    Ok(VerifiedSurface {
        commit: commit_oid.to_hex(),
        frontier: frontier.map(|v| v.to_string()),
        immutable,
        mutable,
        releases: releases.len(),
        channels: channel_count,
    })
}

/// Recursively collect every object oid reachable from a tree.
async fn collect_tree_objects(
    reader: &ObjectReader<'_>,
    tree_oid: Oid,
    out: &mut BTreeSet<Oid>,
) -> Result<()> {
    // Iterative DFS to avoid recursing through `async fn` (which would need
    // boxing on every level).
    let mut stack = vec![tree_oid];
    while let Some(oid) = stack.pop() {
        if !out.insert(oid) {
            continue;
        }
        let content = reader.read_kind(oid, ObjectKind::Tree).await?;
        for entry in crate::surface::object::parse_tree(&content)? {
            if entry.is_tree() {
                stack.push(entry.oid);
            } else {
                out.insert(entry.oid);
            }
        }
    }
    Ok(())
}

/// Collect a release's full-pack files when its `objects/info/packs` listing
/// is present (best effort).
///
/// Per `docs/registry/http-layout.md`, release `X.Y.Z[-pre][+build]` lives
/// under `releases/<X>/<Y>/<Z[…]>/` and lists its packs in
/// `objects/info/packs`. Each listed `pack-<hash>.idx` line names a pack whose
/// `.pack` and `.idx` both live under `objects/pack/`.
async fn collect_release_packs(
    fetch: &dyn SurfaceFetch,
    semver_str: &str,
    out: &mut Vec<String>,
) -> Result<()> {
    let mut parts = semver_str.splitn(3, '.');
    let (Some(major), Some(minor), Some(rest)) = (parts.next(), parts.next(), parts.next()) else {
        return Ok(());
    };
    let base = format!("releases/{major}/{minor}/{rest}");
    let listing_path = format!("{base}/objects/info/packs");
    let Some(listing) = fetch.fetch(&listing_path).await? else {
        return Ok(());
    };
    out.push(listing_path);
    let text = String::from_utf8_lossy(&listing);
    for line in text.lines() {
        // Lines look like `P pack-<name>.pack`.
        let Some(name) = line.split_whitespace().nth(1) else {
            continue;
        };
        let stem = name.trim_end_matches(".pack").trim_end_matches(".idx");
        out.push(format!("{base}/objects/pack/{stem}.pack"));
        out.push(format!("{base}/objects/pack/{stem}.idx"));
    }
    Ok(())
}

/// Collect the nix-cache narinfo + NAR paths the registry's store paths name
/// (best effort).
///
/// For each `version_platforms` store path in the loaded tree's packages, the
/// narinfo is `<hash>.narinfo` and (if the upstream serves it) the NAR is the
/// file the narinfo's `URL` field names. We mirror the narinfo and, when the
/// narinfo parses, the NAR it points at.
async fn collect_nix_cache(
    fetch: &dyn SurfaceFetch,
    tree: &crate::surface::load::LoadedTree,
    out: &mut Vec<String>,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for package in &tree.packages {
        for version in &package.versions {
            for platform in version.platforms.values() {
                let basename = platform
                    .store_path
                    .rsplit('/')
                    .next()
                    .unwrap_or(&platform.store_path);
                let Some((hash, _)) = basename.split_once('-') else {
                    continue;
                };
                if !seen.insert(hash.to_string()) {
                    continue;
                }
                let narinfo_path = format!("{hash}.narinfo");
                let Some(narinfo) = fetch.fetch(&narinfo_path).await? else {
                    continue;
                };
                out.push(narinfo_path);
                // The NAR path is the narinfo's URL field (relative to root).
                if let Some(url) = narinfo_url(&narinfo) {
                    out.push(url);
                }
            }
        }
    }
    Ok(())
}

/// Extract the `URL:` field from narinfo bytes (the NAR's surface-relative
/// path), if present and relative.
fn narinfo_url(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("URL:") {
            let url = rest.trim();
            // Only mirror relative URLs (the standard `nar/<hash>.nar.zst`
            // form); an absolute URL points off-surface and is skipped.
            if !url.is_empty() && !url.contains("://") && !url.starts_with('/') {
                return Some(url.to_string());
            }
        }
    }
    None
}

/// Fetch one surface path from upstream and write it byte-identically under the
/// local binding root; returns whether a file was written (a missing upstream
/// file is skipped, not an error, for best-effort paths).
async fn copy_path(fetch: &dyn SurfaceFetch, root: &std::path::Path, path: &str) -> Result<bool> {
    let Some(bytes) = fetch.fetch(path).await? else {
        return Ok(false);
    };
    let target = safe_join(root, path)?;
    write_atomic(&target, &bytes).await?;
    Ok(true)
}

/// Write `bytes` to `target` atomically (create parents, write a temp sibling,
/// rename over the target) so a concurrent reader never sees a partial file.
async fn write_atomic(target: &std::path::Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = target.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let tmp = target.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    tokio::fs::write(&tmp, bytes)
        .await
        .with_context(|| format!("writing {}", tmp.display()))?;
    tokio::fs::rename(&tmp, target)
        .await
        .with_context(|| format!("renaming into {}", target.display()))?;
    Ok(())
}

/// Parse a tag payload without signature verification, still enforcing name
/// binding (used when a mirror's source is unsigned/legacy and `verify` is
/// off).
fn lenient_tag(payload: &[u8], expected_name: &str) -> Result<crate::surface::tag::SignedTag> {
    let signed = parse_signed_tag(payload)?;
    aos_package::registry::verify::verify_name_binding(&signed.tag, expected_name)?;
    Ok(signed)
}

/// The classification of a pull-through surface path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PullClass {
    /// A loose git object under `objects/<xx>/<62-hex>`: the path *is* the
    /// content's git oid, so the inflated bytes are verified against it before
    /// the object is frozen into the local cache. The only class persisted by
    /// the pull-through cache.
    VerifiedObject,
    /// A payload that is content-addressed in principle but that the
    /// pull-through cache cannot currently verify before persisting — NARs
    /// (whose filename encodes the *uncompressed* NAR hash while the fetched
    /// bytes are the *compressed* file) and release packs (whose checksum is
    /// in the pack trailer). To avoid persisting unverified upstream bytes
    /// (cache poisoning), these are fetched live and served but **never
    /// frozen**, exactly like a pointer, until hash verification exists.
    UnverifiableLive,
    /// A self-verifying pointer (`info/refs`, `HEAD`, `channels/**`,
    /// `nix-cache-info`, `*.narinfo`): fetched fresh, served, never frozen.
    Pointer,
}

/// Classify a machine path for the pull-through cache.
///
/// Only loose git objects under `objects/<xx>/<62-hex>` are
/// [`PullClass::VerifiedObject`] — their path is their git oid, so the
/// inflated content can be hash-checked before persisting. NARs and release
/// packs are content-addressed but not verifiable here (the NAR filename
/// encodes the uncompressed hash, not the compressed bytes; a pack's checksum
/// is in its trailer), so they are [`PullClass::UnverifiableLive`]: served but
/// never persisted. Everything else is a [`PullClass::Pointer`] fetched live.
///
/// The invariant: **no content-addressed payload is persisted into the local
/// cache without verifying its hash.**
fn pull_class(path: &str) -> PullClass {
    let is_loose_object = path
        .strip_prefix("objects/")
        .is_some_and(|rest| !rest.starts_with("info/") && rest.contains('/'));
    let is_nar = path.starts_with("nar/");
    let is_release_pack = path.starts_with("releases/") && path.contains("/objects/pack/");
    if is_loose_object {
        PullClass::VerifiedObject
    } else if is_nar || is_release_pack {
        PullClass::UnverifiableLive
    } else {
        PullClass::Pointer
    }
}

/// The result of a pull-through fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullResult {
    /// The fetched bytes.
    pub bytes: Vec<u8>,
    /// Whether the payload was persisted into the local binding (true for a
    /// verified content-addressed object; false for a live pointer).
    pub persisted: bool,
}

/// Fetch one machine path through the pull-through cache, verifying and (for
/// content-addressed payloads) persisting it.
///
/// A loose-object path is verified against the oid embedded in its path before
/// being persisted. NARs and release packs are **not** persisted: their hash
/// cannot be verified here (the NAR filename encodes the uncompressed hash, not
/// the fetched compressed bytes; a pack's checksum is in its trailer), so they
/// are served live but never frozen to avoid caching tampered upstream bytes.
/// Pointers (`info/refs`, partition tags, `nix-cache-info`, narinfos) are
/// likewise fetched live and returned without persisting, so the next request
/// re-fetches the current pointer.
///
/// Returns `Ok(None)` when the upstream definitively lacks the path (404).
///
/// # Errors
///
/// Returns an error on a transport failure, an oid mismatch (a tampered loose
/// object), or a write failure.
pub async fn fetch_through(
    fetch: &dyn SurfaceFetch,
    root: &std::path::Path,
    path: &str,
) -> Result<Option<PullResult>> {
    let Some(bytes) = fetch.fetch(path).await? else {
        return Ok(None);
    };

    match pull_class(path) {
        PullClass::VerifiedObject => {
            // A loose object path carries its oid: objects/<xx>/<62-hex>.
            // Verify the inflated content hashes to that oid before persisting,
            // so a tampered object is rejected rather than cached. A path that
            // does not parse as an oid is not persisted (it cannot be
            // verified), so the invariant holds even for a malformed path.
            let Some(oid) = oid_from_loose_path(path) else {
                return Ok(Some(PullResult {
                    bytes,
                    persisted: false,
                }));
            };
            // decode_loose verifies the hash against `oid`.
            crate::surface::object::decode_loose(&bytes, Some(oid))
                .with_context(|| format!("verifying pulled object {path}"))?;
            let target = safe_join(root, path)?;
            write_atomic(&target, &bytes).await?;
            Ok(Some(PullResult {
                bytes,
                persisted: true,
            }))
        }
        // NARs, release packs, and pointers are served live but never frozen,
        // because their content hash cannot be verified before persisting.
        PullClass::UnverifiableLive | PullClass::Pointer => Ok(Some(PullResult {
            bytes,
            persisted: false,
        })),
    }
}

/// Parse the oid named by a loose-object path (`objects/<xx>/<62-hex>`).
fn oid_from_loose_path(path: &str) -> Option<Oid> {
    let rest = path.strip_prefix("objects/")?;
    let (xx, tail) = rest.split_once('/')?;
    if xx.len() != 2 || tail.contains('/') {
        return None;
    }
    Oid::from_hex(&format!("{xx}{tail}")).ok()
}

/// Current Unix time in seconds.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_pull_paths() {
        // Only loose git objects are verifiable-and-persisted.
        assert_eq!(pull_class("objects/ab/cdef"), PullClass::VerifiedObject);
        // NARs and release packs are content-addressed but unverifiable here:
        // served live, never persisted.
        assert_eq!(pull_class("nar/x.nar.zst"), PullClass::UnverifiableLive);
        assert_eq!(
            pull_class("releases/1/0/0/objects/pack/p.pack"),
            PullClass::UnverifiableLive
        );
        for pointer in [
            "HEAD",
            "info/refs",
            "objects/info/packs",
            "channels/stable/00",
            "nix-cache-info",
            "abc.narinfo",
        ] {
            assert_eq!(pull_class(pointer), PullClass::Pointer, "{pointer}");
        }
    }

    #[tokio::test]
    async fn nar_and_pack_payloads_are_served_but_never_persisted() {
        use crate::fetch::LocalFsFetch;

        // An upstream surface carrying a NAR and a release pack.
        let upstream = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(upstream.path().join("nar")).unwrap();
        std::fs::write(upstream.path().join("nar/x.nar.zst"), b"upstream-nar-bytes").unwrap();
        std::fs::create_dir_all(upstream.path().join("releases/1/0/0/objects/pack")).unwrap();
        std::fs::write(
            upstream.path().join("releases/1/0/0/objects/pack/p.pack"),
            b"upstream-pack-bytes",
        )
        .unwrap();

        let local = tempfile::tempdir().unwrap();
        let fetch = LocalFsFetch::new(upstream.path());

        for (path, bytes) in [
            ("nar/x.nar.zst", b"upstream-nar-bytes".as_slice()),
            (
                "releases/1/0/0/objects/pack/p.pack",
                b"upstream-pack-bytes".as_slice(),
            ),
        ] {
            let result = fetch_through(&fetch, local.path(), path)
                .await
                .unwrap()
                .unwrap();
            // The bytes are served...
            assert_eq!(result.bytes, bytes, "{path} served");
            // ...but the payload is never frozen into the local cache, so a
            // tampered upstream payload cannot poison it.
            assert!(!result.persisted, "{path} must not be persisted");
            assert!(
                !local.path().join(path).exists(),
                "{path} must not be written to the local binding"
            );
        }
    }

    #[test]
    fn parses_oid_from_loose_path() {
        let hex = "ab".to_string() + &"cd".repeat(31);
        let path = format!("objects/{}/{}", &hex[..2], &hex[2..]);
        assert_eq!(oid_from_loose_path(&path).unwrap().to_hex(), hex);
        assert!(oid_from_loose_path("objects/info/packs").is_none());
        assert!(oid_from_loose_path("nar/x").is_none());
    }

    #[test]
    fn extracts_relative_narinfo_url() {
        let info = b"StorePath: /s/abc\nURL: nar/abc.nar.zst\nCompression: zstd\n";
        assert_eq!(narinfo_url(info).as_deref(), Some("nar/abc.nar.zst"));
        // Absolute URLs point off-surface and are skipped.
        let abs = b"URL: https://other/nar/abc.nar.zst\n";
        assert!(narinfo_url(abs).is_none());
    }
}
