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
//! 2. **Pull-through cache** ([`fetch_through`]) — a Hub delivery route that
//!    fetches-on-miss from upstream, verifies, persists the loose objects it
//!    can hash-check to the local binding, and serves. Loose `objects/<oid>`
//!    are verified by oid and frozen. Narinfos are signature-verified against
//!    the trust roster, and NARs are hash-verified against their
//!    (signature-verified) narinfo, before either is served — a tampered
//!    narinfo or NAR is refused, never proxied, so poison never propagates even
//!    though these are not frozen. Release packs (no in-band checksum) and
//!    pointers (`info/refs`, `HEAD`, `channels/**`, `nix-cache-info`) are
//!    fetched fresh and **not** frozen — fall-through to upstream on every
//!    local miss is the completeness guarantee.
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

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use aos_package::registry::verify::TagTarget;

use crate::db::{Database, RegistryRecord};
use crate::fetch::{fetch_mirror_upstream, safe_join, SurfaceFetch};
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
    /// Roster keys the verified upstream's `keys.toml` added beyond the
    /// mirror's configured `trust_keys` (in-band rotation). Empty when the
    /// trusted set was unchanged. Surfaced in the sync record so a roster
    /// expansion is operator-visible (L4); the rotation itself is by design.
    roster_added: Vec<String>,
    /// The **exact verified bytes** for the narinfo/NAR class, keyed by
    /// surface-relative path.
    ///
    /// Closes a verify-then-copy TOCTOU (sec H-1): [`verify_surface`] verifies
    /// these bytes once and the copy phase writes *these* bytes rather than
    /// re-fetching (which would let a hostile upstream serve clean bytes during
    /// verification and poison during the copy). The git loose-object class is
    /// deliberately *not* retained — it is re-fetched and self-heals via the
    /// post-copy re-index's oid/signature checks; only the unindexed
    /// narinfo/NAR class needs write==verified.
    verified_bytes: BTreeMap<String, Vec<u8>>,
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
        .mirror_source(registry.id)
        .await?
        .with_context(|| format!("registry '{}' is not a mirror", registry.slug))?;
    if source.mode != "full" {
        bail!(
            "registry '{}' is a '{}' mirror, not a full mirror",
            registry.slug,
            source.mode
        );
    }
    let placement = db
        .reconciled_surface_writer(aos_hub_core::db::SurfaceTarget::Registry(registry.id))
        .await
        .with_context(|| format!("mirror '{}' has no reconciled writer", registry.slug))?;
    let binding = db
        .storage_binding(placement.storage_binding_id)
        .await?
        .context("mirror placement references a missing storage binding")?;
    if binding.kind != "local_fs" {
        bail!("native full-mirror sync currently requires a local_fs write placement");
    }
    let root = std::path::PathBuf::from(
        binding
            .local_root_path
            .context("local mirror binding has no localRootPath")?,
    )
    .join(placement.prefix);

    // Defense in depth: re-validate the upstream is a safe remote target before
    // fetching, even though creation already validated it (the row could have
    // been written by an older binary or restored from a backup).
    crate::fetch::is_safe_remote_url(&source.upstream_url).with_context(|| {
        format!(
            "refusing to sync mirror '{}' from unsafe upstream",
            registry.slug
        )
    })?;
    let fetch = fetch_mirror_upstream(&source.upstream_url).await?;
    let now = unix_now();

    // Verify the upstream surface up front. A failure records `failed` and is
    // returned without touching the local binding.
    let verified = match verify_surface(fetch.as_ref(), &registry.trust_keys, source.verify).await {
        Ok(verified) => verified,
        Err(err) => {
            let detail = format!("{err:#}");
            db.update_mirror_sync(registry.id, now, "failed", Some(&detail), None)
                .await?;
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
        // For the narinfo/NAR class, write the EXACT bytes that passed
        // verification in `verify_surface` rather than re-fetching — re-fetching
        // would reopen a verify-then-copy TOCTOU (sec H-1), since the post-copy
        // re-index does not re-validate the narinfo/NAR surface. The git
        // loose-object/pointer classes are re-fetched (and self-heal via the
        // re-index).
        let copied = match verified.verified_bytes.get(path) {
            Some(bytes) => write_verified(&root, path, bytes).await?,
            None => copy_path(fetch.as_ref(), &root, path).await?,
        };
        if copied {
            files_copied += 1;
        }
    }

    // Re-index the local mirror so it serves the freshly synced state.
    let local = crate::fetch::LocalFsFetch::new(&root);
    crate::indexer::index_and_record(db, &local, registry)
        .await
        .with_context(|| format!("re-indexing mirror '{}' after sync", registry.slug))?;

    // Surface an in-band roster expansion in the sync record so the trusted
    // set never silently widens (L4). The rotation is by design; this is the
    // operator-visible signal that it happened.
    let roster_note = if verified.roster_added.is_empty() {
        None
    } else {
        let summary = format!("roster changed: +{}", verified.roster_added.join(", +"));
        tracing::info!(slug = %registry.slug, detail = %summary, "mirror roster expanded");
        Some(summary)
    };
    db.update_mirror_sync(
        registry.id,
        now,
        "ok",
        roster_note.as_deref(),
        verified.frontier.as_deref(),
    )
    .await?;

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
    // rotation (and the indexer). Each newly-trusted active key is recorded so
    // a roster expansion is operator-visible (L4): the rotation is by design,
    // but silently widening the trusted set is not — the sync surfaces it.
    let tree = load_registry_tree(fetch, commit_oid).await?;
    let mut roster_added: Vec<String> = Vec::new();
    if let Some(keys) = &tree.keys {
        for key in &keys.active {
            if !trusted.contains(&key.key) {
                trusted.push(key.key.clone());
                roster_added.push(key.key.clone());
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
    // mirror it plus the narinfos and NARs the indexed store paths name. Under
    // `verify` (the default), every narinfo's `Sig:` is checked against the
    // trust roster and every NAR's bytes against the narinfo's FileHash/NarHash
    // before the pair is admitted to the immutable copy set — a poisoned
    // upstream cache never reaches the binding (C1). With `verify` off the
    // narinfos/NARs are mirrored unverified, the operator's documented opt-out.
    let mut verified_bytes: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    if fetch.fetch("nix-cache-info").await?.is_some() {
        mutable.push("nix-cache-info".to_string());
        collect_nix_cache(
            fetch,
            &tree,
            &trusted,
            verify,
            &mut immutable,
            &mut verified_bytes,
        )
        .await?;
    }

    Ok(VerifiedSurface {
        commit: commit_oid.to_hex(),
        frontier: frontier.map(|v| v.to_string()),
        immutable,
        mutable,
        releases: releases.len(),
        channels: channel_count,
        roster_added,
        verified_bytes,
    })
}

/// Maximum number of objects collected from one upstream tree closure before
/// the full-mirror sync aborts.
///
/// [`collect_tree_objects`] walks the entire HEAD tree closure into an
/// in-memory [`BTreeSet`] (plus the immutable copy list). The tree is
/// attacker-controlled: an upstream an operator chose to full-mirror can fan
/// millions of tiny objects out under arbitrary paths, and the sync runs in the
/// web-server process — so an uncapped walk would let one hostile upstream OOM
/// the hub. Mirrors [`MAX_PACKAGES`](crate::surface::load::MAX_PACKAGES) /
/// [`MAX_CLOSURE_ENTRIES`](crate::surface::load::MAX_CLOSURE_ENTRIES): the sync
/// **aborts** (the upstream is marked failed) rather than truncating, so a
/// registry that overflows is never silently partially mirrored. Sized far
/// above any realistic registry.
pub const MAX_MIRROR_OBJECTS: usize = 2_000_000;

/// Recursively collect every object oid reachable from a tree.
///
/// Caps the closure at [`MAX_MIRROR_OBJECTS`] objects.
///
/// # Errors
///
/// Returns an error on a transport or parse failure, or when the closure would
/// exceed [`MAX_MIRROR_OBJECTS`] objects (a hostile upstream fanning out an
/// unbounded object count) — the sync aborts rather than accumulate without
/// bound.
async fn collect_tree_objects(
    reader: &ObjectReader<'_>,
    tree_oid: Oid,
    out: &mut BTreeSet<Oid>,
) -> Result<()> {
    collect_tree_objects_capped(reader, tree_oid, out, MAX_MIRROR_OBJECTS).await
}

/// Recursively collect every object oid reachable from a tree, aborting once
/// `max` distinct oids have been collected.
///
/// Split out from [`collect_tree_objects`] so the cap can be exercised with a
/// small bound in tests without materializing [`MAX_MIRROR_OBJECTS`] objects.
///
/// # Errors
///
/// Returns an error on a transport or parse failure, or when the closure would
/// exceed `max` objects.
async fn collect_tree_objects_capped(
    reader: &ObjectReader<'_>,
    tree_oid: Oid,
    out: &mut BTreeSet<Oid>,
    max: usize,
) -> Result<()> {
    // Iterative DFS to avoid recursing through `async fn` (which would need
    // boxing on every level).
    let mut stack = vec![tree_oid];
    while let Some(oid) = stack.pop() {
        if out.len() >= max {
            bail!("upstream tree closure exceeds the {max}-object mirror cap; aborting sync");
        }
        if !out.insert(oid) {
            continue;
        }
        let content = reader.read_kind(oid, ObjectKind::Tree).await?;
        for entry in crate::surface::object::parse_tree(&content)? {
            if out.len() >= max {
                bail!("upstream tree closure exceeds the {max}-object mirror cap; aborting sync");
            }
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

/// Collect — and, under `verify`, authenticate — the nix-cache narinfo + NAR
/// paths the registry's store paths name (best effort).
///
/// For each `version_platforms` store path in the loaded tree's packages, the
/// narinfo is `<hash>.narinfo` and (if the upstream serves it) the NAR is the
/// file the narinfo's `URL` field names.
///
/// When `verify` is true (the default, high-assurance posture):
///
/// 1. The narinfo's `Sig:` is checked against `trusted` (the registry's trust
///    roster, extended by the verified in-band roster) with
///    [`crate::validation::verify_narinfo_signature`]. A narinfo with no valid
///    trusted signature **fails the whole sync** — a mirror is a byte courier,
///    not a trust party, so it must not launder an unsigned/forged narinfo. The
///    narinfo's signed `StorePath` hash is then bound to the `<hash>` it was
///    fetched under (sec M-5): a genuinely-signed narinfo for a *different*
///    store hash served at this path is a substitution and **fails the sync**,
///    because the path a narinfo is served at is not covered by its signature.
/// 2. The NAR the (now-trusted) narinfo names is fetched and its bytes verified
///    against the narinfo's `FileHash`/`NarHash`
///    ([`crate::validation::verify_nar_against_narinfo`]). A mismatch **fails
///    the whole sync**.
///
/// Only narinfos and NARs that pass both checks are pushed to `out` (the
/// immutable copy set). Because this runs inside [`verify_surface`] — before
/// any byte is written — a failure aborts the sync with **nothing copied**.
///
/// The narinfo/NAR bytes that pass verification are **retained** in `retained`
/// keyed by their surface path, so the copy phase writes exactly the bytes that
/// were verified rather than re-fetching them (sec H-1): a re-fetch would let a
/// hostile upstream serve clean bytes during verification and poison during the
/// copy, and the post-copy re-index covers only the git surface, never the
/// narinfo/NAR class. Under `verify == false` (the operator's opt-out) bytes
/// are still retained when fetched, but the NAR is not fetched eagerly and the
/// copy phase falls back to a (best-effort, unverified) re-fetch.
///
/// The NAR path is additionally constrained to the conventional `nar/`
/// location (M2): an attacker-controlled `URL:` that steers elsewhere (e.g.
/// `info/refs`, a channel partition) is rejected, so only content-addressed
/// `nar/` payloads ever enter the immutable phase.
async fn collect_nix_cache(
    fetch: &dyn SurfaceFetch,
    tree: &crate::surface::load::LoadedTree,
    trusted: &[String],
    verify: bool,
    out: &mut Vec<String>,
    retained: &mut BTreeMap<String, Vec<u8>>,
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
                let Some(narinfo_bytes) = fetch.fetch(&narinfo_path).await? else {
                    continue;
                };
                let narinfo = std::str::from_utf8(&narinfo_bytes)
                    .with_context(|| format!("{narinfo_path} is not UTF-8"))?;

                if verify {
                    crate::validation::verify_narinfo_signature(narinfo, trusted)
                        .with_context(|| format!("verifying narinfo {narinfo_path}"))?;
                    // Bind the signed narinfo's `StorePath` hash to the `<hash>`
                    // we fetched it under (sec M-5). `verify_narinfo_signature`
                    // only attests that some trusted key signed the narinfo's own
                    // StorePath; it does not bind that store path to `{hash}`.
                    // Without this a hostile upstream serves a genuinely-signed
                    // narinfo for store hash HASHY at the path `HASHX.narinfo`,
                    // laundering HASHY's content into HASHX's binding slot — the
                    // signed fingerprint covers StorePath but the path it is
                    // served at is not part of any signature. Mirrors the
                    // pull-through NAR/Narinfo branches' requested-hash binding.
                    let parsed = aos_core::nar::info::parse(narinfo).with_context(|| {
                        format!("parsing narinfo {narinfo_path} for hash binding")
                    })?;
                    let declared_hash = aos_core::nar::info::store_hash(&parsed.store_path);
                    if declared_hash != hash {
                        bail!(
                            "narinfo {narinfo_path} declares StorePath {} (hash \
                             {declared_hash}), which does not match the requested \
                             store hash {hash}; refusing substitution",
                            parsed.store_path
                        );
                    }
                }

                out.push(narinfo_path.clone());

                // The NAR path is the narinfo's URL field (relative to root),
                // constrained to the conventional `nar/` location.
                if let Some(url) = narinfo_nar_url(narinfo) {
                    if verify {
                        let nar_bytes = fetch.fetch(&url).await?.with_context(|| {
                            format!("NAR {url} named by {narinfo_path} is missing upstream")
                        })?;
                        crate::validation::verify_nar_against_narinfo(narinfo, &nar_bytes)
                            .with_context(|| {
                                format!("verifying NAR {url} for narinfo {narinfo_path}")
                            })?;
                        // Retain the verified NAR bytes so the copy phase writes
                        // these exact bytes, not a re-fetched (poisonable) copy.
                        retained.insert(url.clone(), nar_bytes);
                    }
                    out.push(url);
                }

                // Retain the verified narinfo bytes for the copy phase too.
                retained.insert(narinfo_path, narinfo_bytes);
            }
        }
    }
    Ok(())
}

/// Extract the `URL:` field from narinfo text (the NAR's surface-relative
/// path), if present, relative, and under the conventional `nar/` location.
///
/// Constraining the path to a `nar/` prefix (M2) means a hostile upstream
/// cannot point the `URL:` at a pointer file (`info/refs`, `channels/**`) and
/// smuggle it into the immutable copy phase, breaking the immutable-first
/// write ordering. `safe_join` separately guards `..`; this prefix check is an
/// allow-list on top. An absolute or off-surface URL is skipped.
fn narinfo_nar_url(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("URL:") {
            let url = rest.trim();
            // Only mirror relative `nar/<hash>.nar.zst` paths; an absolute URL
            // points off-surface and anything outside `nar/` is not a
            // content-addressed NAR.
            if url.starts_with("nar/") && !url.contains("://") {
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
    // Containment (L1): mirror copies write into a local binding root the same
    // way the upload facade does. `safe_join` rejects `..`/absolute paths but
    // follows symlinks, so require the canonicalized write parent to stay under
    // the canonicalized root before writing — a binding-root component that is a
    // symlink out of the tree must not let a mirror copy land outside it.
    crate::fetch::ensure_within_root(root, &target).await?;
    write_atomic(&target, &bytes).await?;
    Ok(true)
}

/// Write already-verified `bytes` for a surface path under the local binding
/// root, applying the same containment guard as [`copy_path`] but **without
/// re-fetching** from upstream.
///
/// This is the H-1 fix: the narinfo/NAR class is written from the bytes
/// [`verify_surface`] verified, so the persisted bytes are provably the
/// verified bytes — a hostile upstream cannot serve clean bytes during
/// verification and poison during the copy.
///
/// Returns `true` (a file is always written; the caller only calls this for a
/// path whose bytes were retained).
///
/// # Errors
///
/// Returns an error when the write target escapes the binding root or the
/// atomic write fails.
async fn write_verified(root: &std::path::Path, path: &str, bytes: &[u8]) -> Result<bool> {
    let target = safe_join(root, path)?;
    crate::fetch::ensure_within_root(root, &target).await?;
    write_atomic(&target, bytes).await?;
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
    /// A `<hash>.narinfo` pointer: fetched fresh and served, but only after its
    /// `Sig:` verifies against the trust roster (M1). Never frozen — narinfos
    /// are pointers, re-fetched on each miss.
    Narinfo,
    /// A `nar/<…>` payload: fetched fresh and served, but only after the bytes
    /// verify against the corresponding (signature-verified) narinfo's
    /// FileHash/NarHash (M1). Never frozen.
    Nar,
    /// A payload that is content-addressed in principle but that the
    /// pull-through cache cannot verify before serving — release packs (whose
    /// checksum is in the pack trailer). Served live but **never frozen**, like
    /// a pointer, until hash verification exists.
    UnverifiableLive,
    /// A self-verifying pointer (`info/refs`, `HEAD`, `channels/**`,
    /// `nix-cache-info`): fetched fresh, served, never frozen.
    Pointer,
}

/// Classify a machine path for the pull-through cache.
///
/// Only loose git objects under `objects/<xx>/<62-hex>` are
/// [`PullClass::VerifiedObject`] — their path is their git oid, so the
/// inflated content can be hash-checked before persisting. A `<hash>.narinfo`
/// is a [`PullClass::Narinfo`] (signature-verified before serving) and a
/// `nar/<…>` payload is a [`PullClass::Nar`] (hash-verified against its narinfo
/// before serving). Release packs are content-addressed but not verifiable
/// here (the checksum is in the trailer), so they are
/// [`PullClass::UnverifiableLive`]: served but never persisted. Everything else
/// is a [`PullClass::Pointer`] fetched live.
///
/// The invariant: **no content-addressed payload is persisted into the local
/// cache without verifying its hash, and no narinfo/NAR is served through the
/// pull-through without verifying its signature/hash.**
fn pull_class(path: &str) -> PullClass {
    let is_loose_object = path
        .strip_prefix("objects/")
        .is_some_and(|rest| !rest.starts_with("info/") && rest.contains('/'));
    let is_nar = path.starts_with("nar/");
    let is_narinfo = path.ends_with(".narinfo") && !path.contains('/');
    let is_release_pack = path.starts_with("releases/") && path.contains("/objects/pack/");
    if is_loose_object {
        PullClass::VerifiedObject
    } else if is_narinfo {
        PullClass::Narinfo
    } else if is_nar {
        PullClass::Nar
    } else if is_release_pack {
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
/// being persisted. A narinfo's `Sig:` is verified against `trusted_keys`
/// before it is served; a NAR is verified against its (signature-verified)
/// narinfo's FileHash/NarHash before it is served — a tampered narinfo or NAR
/// is refused (error) rather than proxied, so the pull-through never propagates
/// poison even though it persists nothing (M1). Release packs cannot be
/// verified here (their checksum is in the trailer) and are served live but
/// never frozen. Pointers (`info/refs`, partition tags, `nix-cache-info`) are
/// likewise fetched live and returned without persisting, so the next request
/// re-fetches the current pointer.
///
/// When `verify` is false (the operator's documented opt-out), the narinfo/NAR
/// signature and hash checks are skipped and the bytes are served verbatim.
///
/// Returns `Ok(None)` when the upstream definitively lacks the path (404).
///
/// # Errors
///
/// Returns an error on a transport failure, an oid mismatch (a tampered loose
/// object), a narinfo with no valid trusted `Sig:`, a NAR whose bytes do not
/// match its narinfo, or a write failure. The server maps these to
/// `502 Bad Gateway` so poison is refused, not proxied.
pub async fn fetch_through(
    fetch: &dyn SurfaceFetch,
    root: &std::path::Path,
    path: &str,
    trusted_keys: &[String],
    verify: bool,
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
            // Containment (L1): same symlink-escape guard as the copy/upload
            // paths before persisting a pulled-through object into the cache.
            crate::fetch::ensure_within_root(root, &target).await?;
            write_atomic(&target, &bytes).await?;
            Ok(Some(PullResult {
                bytes,
                persisted: true,
            }))
        }
        PullClass::Narinfo => {
            // Verify the narinfo's Sig against the trust roster before serving.
            if verify {
                let text = std::str::from_utf8(&bytes)
                    .with_context(|| format!("pulled narinfo {path} is not UTF-8"))?;
                crate::validation::verify_narinfo_signature(text, trusted_keys)
                    .with_context(|| format!("verifying pulled narinfo {path}"))?;
                // Bind the served narinfo to the REQUESTED `<hash>.narinfo` path
                // (sec M-5): a valid-but-foreign signed narinfo (packageA's)
                // answering a request for `<hashB>.narinfo` is internally
                // consistent for A yet a substitution/downgrade for B. The
                // signature only attests A; without this binding a hostile
                // upstream could swap a request for one store path with a
                // trusted-signed-but-different (older, vulnerable) store path.
                assert_narinfo_matches_requested(path, text)?;
            }
            Ok(Some(PullResult {
                bytes,
                persisted: false,
            }))
        }
        PullClass::Nar => {
            // Fetch and signature-verify the narinfo that names this NAR, then
            // verify the NAR bytes against it. Without the narinfo we cannot
            // establish the NAR's expected hash, so we refuse rather than proxy.
            if verify {
                let (narinfo_path, requested_store_hash) =
                    narinfo_path_and_store_hash_for_nar(path).with_context(|| {
                        format!("cannot derive narinfo path for pulled NAR {path}")
                    })?;
                let narinfo_bytes = fetch.fetch(&narinfo_path).await?.with_context(|| {
                    format!("narinfo {narinfo_path} for pulled NAR {path} is missing upstream")
                })?;
                let narinfo = std::str::from_utf8(&narinfo_bytes)
                    .with_context(|| format!("narinfo {narinfo_path} is not UTF-8"))?;
                crate::validation::verify_narinfo_signature(narinfo, trusted_keys)
                    .with_context(|| format!("verifying narinfo {narinfo_path} for NAR {path}"))?;
                // Bind the governing narinfo to the requested store hash AND the
                // requested NAR path (sec M-5). Two independent bindings, because
                // the signed fingerprint covers StorePath/NarHash/NarSize/
                // References but NOT the `URL:` field — `URL:` is unsigned and
                // attacker-malleable.
                //
                // 1. StorePath binding: the narinfo's signed `StorePath` hash
                //    MUST equal the `<store-hash>` named by the requested
                //    `nar/<store-hash>-...` path. Without it a hostile upstream
                //    takes packageA's genuinely-signed narinfo (store hash
                //    HASHY), rewrites only its unsigned `URL:` to
                //    `nar/HASHX-...`, and serves it at `HASHX.narinfo`; the
                //    signature still verifies (it attests A) and the URL binding
                //    below still passes (URL: == requested), so A's content is
                //    served under HASHX. This check makes the served NAR
                //    *provably* belong to the requested store hash — matching the
                //    sibling Narinfo branch's `assert_narinfo_matches_requested`.
                // 2. URL binding: a request for `nar/X` is only answered with the
                //    NAR its narinfo's `URL:` actually names, so a trusted-signed
                //    but different NAR (`nar/Y`) cannot be served under `nar/X`.
                assert_nar_store_hash_matches_requested(path, narinfo, requested_store_hash)?;
                assert_nar_matches_requested(path, narinfo)?;
                crate::validation::verify_nar_against_narinfo(narinfo, &bytes)
                    .with_context(|| format!("verifying pulled NAR {path}"))?;
            }
            Ok(Some(PullResult {
                bytes,
                persisted: false,
            }))
        }
        // Release packs and pointers are served live but never frozen, because
        // their content hash cannot be verified before persisting.
        PullClass::UnverifiableLive | PullClass::Pointer => Ok(Some(PullResult {
            bytes,
            persisted: false,
        })),
    }
}

/// Assert that a signature-verified narinfo's `StorePath` hash equals the
/// `<hash>` named by the requested `<hash>.narinfo` path (sec M-5).
///
/// `verify_narinfo_signature` only attests that *some* trusted key signed the
/// narinfo's own `StorePath`; it does not bind that store path to the path the
/// client asked for. A hostile upstream can therefore answer a request for
/// `<hashB>.narinfo` with packageA's genuinely-signed narinfo — a
/// substitution/downgrade to an older, signed-but-vulnerable build. Stock Nix
/// enforces this binding; the pull-through must too.
///
/// # Errors
///
/// Returns an error when `path` is not a `<hash>.narinfo` path, the narinfo
/// cannot be parsed, or the store hash derived from its `StorePath` does not
/// equal the requested hash.
fn assert_narinfo_matches_requested(path: &str, narinfo: &str) -> Result<()> {
    let requested = path
        .strip_suffix(".narinfo")
        .with_context(|| format!("narinfo path {path} does not end in .narinfo"))?;
    let info = aos_core::nar::info::parse(narinfo)
        .with_context(|| format!("parsing pulled narinfo {path} for hash binding"))?;
    let store_hash = aos_core::nar::info::store_hash(&info.store_path);
    if store_hash != requested {
        bail!(
            "pulled narinfo {path} declares StorePath {} (hash {store_hash}), \
             which does not match the requested hash {requested}; refusing \
             substitution",
            info.store_path
        );
    }
    Ok(())
}

/// Assert that the governing narinfo's `URL:` field names exactly the requested
/// NAR `path` (sec M-5).
///
/// A request for `nar/X` must only be answered with the NAR its narinfo points
/// at. Without this check a hostile upstream could serve a trusted-signed but
/// *different* NAR (`nar/Y`) under the name `nar/X` — a substitution/downgrade
/// of the served bytes. The narinfo is `<store-hash>.narinfo` (derived from the
/// requested path), so matching its `URL:` binds the served NAR to the
/// requested store hash.
///
/// # Errors
///
/// Returns an error when the narinfo cannot be parsed or its `URL:` does not
/// equal the requested NAR path (after stripping any leading `/`).
fn assert_nar_matches_requested(path: &str, narinfo: &str) -> Result<()> {
    let info = aos_core::nar::info::parse(narinfo)
        .with_context(|| format!("parsing governing narinfo for NAR {path}"))?;
    let declared = info.url.trim_start_matches('/');
    if declared != path {
        bail!(
            "governing narinfo for NAR {path} declares URL {}, which does not \
             match the requested NAR path; refusing substitution",
            info.url
        );
    }
    Ok(())
}

/// Assert that the governing narinfo's signed `StorePath` hash equals the
/// `<store-hash>` named by the requested `nar/<store-hash>-<…>` NAR path (sec
/// M-5).
///
/// This is the NAR-branch counterpart to [`assert_narinfo_matches_requested`].
/// The signed narinfo fingerprint covers `StorePath` (among NarHash, NarSize,
/// References) but **not** the unsigned, attacker-malleable `URL:` field — so
/// the `URL:` binding in [`assert_nar_matches_requested`] alone does not prove
/// the served NAR belongs to the requested store hash. A hostile upstream can
/// take a genuinely trusted-signed narinfo for store hash `HASHY`, rewrite only
/// its `URL:` to `nar/HASHX-…`, and serve it at `HASHX.narinfo`: the signature
/// verifies (it attests `HASHY`) and the `URL:` matches the request, yet
/// `HASHY`'s content is served under `HASHX`. Binding the signed `StorePath`
/// hash to the requested `<store-hash>` closes that substitution.
///
/// # Errors
///
/// Returns an error when the narinfo cannot be parsed, or when the store hash
/// derived from its signed `StorePath` does not equal `requested_store_hash`.
fn assert_nar_store_hash_matches_requested(
    path: &str,
    narinfo: &str,
    requested_store_hash: &str,
) -> Result<()> {
    let info = aos_core::nar::info::parse(narinfo)
        .with_context(|| format!("parsing governing narinfo for NAR {path} for hash binding"))?;
    let store_hash = aos_core::nar::info::store_hash(&info.store_path);
    if store_hash != requested_store_hash {
        bail!(
            "governing narinfo for NAR {path} declares StorePath {} (hash \
             {store_hash}), which does not match the requested store hash \
             {requested_store_hash}; refusing substitution",
            info.store_path
        );
    }
    Ok(())
}

/// Derive both the `<hash>.narinfo` path and the `<store-hash>` component for a
/// `nar/<store-hash>-<…>` NAR path.
///
/// The static-cache NAR URL is `nar/<store-hash>-<file-hash>.<ext>` (see
/// `aos_core::nar::cache::nar_url`), so the store hash is the basename segment
/// before the first `-`, and its narinfo lives at `<store-hash>.narinfo` at the
/// surface root. The pull-through NAR branch needs the bare `<store-hash>` (not
/// just the derived narinfo path) so it can bind the governing narinfo's signed
/// `StorePath` hash back to the hash the client asked for via
/// [`assert_nar_store_hash_matches_requested`] — the `URL:` field that names the
/// narinfo cannot be relied on for that binding because it is unsigned. Returns
/// `None` for a path that does not fit the `nar/<store-hash>-<…>` shape.
fn narinfo_path_and_store_hash_for_nar(nar_path: &str) -> Option<(String, &str)> {
    let name = nar_path.strip_prefix("nar/")?;
    let (store_hash, _) = name.split_once('-')?;
    if store_hash.is_empty() {
        return None;
    }
    Some((format!("{store_hash}.narinfo"), store_hash))
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
        // A narinfo is signature-verified before serving; a NAR is hash-
        // verified against its narinfo before serving.
        assert_eq!(pull_class("abc.narinfo"), PullClass::Narinfo);
        assert_eq!(pull_class("nar/x.nar.zst"), PullClass::Nar);
        // Release packs are content-addressed but unverifiable here: served
        // live, never persisted.
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
        ] {
            assert_eq!(pull_class(pointer), PullClass::Pointer, "{pointer}");
        }
    }

    /// Write a loose object to `root` and return its oid.
    #[cfg(test)]
    fn put_loose(root: &std::path::Path, kind: ObjectKind, content: &[u8]) -> Oid {
        use crate::surface::object::{encode_loose, hash_object};
        let oid = hash_object(kind, content);
        let path = root.join(oid.loose_path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, encode_loose(kind, content).unwrap()).unwrap();
        oid
    }

    #[tokio::test]
    async fn collect_tree_objects_aborts_over_the_cap() {
        // L-2: a tree closure that exceeds the object cap aborts with the
        // over-limit error rather than accumulating without bound. A closure
        // that fits is collected fine.
        use crate::fetch::LocalFsFetch;
        use crate::surface::object::{encode_tree, TreeEntry};

        let upstream = tempfile::tempdir().unwrap();
        let root = upstream.path();

        // Six distinct blobs under one tree => 1 tree + 6 blobs = 7 oids.
        let mut entries = Vec::new();
        for i in 0u8..6 {
            let blob = put_loose(root, ObjectKind::Blob, &[b'x', i]);
            entries.push(TreeEntry {
                mode: "100644".to_string(),
                name: format!("f{i}"),
                oid: blob,
            });
        }
        let tree_bytes = encode_tree(&entries);
        let tree_oid = put_loose(root, ObjectKind::Tree, &tree_bytes);

        let fetch = LocalFsFetch::new(root);
        let reader = ObjectReader::new(&fetch);

        // A generous cap collects every object (1 tree + 6 blobs).
        let mut all = BTreeSet::new();
        collect_tree_objects_capped(&reader, tree_oid, &mut all, 100)
            .await
            .expect("a closure under the cap is collected");
        assert_eq!(all.len(), 7, "tree + six blobs");

        // A cap of 3 aborts before the whole closure is walked.
        let mut capped = BTreeSet::new();
        let err = collect_tree_objects_capped(&reader, tree_oid, &mut capped, 3)
            .await
            .expect_err("a closure over the cap aborts");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("mirror cap") && msg.contains("aborting sync"),
            "abort should cite the cap, got: {msg}"
        );
    }

    #[tokio::test]
    async fn pack_payloads_are_served_but_never_persisted() {
        use crate::fetch::LocalFsFetch;

        // An upstream surface carrying a release pack.
        let upstream = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(upstream.path().join("releases/1/0/0/objects/pack")).unwrap();
        std::fs::write(
            upstream.path().join("releases/1/0/0/objects/pack/p.pack"),
            b"upstream-pack-bytes",
        )
        .unwrap();

        let local = tempfile::tempdir().unwrap();
        let fetch = LocalFsFetch::new(upstream.path());

        let path = "releases/1/0/0/objects/pack/p.pack";
        let result = fetch_through(&fetch, local.path(), path, &[], true)
            .await
            .unwrap()
            .unwrap();
        // The bytes are served...
        assert_eq!(result.bytes, b"upstream-pack-bytes", "{path} served");
        // ...but the payload is never frozen into the local cache, so a
        // tampered upstream payload cannot poison it.
        assert!(!result.persisted, "{path} must not be persisted");
        assert!(
            !local.path().join(path).exists(),
            "{path} must not be written to the local binding"
        );
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
    fn extracts_relative_nar_url_under_nar_prefix() {
        let info = "StorePath: /s/abc\nURL: nar/abc.nar.zst\nCompression: zstd\n";
        assert_eq!(narinfo_nar_url(info).as_deref(), Some("nar/abc.nar.zst"));
        // Absolute URLs point off-surface and are skipped.
        let abs = "URL: https://other/nar/abc.nar.zst\n";
        assert!(narinfo_nar_url(abs).is_none());
        // A URL outside `nar/` (an attacker steering at a pointer file) is
        // rejected (M2), so it can never enter the immutable copy phase.
        let outside = "URL: info/refs\n";
        assert!(narinfo_nar_url(outside).is_none());
        let channel = "URL: channels/stable/00\n";
        assert!(narinfo_nar_url(channel).is_none());
    }

    #[test]
    fn derives_narinfo_path_and_store_hash_for_nar() {
        // The NAR branch needs the bare `<store-hash>` to bind it to the
        // narinfo's signed StorePath. The store hash is the segment before the
        // first `-` in the basename.
        let (narinfo_path, store_hash) =
            narinfo_path_and_store_hash_for_nar("nar/abc123-sha256-def.nar.zst").unwrap();
        assert_eq!(narinfo_path, "abc123.narinfo");
        assert_eq!(store_hash, "abc123");
        assert!(narinfo_path_and_store_hash_for_nar("nar/nodash.nar").is_none());
    }

    #[test]
    fn nar_store_hash_binding_rejects_url_only_substitution() {
        // FINDING #4 regression (sec M-5): the signed narinfo fingerprint covers
        // StorePath/NarHash/NarSize/References but NOT the `URL:` field. A hostile
        // upstream takes a genuinely trusted-signed narinfo for store hash HASHY
        // and rewrites only its (unsigned) `URL:` to `nar/HASHX-...`, serving it
        // at `HASHX.narinfo`. The signature still verifies (it attests HASHY) and
        // the URL binding (`assert_nar_matches_requested`) still passes (URL: ==
        // requested), so without a StorePath-hash binding HASHY's content is
        // served under HASHX. `assert_nar_store_hash_matches_requested` is what
        // refuses that substitution.
        let requested_nar = "nar/HASHX-sha256-deadbeef.nar.zst";
        let (_narinfo_path, requested_store_hash) =
            narinfo_path_and_store_hash_for_nar(requested_nar).unwrap();
        assert_eq!(requested_store_hash, "HASHX");

        // A foreign-but-genuine narinfo: signed StorePath is HASHY, but its
        // (unsigned) URL has been rewritten to point at the requested HASHX NAR.
        let foreign = "StorePath: /nix/store/HASHY-pkg-1.0\n\
                       URL: nar/HASHX-sha256-deadbeef.nar.zst\n\
                       NarHash: sha256:abc\nNarSize: 1\nReferences: \n";
        // The URL binding passes — URL: matches the requested NAR path exactly,
        // which is precisely why it is insufficient on its own.
        assert_nar_matches_requested(requested_nar, foreign)
            .expect("URL binding passes for a URL-only substitution");
        // The StorePath-hash binding catches it: HASHY != requested HASHX.
        let err =
            assert_nar_store_hash_matches_requested(requested_nar, foreign, requested_store_hash)
                .expect_err("store-hash binding rejects the cross-hash substitution");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("HASHY") && msg.contains("HASHX") && msg.contains("refusing substitution"),
            "error should cite both hashes and refuse, got: {msg}"
        );

        // The honest case: narinfo's StorePath hash equals the requested hash.
        let honest = "StorePath: /nix/store/HASHX-pkg-1.0\n\
                      URL: nar/HASHX-sha256-deadbeef.nar.zst\n\
                      NarHash: sha256:abc\nNarSize: 1\nReferences: \n";
        assert_nar_store_hash_matches_requested(requested_nar, honest, requested_store_hash)
            .expect("matching store hash is accepted");
    }
}
