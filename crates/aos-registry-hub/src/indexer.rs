//! Fetch → verify → load → index orchestration.
//!
//! [`index_registry`] re-walks one registry surface exactly as an `apm`
//! client would and replaces its rebuildable index atomically:
//!
//! 1. Fetch `HEAD` + `info/refs` and pick the default branch's commit.
//! 2. Read the commit loose object; with `require_signatures`, verify its
//!    `gpgsig` SSH signature against the registry's pinned trust anchors
//!    (fail closed — an unverifiable surface is never displayed as fresh).
//! 3. Load the committed tree (`registry.toml`, `keys.toml`, packages,
//!    closures) and extend the trusted set with the verified roster's
//!    active keys, mirroring `apm`'s in-band rotation semantics.
//! 4. Verify every semver release tag (signature + name binding).
//! 5. Resolve every channel (branch) by probing all 256 partition
//!    payloads, verifying each, and mapping its target tag object to a
//!    release.
//! 6. Write the snapshot in one transaction; on any failure, record
//!    `failed` state and keep the last good index.

use anyhow::{bail, Context, Result};
use aos_package::registry::verify::TagTarget;

use crate::db::{ChannelSummary, Database, IndexSnapshot, RegistryRecord, ReleaseRow};
use crate::fetch::SurfaceFetch;
use crate::surface::load::{load_registry_tree, ObjectReader};
use crate::surface::object::ObjectKind;
use crate::surface::refs::{parse_head, parse_info_refs};
use crate::surface::sshsig;
use crate::surface::tag::{parse_signed_tag, verify_signed_tag};

/// Outcome of one indexing run.
#[derive(Debug)]
pub struct IndexOutcome {
    /// The commit the index was built from.
    pub commit: String,
    /// Number of packages indexed.
    pub packages: usize,
    /// Number of verified releases.
    pub releases: usize,
    /// Number of channels resolved.
    pub channels: usize,
}

/// Index one registered registry, recording failure state on error.
///
/// This is the entry point callers should use: it wraps [`index_registry`]
/// so that any failure is persisted as the registry's `failed` index state
/// (with the error text) instead of being lost with the returned error.
///
/// # Errors
///
/// Returns the indexing error after recording it.
pub async fn index_and_record(
    db: &Database,
    fetch: &dyn SurfaceFetch,
    registry: &RegistryRecord,
) -> Result<IndexOutcome> {
    match index_registry(db, fetch, registry).await {
        Ok(outcome) => Ok(outcome),
        Err(err) => {
            db.mark_index_failed(registry.id, &format!("{err:#}"))?;
            Err(err)
        }
    }
}

/// Index one registered registry surface into the database.
///
/// # Errors
///
/// Returns an error when the surface is unreachable, malformed, or — with
/// `require_signatures` — fails any signature or name-binding check.
pub async fn index_registry(
    db: &Database,
    fetch: &dyn SurfaceFetch,
    registry: &RegistryRecord,
) -> Result<IndexOutcome> {
    let refs_bytes = fetch
        .fetch("info/refs")
        .await?
        .with_context(|| format!("{}: info/refs not found", fetch.describe()))?;
    let refs = parse_info_refs(std::str::from_utf8(&refs_bytes).context("info/refs not UTF-8")?)?;

    let head = match fetch.fetch("HEAD").await? {
        Some(bytes) => parse_head(&String::from_utf8_lossy(&bytes)),
        None => None,
    };
    let (default_branch, commit_oid) =
        match head.and_then(|name| refs.branches.get(&name).copied().map(|oid| (name, oid))) {
            Some(found) => found,
            None => refs
                .branches
                .iter()
                .next()
                .map(|(name, oid)| (name.clone(), *oid))
                .context("surface advertises no branches")?,
        };
    tracing::debug!(branch = %default_branch, commit = %commit_oid, "indexing from");

    let reader = ObjectReader::new(fetch);
    let commit = reader.read_commit(commit_oid).await?;
    let mut trusted: Vec<String> = registry.trust_keys.clone();
    if registry.require_signatures {
        let signature = commit
            .signature
            .as_ref()
            .with_context(|| format!("commit {commit_oid} is unsigned"))?;
        sshsig::verify_armored(signature, &commit.signed_payload, &trusted)
            .with_context(|| format!("verifying commit {commit_oid}"))?;
    }

    let tree = load_registry_tree(fetch, commit_oid).await?;

    // In-band rotation: the roster committed by a verified commit extends
    // the trusted set for tag verification (apm pins these on sync).
    let mut roster_rows = Vec::new();
    if let Some(keys) = &tree.keys {
        for key in &keys.active {
            roster_rows.push((key.id.clone(), key.key.clone(), "active".to_string()));
            if !trusted.contains(&key.key) {
                trusted.push(key.key.clone());
            }
        }
        for revoked in &keys.revoked {
            roster_rows.push((revoked.id.clone(), String::new(), "revoked".to_string()));
        }
    }

    // Releases: every semver tag, verified (signature + name binding) and
    // resolved to its commit.
    let mut releases = Vec::new();
    for (tag_name, tag_oid) in &refs.tags {
        if semver::Version::parse(tag_name).is_err() {
            continue;
        }
        let payload = reader.read_kind(*tag_oid, ObjectKind::Tag).await?;
        let (signed, signer) = if registry.require_signatures {
            let signed = verify_signed_tag(&payload, tag_name, &trusted)
                .with_context(|| format!("release tag '{tag_name}'"))?;
            let signer = parse_signed_tag(&payload)
                .ok()
                .map(|s| sshsig_signer(&s.signature));
            (signed, signer.flatten())
        } else {
            (lenient_tag(&payload, tag_name)?, None)
        };
        if signed.tag.target_type != TagTarget::Commit {
            bail!("release tag '{tag_name}' does not target a commit");
        }
        releases.push(ReleaseRow {
            semver: tag_name.clone(),
            tag_oid: tag_oid.to_hex(),
            commit_oid: signed.tag.object.clone(),
            signer,
            tagged_at: signed.tag.tagger_when,
        });
    }

    // Channels: branches are channel names; each resolves through 256
    // partition payloads pointing at release tag objects.
    let mut channels = Vec::new();
    for channel_name in refs.branches.keys() {
        let mut partitions: Vec<Option<String>> = vec![None; 256];
        let mut frontier: Option<semver::Version> = None;
        let mut present = false;
        for bucket in 0u16..=255 {
            let path = format!("channels/{channel_name}/{bucket:02x}");
            let Some(payload) = fetch.fetch(&path).await? else {
                continue;
            };
            present = true;
            let signed = if registry.require_signatures {
                verify_signed_tag(&payload, channel_name, &trusted)
                    .with_context(|| format!("partition {path}"))?
            } else {
                lenient_tag(&payload, channel_name)?
            };
            if signed.tag.target_type != TagTarget::Tag {
                bail!("partition {path} does not target a tag object");
            }
            let release = releases
                .iter()
                .find(|r| r.tag_oid == signed.tag.object)
                .with_context(|| {
                    format!(
                        "partition {path} targets unknown tag object {}",
                        signed.tag.object
                    )
                })?;
            partitions[bucket as usize] = Some(release.semver.clone());
            if let Ok(version) = semver::Version::parse(&release.semver) {
                if frontier.as_ref().is_none_or(|f| version > *f) {
                    frontier = Some(version);
                }
            }
        }
        if present {
            channels.push(ChannelSummary {
                name: channel_name.clone(),
                frontier: frontier.map(|v| v.to_string()),
                partitions,
            });
        }
    }

    let snapshot = IndexSnapshot {
        commit: commit_oid.to_hex(),
        name: tree.root.registry.name.clone(),
        description: tree.root.registry.description.clone(),
        caches: tree
            .root
            .caches
            .iter()
            .map(|c| (c.url.clone(), c.priority))
            .collect(),
        roster: roster_rows,
        packages: tree.packages,
        releases,
        channels,
    };
    let outcome = IndexOutcome {
        commit: snapshot.commit.clone(),
        packages: snapshot.packages.len(),
        releases: snapshot.releases.len(),
        channels: snapshot.channels.len(),
    };
    db.apply_snapshot(registry.id, &snapshot)?;
    Ok(outcome)
}

/// Parse a tag payload without verification (`require_signatures = false`),
/// still enforcing name binding so even unverified display stays
/// path-consistent.
fn lenient_tag(payload: &[u8], expected_name: &str) -> Result<crate::surface::tag::SignedTag> {
    let signed = parse_signed_tag(payload)?;
    aos_package::registry::verify::verify_name_binding(&signed.tag, expected_name)?;
    Ok(signed)
}

/// Extract the signer's base64 key from an armored signature, when parseable.
fn sshsig_signer(armored: &str) -> Option<String> {
    sshsig::parse_armored(armored)
        .ok()
        .map(|s| s.public_key_base64())
}
