//! Read-only admission checks for the exact release pointers held by a stage.
//!
//! Candidate validation authenticates the proposed immutable release before
//! public refs become visible. It also proves that publication preserves every
//! existing release and channel frontier; channel assignment is a separate
//! signed operation.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, ensure};
use aos_registry_surface::keymap;
use aos_registry_surface::object::{self, ObjectKind, Oid};
use aos_registry_surface::pack_index;
use aos_registry_surface::refs::{parse_head, parse_info_refs};
use aos_registry_surface::staging::StageRevision;
use aos_registry_surface::tag::verify_signed_tag;
use aos_registry_surface::tagobject::TagTarget;
use sha2::{Digest as _, Sha256};

use super::load::{ObjectReader, load_release_tree_with_reader};
use crate::db::{Database, RegistryRecord};
use crate::fetch::SurfaceFetch;

/// Caps unsigned mutable listings and pointer preconditions before allocation.
const MAX_POINTER_BYTES: usize = 8 * 1024 * 1024;

/// Authenticates a staged release and preserves existing public distribution pointers.
///
/// This performs no index writes and never installs pointers. The publication
/// transaction still compares the captured pointer hashes before installation.
///
/// # Errors
/// Returns an error for changed pointer preconditions, an altered existing tag
/// or channel/default frontier, an untrusted release signature, a mismatched
/// candidate commit, a malformed committed catalog, or unavailable release packs.
pub(crate) async fn validate_candidate(
    db: &Database,
    surface: &dyn SurfaceFetch,
    registry: &RegistryRecord,
    revision: &StageRevision,
) -> Result<()> {
    revision.validate()?;
    ensure!(
        revision.registry == registry.slug,
        "stage registry identity does not match"
    );

    let release_version = semver::Version::parse(&revision.release_id)?;
    let release_directory = format!(
        "releases/{}/{}/{}",
        release_version.major,
        release_version.minor,
        revision
            .release_id
            .splitn(3, '.')
            .nth(2)
            .context("release patch is absent")?,
    );
    let candidate_packs_path = format!("{release_directory}/objects/info/packs");
    let mut prepared = BTreeMap::new();
    for pointer in &revision.publication {
        ensure!(
            !pointer.path.starts_with("channels/"),
            "stage publication cannot assign channel partitions"
        );
        ensure!(
            pointer.bytes.len() <= MAX_POINTER_BYTES,
            "prepared stage pointer exceeds its byte limit"
        );
        // The service compares physical predecessors under its publication lease.
        // Its candidate fetcher overlays held Git encodings for semantic reads,
        // so those paths must be authenticated rather than read as predecessors.
        let encoded_object = keymap::is_loose_git_object_path(&pointer.path);
        let pack_index_object = keymap::is_git_pack_index_path(&pointer.path);
        let current = if encoded_object || pack_index_object {
            None
        } else {
            surface
                .fetch_bounded(&pointer.path, MAX_POINTER_BYTES)
                .await?
        };
        if !encoded_object && !pack_index_object {
            let current_hash = current
                .as_ref()
                .map(|bytes| format!("sha256:{}", hex::encode(Sha256::digest(bytes))));
            ensure!(
                current_hash == pointer.expected_sha256,
                "stage publication pointer '{}' changed since preparation",
                pointer.path
            );
        }

        if encoded_object {
            let oid = pointer
                .path
                .strip_prefix("objects/")
                .context("invalid staged loose object path")?
                .replace('/', "");
            object::decode_loose(&pointer.bytes, Some(Oid::from_hex(&oid)?))?;
        } else if pack_index_object {
            let pack_path = pack_index::companion_pack_path(&pointer.path)
                .context("invalid staged pack index path")?;
            ensure!(
                revision
                    .inventory
                    .iter()
                    .any(|object| object.path == pack_path),
                "staged pack index has no verified companion pack"
            );
            let pack = surface
                .fetch_bounded(
                    &pack_path,
                    usize::try_from(pack_index::MAX_PUBLISHED_PACK_BYTES)?,
                )
                .await?
                .context("staged companion pack is unavailable")?;
            pack_index::validate_against_pack(&pointer.path, &pointer.bytes, &pack)?;
        } else if pointer.path == "HEAD" {
            ensure!(
                current.as_deref() == Some(pointer.bytes.as_slice()),
                "stage publication must preserve the default channel HEAD"
            );
        } else if matches!(
            pointer.path.as_str(),
            "objects/info/packs" | "objects/info/alternates"
        ) || pointer.path == candidate_packs_path
        {
            preserve_listing_entries(current.as_deref(), &pointer.bytes)?;
            if pointer.path == "objects/info/packs" {
                let old_entries = current
                    .as_deref()
                    .map(std::str::from_utf8)
                    .transpose()?
                    .unwrap_or_default()
                    .lines()
                    .collect::<std::collections::BTreeSet<_>>();
                for line in std::str::from_utf8(&pointer.bytes)?
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                {
                    if old_entries.contains(line) {
                        continue;
                    }
                    let name = line
                        .strip_prefix("P ")
                        .context("malformed root pack listing")?;
                    let key = format!("objects/pack/{name}");
                    ensure!(
                        keymap::is_git_pack_path(&key)
                            && revision.inventory.iter().any(|object| object.path == key),
                        "root pack listing introduces an unverified pack"
                    );
                }
            }
            if pointer.path == "objects/info/alternates" {
                let candidate = format!("../{release_directory}/objects/");
                let old_entries = current
                    .as_deref()
                    .map(std::str::from_utf8)
                    .transpose()?
                    .unwrap_or_default()
                    .lines()
                    .collect::<std::collections::BTreeSet<_>>();
                for line in std::str::from_utf8(&pointer.bytes)?.lines() {
                    ensure!(
                        old_entries.contains(line) || line == candidate,
                        "stage publication introduces an unrelated Git alternate"
                    );
                }
            }
        } else if !matches!(pointer.path.as_str(), "info/refs" | "tuf/timestamp.json") {
            ensure!(
                current.as_deref() == Some(pointer.bytes.as_slice()),
                "stage publication changes an unrelated pointer '{}'",
                pointer.path
            );
        }
        prepared.insert(pointer.path.as_str(), pointer.bytes.as_slice());
    }

    let proposed_refs = prepared
        .get("info/refs")
        .context("stage has no prepared release refs")?;
    let proposed_refs = parse_info_refs(std::str::from_utf8(proposed_refs)?)?;
    super::validate_ref_cardinality(&proposed_refs)?;
    let current_refs = surface
        .fetch_bounded("info/refs", MAX_POINTER_BYTES)
        .await?
        .map(|bytes| parse_info_refs(std::str::from_utf8(&bytes)?))
        .transpose()?
        .unwrap_or_default();
    for name in proposed_refs.tags.keys() {
        ensure!(
            current_refs.tags.contains_key(name) || name == &revision.release_id,
            "stage publication introduces unrelated release tag '{name}'"
        );
    }
    for (name, oid) in &current_refs.tags {
        ensure!(
            proposed_refs.tags.get(name) == Some(oid),
            "stage publication changes existing release tag '{name}'"
        );
    }
    for (name, oid) in &current_refs.branches {
        if name != &revision.source_branch {
            ensure!(
                proposed_refs.branches.get(name) == Some(oid),
                "stage publication changes channel or unrelated branch '{name}'"
            );
        }
    }
    for name in proposed_refs.branches.keys() {
        ensure!(
            current_refs.branches.contains_key(name) || name == &revision.source_branch,
            "stage publication introduces unrelated branch '{name}'"
        );
    }

    if let Some(head) = surface.fetch_bounded("HEAD", 4096).await? {
        if let Some(default) = parse_head(std::str::from_utf8(&head)?) {
            ensure!(
                default != revision.source_branch,
                "stage source branch cannot be the reserved default channel"
            );
        }
    }

    // An existing non-default channel is reserved too. Probe the complete
    // bounded namespace because a partially rolled out channel may occupy any
    // partition; its authoring branch must never become a mutable workspace.
    let buckets = (0u16..=255).collect::<Vec<_>>();
    for batch in buckets.chunks(super::CHANNEL_FETCH_CONCURRENCY) {
        let published = futures_util::future::try_join_all(batch.iter().map(|bucket| {
            let path = format!("channels/{}/{bucket:02x}", revision.source_branch);
            async move {
                Ok::<_, anyhow::Error>(surface.fetch_bounded(&path, 256 * 1024).await?.is_some())
            }
        }))
        .await?;
        ensure!(
            !published.into_iter().any(|present| present),
            "stage source branch cannot be a published channel frontier"
        );
    }

    let tag_oid = proposed_refs
        .tags
        .get(&revision.release_id)
        .context("prepared refs omit the staged release tag")?;
    let reader = ObjectReader::new(surface);
    let payload = reader.read_kind(*tag_oid, ObjectKind::Tag).await?;
    let mut trusted = registry.trust_keys.clone();
    super::append_signing_usage_key(
        db,
        &mut trusted,
        &registry.stable_id,
        "registry_publication",
    )
    .await?;
    for (_id, key, state) in db.list_roster(registry.id).await? {
        if state == "active" && !key.is_empty() && !trusted.contains(&key) {
            trusted.push(key);
        }
    }
    let tag = verify_signed_tag(&payload, &revision.release_id, &trusted)?;
    ensure!(
        tag.tag.target_type == TagTarget::Commit,
        "staged release tag does not target a commit"
    );
    ensure!(
        tag.tag.object == revision.commit,
        "staged release tag targets another candidate commit"
    );
    let candidate_tree =
        load_release_tree_with_reader(&reader, Oid::from_hex(&revision.commit)?).await?;
    match (&revision.container, &candidate_tree.container_release) {
        (Some(container), Some(committed)) => ensure!(
            container.release == committed.document,
            "staged container graph differs from the signed committed catalog"
        ),
        (None, None) => {}
        _ => anyhow::bail!("staged container graph and signed committed catalog disagree"),
    }

    let packs_path = candidate_packs_path;
    let packs = match prepared.get(packs_path.as_str()) {
        Some(bytes) => Some(bytes.to_vec()),
        None => {
            surface
                .fetch_bounded(&packs_path, MAX_POINTER_BYTES)
                .await?
        }
    };
    let packs = packs.context("staged release pack listing is unavailable")?;
    let packs = std::str::from_utf8(&packs)?;
    let mut found_pack = false;
    for line in packs.lines().filter(|line| !line.trim().is_empty()) {
        let name = line
            .strip_prefix("P ")
            .context("malformed staged release pack listing")?;
        let hash = name
            .strip_prefix("pack-")
            .and_then(|name| name.strip_suffix(".pack"))
            .context("invalid staged release pack name")?;
        ensure!(
            matches!(hash.len(), 40 | 64) && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid staged release pack identity"
        );
        let key = format!("{release_directory}/objects/pack/{name}");
        ensure!(
            revision.inventory.iter().any(|object| object.path == key),
            "staged release pack is absent from its verified inventory"
        );
        found_pack = true;
    }
    ensure!(found_pack, "staged release has no release pack");
    Ok(())
}

/// Preserves the availability of already advertised Git transport objects.
fn preserve_listing_entries(current: Option<&[u8]>, proposed: &[u8]) -> Result<()> {
    let proposed = std::str::from_utf8(proposed)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<std::collections::BTreeSet<_>>();
    if let Some(current) = current {
        for line in std::str::from_utf8(current)?
            .lines()
            .filter(|line| !line.trim().is_empty())
        {
            ensure!(
                proposed.contains(line),
                "stage publication removes an existing Git transport entry"
            );
        }
    }
    Ok(())
}
