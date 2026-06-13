//! Hub-side signing for hosted-key registries (RFC-0004 "hosted keys").
//!
//! Signing is client-side by default: the hub holds no private key and a web
//! edit only records a *prepared* operation a maintainer signs locally. When
//! an org opts a registry into a [hosted key](crate::db::HostedKeyRecord),
//! the hub may instead sign directly — advancing channels and re-signing tags
//! from the web — using the same wire format and verification path every
//! client uses, so the hub's output is indistinguishable to the indexer from a
//! maintainer's.
//!
//! The correctness invariant: everything this module emits is consumed by the
//! *same* reader that verifies a client's bytes
//! ([`crate::surface::tag::verify_signed_tag`] over the registry's pinned trust
//! anchors). A release tag object is signed bytes wrapped as a loose `tag`
//! object; a channel partition is the raw signed tag payload written under
//! `channels/<name>/<bucket-hex>`:
//!
//! ```text
//! release tag  objects/<oid>   = zlib( b"tag <n>\0" + render_tag_payload(semver, commit, "commit") + SSHSIG )
//! partition    channels/<ch>/<bb> = render_tag_payload(<ch>, <release-tag-oid>, "tag") + SSHSIG
//! ```
//!
//! For the hub's signatures to verify, the hosted key's public trusted-key
//! line **must be a trust anchor of the registry** (pinned `trust_keys`, or an
//! active roster key). [`advance_channel`] and [`resign_tag`] sign with the
//! hosted key; pinning it is an enrollment-time concern
//! ([`crate::db::Database::create_hosted_key`] returns the line to pin).

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::auth::oidc::SecretSealer;
use crate::db::{Database, RegistryRecord};
use crate::fetch::{safe_join, LocalFsFetch};
use crate::surface::object::{encode_loose, hash_object, ObjectKind, Oid};
use crate::surface::tag::{render_tag_payload, verify_signed_tag};
use crate::surface::{sshsig, tag};

/// The tagger message embedded in hub-signed release tags.
const RELEASE_TAG_MESSAGE: &str = "release";

/// The tagger message embedded in hub-signed channel partitions.
const PARTITION_MESSAGE: &str = "channel partition";

/// A hub-signed release tag object: its oid, loose bytes, and raw payload.
#[derive(Debug, Clone)]
pub struct SignedTagBytes {
    /// The oid of the loose `tag` object (its SHA-256, hex).
    pub oid: Oid,
    /// The zlib-compressed loose `tag` object, ready to write under
    /// `objects/<xx>/<62-hex>`.
    pub loose_bytes: Vec<u8>,
    /// The raw uncompressed tag payload (tag headers + appended armor) — the
    /// same bytes a channel partition would carry, exposed for verification.
    pub raw_payload: Vec<u8>,
}

/// Sign a release tag object pointing at `commit_oid`.
///
/// Builds the `commit`-targeting tag payload named after `semver`, appends an
/// armored SSH signature, and wraps the result as a loose `tag` object. The
/// returned [`SignedTagBytes::oid`] is the tag object the channel partitions
/// will point at; writing [`SignedTagBytes::loose_bytes`] under that oid's
/// loose path materializes the release tag on the surface.
///
/// # Errors
///
/// Returns an error when the tag payload cannot be rendered (e.g. an invalid
/// target type — never, here, since the type is fixed to `commit`).
pub fn sign_release_tag(
    signing_key: &ed25519_dalek::SigningKey,
    semver: &str,
    commit_oid: &str,
    when: i64,
) -> Result<SignedTagBytes> {
    let body = render_tag_payload(semver, commit_oid, "commit", RELEASE_TAG_MESSAGE, when)?;
    let armor = sshsig::sign_armored(body.as_bytes(), signing_key);
    let mut raw_payload = body.into_bytes();
    raw_payload.extend_from_slice(armor.as_bytes());
    raw_payload.push(b'\n');
    let oid = hash_object(ObjectKind::Tag, &raw_payload);
    let loose_bytes = encode_loose(ObjectKind::Tag, &raw_payload);
    Ok(SignedTagBytes {
        oid,
        loose_bytes,
        raw_payload,
    })
}

/// Sign a channel partition payload pointing at a release tag object.
///
/// Builds the `tag`-targeting payload named after `channel_name`, pointing at
/// `release_tag_oid` (the loose tag object oid from [`sign_release_tag`] or an
/// already-published release), and appends an armored SSH signature. The
/// result is written **raw** (not as a loose object) under
/// `channels/<channel>/<bucket-hex>`, matching how the indexer reads
/// partitions and how the fixture builder writes them.
///
/// # Errors
///
/// Returns an error when the tag payload cannot be rendered.
pub fn sign_partition(
    signing_key: &ed25519_dalek::SigningKey,
    channel_name: &str,
    release_tag_oid: &str,
    when: i64,
) -> Result<Vec<u8>> {
    let body = render_tag_payload(
        channel_name,
        release_tag_oid,
        "tag",
        PARTITION_MESSAGE,
        when,
    )?;
    let armor = sshsig::sign_armored(body.as_bytes(), signing_key);
    let mut payload = body.into_bytes();
    payload.extend_from_slice(armor.as_bytes());
    payload.push(b'\n');
    Ok(payload)
}

/// The outcome of a hosted-key [`advance_channel`].
#[derive(Debug, Clone)]
pub struct AdvanceResult {
    /// The channel that was advanced.
    pub channel: String,
    /// The release the advanced partitions now point at.
    pub release: String,
    /// How many partitions this advance newly moved to `release`.
    pub moved: usize,
    /// How many of the 256 partitions point at `release` after the advance.
    pub at_target: usize,
    /// The rollout percentage (`at_target` / 256), rounded to a whole number.
    pub rollout_percent: u32,
}

/// Advance a hosted-key registry's channel to an existing release, server-side.
///
/// Loads the registry's hosted signing key, locates the release tag object for
/// `target_semver` (the release must already exist on the surface — publishing
/// a new release is a separate concern), then signs and writes the next `count`
/// partitions not already at the target. Each partition is a freshly
/// hub-signed payload written atomically under
/// `channels/<channel>/<bucket-hex>` in the registry's storage binding root.
/// The registry is re-indexed inline so its index reflects the advance the
/// instant this returns, and a `channel.advance` audit row is recorded with the
/// hosted key as actor.
///
/// The advance respects the anti-rollback floor: if the registry has recorded a
/// floor for this channel above `target_semver`, the advance is refused rather
/// than writing partitions the next index would reject.
///
/// # Errors
///
/// Returns an error when the registry has no hosted key, has no on-disk surface
/// root (an HTTP-sourced registry cannot be written), when `target_semver` has
/// no indexed release, when `target_semver` is below the channel's floor, when
/// signing or writing a partition fails, or when the re-index fails.
pub async fn advance_channel(
    db: &Database,
    sealer: &dyn SecretSealer,
    registry: &RegistryRecord,
    channel_name: &str,
    target_semver: &str,
    count: usize,
    when: i64,
) -> Result<AdvanceResult> {
    let hosted_key_id = registry.hosted_key_id.with_context(|| {
        format!(
            "registry '{}' has no hosted signing key: prepare the advance for client-side \
             signing instead (apr channel advance --from-hub)",
            registry.slug
        )
    })?;
    let root = db
        .registry_surface_root(registry.id)?
        .with_context(|| format!("registry '{}' has no writable surface root", registry.slug))?;

    // Anti-rollback: never advance below the recorded floor.
    if let (Some(floor), Ok(target)) = (
        db.channel_floor(registry.id, channel_name)?,
        semver::Version::parse(target_semver),
    ) {
        if let Ok(floor_v) = semver::Version::parse(&floor) {
            if target < floor_v {
                bail!(
                    "refusing to advance channel '{channel_name}' to {target_semver}: \
                     below the recorded floor {floor}"
                );
            }
        }
    }

    // Locate the release tag object that the partitions must point at. The
    // indexed release row carries the tag oid the (already published) release
    // tag object hashes to.
    let release = db
        .list_releases(registry.id)?
        .into_iter()
        .find(|r| r.semver == target_semver)
        .with_context(|| {
            format!(
                "no indexed release '{target_semver}' for registry '{}': \
                 the release must be published before a channel can advance to it",
                registry.slug
            )
        })?;
    let release_tag_oid = release.tag_oid;

    let (key_id, signing_key, _public) = db.load_hosted_signing_key(sealer, hosted_key_id)?;

    // Which buckets already point at the target, and which are candidates to
    // move. The indexed `ChannelSummary` carries the resolved semver per
    // bucket (an empty vec when the channel has not been indexed yet).
    let current: Vec<Option<String>> = db
        .list_channels(registry.id)?
        .into_iter()
        .find(|c| c.name == channel_name)
        .map(|c| c.partitions)
        .unwrap_or_else(|| vec![None; 256]);
    let mut at_target = current
        .iter()
        .filter(|slot| slot.as_deref() == Some(target_semver))
        .count();

    let payload = sign_partition(&signing_key, channel_name, &release_tag_oid, when)?;
    let mut moved = 0usize;
    for bucket in 0u16..=255 {
        if moved >= count {
            break;
        }
        if current
            .get(bucket as usize)
            .map(|slot| slot.as_deref() == Some(target_semver))
            .unwrap_or(false)
        {
            continue;
        }
        let rel_path = format!("channels/{channel_name}/{bucket:02x}");
        let target = safe_join(&root, &rel_path)
            .with_context(|| format!("resolving partition path {rel_path}"))?;
        write_atomic(&target, &payload).await?;
        moved += 1;
        at_target += 1;
    }

    // Re-index from the binding root so the index reflects the new partitions.
    let fetch = LocalFsFetch::new(&root);
    let outcome = crate::indexer::index_and_record(db, &fetch, registry).await?;

    let rollout_percent = ((at_target as f64 / 256.0) * 100.0).round() as u32;
    let detail = serde_json::json!({
        "channel": channel_name,
        "release": target_semver,
        "moved": moved,
        "at_target": at_target,
        "rollout_percent": rollout_percent,
    })
    .to_string();
    db.record_audit(
        "key",
        None,
        &format!("hosted-key:{key_id}"),
        "channel.advance",
        &registry.slug,
        None,
        Some(&outcome.commit),
        None,
        Some(&detail),
    )?;

    // Notify subscribers of the advance. Additive and non-fatal: a webhook
    // failure never undoes the partitions just written.
    if let Some(org_id) = registry.org_id {
        let event = crate::webhook::WebhookEvent::ChannelAdvanced {
            registry: registry.slug.clone(),
            channel: channel_name.to_string(),
            release: target_semver.to_string(),
            moved,
            at_target,
            rollout_percent,
            at: when,
        };
        if let Err(err) = crate::webhook::dispatch(db, org_id, &event) {
            tracing::warn!(slug = %registry.slug, error = %format!("{err:#}"), "dispatching channel.advanced webhook");
        }
    }

    Ok(AdvanceResult {
        channel: channel_name.to_string(),
        release: target_semver.to_string(),
        moved,
        at_target,
        rollout_percent,
    })
}

/// Re-sign a release tag with the registry's hosted key (key rotation).
///
/// Produces a fresh signed `tag` object for `semver` over `commit_oid`,
/// signed by the hosted key rather than the original signer, and writes it as
/// a loose object under the binding root. This supports the rotation re-sign
/// flow: when a registry adopts a hosted key, its existing release tags can be
/// re-signed under the new anchor so they verify against it. Returns the
/// re-signed tag's oid.
///
/// The re-signed tag object's oid differs from the original only if the
/// signature bytes differ; callers that need the channel partitions to follow
/// (because the oid changed) re-advance the channel afterward.
///
/// # Errors
///
/// Returns an error when the registry has no hosted key, has no writable
/// surface root, or when signing or writing the tag object fails.
pub async fn resign_tag(
    db: &Database,
    sealer: &dyn SecretSealer,
    registry: &RegistryRecord,
    semver: &str,
    commit_oid: &str,
    when: i64,
) -> Result<Oid> {
    let hosted_key_id = registry.hosted_key_id.with_context(|| {
        format!(
            "registry '{}' has no hosted signing key to re-sign with",
            registry.slug
        )
    })?;
    let root = db
        .registry_surface_root(registry.id)?
        .with_context(|| format!("registry '{}' has no writable surface root", registry.slug))?;
    let (key_id, signing_key, _public) = db.load_hosted_signing_key(sealer, hosted_key_id)?;

    let signed = sign_release_tag(&signing_key, semver, commit_oid, when)?;
    let target = safe_join(&root, &signed.oid.loose_path())
        .with_context(|| format!("resolving loose path for tag {}", signed.oid))?;
    write_atomic(&target, &signed.loose_bytes).await?;

    db.record_audit(
        "key",
        None,
        &format!("hosted-key:{key_id}"),
        "tag.resign",
        &registry.slug,
        None,
        Some(commit_oid),
        Some(&signed.oid.to_hex()),
        Some(semver),
    )?;
    Ok(signed.oid)
}

/// Verify a hub-signed release tag object against a trust anchor set.
///
/// A thin wrapper over [`crate::surface::tag::verify_signed_tag`] confirming
/// the hub's own output is consumable by the indexer's verification path: the
/// signature checks against `trusted_keys` and the embedded name binds to
/// `semver`.
///
/// # Errors
///
/// Returns an error when the payload is malformed, signed by an untrusted key,
/// or name-bound to a different name.
pub fn verify_release_tag(
    signed: &SignedTagBytes,
    semver: &str,
    trusted_keys: &[String],
) -> Result<tag::SignedTag> {
    verify_signed_tag(&signed.raw_payload, semver, trusted_keys)
}

/// Write `bytes` to `target` atomically: create the parent directory, write a
/// sibling temp file, then rename over `target`.
///
/// Mirrors [`crate::facade`]'s write so a concurrent reader (the read facade,
/// the indexer) never observes a half-written partition or tag object.
async fn write_atomic(target: &Path, bytes: &[u8]) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    fn trusted(k: &ed25519_dalek::SigningKey) -> Vec<String> {
        vec![sshsig::trusted_key_line("hosted", &k.verifying_key())]
    }

    #[test]
    fn release_tag_round_trips_through_the_indexer_verifier() {
        let signer = key(11);
        let commit = "ab".repeat(32);
        let signed = sign_release_tag(&signer, "1.2.3", &commit, 1_770_000_000).unwrap();

        // The loose bytes decode back to the same oid (hash-verified).
        let (kind, content) =
            crate::surface::object::decode_loose(&signed.loose_bytes, Some(signed.oid)).unwrap();
        assert_eq!(kind, ObjectKind::Tag);
        assert_eq!(content, signed.raw_payload);

        // And the raw payload verifies under the signer's anchor, name-bound.
        let verified = verify_release_tag(&signed, "1.2.3", &trusted(&signer)).unwrap();
        assert_eq!(verified.tag.object, commit);
    }

    #[test]
    fn partition_verifies_with_channel_name_binding() {
        let signer = key(12);
        let tag_oid = "cd".repeat(32);
        let payload = sign_partition(&signer, "stable", &tag_oid, 1_770_000_000).unwrap();
        let verified = verify_signed_tag(&payload, "stable", &trusted(&signer)).unwrap();
        assert_eq!(verified.tag.object, tag_oid);
        // Name binding: the same bytes must not verify under another channel.
        assert!(verify_signed_tag(&payload, "beta", &trusted(&signer)).is_err());
    }

    #[test]
    fn a_different_key_is_rejected() {
        let signer = key(13);
        let other = key(99);
        let signed = sign_release_tag(&signer, "2.0.0", &"ef".repeat(32), 1_770_000_000).unwrap();
        assert!(verify_release_tag(&signed, "2.0.0", &trusted(&other)).is_err());

        let partition = sign_partition(&signer, "stable", &"01".repeat(32), 1_770_000_000).unwrap();
        assert!(verify_signed_tag(&partition, "stable", &trusted(&other)).is_err());
    }
}
