//! Pure signing and verification primitives for registry artifacts.
//!
//! These functions transform a caller-supplied Ed25519 key into the immutable
//! release-tag and channel-partition wire formats. They do not load private
//! material, select custody, mutate topology, or write surfaces. The retained
//! control plane owns those decisions through signing-key generations and
//! exact consumer usage pins.
//!
//! The correctness invariant: everything this module emits is consumed by the
//! *same* reader that verifies a client's bytes
//! ([`aos_registry_surface::tag::verify_signed_tag`] over the registry's pinned
//! trust anchors). A release tag object is signed bytes wrapped as a loose `tag`
//! object; a channel partition is the raw signed tag payload written under
//! `channels/<name>/<bucket-hex>`:
//!
//! ```text
//! release tag  objects/<oid>   = zlib( b"tag <n>\0" + render_tag_payload(semver, commit, "commit") + SSHSIG )
//! partition    channels/<ch>/<bb> = render_tag_payload(<ch>, <release-tag-oid>, "tag") + SSHSIG
//! ```
//!
//! Public signing-key generations and exact consumer usage pins are retained
//! by the Hub. Private-key operations happen in external custody; signed
//! artifacts arrive over the ordinary immutable publication path.
//!
use anyhow::Result;

use aos_registry_surface::object::{encode_loose, hash_object, ObjectKind, Oid};
use aos_registry_surface::tag::{render_tag_payload, verify_signed_tag};
use aos_registry_surface::{sshsig, tag};

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
    let loose_bytes = encode_loose(ObjectKind::Tag, &raw_payload)?;
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

/// Verifies a signed release tag against an exact release name and trust set.
///
/// # Errors
///
/// Returns an error when the signature is invalid, untrusted, malformed, or
/// name-bound to a different release.
pub fn verify_release_tag(
    signed: &SignedTagBytes,
    semver: &str,
    trusted_keys: &[String],
) -> Result<tag::SignedTag> {
    verify_signed_tag(&signed.raw_payload, semver, trusted_keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_registry_surface::object::decode_loose;

    fn key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    fn trusted(k: &ed25519_dalek::SigningKey) -> Vec<String> {
        vec![sshsig::trusted_key_line("test-signer", &k.verifying_key())]
    }

    #[test]
    fn release_tag_round_trips_through_the_indexer_verifier() {
        let signer = key(11);
        let commit = "ab".repeat(32);
        let signed = sign_release_tag(&signer, "1.2.3", &commit, 1_770_000_000).unwrap();

        // The loose bytes decode back to the same oid (hash-verified).
        let (kind, content) = decode_loose(&signed.loose_bytes, Some(signed.oid)).unwrap();
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
