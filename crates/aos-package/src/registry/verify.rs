//! Signed tag-object parsing and name-binding helpers.
//!
//! Channel-tracked registries select releases through a two-hop chain of
//! signed annotated tags: a *channel tag* (served as a static partition
//! object) points at a *release tag*, which points at the release commit.
//! [`verify_tag_chain`] checks the whole chain: both signatures against the
//! trusted key set, the embedded tag names against the names the objects
//! were served under (*name binding*, so a valid tag for one channel or
//! release cannot be replayed as another), and the hop target types.
//!
//! The raw tag-object format parsed here is git's standard header layout:
//!
//! ```text
//! object <oid>
//! type commit
//! tag 1.2.3
//! tagger Name <email> 1770000000 +0000
//! ```

use std::path::Path;

use crate::security::verify_tag_signature;
use anyhow::{Context, Result, bail};

// The tag-object header parser, the `TagObject`/`TagTarget` types, and the
// name-binding check are the *pure* core of tag verification. They live in
// `aos-registry-surface` so the same code runs on a native server, a
// Cloudflare Worker, and in the browser (the registry web-surface SPA), and
// are re-exported here so `apm`'s git-CLI path and every existing caller of
// `aos_package::registry::verify::{TagObject, TagTarget, parse_tag_object,
// verify_name_binding}` keep working against the canonical definitions.
pub use aos_registry_surface::tagobject::{
    TagObject, TagTarget, parse_tag_object, verify_name_binding,
};

/// Verified release selected by a channel partition tag chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRelease {
    /// The release version named by the verified release tag.
    pub semver: semver::Version,
    /// The release commit the verified tag chain resolves to.
    pub commit: String,
}

/// Read and parse a tag object named by oid or ref via libgit2.
///
/// # Errors
///
/// Returns an error if the object is not readable or lacks required tag fields.
pub fn read_tag_object(repo: &Path, oid: &str) -> Result<TagObject> {
    let body = crate::registry::repo::object_body_blocking(repo, oid)
        .with_context(|| format!("reading tag object {oid}"))?;
    parse_tag_object(&String::from_utf8_lossy(&body))
}

/// Verify `channel tag -> semver tag -> commit` and return the trusted release.
///
/// `channel_tag` may be an object id or ref for the partition tag. `release_tag`
/// is the expected semver tag name, without `refs/tags/`. Each tag signature
/// must match *any* key in `trusted_keys` (each in
/// `registry:Ed25519:<base64>` form); an empty key set is an error.
///
/// # Errors
///
/// Returns an error when either tag is not signed by a trusted key, a name
/// binding fails, the channel tag does not target the release tag object,
/// either hop has the wrong target type, the release tag name is not valid
/// semver, or a git invocation fails.
pub fn verify_tag_chain(
    repo: &Path,
    channel_tag: &str,
    channel_name: &str,
    release_tag: &str,
    trusted_keys: &[String],
) -> Result<VerifiedRelease> {
    if !verify_tag_signature(repo, channel_tag, trusted_keys)? {
        bail!("channel tag '{channel_tag}' is not signed by any trusted key");
    }
    if !verify_tag_signature(repo, release_tag, trusted_keys)? {
        bail!("release tag '{release_tag}' is not signed by any trusted key");
    }

    let channel = read_tag_object(repo, channel_tag)
        .with_context(|| format!("reading channel tag '{channel_tag}'"))?;
    verify_name_binding(&channel, channel_name)?;
    if channel.target_type != TagTarget::Tag {
        bail!(
            "channel tag '{channel_tag}' targets {:?}, expected tag",
            channel.target_type,
        );
    }

    let release_oid = resolve_tag_object(repo, release_tag)?;
    if channel.object != release_oid {
        bail!(
            "channel tag '{channel_tag}' points at {}, expected release tag object {}",
            channel.object,
            release_oid,
        );
    }

    let release = read_tag_object(repo, release_tag)
        .with_context(|| format!("reading release tag '{release_tag}'"))?;
    verify_name_binding(&release, release_tag)?;
    if release.target_type != TagTarget::Commit {
        bail!(
            "release tag '{release_tag}' targets {:?}, expected commit",
            release.target_type,
        );
    }

    let semver = semver::Version::parse(release_tag)
        .with_context(|| format!("release tag '{release_tag}' is not semver"))?;

    Ok(VerifiedRelease {
        semver,
        commit: release.object,
    })
}

/// Resolve a tag ref to its tag *object* id (not the peeled commit).
fn resolve_tag_object(repo: &Path, tag: &str) -> Result<String> {
    crate::registry::repo::rev_parse_blocking(repo, &format!("{tag}^{{tag}}"))
        .with_context(|| format!("resolving tag object for {tag}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG_TEXT: &str = "\
object 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
type commit
tag 1.2.3
tagger AOS Registry <registry@example.com> 1770000000 +0000

release 1.2.3
";

    #[test]
    fn parse_tag_object_reads_headers() {
        let tag = parse_tag_object(TAG_TEXT).unwrap();
        assert_eq!(tag.name, "1.2.3");
        assert_eq!(tag.target_type, TagTarget::Commit);
        assert_eq!(tag.tagger_when, Some(1770000000));
    }

    #[test]
    fn name_binding_accepts_expected_name() {
        let tag = parse_tag_object(TAG_TEXT).unwrap();
        verify_name_binding(&tag, "1.2.3").unwrap();
    }

    #[test]
    fn name_binding_rejects_mismatch() {
        let tag = parse_tag_object(TAG_TEXT).unwrap();
        assert!(verify_name_binding(&tag, "stable").is_err());
    }

    #[test]
    fn tag_target_parses_tag_hop() {
        let text = TAG_TEXT
            .replace("type commit", "type tag")
            .replace("tag 1.2.3", "tag stable");
        let tag = parse_tag_object(&text).unwrap();
        assert_eq!(tag.name, "stable");
        assert_eq!(tag.target_type, TagTarget::Tag);
    }

    #[test]
    fn semver_release_name_is_required_for_verified_release() {
        assert!(semver::Version::parse("1.2.3").is_ok());
        assert!(semver::Version::parse("v1.2.3").is_err());
    }
}
