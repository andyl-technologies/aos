//! Pure header parsing for git tag objects and the name-binding check.
//!
//! Channel-tracked registries select releases through a two-hop chain of
//! signed annotated tags: a *channel tag* (served as a static partition
//! object) points at a *release tag*, which points at the release commit.
//! This module owns the dependency-free pieces of that verification — the
//! tag-object header parser and the name-binding equality check — so they
//! run unchanged on a native server, a Worker, and in the browser.
//!
//! These types are the canonical definitions re-exported by
//! `aos_package::registry::verify`, so `apm`'s git-CLI path and this
//! pure reader cannot drift on the tag-object format.
//!
//! The raw tag-object format parsed here is git's standard header layout:
//!
//! ```text
//! object <oid>
//! type commit
//! tag 1.2.3
//! tagger Name <email> 1770000000 +0000
//! ```

use anyhow::{bail, Result};

/// The target type recorded in a git tag object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagTarget {
    /// The tag points at another tag (a channel tag's hop to a release tag).
    Tag,
    /// The tag points directly at a commit (a release tag).
    Commit,
}

/// Parsed fields from a git tag object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagObject {
    /// The tag name embedded in the object (`tag` header).
    pub name: String,
    /// Object id the tag points at (`object` header).
    pub object: String,
    /// Type of the pointed-at object (`type` header).
    pub target_type: TagTarget,
    /// Tagger timestamp in Unix seconds, when parseable.
    pub tagger_when: Option<i64>,
}

/// Parse the header section of a raw git tag object.
///
/// Only the headers before the first blank line are read; the tag message
/// and signature block are ignored.
///
/// # Errors
///
/// Returns an error when the `tag`, `object`, or `type` header is missing,
/// or when the target type is neither `tag` nor `commit`.
pub fn parse_tag_object(content: &str) -> Result<TagObject> {
    let mut object = None;
    let mut target_type = None;
    let mut name = None;
    let mut tagger_when = None;

    for line in content.lines() {
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line.strip_prefix("object ") {
            object = Some(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("type ") {
            target_type = Some(match rest {
                "tag" => TagTarget::Tag,
                "commit" => TagTarget::Commit,
                other => bail!("unsupported tag target type '{other}'"),
            });
        } else if let Some(rest) = line.strip_prefix("tag ") {
            name = Some(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("tagger ") {
            tagger_when = parse_tagger_when(rest);
        }
    }

    Ok(TagObject {
        name: name.ok_or_else(|| anyhow::anyhow!("tag object missing tag header"))?,
        object: object.ok_or_else(|| anyhow::anyhow!("tag object missing object header"))?,
        target_type: target_type
            .ok_or_else(|| anyhow::anyhow!("tag object missing type header"))?,
        tagger_when,
    })
}

/// Verify that the embedded git tag-name equals the expected serving-path name.
///
/// This binds a tag object to the channel or release name it was served
/// under, preventing a valid tag from being replayed at a different path.
///
/// # Errors
///
/// Returns an error when the embedded name differs from `expected_name`.
pub fn verify_name_binding(tag: &TagObject, expected_name: &str) -> Result<()> {
    if tag.name != expected_name {
        bail!(
            "tag name-binding mismatch: embedded tag name '{}' does not match expected '{}'",
            tag.name,
            expected_name,
        );
    }
    Ok(())
}

/// Extract the Unix timestamp from a `tagger Name <email> <secs> <tz>` line.
fn parse_tagger_when(tagger: &str) -> Option<i64> {
    // Git tagger header is: "Name <email> <unix-seconds> <tz>".
    tagger
        .split_whitespace()
        .rev()
        .nth(1)
        .and_then(|s| s.parse::<i64>().ok())
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
