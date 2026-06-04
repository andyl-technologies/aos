//! Signed tag-object parsing and name-binding helpers.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::security::verify_tag_signature;

/// The target type recorded in a git tag object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagTarget {
    Tag,
    Commit,
}

/// Parsed fields from a git tag object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagObject {
    pub name: String,
    pub object: String,
    pub target_type: TagTarget,
    pub tagger_when: Option<i64>,
}

/// Verified release selected by a channel partition tag chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRelease {
    pub semver: semver::Version,
    pub commit: String,
}

/// Read a tag object by oid/ref using `git cat-file -p`.
///
/// # Errors
///
/// Returns an error if the object is not readable or lacks required tag fields.
pub fn read_tag_object(repo: &Path, oid: &str) -> Result<TagObject> {
    let output = Command::new("git")
        .args(["cat-file", "-p", oid])
        .current_dir(repo)
        .output()
        .with_context(|| format!("running git cat-file -p {oid}"))?;
    if !output.status.success() {
        bail!(
            "git cat-file -p {oid} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    parse_tag_object(&String::from_utf8_lossy(&output.stdout))
}

/// Verify that the embedded git tag-name equals the expected serving-path name.
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

/// Verify `channel tag -> semver tag -> commit` and return the trusted release.
///
/// `channel_tag` may be an object id or ref for the partition tag. `release_tag`
/// is the expected semver tag name, without `refs/tags/`.
pub fn verify_tag_chain(
    repo: &Path,
    channel_tag: &str,
    channel_name: &str,
    release_tag: &str,
    expected_key: &str,
) -> Result<VerifiedRelease> {
    if !verify_tag_signature(repo, channel_tag, expected_key)? {
        bail!("channel tag '{channel_tag}' is not signed by the trusted key");
    }
    if !verify_tag_signature(repo, release_tag, expected_key)? {
        bail!("release tag '{release_tag}' is not signed by the trusted key");
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

fn parse_tag_object(content: &str) -> Result<TagObject> {
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

fn resolve_tag_object(repo: &Path, tag: &str) -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", &format!("{tag}^{{tag}}")])
        .current_dir(repo)
        .output()
        .with_context(|| format!("running git rev-parse {tag}^{{tag}}"))?;
    if !output.status.success() {
        bail!(
            "git rev-parse {tag}^{{tag}} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

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
        let text = TAG_TEXT.replace("type commit", "type tag").replace("tag 1.2.3", "tag stable");
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
