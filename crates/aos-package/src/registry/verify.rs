//! Signed tag-object parsing and name-binding helpers.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

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
}
