//! Dumb-HTTP ref advertisement parsing (`info/refs` and `HEAD`).
//!
//! A dumb-HTTP git origin advertises refs as tab-separated lines:
//!
//! ```text
//! <oid>\trefs/heads/stable
//! <oid>\trefs/tags/1.2.3
//! <oid>\trefs/tags/1.2.3^{}
//! ```
//!
//! Annotated tags appear twice — the tag *object* id on the plain line and
//! the peeled commit on the `^{}` line. Channel partitions point at tag
//! objects, so the unpeeled id is the one the registry model cares about.

use std::collections::BTreeMap;

use anyhow::{Context, Result};

use super::object::Oid;

/// Parsed ref advertisement of a registry surface.
#[derive(Debug, Clone, Default)]
pub struct Refs {
    /// Branch heads (`refs/heads/<name>` → commit oid). Branch names are
    /// the registry's channel names.
    pub branches: BTreeMap<String, Oid>,
    /// Tags (`refs/tags/<name>` → unpeeled tag object oid).
    pub tags: BTreeMap<String, Oid>,
    /// Peeled targets for annotated tags (`<name>` → commit oid).
    pub peeled_tags: BTreeMap<String, Oid>,
}

/// Parse an `info/refs` advertisement.
///
/// Unknown ref namespaces are ignored; blank lines are skipped.
///
/// # Errors
///
/// Returns an error on a malformed line or invalid oid.
pub fn parse_info_refs(content: &str) -> Result<Refs> {
    let mut refs = Refs::default();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let (oid_hex, name) = line
            .split_once('\t')
            .with_context(|| format!("malformed info/refs line '{line}'"))?;
        let oid = Oid::from_hex(oid_hex)?;
        if let Some(branch) = name.strip_prefix("refs/heads/") {
            refs.branches.insert(branch.to_string(), oid);
        } else if let Some(tag) = name.strip_prefix("refs/tags/") {
            if let Some(peeled) = tag.strip_suffix("^{}") {
                refs.peeled_tags.insert(peeled.to_string(), oid);
            } else {
                refs.tags.insert(tag.to_string(), oid);
            }
        }
    }
    Ok(refs)
}

/// Parse a `HEAD` file into the default branch name, when symbolic.
///
/// Returns `None` for a detached (bare-oid) HEAD.
pub fn parse_head(content: &str) -> Option<String> {
    content
        .trim()
        .strip_prefix("ref: refs/heads/")
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_branches_and_tags() {
        let oid_a = "a".repeat(64);
        let oid_b = "b".repeat(64);
        let oid_c = "c".repeat(64);
        let text = format!(
            "{oid_a}\trefs/heads/stable\n{oid_b}\trefs/tags/1.2.3\n{oid_c}\trefs/tags/1.2.3^{{}}\n",
        );
        let refs = parse_info_refs(&text).unwrap();
        assert_eq!(refs.branches.len(), 1);
        assert_eq!(refs.tags["1.2.3"].to_hex(), oid_b);
        assert_eq!(refs.peeled_tags["1.2.3"].to_hex(), oid_c);
    }

    #[test]
    fn head_parses_symbolic_ref() {
        assert_eq!(
            parse_head("ref: refs/heads/stable\n").as_deref(),
            Some("stable")
        );
        assert_eq!(parse_head(&"a".repeat(64)), None);
    }
}
