//! Reading a registry's committed git surface (RFC-0004 "Configuration
//! management", read side).
//!
//! Half of a registry's configuration — `registry.toml`, `keys.toml`,
//! `packages/` — lives in a committed git tree the hub indexes and the WebUI
//! shows. This module reads that tree through the surface-read port
//! ([`SurfaceFetch`](crate::fetch::SurfaceFetch)) without the git CLI: it
//! inflates and hash-verifies loose objects with the pure parsers in
//! [`aos_registry_surface::object`], walks `commit → tree → blob`, and renders
//! the commit log, config diffs, and the change-request views the
//! `GitService` RPCs return.
//!
//! Every function here is transport- and target-agnostic — it takes a
//! `&dyn SurfaceFetch` and pure data — so the same code runs on the native hub
//! (filesystem/HTTP surface) and the Cloudflare Worker (R2 surface), and
//! compiles to both native and `wasm32-unknown-unknown`. Unlike the indexer's
//! tree load, these reads touch only the loose-object and tree formats from
//! [`aos_registry_surface`]; they pull in none of `aos-package`'s
//! committed-file parsers.
//!
//! The write side (proposing a signed draft change request) and the indexer's
//! full-tree load stay in the native hub, which has a writable filesystem and
//! the `aos-package` schema; this module is the read logic shared with the
//! Worker.

use anyhow::{bail, Context, Result};

use crate::config::ChangeId;
use crate::fetch::SurfaceFetch;
use aos_registry_surface::object::{self, Commit, ObjectKind, Oid};

/// Maximum commits returned by one [`commit_log`] walk.
///
/// A linear publish history is the common case; the cap bounds the work a
/// single `GitLog` call performs against an attacker-influenced history.
pub const GIT_LOG_LIMIT: usize = 1000;

/// The commit-message trailer key cross-referencing a hub change request to
/// its `change_id` (RFC-0004).
pub const CHANGE_ID_TRAILER: &str = "AOS-Change-Id";

/// The committed config files a [`diff_config_files`] diff covers (the
/// human-meaningful surface).
pub const DIFFED_FILES: &[&str] = &["registry.toml", "keys.toml"];

/// Reads loose objects through a [`SurfaceFetch`], verifying each object's
/// content hash against the oid it was requested by.
pub struct ObjectReader<'a> {
    fetch: &'a dyn SurfaceFetch,
}

impl<'a> ObjectReader<'a> {
    /// Create a reader over a surface transport.
    #[must_use]
    pub fn new(fetch: &'a dyn SurfaceFetch) -> Self {
        Self { fetch }
    }

    /// Read and verify one loose object.
    ///
    /// # Errors
    ///
    /// Returns an error when the object is absent (the publishing pipeline
    /// guarantees loose presence, so absence is surface corruption), fails to
    /// inflate, or hashes to a different oid.
    pub async fn read(&self, oid: Oid) -> Result<(ObjectKind, Vec<u8>)> {
        let path = oid.loose_path();
        let bytes = self
            .fetch
            .fetch(&path)
            .await?
            .with_context(|| format!("loose object {path} is missing from the surface"))?;
        object::decode_loose(&bytes, Some(oid))
    }

    /// Read one loose object, requiring a specific kind.
    ///
    /// # Errors
    ///
    /// Returns an error on read failure or kind mismatch.
    pub async fn read_kind(&self, oid: Oid, want: ObjectKind) -> Result<Vec<u8>> {
        let (kind, content) = self.read(oid).await?;
        if kind != want {
            bail!(
                "object {oid} is a {}, expected {}",
                kind.as_str(),
                want.as_str()
            );
        }
        Ok(content)
    }

    /// Read and parse a commit object.
    ///
    /// # Errors
    ///
    /// Returns an error on read failure or malformed commit.
    pub async fn read_commit(&self, oid: Oid) -> Result<Commit> {
        let content = self.read_kind(oid, ObjectKind::Commit).await?;
        object::parse_commit(&content)
    }
}

/// One commit returned by [`commit_log`].
#[derive(Debug, Clone)]
pub struct LoggedCommit {
    /// Commit object id (64-hex).
    pub oid: String,
    /// Parent commit oids, in header order.
    pub parents: Vec<String>,
    /// Commit message body.
    pub message: String,
    /// Committer identity ("Name <email>").
    pub author: String,
    /// Committer Unix timestamp.
    pub when: i64,
    /// The `AOS-Change-Id` trailer when present.
    pub change_id: Option<String>,
}

/// Extract the `AOS-Change-Id: <id>` trailer from a commit message, if present.
///
/// The trailer is matched at the start of any message line (trailers live in
/// the message body, after the commit headers), tolerating surrounding
/// whitespace. Returns the trimmed id.
#[must_use]
pub fn extract_change_id_trailer(message: &str) -> Option<String> {
    let prefix = format!("{CHANGE_ID_TRAILER}:");
    message.lines().find_map(|line| {
        line.trim()
            .strip_prefix(&prefix)
            .map(|rest| rest.trim().to_string())
    })
}

/// Extract `Name <email>` from a `committer Name <email> <secs> <tz>` line.
fn committer_ident(rest: &str) -> String {
    match rest.rfind('>') {
        Some(end) => rest[..=end].to_string(),
        None => rest.to_string(),
    }
}

/// Walk a registry's committed history from `head`, newest first, capped.
///
/// Follows the first parent of each commit through loose objects up to `limit`
/// commits (a linear publish history is the common case). Returns each commit's
/// oid, parents, committer line, timestamp, message, and `AOS-Change-Id`
/// trailer when present.
///
/// # Errors
///
/// Returns an error when reading or parsing any commit object fails.
pub async fn commit_log(
    fetch: &dyn SurfaceFetch,
    head: Oid,
    limit: usize,
) -> Result<Vec<LoggedCommit>> {
    let reader = ObjectReader::new(fetch);
    let mut out = Vec::new();
    let mut next = Some(head);
    while let (Some(oid), true) = (next, out.len() < limit) {
        let commit = reader.read_commit(oid).await?;
        let text = String::from_utf8_lossy(&commit.signed_payload);
        let (header_block, message) = match text.split_once("\n\n") {
            Some((h, m)) => (h, m.to_string()),
            None => (text.as_ref(), String::new()),
        };
        let author = header_block
            .lines()
            .find_map(|l| l.strip_prefix("committer "))
            .map(committer_ident)
            .unwrap_or_default();
        out.push(LoggedCommit {
            oid: oid.to_hex(),
            parents: commit.parents.iter().map(Oid::to_hex).collect(),
            message: message.clone(),
            author,
            when: commit.committer_when.unwrap_or_default(),
            change_id: extract_change_id_trailer(&message),
        });
        next = commit.parents.first().copied();
    }
    Ok(out)
}

/// Diff a registry's committed config files between two commits.
///
/// Renders a [`unified_diff`] per file in [`DIFFED_FILES`] whose contents
/// changed between `from` and `to`. A `None` `from` diffs the whole `to` tree
/// as additions. Returns the concatenated diff text (empty when nothing
/// changed).
///
/// # Errors
///
/// Returns an error when reading either commit's tree or any file blob fails.
pub async fn diff_config_files(
    fetch: &dyn SurfaceFetch,
    from: Option<Oid>,
    to: Oid,
) -> Result<String> {
    let mut out = String::new();
    for name in DIFFED_FILES {
        let old = match from {
            Some(from) => load_committed_file(fetch, from, name)
                .await?
                .unwrap_or_default(),
            None => String::new(),
        };
        let new = load_committed_file(fetch, to, name)
            .await?
            .unwrap_or_default();
        out.push_str(&unified_diff(name, &old, &new));
    }
    Ok(out)
}

/// Render a simple line-oriented unified-ish diff between two file versions.
///
/// Lines present only in `old` are prefixed `-`, lines only in `new` are
/// prefixed `+`, and shared context lines are prefixed by a space. The
/// algorithm is a longest-common-subsequence-free, prefix/suffix-trimmed line
/// diff — adequate for the small committed config files (`registry.toml`,
/// `keys.toml`, package TOML) it renders, and deterministic. `path` heads the
/// diff with a `--- a/<path>` / `+++ b/<path>` banner.
#[must_use]
pub fn unified_diff(path: &str, old: &str, new: &str) -> String {
    if old == new {
        return String::new();
    }
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();

    // Trim the common prefix and suffix so unchanged regions render as context.
    let mut head = 0;
    while head < old_lines.len() && head < new_lines.len() && old_lines[head] == new_lines[head] {
        head += 1;
    }
    let mut tail = 0;
    while tail < old_lines.len() - head.min(old_lines.len())
        && tail < new_lines.len() - head.min(new_lines.len())
        && old_lines[old_lines.len() - 1 - tail] == new_lines[new_lines.len() - 1 - tail]
    {
        tail += 1;
    }

    let mut out = format!("--- a/{path}\n+++ b/{path}\n");
    for line in &old_lines[..head] {
        out.push_str(&format!(" {line}\n"));
    }
    for line in &old_lines[head..old_lines.len() - tail] {
        out.push_str(&format!("-{line}\n"));
    }
    for line in &new_lines[head..new_lines.len() - tail] {
        out.push_str(&format!("+{line}\n"));
    }
    for line in &old_lines[old_lines.len() - tail..] {
        out.push_str(&format!(" {line}\n"));
    }
    out
}

/// Read a top-level committed file's raw text from a commit, if present.
///
/// Walks `commit → tree → <name>` through loose objects. Returns `None` when
/// the file is absent from the committed tree (so a diff can render an
/// add/delete), and an error when an object is missing, malformed, or
/// non-UTF-8.
///
/// # Errors
///
/// Returns an error when reading the commit, its tree, or the blob fails, or
/// when the named entry is a directory.
pub async fn load_committed_file(
    fetch: &dyn SurfaceFetch,
    commit_oid: Oid,
    name: &str,
) -> Result<Option<String>> {
    let reader = ObjectReader::new(fetch);
    let commit = reader.read_commit(commit_oid).await?;
    let entries = object::tree_map(&reader.read_kind(commit.tree, ObjectKind::Tree).await?)?;
    let Some(entry) = entries.get(name) else {
        return Ok(None);
    };
    if entry.is_tree() {
        bail!("'{name}' is a directory, not a file");
    }
    let bytes = reader.read_kind(entry.oid, ObjectKind::Blob).await?;
    Ok(Some(String::from_utf8(bytes).with_context(|| {
        format!("committed file '{name}' is not UTF-8")
    })?))
}

/// The `apr change merge <change_id>` command a proposed change renders.
///
/// The maintainer runs it against the registry remote to fetch the draft,
/// review the diff, re-sign the same tree with a roster key, and push.
#[must_use]
pub fn merge_command(registry_url: &str, change_id: &ChangeId) -> String {
    format!(
        "apr change merge {change_id} --registry {}",
        registry_url.trim_end_matches('/'),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_trailer_finds_change_id() {
        let msg = "config: edit registry.toml\n\nAOS-Change-Id: 01abc\n";
        assert_eq!(extract_change_id_trailer(msg).as_deref(), Some("01abc"));
        assert_eq!(extract_change_id_trailer("no trailer here"), None);
    }

    #[test]
    fn unified_diff_marks_changed_lines() {
        let old = "a\nb\nc\n";
        let new = "a\nB\nc\n";
        let diff = unified_diff("f.toml", old, new);
        assert!(diff.contains("--- a/f.toml"));
        assert!(diff.contains("-b"));
        assert!(diff.contains("+B"));
        assert!(diff.contains(" a"));
        assert!(diff.contains(" c"));
        // Identical inputs render nothing.
        assert_eq!(unified_diff("f.toml", old, old), "");
    }

    #[test]
    fn merge_command_trims_trailing_slash() {
        let cmd = merge_command("https://hub.example/acme/cdn/", &ChangeId("01J0".into()));
        assert_eq!(
            cmd,
            "apr change merge 01J0 --registry https://hub.example/acme/cdn"
        );
    }
}
