//! Writing git-backed configuration change requests (RFC-0004
//! "Configuration management", git-backed path).
//!
//! Half of a registry's configuration — `registry.toml`, `keys.toml`,
//! `packages/` — lives in the committed git tree, and consumers trust only
//! roster-signed state. So a web edit cannot be applied directly: instead the
//! hub commits it to `refs/hub/changes/<change_id>`, signed by the
//! per-instance **draft-signing key**
//! ([`crate::db::Database::get_or_create_draft_signing_key`]). That key is
//! deliberately *not* in any roster, so the draft never verifies for consumers
//! — clients follow only signed tags and partitions, never branches. Promotion
//! is a maintainer running `apr change merge <change_id>`, which fetches the
//! draft, shows the diff, re-signs the same tree with a roster key, and pushes.
//!
//! # What this module writes
//!
//! Given the registry's current tracked-branch HEAD commit and an edit to one
//! top-level committed file, [`propose_config_change`]:
//!
//! 1. loads the base commit's root tree, replaces the edited blob, and
//!    re-hashes the tree (the rest of the tree is carried byte-for-byte);
//! 2. builds a new commit object whose parent is the base commit and whose
//!    message carries an `AOS-Change-Id: <change_id>` trailer;
//! 3. signs the commit with the draft-signing key, inserting the armored
//!    signature as a `gpgsig-sha256` header — the exact reverse of
//!    [`crate::surface::object::parse_commit`], which strips that header to
//!    recover the signed payload;
//! 4. writes the new blob, tree, and commit as loose objects under the
//!    registry's storage-binding root, plus the ref file
//!    `refs/hub/changes/<change_id>` (a ref, not a branch, so the indexer and
//!    consumers never follow it);
//! 5. records a `draft` git-backed change-set, a `config_revision` carrying the
//!    old/new file contents, and an audit row.
//!
//! ```text
//! refs/hub/changes/<change_id>   = <draft commit oid>\n
//! objects/<oid>/…                = the new blob, tree, and signed commit
//! ```

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::auth::oidc::SecretSealer;
use crate::config::ChangeId;
use crate::db::{Database, RegistryRecord};
use crate::fetch::{safe_join, LocalFsFetch};
use crate::surface::load::ObjectReader;
use crate::surface::object::{
    encode_loose, encode_tree, hash_object, tree_map, ObjectKind, Oid, TreeEntry,
};

/// The commit-message trailer key cross-referencing a hub change request to
/// its `change_id` (RFC-0004).
pub const CHANGE_ID_TRAILER: &str = "AOS-Change-Id";

/// The author/committer identity stamped on hub-authored draft commits.
const HUB_IDENT_NAME: &str = "AOS Hub";

/// The author/committer email stamped on hub-authored draft commits.
const HUB_IDENT_EMAIL: &str = "hub@aos";

/// A proposed git-backed change request the hub has written to a surface.
#[derive(Debug, Clone)]
pub struct ProposedChange {
    /// The change-set id; also the `AOS-Change-Id` trailer and the ref name
    /// suffix.
    pub change_id: ChangeId,
    /// The signed draft-commit oid `refs/hub/changes/<change_id>` points at.
    pub commit_oid: String,
    /// The draft ref written into the surface.
    pub git_ref: String,
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

/// Build a signed commit object from a tree, parent, message, and trailer.
///
/// The commit payload is rendered first *without* a signature (tree, parent,
/// author, committer, blank line, then the message with the `AOS-Change-Id`
/// trailer appended), signed over those exact bytes, and the armored signature
/// is inserted as a multi-line `gpgsig-sha256` header (continuation lines
/// prefixed by one space) — mirroring how real git signs a SHA-256 commit and
/// the inverse of [`crate::surface::object::parse_commit`]. Returns the signed
/// commit content (uncompressed) and its oid.
///
/// `when` is the Unix author/committer timestamp.
fn build_signed_commit(
    signing_key: &ed25519_dalek::SigningKey,
    tree: Oid,
    parent: Option<Oid>,
    summary: &str,
    change_id: &ChangeId,
    when: i64,
) -> (Vec<u8>, Oid) {
    let ident = format!("{HUB_IDENT_NAME} <{HUB_IDENT_EMAIL}> {when} +0000");
    let mut headers = format!("tree {tree}\n");
    if let Some(parent) = parent {
        headers.push_str(&format!("parent {parent}\n"));
    }
    headers.push_str(&format!("author {ident}\ncommitter {ident}\n"));
    let message = format!("{summary}\n\n{CHANGE_ID_TRAILER}: {change_id}\n");

    // The payload the signature covers: headers, blank line, message.
    let payload = format!("{headers}\n{message}");
    let armor = crate::surface::sshsig::sign_armored(payload.as_bytes(), signing_key);

    // Re-insert the armor as a gpgsig-sha256 header: the first armor line on
    // the header line, every continuation line prefixed by one space.
    let mut armor_lines = armor.lines();
    let first = armor_lines.next().unwrap_or_default();
    let mut gpgsig = format!("gpgsig-sha256 {first}\n");
    for line in armor_lines {
        gpgsig.push(' ');
        gpgsig.push_str(line);
        gpgsig.push('\n');
    }
    let signed = format!("{headers}{gpgsig}\n{message}");
    let content = signed.into_bytes();
    let oid = hash_object(ObjectKind::Commit, &content);
    (content, oid)
}

/// Propose a git-backed change request editing one top-level committed file.
///
/// `file_path` is a top-level committed file name (`registry.toml` or
/// `keys.toml`); `new_contents` is its full replacement text. The base is the
/// registry's current tracked-branch HEAD (its last-indexed commit). The
/// resulting signed draft commit and ref are written under the registry's
/// storage-binding root, and a `draft` git-backed change-set plus a
/// `config_revision` (old/new file contents) and an audit row are recorded.
///
/// The change request is **not** applied: consumers never follow
/// `refs/hub/changes/*`, and the draft commit is signed by the non-roster
/// draft-signing key, so the edit takes effect only when a maintainer runs
/// `apr change merge <change_id>` to re-sign and push it onto the tracked
/// branch.
///
/// # Errors
///
/// Returns an error when the registry has no writable surface root, has no
/// indexed base commit, when the edited file is not a top-level blob in the
/// base tree, when reading or writing any object fails, or on database
/// failure.
#[allow(clippy::too_many_arguments)]
pub async fn propose_config_change(
    db: &Database,
    sealer: &dyn SecretSealer,
    registry: &RegistryRecord,
    file_path: &str,
    new_contents: &str,
    actor_kind: &str,
    actor_id: Option<i64>,
    actor_label: &str,
    when: i64,
) -> Result<ProposedChange> {
    if file_path.contains('/') {
        bail!("only top-level committed files may be edited as change requests, got '{file_path}'");
    }
    let root = db
        .registry_surface_root(registry.id)
        .await?
        .with_context(|| format!("registry '{}' has no writable surface root", registry.slug))?;
    let base_commit_hex = db
        .index_status(registry.id)
        .await?
        .and_then(|status| status.last_indexed_commit)
        .with_context(|| {
            format!(
                "registry '{}' has no indexed base commit to branch a change request from",
                registry.slug
            )
        })?;
    let base_commit = Oid::from_hex(&base_commit_hex)?;

    let fetch = LocalFsFetch::new(&root);
    let reader = ObjectReader::new(&fetch);
    let commit = reader.read_commit(base_commit).await?;
    let mut entries = tree_map(&reader.read_kind(commit.tree, ObjectKind::Tree).await?)?;

    let old_entry = entries
        .get(file_path)
        .with_context(|| format!("committed tree has no top-level file '{file_path}'"))?;
    if old_entry.is_tree() {
        bail!("'{file_path}' is a directory, not an editable file");
    }
    let old_contents = String::from_utf8(reader.read_kind(old_entry.oid, ObjectKind::Blob).await?)
        .with_context(|| format!("committed file '{file_path}' is not UTF-8"))?;

    let (signing_key, _public) = db.get_or_create_draft_signing_key(sealer).await?;
    let change_id = ChangeId::new();

    // Write the new blob and replace it in the root tree.
    let new_blob_oid = write_loose(&root, ObjectKind::Blob, new_contents.as_bytes()).await?;
    entries.insert(
        file_path.to_string(),
        TreeEntry {
            mode: "100644".to_string(),
            name: file_path.to_string(),
            oid: new_blob_oid,
        },
    );
    // Canonical git trees are sorted by name; the BTreeMap iteration already is.
    let tree_entries: Vec<TreeEntry> = entries.into_values().collect();
    let new_tree_content = encode_tree(&tree_entries);
    let new_tree_oid = write_loose(&root, ObjectKind::Tree, &new_tree_content).await?;

    let summary = format!("config: edit {file_path} in {}", registry.slug);
    let (commit_content, commit_oid) = build_signed_commit(
        &signing_key,
        new_tree_oid,
        Some(base_commit),
        &summary,
        &change_id,
        when,
    );
    let written_oid = write_loose_with_oid(&root, ObjectKind::Commit, &commit_content).await?;
    debug_assert_eq!(written_oid, commit_oid);

    // Write the draft ref (a ref, not a branch consumers follow).
    let git_ref = format!("refs/hub/changes/{change_id}");
    let ref_target = safe_join(&root, &git_ref)
        .with_context(|| format!("resolving draft ref path {git_ref}"))?;
    write_atomic(&ref_target, format!("{commit_oid}\n").as_bytes()).await?;

    // Record the change-set, the file revision, and an audit row.
    db.create_git_changeset(
        change_id.as_str(),
        actor_kind,
        actor_id,
        actor_label,
        &registry.slug,
        Some(&summary),
        &git_ref,
        &commit_oid.to_hex(),
    )
    .await?;
    db.add_revision(
        change_id.as_str(),
        "registry_file",
        file_path,
        crate::config::ConfigOp::Update.as_str(),
        Some(&old_contents),
        Some(new_contents),
    )
    .await?;
    db.record_audit(
        actor_kind,
        actor_id,
        actor_label,
        "config.change_request",
        &registry.slug,
        Some(change_id.as_str()),
        Some(&commit_oid.to_hex()),
        None,
        Some(&summary),
    )
    .await?;

    Ok(ProposedChange {
        change_id,
        commit_oid: commit_oid.to_hex(),
        git_ref,
    })
}

/// Build a surface fetcher for a registry's committed git surface.
///
/// A managed registry (one with a storage-binding root) is read from that root
/// over the filesystem; a registration-only registry is read through its
/// `source_url` (`file://`, a bare path, or `http(s)://`).
///
/// # Errors
///
/// Returns an error on database failure resolving the surface root, or for an
/// unsupported `source_url` scheme.
pub async fn fetcher_for_registry(
    db: &Database,
    registry: &RegistryRecord,
) -> Result<Box<dyn crate::fetch::SurfaceFetch>> {
    if let Some(root) = db.registry_surface_root(registry.id).await? {
        return Ok(Box::new(LocalFsFetch::new(root)));
    }
    crate::fetch::fetch_for_url(&registry.source_url).await
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
    fetch: &dyn crate::fetch::SurfaceFetch,
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

/// Extract `Name <email>` from a `committer Name <email> <secs> <tz>` line.
fn committer_ident(rest: &str) -> String {
    match rest.rfind('>') {
        Some(end) => rest[..=end].to_string(),
        None => rest.to_string(),
    }
}

/// The committed config files a diff covers (the human-meaningful surface).
pub const DIFFED_FILES: &[&str] = &["registry.toml", "keys.toml"];

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
    fetch: &dyn crate::fetch::SurfaceFetch,
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
/// algorithm is a longest-common-subsequence-free, prefix/suffix-trimmed
/// line diff — adequate for the small committed config files
/// (`registry.toml`, `keys.toml`, package TOML) it renders, and deterministic.
/// `path` heads the diff with a `--- a/<path>` / `+++ b/<path>` banner.
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
    fetch: &dyn crate::fetch::SurfaceFetch,
    commit_oid: Oid,
    name: &str,
) -> Result<Option<String>> {
    let reader = ObjectReader::new(fetch);
    let commit = reader.read_commit(commit_oid).await?;
    let entries = tree_map(&reader.read_kind(commit.tree, ObjectKind::Tree).await?)?;
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

/// Encode and write one loose object under `root`, returning its oid.
async fn write_loose(root: &Path, kind: ObjectKind, content: &[u8]) -> Result<Oid> {
    write_loose_with_oid(root, kind, content).await
}

/// Encode and write one loose object under `root`, returning its oid.
async fn write_loose_with_oid(root: &Path, kind: ObjectKind, content: &[u8]) -> Result<Oid> {
    let oid = hash_object(kind, content);
    let loose = encode_loose(kind, content)?;
    let target = safe_join(root, &oid.loose_path())
        .with_context(|| format!("resolving loose path for {oid}"))?;
    write_atomic(&target, &loose).await?;
    Ok(oid)
}

/// Write `bytes` to `target` atomically (temp file + rename), creating parents.
///
/// Mirrors [`crate::facade`] and [`crate::signing`] so a concurrent reader
/// never observes a half-written object or ref.
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
    use crate::surface::object::{decode_loose, parse_commit};

    fn key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn extract_trailer_finds_change_id() {
        let msg = "config: edit registry.toml\n\nAOS-Change-Id: 01abc\n";
        assert_eq!(extract_change_id_trailer(msg).as_deref(), Some("01abc"));
        assert_eq!(extract_change_id_trailer("no trailer here"), None);
    }

    #[test]
    fn signed_draft_commit_round_trips() {
        // Write a signed commit, read it back as a loose object (hash-verified),
        // verify its gpgsig against the draft-signing public key, and confirm
        // parse_commit recovers the tree, parent, and the AOS-Change-Id trailer.
        let signer = key(7);
        let tree = hash_object(ObjectKind::Tree, b"tree-bytes");
        let parent = hash_object(ObjectKind::Commit, b"parent-bytes");
        let change_id = ChangeId("01J0TESTCHANGEID".into());

        let (content, oid) = build_signed_commit(
            &signer,
            tree,
            Some(parent),
            "config: edit registry.toml",
            &change_id,
            1_770_000_000,
        );

        // Loose round-trip: encode, decode with the expected oid (hash-verified).
        let loose = encode_loose(ObjectKind::Commit, &content).unwrap();
        let (kind, decoded) = decode_loose(&loose, Some(oid)).unwrap();
        assert_eq!(kind, ObjectKind::Commit);
        assert_eq!(decoded, content);

        // parse_commit recovers the structure and the signed payload.
        let commit = parse_commit(&content).unwrap();
        assert_eq!(commit.tree, tree);
        assert_eq!(commit.parents, vec![parent]);
        let trailer =
            extract_change_id_trailer(std::str::from_utf8(&content).expect("commit is UTF-8"));
        assert_eq!(trailer.as_deref(), Some(change_id.as_str()));

        // The gpgsig verifies against the signer's trust anchor over the
        // recovered signed payload.
        let signature = commit.signature.expect("commit is signed");
        let trusted = vec![crate::surface::sshsig::trusted_key_line(
            "aos-hub-draft",
            &signer.verifying_key(),
        )];
        crate::surface::sshsig::verify_armored(&signature, &commit.signed_payload, &trusted)
            .expect("draft signature verifies against the draft-signing key");

        // A different key must not verify.
        let other = vec![crate::surface::sshsig::trusted_key_line(
            "other",
            &key(9).verifying_key(),
        )];
        assert!(
            crate::surface::sshsig::verify_armored(&signature, &commit.signed_payload, &other)
                .is_err()
        );
    }
}
