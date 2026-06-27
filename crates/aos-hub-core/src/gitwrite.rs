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
//! The read side of this flow (`commit_log`, `diff_config_files`,
//! `load_committed_file`, `unified_diff`, `merge_command`, and the
//! `AOS-Change-Id` trailer parser) lives in [`crate::git`]; this module owns the
//! *write* side and reuses that reader for its base-commit/tree lookups.
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
//!    [`aos_registry_surface::object::parse_commit`], which strips that header
//!    to recover the signed payload;
//! 4. writes the new blob, tree, and commit as loose objects through the
//!    [`SurfaceWrite`] port (at logical paths `objects/<xx>/<rest>`), plus the
//!    ref file `refs/hub/changes/<change_id>` (a ref, not a branch, so the
//!    indexer and consumers never follow it);
//! 5. records a `draft` git-backed change-set, a `config_revision` carrying the
//!    old/new file contents, and an audit row.
//!
//! ```text
//! refs/hub/changes/<change_id>   = <draft commit oid>\n
//! objects/<xx>/<rest>            = the new blob, tree, and signed commit
//! ```

use anyhow::{bail, Context, Result};

use crate::auth::seal::SecretSealer;
use crate::config::ChangeId;
use crate::db::{Database, RegistryRecord};
use crate::fetch::SurfaceFetch;
use crate::git::{ObjectReader, CHANGE_ID_TRAILER};
use crate::surface_write::SurfaceWrite;

use aos_registry_surface::object::{
    encode_loose, encode_tree, hash_object, tree_map, ObjectKind, Oid, TreeEntry,
};

/// The author/committer identity stamped on hub-authored draft commits.
const HUB_IDENT_NAME: &str = "AOS Hub";

/// The author/committer email stamped on hub-authored draft commits.
const HUB_IDENT_EMAIL: &str = "hub@aos";

/// Human-authored metadata for a change request — the title and description a
/// proposer types when opening it from the console.
///
/// Kept separate from the git commit message (which stays the deterministic
/// `config: edit <file> in <slug>` summary so signing is reproducible): the
/// title/body live only in the `config_changesets` row and drive the review
/// surface's headings. [`ProposeMeta::default`] (both `None`) is used by
/// non-interactive callers such as the cache-toggle path.
#[derive(Debug, Clone, Default)]
pub struct ProposeMeta {
    /// Short PR-style title, or `None` to fall back to the commit summary.
    pub title: Option<String>,
    /// Optional free-text description.
    pub body: Option<String>,
}

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

/// Build a signed commit object from a tree, parent, message, and trailer.
///
/// The commit payload is rendered first *without* a signature (tree, parent,
/// author, committer, blank line, then the message with the `AOS-Change-Id`
/// trailer appended), signed over those exact bytes, and the armored signature
/// is inserted as a multi-line `gpgsig-sha256` header (continuation lines
/// prefixed by one space) — mirroring how real git signs a SHA-256 commit and
/// the inverse of [`aos_registry_surface::object::parse_commit`]. Returns the
/// signed commit content (uncompressed) and its oid.
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
    let armor = aos_registry_surface::sshsig::sign_armored(payload.as_bytes(), signing_key);

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
/// registry's current tracked-branch HEAD (its last-indexed commit), read
/// through `fetch`. The resulting signed draft commit and ref are written
/// through `writer` (the [`SurfaceWrite`] port), and a `draft` git-backed
/// change-set plus a `config_revision` (old/new file contents) and an audit row
/// are recorded.
///
/// The change request is **not** applied: consumers never follow
/// `refs/hub/changes/*`, and the draft commit is signed by the non-roster
/// draft-signing key, so the edit takes effect only when a maintainer runs
/// `apr change merge <change_id>` to re-sign and push it onto the tracked
/// branch.
///
/// `fetch` reads the base commit and its tree from the registry's surface;
/// `writer` writes the new loose objects and the draft ref to the same surface.
/// Both are resolved per-registry by the deployment's surface providers, so the
/// same flow runs on the native hub and the Cloudflare Worker.
///
/// # Errors
///
/// Returns an error when the registry has no indexed base commit, when the
/// edited file is not a top-level blob in the base tree, when reading or
/// writing any object fails, or on database failure.
#[allow(clippy::too_many_arguments)]
pub async fn propose_config_change(
    db: &Database,
    sealer: &dyn SecretSealer,
    fetch: &dyn SurfaceFetch,
    writer: &dyn SurfaceWrite,
    registry: &RegistryRecord,
    file_path: &str,
    new_contents: &str,
    actor_kind: &str,
    actor_id: Option<i64>,
    actor_label: &str,
    when: i64,
    meta: ProposeMeta,
) -> Result<ProposedChange> {
    if file_path.contains('/') {
        bail!("only top-level committed files may be edited as change requests, got '{file_path}'");
    }
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

    let reader = ObjectReader::new(fetch);
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
    let new_blob_oid = write_loose(writer, ObjectKind::Blob, new_contents.as_bytes()).await?;
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
    let new_tree_oid = write_loose(writer, ObjectKind::Tree, &new_tree_content).await?;

    let summary = format!("config: edit {file_path} in {}", registry.slug);
    let (commit_content, commit_oid) = build_signed_commit(
        &signing_key,
        new_tree_oid,
        Some(base_commit),
        &summary,
        &change_id,
        when,
    );
    let written_oid = write_loose(writer, ObjectKind::Commit, &commit_content).await?;
    debug_assert_eq!(written_oid, commit_oid);

    // Write the draft ref (a ref, not a branch consumers follow).
    let git_ref = format!("refs/hub/changes/{change_id}");
    writer
        .write(&git_ref, format!("{commit_oid}\n").as_bytes())
        .await
        .with_context(|| format!("writing draft ref {git_ref}"))?;

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
        meta.title.as_deref(),
        meta.body.as_deref(),
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

/// Encode and write one loose object through `writer`, returning its oid.
///
/// The loose object is written at its logical surface path `objects/<xx>/<rest>`
/// ([`Oid::loose_path`]); the [`SurfaceWrite`] implementation maps that to its
/// store and writes it atomically.
///
/// # Errors
///
/// Returns an error when the object cannot be encoded or the write fails.
async fn write_loose(writer: &dyn SurfaceWrite, kind: ObjectKind, content: &[u8]) -> Result<Oid> {
    let oid = hash_object(kind, content);
    let loose = encode_loose(kind, content)?;
    let path = oid.loose_path();
    writer
        .write(&path, &loose)
        .await
        .with_context(|| format!("writing loose object {oid}"))?;
    Ok(oid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_registry_surface::object::{decode_loose, parse_commit};

    fn key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
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
        let trailer = crate::git::extract_change_id_trailer(
            std::str::from_utf8(&content).expect("commit is UTF-8"),
        );
        assert_eq!(trailer.as_deref(), Some(change_id.as_str()));

        // The gpgsig verifies against the signer's trust anchor over the
        // recovered signed payload.
        let signature = commit.signature.expect("commit is signed");
        let trusted = vec![aos_registry_surface::sshsig::trusted_key_line(
            "aos-hub-draft",
            &signer.verifying_key(),
        )];
        aos_registry_surface::sshsig::verify_armored(&signature, &commit.signed_payload, &trusted)
            .expect("draft signature verifies against the draft-signing key");

        // A different key must not verify.
        let other = vec![aos_registry_surface::sshsig::trusted_key_line(
            "other",
            &key(9).verifying_key(),
        )];
        assert!(aos_registry_surface::sshsig::verify_armored(
            &signature,
            &commit.signed_payload,
            &other
        )
        .is_err());
    }
}
