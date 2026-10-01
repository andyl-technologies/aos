//! Verified Git-tree predicates and bounded entry projections.
//!
//! The only predicate is an exact, ordered set of entry names. The projection
//! contains name, Git entry kind and object ID; it cannot request source bytes
//! or evaluate a program. Continuations bind the tree, predicate and observed
//! source snapshot, so a retry cannot silently select another representation.
//!
//! ```text
//! FilterGitTreeEntries { oid, names, cursor }
//! GitTreeEntriesPage { tree_oid, selection_digest, source_commitment,
//!                      start_index, end_index, entries, next_cursor }
//! ```

use std::collections::BTreeMap;

use anyhow::{ensure, Context as _, Result};
use aos_registry_surface::object::{self, ObjectKind, Oid, TreeEntry};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Maximum exact names admitted by one tree predicate.
pub const MAX_TREE_SELECTION_NAMES: usize = 64;
/// Maximum UTF-8 bytes in an admitted tree entry name.
pub const MAX_TREE_ENTRY_NAME_BYTES: usize = 255;
/// Maximum matching rows returned by one page.
pub const MAX_TREE_PAGE_ENTRIES: usize = 16;
/// Maximum encoded bytes in one tree projection page.
pub const MAX_TREE_PAGE_BYTES: usize = 16 * 1024;
/// Maximum decoded tree bytes parsed beside storage.
pub const MAX_TREE_CONTENT_BYTES: usize = 8 * 1024 * 1024;
/// Maximum inflated tree framing and content before the decoded-content check.
pub const MAX_TREE_INFLATED_BYTES: u64 = MAX_TREE_CONTENT_BYTES as u64 + 64;
/// Maximum entries parsed from one verified source tree.
pub const MAX_TREE_SOURCE_ENTRIES: usize = 65_536;

/// Git entry kinds preserving the original tree mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitTreeEntryKind {
    /// A directory tree (`40000`).
    Tree,
    /// An ordinary file blob (`100644`).
    Blob,
    /// An executable file blob (`100755`).
    ExecutableBlob,
    /// A symbolic-link blob (`120000`).
    Symlink,
    /// A submodule commit (`160000`).
    Commit,
}

impl GitTreeEntryKind {
    /// Returns the canonical Git mode represented by this kind.
    #[must_use]
    pub const fn mode(self) -> &'static str {
        match self {
            Self::Tree => "40000",
            Self::Blob => "100644",
            Self::ExecutableBlob => "100755",
            Self::Symlink => "120000",
            Self::Commit => "160000",
        }
    }

    fn from_mode(mode: &str) -> Result<Self> {
        match mode {
            "40000" => Ok(Self::Tree),
            "100644" => Ok(Self::Blob),
            "100755" => Ok(Self::ExecutableBlob),
            "120000" => Ok(Self::Symlink),
            "160000" => Ok(Self::Commit),
            _ => anyhow::bail!("unsupported Git tree entry mode"),
        }
    }
}

/// One selected row without the source object's bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitTreeEntryProjection {
    /// Exact selected component name.
    pub name: String,
    /// Entry kind preserving its original Git mode.
    pub kind: GitTreeEntryKind,
    /// Canonical lowercase SHA-256 object ID.
    pub oid: String,
}

impl GitTreeEntryProjection {
    /// Restores the shared tree-entry representation without fetching its body.
    ///
    /// # Errors
    /// Returns an error for an invalid name or object ID.
    pub fn tree_entry(&self) -> Result<TreeEntry> {
        ensure!(valid_name(&self.name), "invalid projected tree name");
        let oid = canonical_oid(&self.oid)?;
        Ok(TreeEntry {
            name: self.name.clone(),
            mode: self.kind.mode().into(),
            oid,
        })
    }
}

/// An exact continuation for one predicate and physical source snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitTreeCursor {
    /// Verified source tree ID from the original request.
    pub tree_oid: String,
    /// Domain-separated digest of the original ordered selected names.
    pub selection_digest: String,
    /// Commitment to the original provider snapshot or local verified bytes.
    pub source_commitment: String,
    /// First selected-name position not yet examined.
    pub next_index: usize,
}

/// A bounded ordered projection, including the examined predicate range.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitTreeEntriesPage {
    /// Verified source tree ID, excluding any source body.
    pub tree_oid: String,
    /// Commitment to the complete ordered selected-name predicate.
    pub selection_digest: String,
    /// Commitment to the exact observed source snapshot.
    pub source_commitment: String,
    /// Inclusive first examined selected-name position.
    pub start_index: usize,
    /// Exclusive last examined position, including selected names absent from the tree.
    pub end_index: usize,
    /// Matching name/kind/OID rows, ordered by the requested names.
    pub entries: Vec<GitTreeEntryProjection>,
    /// Continuation bound to this source, or `None` after every name is examined.
    pub next_cursor: Option<GitTreeCursor>,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_TREE_ENTRY_NAME_BYTES
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|character| character.is_control() || character == '/' || character == '\\')
}

fn canonical_oid(value: &str) -> Result<Oid> {
    ensure!(valid_digest(value), "noncanonical Git object ID");
    Oid::from_hex(value)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Validates a closed predicate and computes its domain-separated commitment.
///
/// # Errors
/// Returns an error for an empty, excessive, noncanonical or unordered name set.
pub fn selection_digest(names: &[String]) -> Result<String> {
    ensure!(
        !names.is_empty()
            && names.len() <= MAX_TREE_SELECTION_NAMES
            && names.iter().all(|name| valid_name(name))
            && names.windows(2).all(|pair| pair[0] < pair[1]),
        "invalid Git tree name predicate"
    );
    let mut hash = Sha256::new();
    hash.update(b"aos.storage.git-tree-selection.v1\0");
    hash.update(serde_json::to_vec(names)?);
    Ok(hex::encode(hash.finalize()))
}

/// Commits the observed provider identity used to bind every projection page.
///
/// # Errors
/// Returns an error when the source identity cannot be encoded.
pub fn source_commitment(source: &crate::storage_work::StorageObjectIdentity) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(b"aos.storage.git-tree-source.v1\0");
    hash.update(serde_json::to_vec(source)?);
    Ok(hex::encode(hash.finalize()))
}

/// Validates the predicate and continuation before any provider I/O.
///
/// # Errors
/// Returns an error for malformed identities, changed predicates or invalid cursors.
pub fn validate_request(oid: &str, names: &[String], cursor: Option<&GitTreeCursor>) -> Result<()> {
    canonical_oid(oid)?;
    let selection = selection_digest(names)?;
    if let Some(cursor) = cursor {
        ensure!(
            cursor.tree_oid == oid
                && cursor.selection_digest == selection
                && valid_digest(&cursor.source_commitment)
                && cursor.next_index > 0
                && cursor.next_index < names.len(),
            "Git tree cursor does not match its original selection"
        );
    }
    Ok(())
}

impl GitTreeEntriesPage {
    /// Checks correlation, ordering, bounds and source continuity before retaining rows.
    ///
    /// # Errors
    /// Returns an error for another source or predicate, skipped/repeated positions,
    /// unselected rows, invalid entry IDs or an oversized page.
    pub fn validate(
        &self,
        oid: &str,
        names: &[String],
        cursor: Option<&GitTreeCursor>,
        source: &str,
    ) -> Result<()> {
        validate_request(oid, names, cursor)?;
        let start = cursor.map_or(0, |cursor| cursor.next_index);
        ensure!(
            valid_digest(source)
                && self.tree_oid == oid
                && self.selection_digest == selection_digest(names)?
                && self.source_commitment == source
                && cursor.is_none_or(|cursor| cursor.source_commitment == source)
                && self.start_index == start
                && self.end_index > start
                && self.end_index <= names.len()
                && self.entries.len() <= MAX_TREE_PAGE_ENTRIES,
            "Git tree page changed its source, predicate or range"
        );
        let selected = &names[start..self.end_index];
        for entry in &self.entries {
            entry.tree_entry()?;
            ensure!(
                selected.binary_search(&entry.name).is_ok(),
                "unselected Git tree entry"
            );
        }
        ensure!(
            self.entries
                .windows(2)
                .all(|pair| pair[0].name < pair[1].name),
            "Git tree page entries are not strictly ordered"
        );
        let expected_cursor = (self.end_index < names.len()).then(|| GitTreeCursor {
            tree_oid: oid.into(),
            selection_digest: self.selection_digest.clone(),
            source_commitment: source.into(),
            next_index: self.end_index,
        });
        ensure!(
            self.next_cursor == expected_cursor,
            "invalid Git tree continuation"
        );
        if self.next_cursor.is_some() {
            ensure!(
                self.entries.len() == MAX_TREE_PAGE_ENTRIES
                    && self
                        .entries
                        .last()
                        .is_some_and(|entry| entry.name == names[self.end_index - 1]),
                "Git tree page stopped before its admitted row bound"
            );
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_TREE_PAGE_BYTES,
            "Git tree page exceeds its byte bound"
        );
        Ok(())
    }
}

/// Verifies one decoded tree and returns only matching bounded entry rows.
///
/// # Errors
/// Returns an error for hash/kind mismatch, excessive source size/count,
/// ambiguous entries, invalid names/modes or changed source continuity.
pub fn project_tree(
    oid: &str,
    content: &[u8],
    names: &[String],
    cursor: Option<&GitTreeCursor>,
    source: &str,
) -> Result<GitTreeEntriesPage> {
    validate_request(oid, names, cursor)?;
    ensure!(
        valid_digest(source) && cursor.is_none_or(|cursor| cursor.source_commitment == source),
        "Git tree source changed across projection pages"
    );
    ensure!(
        content.len() <= MAX_TREE_CONTENT_BYTES,
        "Git tree exceeds its source byte bound"
    );
    ensure!(
        object::hash_object(ObjectKind::Tree, content) == canonical_oid(oid)?,
        "Git tree hash differs from its selected identity"
    );
    let mut parsed = object::parse_tree(content)?;
    ensure!(
        parsed.len() <= MAX_TREE_SOURCE_ENTRIES,
        "Git tree exceeds its entry bound"
    );
    parsed.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    ensure!(
        parsed.windows(2).all(|pair| pair[0].name != pair[1].name),
        "duplicate source tree name"
    );
    let mut entries = BTreeMap::new();
    for entry in parsed {
        ensure!(valid_name(&entry.name), "noncanonical source tree name");
        let kind = GitTreeEntryKind::from_mode(&entry.mode)?;
        if names.binary_search(&entry.name).is_err() {
            continue;
        }
        let row = GitTreeEntryProjection {
            name: entry.name.clone(),
            kind,
            oid: entry.oid.to_hex(),
        };
        entries.insert(entry.name, row);
    }
    let start = cursor.map_or(0, |cursor| cursor.next_index);
    let mut end = start;
    let mut matches = Vec::new();
    for name in &names[start..] {
        end += 1;
        if let Some(entry) = entries.get(name) {
            matches.push(entry.clone());
            if matches.len() == MAX_TREE_PAGE_ENTRIES {
                break;
            }
        }
    }
    let selection = selection_digest(names)?;
    let page = GitTreeEntriesPage {
        tree_oid: oid.into(),
        selection_digest: selection.clone(),
        source_commitment: source.into(),
        start_index: start,
        end_index: end,
        entries: matches,
        next_cursor: (end < names.len()).then(|| GitTreeCursor {
            tree_oid: oid.into(),
            selection_digest: selection,
            source_commitment: source.into(),
            next_index: end,
        }),
    };
    page.validate(oid, names, cursor, source)
        .context("validating verified Git tree projection")?;
    Ok(page)
}

#[cfg(test)]
mod tests;
