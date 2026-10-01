//! Extracts inline subtrees and removes compatible graft boundaries.
//!
//! Prepared split and flatten values own canonical rewritten hard-link bytes.
//! Flattening also retains the resolved parent ownership and rejects loss of
//! effective authority or trust policy at the removed boundary.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::{Error, Roots, beneath};
use crate::identity::Digest;
use crate::tree_builder::Tree;
use crate::tree_format::{self, EntryKind, LeafItem, TreeUse};

/// Extracts an inline subtree, or returns an existing graft target directly.
///
/// # Errors
/// Returns a key error, `Structure` when the prefix is not a directory or
/// graft, `MissingRoot` for an unavailable target, `RootIdentity` for a resolver
/// mismatch, a builder error, or `DomainContext` when an inline split has no
/// explicit ownership. Inherited domains use [`split_with_domains`].
/// Cross-prefix hard-link sets use [`prepare_split`].
pub fn split<'a>(
    tree: &Tree<'a>,
    prefix: &[u8],
    roots: &impl Roots<'a>,
) -> Result<Tree<'a>, Error> {
    split_inner(tree, prefix, roots, None)
}

/// Extracts a subtree while retaining its trusted effective disclosure domain.
///
/// # Errors
/// Returns the errors of [`split`] and `DomainContext` for missing ownership.
pub fn split_with_domains<'a>(
    tree: &Tree<'a>,
    prefix: &[u8],
    roots: &impl Roots<'a>,
    domains: &'a super::OperationDomains,
) -> Result<Tree<'a>, Error> {
    split_inner(tree, prefix, roots, Some(domains))
}

fn split_inner<'a>(
    tree: &Tree<'a>,
    prefix: &[u8],
    roots: &impl Roots<'a>,
    domains: Option<&'a super::OperationDomains>,
) -> Result<Tree<'a>, Error> {
    tree_format::validate_key(prefix).map_err(Error::Key)?;
    match &tree.get(prefix).ok_or(Error::Structure)?.kind {
        EntryKind::Tree { root, .. } => {
            let target = roots.resolve(root).ok_or(Error::MissingRoot)?;
            if target.root_identity() != *root {
                return Err(Error::RootIdentity);
            }
            Ok(target.clone())
        }
        EntryKind::Directory { .. } => {
            let mut start = prefix.to_vec();
            start.push(b'/');
            let items = tree
                .cursor_from(&start)
                .take_while(|item| beneath(&item.key, prefix))
                .map(|item| {
                    let mut entry = item.entry.clone();
                    if let EntryKind::File {
                        link_id: Some(id), ..
                    } = &mut entry.kind
                        && beneath(id, prefix)
                    {
                        *id = &id[prefix.len() + 1..];
                    }
                    LeafItem {
                        key: item.key[prefix.len() + 1..].to_vec(),
                        entry,
                    }
                })
                .collect();
            Ok(Tree::build(
                items,
                super::domain::preserved_properties(tree, None, domains)?,
                tree.min_chunk_size(),
                tree.usage(),
            )?)
        }
        _ => Err(Error::Structure),
    }
}

/// Owns an inline subtree's relative entries and canonical hard-link identities.
#[derive(Clone, Debug)]
pub struct PreparedSplit {
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    min_chunk_size: u64,
    usage: TreeUse,
    domain: Vec<u8>,
}

impl PreparedSplit {
    /// Builds the standalone subtree while borrowing this owner's entry bytes.
    ///
    /// # Errors
    /// Rejects malformed entry bytes or an invalid final namespace.
    pub fn materialize(&self) -> Result<Tree<'_>, Error> {
        let items = self
            .entries
            .iter()
            .map(|(key, bytes)| {
                Ok(LeafItem {
                    key: key.clone(),
                    entry: tree_format::decode_entry_bytes(bytes, self.min_chunk_size)
                        .map_err(Error::Key)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Tree::build(
            items,
            Some(alloc::vec![tree_format::Property {
                name: "domain",
                value: &self.domain,
            }]),
            self.min_chunk_size,
            self.usage,
        )?)
    }
}

/// Prepares an inline split, relabeling groups whose first member is outside it.
///
/// The single subtree range scan assigns each retained group's first relative
/// key as its identity. A graft entry should use [`split`] to return its target
/// directly without reading nodes.
///
/// # Errors
/// Rejects malformed keys, a prefix that is not an inline directory, or entries
/// that cannot be canonically encoded.
pub fn prepare_split(tree: &Tree<'_>, prefix: &[u8]) -> Result<PreparedSplit, Error> {
    prepare_split_inner(tree, prefix, None)
}

/// Prepares an inline split with canonical hard links and resolved ownership.
///
/// # Errors
/// Returns the errors of [`prepare_split`] and missing ownership context.
pub fn prepare_split_with_domains(
    tree: &Tree<'_>,
    prefix: &[u8],
    domains: &super::OperationDomains,
) -> Result<PreparedSplit, Error> {
    prepare_split_inner(tree, prefix, Some(domains))
}

fn prepare_split_inner(
    tree: &Tree<'_>,
    prefix: &[u8],
    domains: Option<&super::OperationDomains>,
) -> Result<PreparedSplit, Error> {
    tree_format::validate_key(prefix).map_err(Error::Key)?;
    if !matches!(
        tree.get(prefix).map(|entry| &entry.kind),
        Some(EntryKind::Directory { .. })
    ) {
        return Err(Error::Structure);
    }

    let mut entries = Vec::new();
    let mut groups = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    let mut start = prefix.to_vec();
    start.push(b'/');
    for item in tree
        .cursor_from(&start)
        .take_while(|item| beneath(&item.key, prefix))
    {
        let key = item.key[prefix.len() + 1..].to_vec();
        let mut entry = item.entry.clone();
        if let EntryKind::File {
            link_id: Some(id), ..
        } = &mut entry.kind
        {
            *id = groups.entry(id.to_vec()).or_insert_with(|| key.clone());
        }
        entries.push((
            key,
            tree_format::encode_entry(&entry, tree.min_chunk_size()).map_err(Error::Key)?,
        ));
    }

    Ok(PreparedSplit {
        entries,
        min_chunk_size: tree.min_chunk_size(),
        usage: tree.usage(),
        domain: super::domain::encoded_domain(
            &super::domain::owned_context(tree, domains)?,
            &tree.root_identity(),
        )?,
    })
}

/// Owns canonical prefixed values needed to materialize a flattened graft.
///
/// The owner keeps rewritten hard-link identities alive while the result tree
/// borrows decoded entry fields. Keep this owner alive as long as that tree.
#[derive(Clone, Debug)]
pub struct PreparedFlatten {
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    parent: Digest,
    domains: super::OperationDomains,
}

impl PreparedFlatten {
    /// Builds the flattened tree while borrowing canonical values from this owner.
    ///
    /// # Errors
    /// Returns a codec or builder error if the prepared values or resulting
    /// namespace fail validation under the parent's chunk profile.
    pub fn materialize<'a>(&'a self, parent: &Tree<'a>) -> Result<Tree<'a>, Error> {
        if parent.root_identity() != self.parent {
            return Err(Error::RootIdentity);
        }
        let Some(((path, encoded), descendants)) = self.entries.split_first() else {
            return Err(Error::Structure);
        };
        let entry = tree_format::decode_entry_bytes(encoded, parent.min_chunk_size())
            .map_err(Error::Key)?;
        let mut result = parent
            .insert(LeafItem {
                key: path.clone(),
                entry,
            })?
            .tree;
        let mut entries = Vec::new();
        for (key, encoded) in descendants {
            entries.push(LeafItem {
                key: key.clone(),
                entry: tree_format::decode_entry_bytes(encoded, parent.min_chunk_size())
                    .map_err(Error::Key)?,
            });
        }
        let mut start = path.clone();
        start.push(b'/');
        let mut end = path.clone();
        end.push(b'0');
        result = result.replace_range(&start, Some(&end), entries)?.tree;
        Ok(super::domain::preserve(parent, result, Some(&self.domains))?.tree)
    }
}

/// Prepares the canonical values that inline a graft at an authority-compatible path.
///
/// The supplied policies are resolved along the current view's graft path,
/// including graft overrides. Domain, store, ACL, and trust bindings must agree:
/// inline entries cannot retain the removed root's policy context.
/// Call [`PreparedFlatten::materialize`] to
/// obtain the root; its separate owner preserves rewritten hard-link bytes.
///
/// # Errors
/// Returns `Structure` for a nongraft path, `MissingRoot` for an unavailable
/// target, `RootIdentity` for a resolver mismatch, `Boundary` when effective
/// authority properties differ, or a codec error if prefixing exceeds a limit.
pub fn flatten<'a>(
    parent: &Tree<'a>,
    at: &[u8],
    roots: &impl Roots<'a>,
    parent_properties: &crate::properties::EffectiveProperties<'_>,
    target_properties: &crate::properties::EffectiveProperties<'_>,
) -> Result<PreparedFlatten, Error> {
    let entry = parent.get(at).ok_or(Error::Structure)?;
    let EntryKind::Tree { root, .. } = entry.kind else {
        return Err(Error::Structure);
    };
    let target = roots.resolve(&root).ok_or(Error::MissingRoot)?;
    if target.root_identity() != root {
        return Err(Error::RootIdentity);
    }
    if !parent_properties.same_boundaries(target_properties)
        || parent_properties.get(crate::properties::PropertyName::Trust)
            != target_properties.get(crate::properties::PropertyName::Trust)
        || parent_properties.get(crate::properties::PropertyName::Baseline)
            != target_properties.get(crate::properties::PropertyName::Baseline)
    {
        return Err(Error::Boundary);
    }

    let mut entries = Vec::new();
    let mut directory = entry.clone();
    directory.kind = EntryKind::Directory { mode: 0o755 };
    entries.push((
        at.to_vec(),
        tree_format::encode_entry(&directory, parent.min_chunk_size()).map_err(Error::Key)?,
    ));
    for item in target.iter() {
        if matches!(item.entry.kind, EntryKind::Whiteout) {
            continue;
        }
        let mut key = at.to_vec();
        key.push(b'/');
        key.extend_from_slice(&item.key);
        tree_format::validate_key(&key).map_err(Error::Key)?;
        let mut rewritten_link = Vec::new();
        let mut value = item.entry.clone();
        if let EntryKind::File {
            link_id: Some(link_id),
            ..
        } = value.kind
        {
            rewritten_link.extend_from_slice(at);
            rewritten_link.push(b'/');
            rewritten_link.extend_from_slice(link_id);
        }
        if let EntryKind::File { link_id, .. } = &mut value.kind
            && !rewritten_link.is_empty()
        {
            *link_id = Some(&rewritten_link);
        }
        entries.push((
            key,
            tree_format::encode_entry(&value, parent.min_chunk_size()).map_err(Error::Key)?,
        ));
    }
    let mut domains = super::OperationDomains::new();
    domains
        .bind_resolved(parent.root_identity(), parent_properties)
        .map_err(Error::DomainContext)?;
    Ok(PreparedFlatten {
        entries,
        parent: parent.root_identity(),
        domains,
    })
}
