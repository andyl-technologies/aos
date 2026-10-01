//! Owns canonical tree staging independently of mutable reference publication.

use terrane_core::{
    identity::{Digest, IdentityKind},
    tree_builder::Tree,
    tree_format::{self, LeafItem, Property, TreeUse},
};

use crate::ref_advance::StagedUpload;

/// Holds a canonical tree and immutable uploads awaiting guarded publication.
///
/// Entries retain their canonical encoding rather than defining a second
/// representation of the core [`terrane_core::tree_format::Entry`] type.
#[derive(Debug)]
pub struct PreparedTree {
    /// Canonical entry keys paired with their encoded core entries.
    pub(crate) entries: Vec<(Vec<u8>, Vec<u8>)>,
    /// Canonical root property names and encoded values, when present.
    pub(crate) properties: Option<Vec<(String, Vec<u8>)>>,
    /// Immutable identity of the staged canonical root node.
    pub(crate) root: Digest,
    /// Owned immutable payloads awaiting guarded publication.
    pub(crate) uploads: Vec<StagedUpload>,
    /// Configured minimum chunk size used to encode and decode entries.
    pub(crate) minimum: u64,
    /// Core tree usage governing namespace and conflict validation.
    pub(crate) usage: TreeUse,
}

impl PreparedTree {
    /// Reports whether the staged root has an explicit domain property.
    pub(crate) fn has_domain(&self) -> bool {
        self.properties
            .as_ref()
            .is_some_and(|properties| properties.iter().any(|(name, _)| name == "domain"))
    }

    /// Pins inherited ownership before an edited root acquires a new identity.
    ///
    /// # Errors
    /// Returns an error if the existing or rebuilt entries, properties or tree
    /// relationships cannot be encoded under the staged tree configuration.
    pub(crate) fn inherit_domain(&mut self, domain: &str) -> Result<(), tree_format::Error> {
        if self.has_domain() {
            return Ok(());
        }
        let replaced_nodes = self
            .tree()?
            .nodes()
            .map(|node| node.encoded().to_vec())
            .collect::<std::collections::BTreeSet<_>>();
        let mut encoded = Vec::new();
        terrane_core::cbor::write_text(&mut encoded, domain);
        let properties = self.properties.get_or_insert_with(Vec::new);
        properties.push(("domain".to_owned(), encoded));
        properties.sort_by(|left, right| {
            left.0
                .len()
                .cmp(&right.0.len())
                .then_with(|| left.0.cmp(&right.0))
        });

        let rebuilt = {
            let tree = self.tree()?;
            Self::from_tree(&tree)?
        };
        let original_uploads = std::mem::take(&mut self.uploads);
        self.root = rebuilt.root;
        self.uploads = rebuilt.uploads;
        self.uploads
            .extend(original_uploads.into_iter().filter(|upload| {
                !matches!(upload, StagedUpload::Meta { kind: IdentityKind::Node, bytes }
                if replaced_nodes.contains(bytes))
            }));
        Ok(())
    }

    /// Stages a core tree without publishing any immutable content or refs.
    ///
    /// # Errors
    /// Returns an encoding error when any entry cannot be encoded under the
    /// selected chunk profile.
    pub fn from_tree(tree: &Tree<'_>) -> Result<Self, tree_format::Error> {
        let minimum = tree.min_chunk_size();
        let entries = tree
            .iter()
            .map(|item| {
                Ok((
                    item.key.clone(),
                    tree_format::encode_entry(&item.entry, minimum)?,
                ))
            })
            .collect::<Result<Vec<_>, tree_format::Error>>()?;
        let properties = tree.props().map(|properties| {
            properties
                .iter()
                .map(|property| (property.name.to_owned(), property.value.to_vec()))
                .collect()
        });
        let uploads = tree
            .nodes()
            .map(|node| StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes: node.encoded().to_vec(),
            })
            .collect();

        Ok(Self {
            entries,
            properties,
            root: tree.root_identity(),
            uploads,
            minimum,
            usage: tree.usage(),
        })
    }

    /// Returns the immutable canonical tree root identity.
    pub const fn root(&self) -> Digest {
        self.root
    }

    /// Decodes the staged entries as the existing core tree type.
    ///
    /// # Errors
    /// Returns an error for malformed entries, invalid properties, or a tree
    /// whose namespace or hard-link relationships violate the format.
    pub fn tree(&self) -> Result<Tree<'_>, tree_format::Error> {
        let entries = self
            .entries
            .iter()
            .map(|(key, bytes)| {
                Ok(LeafItem {
                    key: key.clone(),
                    entry: tree_format::decode_entry_bytes(bytes, self.minimum)?,
                })
            })
            .collect::<Result<Vec<_>, tree_format::Error>>()?;
        let properties = self.properties.as_ref().map(|properties| {
            properties
                .iter()
                .map(|(name, value)| Property { name, value })
                .collect()
        });
        Tree::build(entries, properties, self.minimum, self.usage)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests require canonical tree fixtures")]
mod tests {
    use super::*;

    #[test]
    fn inherited_ownership_rebuilds_only_the_edited_roots_nodes() {
        let tree = Tree::build(Vec::new(), None, 1024, TreeUse::Ordinary).unwrap();
        let mut prepared = PreparedTree::from_tree(&tree).unwrap();
        let mut public = Vec::new();
        terrane_core::cbor::write_text(&mut public, "public");
        let other = Tree::build(
            Vec::new(),
            Some(vec![Property {
                name: "domain",
                value: &public,
            }]),
            1024,
            TreeUse::Ordinary,
        )
        .unwrap();
        let other_bytes = other.nodes().next().unwrap().encoded().to_vec();
        prepared.uploads.push(StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: other_bytes.clone(),
        });

        prepared.inherit_domain("private:original-owner").unwrap();

        assert_ne!(prepared.root(), tree.root_identity());
        assert!(prepared.has_domain());
        assert!(prepared.uploads.iter().any(|upload| matches!(
            upload,
            StagedUpload::Meta { kind: IdentityKind::Node, bytes } if bytes == &other_bytes
        )));
        let inherited_root = prepared.root();
        prepared.inherit_domain("private:another-owner").unwrap();
        assert_eq!(prepared.root(), inherited_root);
    }
}
