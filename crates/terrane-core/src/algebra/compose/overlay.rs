//! Resolves ordered virtual layers and materializes canonical overlay recipes.
//!
//! Layer precedence and whiteouts apply identically to lookup, listings, and
//! materialization. Materialized roots retain the top layer's actual ownership.

use alloc::vec::Vec;

use super::{Error, MaterializedRoot, Roots, lookup};
use crate::tree_builder::Tree;
use crate::tree_format::{Entry, EntryKind, LeafItem, TreeUse};

/// An ordered virtual overlay whose creation never traverses its layers.
#[derive(Clone, Copy)]
pub struct Overlay<'t, 'a> {
    layers: &'t [&'t Tree<'a>],
}

impl<'t, 'a> Overlay<'t, 'a> {
    /// Records layers from highest to lowest precedence.
    pub const fn new(layers: &'t [&'t Tree<'a>]) -> Self {
        Self { layers }
    }

    /// Looks up the highest-precedence value, suppressing whiteouts.
    pub fn get(&self, key: &[u8]) -> Option<&'t Entry<'a>> {
        for layer in self.layers {
            if let Some(entry) = layer.get(key) {
                return if matches!(entry.kind, EntryKind::Whiteout) {
                    None
                } else {
                    Some(entry)
                };
            }
        }
        None
    }

    /// Merges layer ranges in path order with whiteouts suppressing lower keys.
    pub fn entries(&self) -> Vec<LeafItem<'a>> {
        self.range(&[], None)
    }

    /// Lists a half-open key range without visiting entries before its start.
    pub fn range(&self, start: &[u8], end: Option<&[u8]>) -> Vec<LeafItem<'a>> {
        let mut cursors: Vec<_> = self
            .layers
            .iter()
            .map(|tree| tree.cursor_from(start).peekable())
            .collect();
        let mut output = Vec::new();
        while let Some(key) = cursors
            .iter_mut()
            .filter_map(|cursor| cursor.peek().map(|item| item.key.as_slice()))
            .min()
            .map(<[u8]>::to_vec)
        {
            if end.is_some_and(|end| key.as_slice() >= end) {
                break;
            }
            let mut winner = None;
            for cursor in &mut cursors {
                if cursor.peek().is_some_and(|item| item.key == key) {
                    let item = cursor.next();
                    if winner.is_none() {
                        winner = item;
                    }
                }
            }
            if let Some(item) = winner
                && !matches!(item.entry.kind, EntryKind::Whiteout)
            {
                output.push(item.clone());
            }
        }
        output
    }

    /// Looks up a visible value across nested grafts in layer order.
    ///
    /// # Errors
    /// Returns errors from malformed keys or unavailable or cyclic graft targets.
    pub fn lookup(
        &self,
        key: &[u8],
        roots: &'t impl Roots<'a>,
    ) -> Result<Option<&'t Entry<'a>>, Error> {
        for layer in self.layers {
            if let Some(entry) = lookup(layer, key, roots)? {
                return Ok(if matches!(entry.kind, EntryKind::Whiteout) {
                    None
                } else {
                    Some(entry)
                });
            }
        }
        Ok(None)
    }

    /// Materializes the overlay and retains its canonical recipe for a commit.
    ///
    /// # Errors
    /// Returns the same construction errors as [`Self::materialize`].
    pub fn materialize_with_recipe(&self) -> Result<MaterializedRoot<'a>, Error> {
        self.materialize_recipe_inner(None)
    }

    /// Materializes an overlay recipe with trusted input ownership.
    ///
    /// # Errors
    /// Returns the errors of [`Self::materialize_with_domains`].
    pub fn materialize_with_recipe_and_domains(
        &self,
        domains: &'a super::OperationDomains,
    ) -> Result<MaterializedRoot<'a>, Error> {
        self.materialize_recipe_inner(Some(domains))
    }

    fn materialize_recipe_inner(
        &self,
        domains: Option<&'a super::OperationDomains>,
    ) -> Result<MaterializedRoot<'a>, Error> {
        let tree = self.materialize_inner(domains)?;
        let roots: Vec<_> = self
            .layers
            .iter()
            .map(|tree| tree.root_identity())
            .collect();
        Ok(MaterializedRoot {
            tree,
            recipe: match domains {
                Some(domains) => super::Recipe::OverlayWithDomains {
                    roots: &roots,
                    domains,
                }
                .encode(),
                None => super::Recipe::Overlay(&roots).encode(),
            },
        })
    }

    /// Materializes the overlay as one canonical namespace tree.
    ///
    /// # Errors
    /// Returns `Structure` for an empty layer list, or a builder error when
    /// layer combinations produce an invalid filesystem namespace. Missing
    /// explicit top-layer ownership requires [`Self::materialize_with_domains`].
    pub fn materialize(&self) -> Result<Tree<'a>, Error> {
        self.materialize_inner(None)
    }

    /// Materializes layers while retaining the top root's effective ownership.
    ///
    /// # Errors
    /// Returns structural or builder errors and missing ownership context.
    pub fn materialize_with_domains(
        &self,
        domains: &'a super::OperationDomains,
    ) -> Result<Tree<'a>, Error> {
        self.materialize_inner(Some(domains))
    }

    fn materialize_inner(
        &self,
        domains: Option<&'a super::OperationDomains>,
    ) -> Result<Tree<'a>, Error> {
        let top = self.layers.first().ok_or(Error::Structure)?;
        Ok(Tree::build(
            self.entries(),
            super::domain::preserved_properties(top, top.props().map(<[_]>::to_vec), domains)?,
            top.min_chunk_size(),
            TreeUse::Ordinary,
        )?)
    }
}
