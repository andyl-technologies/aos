//! Validates immutable source closure separately from changed-input discovery.
//!
//! A prepared source borrows canonical Tree values. Preparation visits reachable
//! inputs to refuse unsupported/invalid graph semantics and retains a flat sorted
//! table of distinct reachable borrowed handles. It creates no occurrence map,
//! auxiliary tree or new index. Its events never enter discovery accounting.
//! Supplied-map resolutions and reachable-table construction are full preparation:
//! BTreeMap collection can compare keys and allocate storage, and conversion to
//! the shared vector copies each distinct handle once. These costs are separate
//! from lookup calls/probes/comparisons and canonical boundary B.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::super::carrier::{SemanticContext, validate_namespace_attributes};
use super::super::evaluation::Source;
use super::super::{IndexEvaluationRecipe, IndexRoots};
use super::{Error, SourceLookup, SourceLookupWork};
use crate::identity::Digest;
use crate::tree_builder::Tree;
use crate::tree_format::{EntryKind, MAX_GRAFT_DEPTH, MAX_TREE_LEVEL};

/// Counts independent source preparation work, excluding incremental discovery.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PreparationWork {
    /// Reachable root occurrences checked, including repeated grafts.
    pub roots: usize,
    /// Canonical physical nodes inspected for height and closure context.
    pub nodes: usize,
    /// Namespace entries inspected for attributes and graft closure.
    pub entries: usize,
    /// Owner-local structural bindings decoded without resolving their pointers.
    pub bindings: usize,
    /// Original supplied-map resolutions during full validation and collection.
    /// Their BTreeMap comparison cost can depend on unrelated supplied roots;
    /// this is preparation work, never incremental lookup or boundary B.
    pub supplied_map_lookups: usize,
    /// Distinct reachable borrowed handles stored in the selected table.
    pub cached_roots: usize,
    /// Reachable handle collection attempts, including repeated occurrences.
    pub cache_insertions: usize,
}

/// Borrows an independently checked immutable namespace graph for one value.
///
/// The private token only proves supported ordinary or overlay-layer immutable
/// source semantics.
/// It grants no current authority or producer/coverage verification. Immutable
/// Tree values cannot change while this token borrows the supplied graph.
pub struct PreparedSource<'graph, 'value> {
    /// Shared exact source/context checks used by ordinary evaluation.
    pub(super) source: Source<'graph, 'value>,
    /// Independently selected owner root.
    pub(super) root: Digest,
    work: PreparationWork,
    lookup: SourceLookup<'graph, 'value>,
    /// Exact active carrier semantics supplied during source preparation.
    pub(super) context: SemanticContext,
}

impl<'graph, 'value> PreparedSource<'graph, 'value> {
    /// Checks an ordinary or overlay-layer source graph without constructing an index.
    ///
    /// The explicit context accepts only the registered semantic revisions;
    /// recipe registration remains the existing closed executable profile.
    /// Every repeated graft path is checked with its own active branch and depth.
    /// Only the reached closure is checked; unrelated supplied roots are ignored.
    ///
    /// # Errors
    /// Rejects missing/wrong roots, unsupported Tree uses or chunk geometry,
    /// conflicts, structural namespace attributes, invalid typed inline values,
    /// misplaced auxiliary bindings, cycles and tree/graft depth limits.
    pub fn new(
        recipe: &IndexEvaluationRecipe<'graph>,
        trees: &'graph BTreeMap<Digest, Tree<'value>>,
        minimum: u64,
        context: SemanticContext,
    ) -> Result<Self, Error> {
        let source = Source {
            trees,
            attribute: recipe.attribute(),
            minimum,
        };
        let mut work = PreparationWork::default();
        let mut selected = BTreeMap::new();
        check(
            &source,
            recipe.owner(),
            &mut Vec::new(),
            &mut work,
            &mut selected,
        )?;
        work.cached_roots = selected.len();
        let lookup = SourceLookup::new(selected.into_iter().collect());

        Ok(Self {
            source,
            root: recipe.owner(),
            work,
            lookup,
            context,
        })
    }

    /// Returns the independently selected owner source root.
    pub fn root(&self) -> Digest {
        self.root
    }

    /// Returns the registered value attribute selected for discovery.
    pub fn attribute(&self) -> &str {
        self.source.attribute
    }

    /// Borrows the selected reachable-root snapshot for subsequent discovery.
    ///
    /// Cloning this handle is constant-time and does not copy or scan Trees.
    pub fn lookup(&self) -> &SourceLookup<'graph, 'value> {
        &self.lookup
    }

    /// Resolves an already validated immutable handle with separate bookkeeping.
    ///
    /// # Errors
    /// Rejects roots outside the selected closure and lookup counter overflow.
    pub(super) fn tree(
        &self,
        root: Digest,
        work: &mut SourceLookupWork,
    ) -> Result<&'graph Tree<'value>, Error> {
        self.lookup.tree(root, work)
    }

    /// Selects the already validated inline attribute from a reached entry.
    pub(super) fn value(&self, entry: &crate::tree_format::Entry<'value>) -> Option<&'value [u8]> {
        entry
            .attrs
            .iter()
            .find(|attribute| attribute.name == self.attribute())
            .map(|attribute| attribute.value)
    }

    /// Returns preparation events measured separately from discovery.
    pub fn preparation_work(&self) -> PreparationWork {
        self.work
    }
}

fn check<'graph, 'value>(
    source: &Source<'graph, 'value>,
    root: Digest,
    active: &mut Vec<Digest>,
    work: &mut PreparationWork,
    selected: &mut BTreeMap<Digest, &'graph Tree<'value>>,
) -> Result<(), Error> {
    if active.len() > MAX_GRAFT_DEPTH || active.contains(&root) {
        return Err(Error::Limit);
    }
    work.supplied_map_lookups = work
        .supplied_map_lookups
        .checked_add(1)
        .ok_or(Error::Limit)?;
    source.tree(root)?;
    work.supplied_map_lookups = work
        .supplied_map_lookups
        .checked_add(1)
        .ok_or(Error::Limit)?;
    let tree = source.trees.get(&root).ok_or(Error::MissingSource)?;
    work.cache_insertions = work.cache_insertions.checked_add(1).ok_or(Error::Limit)?;
    selected.insert(root, tree);
    if let Some(properties) = tree.props() {
        for property in properties {
            if property.name == "index-roots" {
                IndexRoots::decode_binding(property.value)?;
                work.bindings = work.bindings.checked_add(1).ok_or(Error::Limit)?;
            }
        }
    }
    active.push(root);
    work.roots = work.roots.checked_add(1).ok_or(Error::Limit)?;

    for node in tree.nodes() {
        work.nodes = work.nodes.checked_add(1).ok_or(Error::Limit)?;
        if node.level() > MAX_TREE_LEVEL {
            return Err(Error::Limit);
        }
    }
    for item in tree.iter() {
        work.entries = work.entries.checked_add(1).ok_or(Error::Limit)?;
        validate_namespace_attributes(2, &item.entry)?;
        match &item.entry.kind {
            EntryKind::File { .. } => {
                source.value(&item.entry)?;
            }
            EntryKind::Tree { root, props } => {
                if props.as_ref().is_some_and(|properties| {
                    properties
                        .iter()
                        .any(|property| matches!(property.name, "index-roots" | "index-gaps"))
                }) {
                    return Err(Error::Source);
                }
                check(source, *root, active, work, selected)?;
            }
            EntryKind::Conflict { .. } => return Err(Error::Incomplete),
            _ => {}
        }
    }
    active.pop();
    Ok(())
}

/// Exercises the production active-branch guard with a real canonical root.
///
/// # Panics
/// Panics if the guard accepts an active root or performs validation work.
#[cfg(test)]
pub(super) fn assert_active_cycle(source: &PreparedSource<'_, '_>) {
    // A canonical content-hash cycle cannot be manufactured through public
    // Tree construction without a hash fixed point. Check the running branch
    // directly instead of weakening immutable identity validation for a test.
    let mut active = alloc::vec![source.root];
    let mut work = PreparationWork::default();
    assert_eq!(
        check(
            &source.source,
            source.root,
            &mut active,
            &mut work,
            &mut BTreeMap::new()
        ),
        Err(Error::Limit)
    );
    assert_eq!(work, PreparationWork::default());
}
