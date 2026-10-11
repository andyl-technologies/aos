//! Resolves ordered virtual layers and materializes canonical overlay recipes.
//!
//! Layer precedence and whiteouts apply identically to lookup, listings, and
//! materialization. Materialized roots retain the top layer's actual ownership
//! and expose ordinary graft targets through an owned preparation value.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Bound;

use super::{Error, MaterializedRoot, Roots, lookup};
use crate::identity::Digest;
use crate::properties::{PropertyName, RootLayer, Value};
use crate::tree_builder::Tree;
use crate::tree_format::{self, Entry, EntryKind, LeafItem, Property, TreeUse};

mod policy;

pub use policy::OverlayPolicy;

/// Owns property names and their canonical encoded values during preparation.
type PreparedPropertyBindings = Vec<(String, Vec<u8>)>;

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

    /// Merges physical layer ranges, retaining graft descriptors without descent.
    pub fn entries(&self) -> Vec<LeafItem<'a>> {
        self.range(&[], None)
    }

    /// Lists a physical half-open range without resolving graft targets.
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

    /// Lists the complete virtual namespace, resolving grafts in layer order.
    ///
    /// Graft descriptors and their descendants use absolute namespace paths;
    /// this listing is a view rather than a physical tree's leaf sequence.
    ///
    /// # Errors
    /// Returns unavailable-root, identity, cycle, or nesting-limit errors.
    pub fn entries_with_roots(&self, roots: &impl Roots<'a>) -> Result<Vec<LeafItem<'a>>, Error> {
        self.range_with_roots(&[], None, roots)
    }

    /// Lists a virtual half-open range without scanning preceding namespaces.
    ///
    /// Each layer seeks to the range start. Graft ancestors of that start are
    /// resolved directly; subsequent grafts are visited only while their ranges
    /// intersect the requested range. Equal paths use layer precedence and a
    /// winning whiteout suppresses that path in every lower layer.
    ///
    /// # Errors
    /// Returns unavailable-root, identity, cycle, or nesting-limit errors for
    /// grafts traversed by the requested range.
    pub fn range_with_roots(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        roots: &impl Roots<'a>,
    ) -> Result<Vec<LeafItem<'a>>, Error> {
        let mut ranges = Vec::new();
        for layer in self.layers {
            let mut items = Vec::new();
            collect_range(layer, &[], start, end, roots, &mut Vec::new(), &mut items)?;
            ranges.push(items.into_iter().peekable());
        }

        let mut output = Vec::new();
        while let Some(key) = ranges
            .iter_mut()
            .filter_map(|cursor| cursor.peek().map(|item| item.key.as_slice()))
            .min()
            .map(<[u8]>::to_vec)
        {
            let mut winner = None;
            for cursor in &mut ranges {
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
                output.push(item);
            }
        }
        Ok(output)
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
        Ok(MaterializedRoot {
            tree,
            recipe: self.recipe(domains),
        })
    }

    /// Materializes the overlay as one canonical namespace tree.
    ///
    /// # Errors
    /// Returns `Structure` for an empty layer list, or a builder error when
    /// layer combinations produce an invalid filesystem namespace. Missing
    /// explicit top-layer ownership requires [`Self::materialize_with_domains`].
    /// Grafted layers return `MissingRoot`; use [`Self::prepare_with_roots`] to
    /// supply their complete contextual closure.
    pub fn materialize(&self) -> Result<Tree<'a>, Error> {
        self.materialize_inner(None)
    }

    /// Materializes layers while retaining the top root's effective ownership.
    ///
    /// # Errors
    /// Returns structural or builder errors and missing ownership context.
    /// Grafted layers require [`Self::prepare_with_roots`].
    pub fn materialize_with_domains(
        &self,
        domains: &'a super::OperationDomains,
    ) -> Result<Tree<'a>, Error> {
        self.materialize_inner(Some(domains))
    }

    /// Prepares a canonical overlay including every reachable graft namespace.
    ///
    /// The caller supplies previously verified immutable roots and independently
    /// authenticated effective policy for each original layer root and absolute
    /// graft occurrence path. The empty path denotes that layer's root. The
    /// resolver must use the same selected immutable interpretation and defaults
    /// used by recipe replay; decoded claims alone do not supply authority.
    /// The result resolver evaluates the actual emitted ancestor-first root
    /// layers under the original top layer's selected interpretation and defaults.
    /// Target properties are made explicit only when needed to preserve their
    /// source policy. The emitted policy is checked again after that projection;
    /// inherited administrator rights cannot be removed. Caller authorization
    /// remains the repository's responsibility. Flat layers and unchanged graft
    /// targets retain their existing byte identities.
    ///
    /// The returned owner keeps rewritten hard-link and property bytes alive.
    /// Its materialized result exposes every synthesized target root so callers
    /// can publish the complete immutable node closure.
    ///
    /// # Errors
    /// Returns missing-root, identity, cycle, ownership, codec, and structural
    /// errors, errors from the policy resolver, or `Boundary` when retained
    /// source policy cannot represent selected entries without widening policy.
    pub fn prepare_with_roots(
        &self,
        roots: &impl Roots<'a>,
        domains: Option<&super::OperationDomains>,
        source_policy: impl Fn(&Digest, &[u8]) -> Result<OverlayPolicy, Error>,
        result_policy: impl Fn(&Digest, &[RootLayer<'_>]) -> Result<OverlayPolicy, Error>,
    ) -> Result<PreparedOverlay, Error> {
        let top = self.layers.first().ok_or(Error::Structure)?;
        let mut selected = BTreeMap::new();
        let mut graph = super::RootGraph::new();
        for layer in self.layers {
            graph.admit(layer, roots)?;
            expand_layer(layer, layer.root_identity(), &[], roots, &mut selected)?;
        }
        selected.retain(|_, item| !matches!(item.entry.kind, EntryKind::Whiteout));

        let mut preparation = Preparation {
            selected: &selected,
            domains,
            source_policy,
            result_policy,
            view: top.root_identity(),
            output: Vec::new(),
        };
        let context = Context {
            tree: top,
            view: top.root_identity(),
            at: Vec::new(),
        };
        preparation.root(&context, &[], &[], &[], None)?;
        Ok(PreparedOverlay {
            roots: preparation.output,
            recipe: self.recipe(domains),
        })
    }

    fn recipe(&self, domains: Option<&super::OperationDomains>) -> Vec<u8> {
        let roots: Vec<_> = self
            .layers
            .iter()
            .map(|tree| tree.root_identity())
            .collect();
        match domains {
            Some(domains) => super::Recipe::OverlayWithDomains {
                roots: &roots,
                domains,
            }
            .encode(),
            None => super::Recipe::Overlay(&roots).encode(),
        }
    }

    fn materialize_inner(
        &self,
        domains: Option<&'a super::OperationDomains>,
    ) -> Result<Tree<'a>, Error> {
        let top = self.layers.first().ok_or(Error::Structure)?;
        // Physical ranges cannot reproduce fallback through graft targets. The
        // explicit resolver API owns that work rather than silently dropping it.
        if self.layers.iter().any(|tree| {
            tree.iter()
                .any(|item| matches!(item.entry.kind, EntryKind::Tree { .. }))
        }) {
            return Err(Error::MissingRoot);
        }
        Ok(Tree::build(
            self.entries(),
            super::domain::preserved_properties(top, top.props().map(<[_]>::to_vec), domains)?,
            top.min_chunk_size(),
            TreeUse::Ordinary,
        )?)
    }
}

/// Owns canonical values for a complete materialized overlay root graph.
#[derive(Clone, Debug)]
pub struct PreparedOverlay {
    roots: Vec<PreparedRoot>,
    recipe: Vec<u8>,
}

impl PreparedOverlay {
    /// Builds the ordinary result and all synthesized graft targets.
    ///
    /// # Errors
    /// Returns codec or construction errors for an invalid prepared namespace.
    pub fn materialize(&self) -> Result<MaterializedOverlay<'_>, Error> {
        let mut grafts = self
            .roots
            .iter()
            .map(PreparedRoot::materialize)
            .collect::<Result<Vec<_>, Error>>()?;
        let tree = grafts.pop().ok_or(Error::Structure)?;
        Ok(MaterializedOverlay {
            tree,
            grafts,
            recipe: self.recipe.clone(),
        })
    }
}

/// An ordinary overlay root, its complete synthesized graph, and its recipe.
#[derive(Clone, Debug)]
pub struct MaterializedOverlay<'a> {
    /// The canonical top root ready for immutable publication.
    pub tree: Tree<'a>,
    /// Ordinary graft targets, in child-before-parent construction order.
    pub grafts: Vec<Tree<'a>>,
    /// Canonical operation and original ordered input roots.
    pub recipe: Vec<u8>,
}

impl<'a> Roots<'a> for MaterializedOverlay<'a> {
    fn resolve(&self, identity: &Digest) -> Option<&Tree<'a>> {
        core::iter::once(&self.tree)
            .chain(&self.grafts)
            .find(|tree| tree.root_identity() == *identity)
    }
}

#[derive(Clone, Debug)]
struct PreparedRoot {
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    properties: Option<PreparedPropertyBindings>,
    min_chunk_size: u64,
}

impl PreparedRoot {
    fn materialize(&self) -> Result<Tree<'_>, Error> {
        let entries = self
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
        let properties = self.properties.as_ref().map(|properties| {
            properties
                .iter()
                .map(|(name, value)| Property { name, value })
                .collect()
        });
        Ok(Tree::build(
            entries,
            properties,
            self.min_chunk_size,
            TreeUse::Ordinary,
        )?)
    }
}

struct Context<'t, 'a> {
    tree: &'t Tree<'a>,
    view: Digest,
    at: Vec<u8>,
}

struct Selected<'t, 'a> {
    entry: &'t Entry<'a>,
    context: Context<'t, 'a>,
    target: Option<&'t Tree<'a>>,
}

fn joined(prefix: &[u8], key: &[u8]) -> Vec<u8> {
    let mut path = prefix.to_vec();
    if !path.is_empty() {
        path.push(b'/');
    }
    path.extend_from_slice(key);
    path
}

fn expand_layer<'t, 'a>(
    tree: &'t Tree<'a>,
    view: Digest,
    at: &[u8],
    roots: &'t impl Roots<'a>,
    selected: &mut BTreeMap<Vec<u8>, Selected<'t, 'a>>,
) -> Result<(), Error> {
    for item in tree.iter() {
        let path = joined(at, &item.key);
        let target = match &item.entry.kind {
            EntryKind::Tree { root, .. } => {
                let target = roots.resolve(root).ok_or(Error::MissingRoot)?;
                if target.root_identity() != *root {
                    return Err(Error::RootIdentity);
                }
                Some(target)
            }
            _ => None,
        };
        selected.entry(path.clone()).or_insert_with(|| Selected {
            entry: &item.entry,
            context: Context {
                tree,
                view,
                at: at.to_vec(),
            },
            target,
        });
        if let Some(target) = target {
            expand_layer(target, view, &path, roots, selected)?;
        }
    }
    Ok(())
}

struct Preparation<'r, 't, 'a, S, D> {
    selected: &'r BTreeMap<Vec<u8>, Selected<'t, 'a>>,
    domains: Option<&'r super::OperationDomains>,
    source_policy: S,
    result_policy: D,
    view: Digest,
    output: Vec<PreparedRoot>,
}

impl<'t, 'a, S, D> Preparation<'_, 't, 'a, S, D>
where
    S: Fn(&Digest, &[u8]) -> Result<OverlayPolicy, Error>,
    D: Fn(&Digest, &[RootLayer<'_>]) -> Result<OverlayPolicy, Error>,
{
    fn root(
        &mut self,
        context: &Context<'t, 'a>,
        prefix: &[u8],
        ancestors: &[RootLayer<'_>],
        overrides: &[Property<'_>],
        parent_policy: Option<&OverlayPolicy>,
    ) -> Result<Digest, Error> {
        let source_policy = (self.source_policy)(&context.view, &context.at)?;
        let mut properties = retained_properties(context, self.domains, &source_policy)?;
        let mut actual = self.emitted_policy(&properties, overrides, ancestors)?;
        if actual != source_policy {
            if context.at.is_empty() {
                return Err(Error::Boundary);
            }
            for (name, value) in &source_policy.values {
                if actual.value(*name)? != value.as_deref() {
                    // Some effective defaults, including an unset baseline,
                    // have no explicit binding in the existing property grammar.
                    // Such a value cannot override a different emitted ancestor.
                    let value = value.as_ref().ok_or(Error::Boundary)?;
                    if *name == PropertyName::Domain
                        && self.domains.is_none()
                        && context.tree.props().is_none_or(|props| {
                            !props.iter().any(|property| property.name == "domain")
                        })
                    {
                        return Err(Error::DomainContext(super::domain::DomainError::Missing(
                            context.tree.root_identity(),
                        )));
                    }
                    let properties = properties.get_or_insert_with(Vec::new);
                    properties.retain(|(existing, _)| existing != name.as_str());
                    properties.push((String::from(name.as_str()), value.clone()));
                }
            }
            if let Some(properties) = &mut properties {
                properties.sort_by(|left, right| {
                    left.0
                        .len()
                        .cmp(&right.0.len())
                        .then_with(|| left.0.as_bytes().cmp(right.0.as_bytes()))
                });
            }
            actual = self.emitted_policy(&properties, overrides, ancestors)?;
            if actual != source_policy {
                return Err(Error::Boundary);
            }
        }
        if let Some(parent) = parent_policy {
            actual.validate_parent(parent)?;
        }

        let property_refs = borrowed_properties(&properties);
        let mut layers = ancestors.to_vec();
        layers.push(RootLayer {
            properties: &property_refs,
            overrides,
        });
        let selected = self.selected;

        let mut entries = Vec::new();
        let mut hidden = Vec::<Vec<u8>>::new();
        let mut groups = BTreeMap::<Vec<u8>, Vec<u8>>::new();
        let start = if prefix.is_empty() {
            Vec::new()
        } else {
            joined(prefix, &[])
        };
        let end = if prefix.is_empty() {
            None
        } else {
            let mut end = prefix.to_vec();
            end.push(b'0');
            Some(end)
        };
        let bounds = (
            Bound::Included(start.as_slice()),
            end.as_deref().map_or(Bound::Unbounded, Bound::Excluded),
        );
        let project_links = !context.at.is_empty()
            || selected
                .range::<[u8], _>(bounds)
                .any(|(_, source)| source.target.is_some() || !source.context.at.is_empty());
        for (path, source) in selected.range::<[u8], _>(bounds) {
            while hidden.last().is_some_and(|at| {
                let mut end = at.clone();
                end.push(b'0');
                path >= &end
            }) {
                hidden.pop();
            }
            if hidden.last().is_some_and(|at| super::beneath(path, at)) {
                continue;
            }
            let key = if prefix.is_empty() {
                path.as_slice()
            } else {
                &path[prefix.len() + 1..]
            };
            tree_format::validate_key(key).map_err(Error::Key)?;

            // Removing a root context must preserve its authority and trust policy.
            // Flat inputs retain the existing top-root composition semantics.
            if (!context.at.is_empty() || !source.context.at.is_empty())
                && (context.view != source.context.view || context.at != source.context.at)
                && actual != (self.source_policy)(&source.context.view, &source.context.at)?
            {
                return Err(Error::Boundary);
            }

            let mut entry = source.entry.clone();
            if let Some(target) = source.target {
                let child_context = Context {
                    tree: target,
                    view: source.context.view,
                    at: path.clone(),
                };
                let graft_overrides = match &source.entry.kind {
                    EntryKind::Tree { props, .. } => props.as_deref().unwrap_or_default(),
                    _ => return Err(Error::Structure),
                };
                let root = self.root(
                    &child_context,
                    path,
                    &layers,
                    graft_overrides,
                    Some(&actual),
                )?;
                if let EntryKind::Tree { root: original, .. } = &mut entry.kind
                    && *original != root
                {
                    *original = root;
                    entry.provenance = None;
                }
                hidden.push(path.clone());
            }
            if let EntryKind::File {
                link_id: Some(id), ..
            } = &mut entry.kind
                && project_links
            {
                // Layered roots at one occurrence share root-relative link identities.
                // Different occurrences remain separate after inlining their keys.
                let group = joined(&source.context.at, id);
                *id = groups.entry(group).or_insert_with(|| key.to_vec());
            }
            entries.push((
                key.to_vec(),
                tree_format::encode_entry(&entry, context.tree.min_chunk_size())
                    .map_err(Error::Key)?,
            ));
        }

        let prepared = PreparedRoot {
            entries,
            properties,
            min_chunk_size: context.tree.min_chunk_size(),
        };
        let identity = prepared.materialize()?.root_identity();
        self.output.push(prepared);
        Ok(identity)
    }

    fn emitted_policy(
        &self,
        properties: &Option<PreparedPropertyBindings>,
        overrides: &[Property<'_>],
        ancestors: &[RootLayer<'_>],
    ) -> Result<OverlayPolicy, Error> {
        let property_refs = borrowed_properties(properties);
        let mut layers = ancestors.to_vec();
        layers.push(RootLayer {
            properties: &property_refs,
            overrides,
        });
        (self.result_policy)(&self.view, &layers)
    }
}

fn borrowed_properties(properties: &Option<PreparedPropertyBindings>) -> Vec<Property<'_>> {
    properties
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|(name, value)| Property { name, value })
        .collect()
}

fn retained_properties(
    context: &Context<'_, '_>,
    domains: Option<&super::OperationDomains>,
    source_policy: &OverlayPolicy,
) -> Result<Option<PreparedPropertyBindings>, Error> {
    let raw = context.tree.props();
    if !context.at.is_empty()
        && domains.is_none()
        && raw.is_none_or(|props| !props.iter().any(|property| property.name == "domain"))
    {
        return Ok(raw.map(|properties| {
            properties
                .iter()
                .map(|property| (String::from(property.name), property.value.to_vec()))
                .collect()
        }));
    }
    let properties = super::domain::preserved_properties(
        context.tree,
        context.tree.props().map(<[_]>::to_vec),
        domains,
    )?;
    let domain = properties
        .as_ref()
        .and_then(|properties| properties.iter().find(|property| property.name == "domain"))
        .ok_or(Error::Boundary)?;
    let (_, retained_domain) =
        crate::properties::validate_property(domain).map_err(|_| Error::Boundary)?;
    let Value::Text(retained_domain) = retained_domain else {
        return Err(Error::Boundary);
    };
    let mut encoded = Vec::new();
    crate::cbor::write_text(&mut encoded, retained_domain);
    if source_policy.value(PropertyName::Domain)? != Some(encoded.as_slice()) {
        return Err(Error::Boundary);
    }
    let retained = if context.at.is_empty() {
        properties.as_deref()
    } else {
        raw
    };
    Ok(retained.map(|properties| {
        properties
            .iter()
            .map(|property| (String::from(property.name), property.value.to_vec()))
            .collect()
    }))
}

fn collect_range<'a>(
    tree: &Tree<'a>,
    at: &[u8],
    start: &[u8],
    end: Option<&[u8]>,
    roots: &impl Roots<'a>,
    visited: &mut Vec<Digest>,
    output: &mut Vec<LeafItem<'a>>,
) -> Result<(), Error> {
    if !namespace_intersects(at, start, end) {
        return Ok(());
    }
    if visited.contains(&tree.root_identity()) || visited.len() > tree_format::MAX_GRAFT_DEPTH {
        return Err(Error::Cycle);
    }
    visited.push(tree.root_identity());

    let local_start = if at.is_empty() {
        start
    } else if super::beneath(start, at) {
        &start[at.len() + 1..]
    } else {
        &[]
    };
    let mut pending = Vec::<(Vec<u8>, &Tree<'a>)>::new();
    // A seek skips prefix descriptors whose descendant ranges can still follow
    // the start: `g/child` follows `g!`, as well as containing `g/child/x`.
    // Prefix seeks find these ranges without scanning preceding siblings. Longer
    // matching prefixes have earlier ranges and are consumed first from the stack.
    for (offset, byte) in local_start.iter().enumerate() {
        if *byte <= b'/'
            && let Some(Entry {
                kind: EntryKind::Tree { root, .. },
                ..
            }) = tree.get(&local_start[..offset])
        {
            let path = joined(at, &local_start[..offset]);
            if namespace_intersects(&path, start, end) {
                pending.push((path, resolved_target(root, roots)?));
            }
        }
    }
    let mut cursor = tree.cursor_from(local_start).peekable();
    loop {
        // Descriptor order and descendant order differ for siblings such as
        // `g!` and `g/child`. Defer a graft until its namespace range starts.
        // TREE-5 makes those ranges disjoint; the newest pending prefix is the
        // earliest one until the physical cursor reaches it.
        if let Some((path, _)) = pending.last() {
            let lower = joined(path, &[]);
            if cursor
                .peek()
                .is_none_or(|item| joined(at, &item.key) >= lower)
            {
                if let Some((path, target)) = pending.pop() {
                    collect_range(target, &path, start, end, roots, visited, output)?;
                }
                continue;
            }
        }
        let Some(item) = cursor.next() else {
            break;
        };
        let path = joined(at, &item.key);
        if end.is_some_and(|end| path.as_slice() >= end) {
            break;
        }
        if path.as_slice() >= start {
            output.push(LeafItem {
                key: path.clone(),
                entry: item.entry.clone(),
            });
        }
        if let EntryKind::Tree { root, .. } = &item.entry.kind
            && namespace_intersects(&path, start, end)
        {
            pending.push((path, resolved_target(root, roots)?));
        }
    }
    visited.pop();
    Ok(())
}

fn namespace_intersects(at: &[u8], start: &[u8], end: Option<&[u8]>) -> bool {
    if end.is_some_and(|end| start >= end) {
        return false;
    }
    if at.is_empty() {
        return true;
    }
    let mut lower = at.to_vec();
    lower.push(b'/');
    let mut upper = at.to_vec();
    upper.push(b'0');
    start < upper.as_slice() && end.is_none_or(|end| end > lower.as_slice())
}

fn resolved_target<'t, 'a>(
    root: &Digest,
    roots: &'t impl Roots<'a>,
) -> Result<&'t Tree<'a>, Error> {
    let target = roots.resolve(root).ok_or(Error::MissingRoot)?;
    if target.root_identity() != *root {
        return Err(Error::RootIdentity);
    }
    Ok(target)
}
