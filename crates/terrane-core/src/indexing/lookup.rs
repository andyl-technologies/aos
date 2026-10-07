//! Queries completely checked immutable primary and local occurrence data.
//!
//! Preparation verifies the complete owner-bound relationship and loads stable
//! physical Nodes. Equality seeks use a retained sorted primary index; route
//! walks resolve only actual local keys in the independently selected sources.
//! Results are immutable candidates, never authorized answers or producer evidence.
//!
//! ```text
//! canonical-CBOR(value) || object[32] -> nonempty local occurrence route
//! index-gaps -> object[32] -> nonempty missing-value route
//! ```

mod traversal;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cmp::Ordering;

use super::carrier::{Role, SemanticContext, validate_node, validate_row};
use super::evaluation::{self, Error, IndexData, Verification};
use super::{IndexEvaluationRecipe, IndexKey, IndexRoots};
use crate::identity::Digest;
use crate::tree_builder::Tree;
use crate::tree_format::{LeafItem, Node, NodeItems, decode_node_for};

pub use traversal::{Hop, Occurrence, OccurrenceProbe, Occurrences};

/// Counts immutable C/P and W operations independently of current checks.
///
/// Comparisons count comparison calls, not compared bytes: digests have 32
/// bytes, names at most 255 bytes, and keys/values at most 4096 bytes. Carrier
/// and canonical-value checks have those fixed profile bounds. Every cache
/// probe, source-key comparison, attribute-name probe, active-branch comparison
/// and explicit object/value check contributes to W instead of being hidden in
/// a Node/root visit. Current producer, authority and trust work is not performed.
///
/// Output stores one fixed-size [`Candidate`] per C or missing row and one
/// fixed-size [`Occurrence`] per P. Each copied [`Hop`] record is counted, and
/// all cloned key bytes are counted separately. At most 64 hops accompany a
/// terminal, so terminal export copies at most 65 * 4096 key bytes and 64 Hop
/// records per P; creating a forwarding Hop copies at most 4096 key bytes.
/// Fixed record storage and amortized vector growth are charged to those
/// C/P/Hop records, not described as measured allocator or machine instructions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Work {
    /// Ordered primary/gap seek comparison calls on keys of at most 4096 bytes.
    pub comparisons: usize,
    /// Primary rows returned, before any current checks (C).
    pub candidates: usize,
    /// Missing-object rows returned, separately from primary C.
    pub missing_rows: usize,
    /// Actual terminal file occurrences returned (P).
    pub occurrences: usize,
    /// Physical auxiliary Node visits during route walking (W).
    pub route_nodes: usize,
    /// Internal auxiliary child edges traversed (W), including early prefixes.
    pub route_edges: usize,
    /// Local auxiliary leaf rows examined (W).
    pub route_rows: usize,
    /// Physical namespace Node visits during local resolution (W).
    pub source_nodes: usize,
    /// Namespace separator/leaf key comparison calls (W).
    pub source_comparisons: usize,
    /// Source-root occurrences entered, counting shared sibling grafts (W).
    pub source_roots: usize,
    /// Sorted physical-Node cache searches attempted (W).
    pub physical_cache_lookups: usize,
    /// Physical-cache digest probes, each making one 32-byte comparison (W).
    pub physical_cache_comparisons: usize,
    /// Sorted source-root cache searches attempted (W).
    pub source_cache_lookups: usize,
    /// Source-cache digest probes, each making one 32-byte comparison (W).
    pub source_cache_comparisons: usize,
    /// Namespace attribute-name equality probes, each bounded to 255 bytes (W).
    pub attribute_name_probes: usize,
    /// Actual terminal canonical value/absence equality checks (W).
    pub terminal_value_checks: usize,
    /// Explicit carrier-O and actual file-O digest equality checks (W).
    pub object_checks: usize,
    /// Closed contextual carrier validation calls, including bounded key checks (W).
    pub carrier_checks: usize,
    /// Query value schema/canonical validation calls on bounded operands (W).
    pub value_validations: usize,
    /// Additional canonical key construction/decoding checks (W).
    pub key_checks: usize,
    /// Source active-branch digest equality comparisons (W).
    pub source_cycle_comparisons: usize,
    /// Physical route active-branch digest equality comparisons (W).
    pub route_cycle_comparisons: usize,
    /// Bytes copied into seek bounds, new local keys and cloned hop keys (W).
    pub key_bytes_copied: usize,
    /// Hop records created or copied into terminal paths, excluding borrowed Entry data (W).
    pub hop_records_copied: usize,
}

fn increment(counter: &mut usize, amount: usize) -> Result<(), Error> {
    *counter = counter.checked_add(amount).ok_or(Error::Limit)?;
    Ok(())
}

/// Separates complete verification from subsequent one-time index/cache loading.
///
/// The verifier reports source/Node/row events separately from supplied-Node
/// hashing and canonical reconstruction phases. Loading reports decoded input
/// bytes, retained cache entries and ordered-index copies separately. These
/// reports do not claim complete preparation CPU or allocation costs, or a
/// bound on the potentially superlinear exhaustive verifier. Cloning this
/// report also clones its retained reconstruction traces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Preparation {
    /// Complete relationship result with separate verifier physical work.
    pub verification: Verification,
    /// Physical Nodes decoded once into the retained auxiliary closure.
    pub loaded_nodes: usize,
    /// Encoded auxiliary bytes loaded, including Node framing.
    pub loaded_bytes: usize,
    /// Primary and gap leaf rows copied into ordered seek indexes.
    pub indexed_rows: usize,
    /// Complete physical-Node cache entries retained in digest order.
    pub physical_cache_roots: usize,
    /// Borrowed source-root cache entries retained, including unrelated supplied roots.
    pub source_cache_roots: usize,
    /// Physical-cache searches used to load primary/gap indexes and root metadata.
    pub cache_lookups: usize,
    /// Digest comparison calls during those preparation-only searches.
    pub cache_comparisons: usize,
}

/// Retains a private, completely checked owner/attribute/context relationship.
///
/// Construction is available only through [`Self::prepare`]. Borrowed inputs
/// remain immutable for its lifetime. This establishes no current authority,
/// trust, producer applicability, or coverage exclusions.
pub struct Prepared<'data, 'value> {
    trees: Vec<(Digest, &'data Tree<'value>)>,
    recipe: IndexEvaluationRecipe<'data>,
    context: SemanticContext,
    minimum: u64,
    root: Digest,
    gap: Option<Digest>,
    nodes: Vec<(Digest, Node<'data>)>,
    primary: Vec<LeafItem<'data>>,
    gaps: Vec<LeafItem<'data>>,
    preparation: Preparation,
}

impl<'data, 'value> Prepared<'data, 'value> {
    /// Checks owner binding and the entire immutable relationship before loading.
    ///
    /// # Errors
    /// Rejects absent or divergent owner-local bindings, incomplete source
    /// evidence, malformed or unsupported contexts, geometry, values, physical
    /// Nodes, closures, routes and all omitted or extra occurrences.
    pub fn prepare(
        recipe: IndexEvaluationRecipe<'data>,
        trees: &'data BTreeMap<Digest, Tree<'value>>,
        minimum: u64,
        context: SemanticContext,
        data: &'data IndexData,
    ) -> Result<Self, Error> {
        let owner = trees.get(&recipe.owner()).ok_or(Error::MissingSource)?;
        let binding = owner
            .props()
            .and_then(|properties| {
                properties
                    .iter()
                    .find(|property| property.name == "index-roots")
            })
            .ok_or(Error::Incomplete)?;
        match IndexRoots::decode_binding(binding.value)?.get(recipe.attribute()) {
            Some(root) if root == data.root => {}
            Some(_) => return Err(Error::Relationship),
            None => return Err(Error::Incomplete),
        }
        let verification = evaluation::verify(&recipe, trees, minimum, context, data)?;

        let mut nodes = Vec::with_capacity(data.nodes.len());
        let mut loaded_bytes = 0;
        for (digest, bytes) in &data.nodes {
            increment(&mut loaded_bytes, bytes.len())?;
            nodes.push((
                *digest,
                decode_node_for(bytes, true, minimum, crate::tree_format::TreeUse::Index)?,
            ));
        }
        let mut cache_lookups = 1;
        let mut cache_comparisons = 0;
        let position =
            cache_position(&nodes, data.root, &mut cache_comparisons)?.ok_or(Error::MissingNode)?;
        let root = &nodes[position].1;
        let gap = validate_node(context, Role::Primary, root, true)?.map(|binding| binding.node());
        let mut primary = Vec::new();
        collect(
            &nodes,
            data.root,
            &mut primary,
            &mut cache_lookups,
            &mut cache_comparisons,
        )?;
        let mut gaps = Vec::new();
        if let Some(root) = gap {
            collect(
                &nodes,
                root,
                &mut gaps,
                &mut cache_lookups,
                &mut cache_comparisons,
            )?;
        }
        let indexed_rows = primary.len().checked_add(gaps.len()).ok_or(Error::Limit)?;
        // Both source maps already iterate in digest order. References point
        // into the separately borrowed immutable graph, never into this value.
        let trees: Vec<_> = trees.iter().map(|(digest, tree)| (*digest, tree)).collect();
        let preparation = Preparation {
            verification,
            loaded_nodes: nodes.len(),
            loaded_bytes,
            indexed_rows,
            physical_cache_roots: nodes.len(),
            source_cache_roots: trees.len(),
            cache_lookups,
            cache_comparisons,
        };
        Ok(Self {
            trees,
            recipe,
            context,
            minimum,
            root: data.root,
            gap,
            nodes,
            primary,
            gaps,
            preparation,
        })
    }

    /// Returns the independently selected immutable owner identity.
    pub fn owner(&self) -> Digest {
        self.recipe.owner()
    }

    /// Returns the recipe's exact attribute name.
    pub fn attribute(&self) -> &str {
        self.recipe.attribute()
    }

    /// Returns the canonical primary root selected by the actual owner binding.
    pub fn root(&self) -> Digest {
        self.root
    }

    /// Returns the actual missing-value root, without closing current coverage gaps.
    pub fn gap_root(&self) -> Option<Digest> {
        self.gap
    }

    /// Returns the independently checked semantic revisions.
    pub fn context(&self) -> SemanticContext {
        self.context
    }

    /// Returns the independently checked physical content geometry.
    pub fn minimum(&self) -> u64 {
        self.minimum
    }

    /// Returns the closed executable recipe profile.
    pub fn profile(&self) -> &'static str {
        self.recipe.profile()
    }

    /// Borrows the complete verification result and precisely scoped loading events.
    pub fn preparation(&self) -> &Preparation {
        &self.preparation
    }

    /// Discovers an exact canonical value range in O(log(max(2,n)) + C).
    ///
    /// Ordered index comparisons and returned rows are measured; no source or
    /// auxiliary Node traversal occurs during discovery. Preparation owns the
    /// complete loading cost. Empty discovery does not close missing coverage.
    ///
    /// # Errors
    /// Rejects malformed, unsupported registered values and counter overflow.
    pub fn candidates(&self, value: &[u8]) -> Result<Candidates<'_, 'data, 'value>, Error> {
        let mut work = Work::default();
        increment(&mut work.value_validations, 1)?;
        evaluation::validate_value(self.attribute(), value)?;
        increment(&mut work.key_checks, 1)?;
        let (lower, upper) = IndexKey::new(value, [0; 32])?.equality_bounds();
        increment(&mut work.key_bytes_copied, lower.len())?;
        increment(&mut work.key_bytes_copied, upper.len())?;
        let start = bound(&self.primary, &lower, false, &mut work.comparisons)?;
        let end = bound(&self.primary, &upper, true, &mut work.comparisons)?;
        let rows = self.selections(&self.primary[start..end], Role::Primary, &mut work)?;
        Ok(Candidates { rows, work })
    }

    /// Discovers one missing object's row independently of candidate discovery.
    ///
    /// # Errors
    /// Reports counter overflow or invalid retained relationships.
    pub fn missing(&self, object: Digest) -> Result<Candidates<'_, 'data, 'value>, Error> {
        let mut work = Work::default();
        let start = bound(&self.gaps, &object, false, &mut work.comparisons)?;
        let end = bound(&self.gaps, &object, true, &mut work.comparisons)?;
        let rows = self.selections(&self.gaps[start..end], Role::Gap, &mut work)?;
        Ok(Candidates { rows, work })
    }

    /// Exports every missing object row with explicit linear row cost.
    ///
    /// # Errors
    /// Reports counter overflow or invalid retained relationships.
    pub fn all_missing(&self) -> Result<Candidates<'_, 'data, 'value>, Error> {
        let mut work = Work::default();
        let rows = self.selections(&self.gaps, Role::Gap, &mut work)?;
        Ok(Candidates { rows, work })
    }

    fn selections<'query>(
        &'query self,
        rows: &'query [LeafItem<'data>],
        role: Role,
        work: &mut Work,
    ) -> Result<Vec<Candidate<'query, 'data, 'value>>, Error> {
        let mut output = Vec::with_capacity(rows.len());
        for item in rows {
            if role == Role::Primary {
                increment(&mut work.candidates, 1)?;
            } else {
                increment(&mut work.missing_rows, 1)?;
            }
            increment(&mut work.carrier_checks, 1)?;
            let row = validate_row(self.context, role, &item.key, &item.entry)?;
            let value = if role == Role::Primary {
                increment(&mut work.key_checks, 1)?;
                Some(IndexKey::decode(&item.key)?.value())
            } else {
                None
            };
            output.push(Candidate {
                prepared: self,
                object: row.object(),
                route: row.route().ok_or(Error::Relationship)?,
                value,
            });
        }
        Ok(output)
    }
}

fn collect<'data>(
    nodes: &[(Digest, Node<'data>)],
    root: Digest,
    output: &mut Vec<LeafItem<'data>>,
    lookups: &mut usize,
    comparisons: &mut usize,
) -> Result<(), Error> {
    increment(lookups, 1)?;
    let position = cache_position(nodes, root, comparisons)?.ok_or(Error::MissingNode)?;
    match &nodes[position].1.items {
        NodeItems::Leaf(items) => output.extend(items.iter().cloned()),
        NodeItems::Internal(items) => {
            for item in items {
                collect(nodes, item.child, output, lookups, comparisons)?;
            }
        }
    }
    Ok(())
}

fn cache_position<T>(
    cache: &[(Digest, T)],
    wanted: Digest,
    comparisons: &mut usize,
) -> Result<Option<usize>, Error> {
    let mut low = 0;
    let mut high = cache.len();
    while low < high {
        let middle = low + (high - low) / 2;
        increment(comparisons, 1)?;
        match cache[middle].0.cmp(&wanted) {
            Ordering::Less => low = middle + 1,
            Ordering::Greater => high = middle,
            Ordering::Equal => return Ok(Some(middle)),
        }
    }
    Ok(None)
}

fn bound(
    rows: &[LeafItem<'_>],
    key: &[u8],
    inclusive: bool,
    comparisons: &mut usize,
) -> Result<usize, Error> {
    let mut low = 0;
    let mut high = rows.len();
    while low < high {
        let middle = low + (high - low) / 2;
        increment(comparisons, 1)?;
        let order = rows[middle].key.as_slice().cmp(key);
        if order == Ordering::Less || (inclusive && order == Ordering::Equal) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    Ok(low)
}

/// Contains immutable candidate rows and the discovery work that produced them.
pub struct Candidates<'query, 'data, 'value> {
    /// Exact typed rows, independent of current authorization and trust.
    pub rows: Vec<Candidate<'query, 'data, 'value>>,
    /// Discovery counters, including C and ordered index probes.
    pub work: Work,
}

/// Binds an actual O and nonempty P to its private prepared context.
pub struct Candidate<'query, 'data, 'value> {
    prepared: &'query Prepared<'data, 'value>,
    object: Digest,
    route: Digest,
    value: Option<&'query [u8]>,
}

impl<'query, 'data, 'value> Candidate<'query, 'data, 'value> {
    /// Borrows the checked owner, attribute, profile, geometry and role context.
    pub fn prepared(&self) -> &'query Prepared<'data, 'value> {
        self.prepared
    }

    /// Returns the actual file object identity O.
    pub fn object(&self) -> Digest {
        self.object
    }

    /// Returns the nonempty occurrence route P.
    pub fn route(&self) -> Digest {
        self.route
    }

    /// Borrows the exact present canonical value, or identifies a missing route.
    pub fn value(&self) -> Option<&[u8]> {
        self.value
    }
}
