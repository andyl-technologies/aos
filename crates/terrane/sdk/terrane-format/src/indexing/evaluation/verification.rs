//! Checks physical Nodes and exact source relations with measured canonical reconstruction.
//!
//! One exhaustive namespace traversal builds occurrence-owned expected routes.
//! Carrier checking then visits only that relation output, retaining independent
//! physical checks for every repeated route occurrence.

use super::*;

/// Expected rows for one predicate at one namespace occurrence.
struct ExpectedRow {
    key: Vec<u8>,
    children: Option<Vec<ExpectedRow>>,
}

/// Inventories independently loaded namespace occurrences without consulting carriers.
///
/// Retains the complete expected relation output rather than only predicates.
/// Source counters measure enumeration, not allocation or total CPU work.
fn inventory(
    source: &Source<'_, '_>,
    root: Digest,
    active: &mut Vec<Digest>,
    work: &mut Work,
) -> Result<BTreeMap<Predicate, Vec<ExpectedRow>>, Error> {
    source.enter(root, active, work)?;
    let mut relations: BTreeMap<Predicate, Vec<ExpectedRow>> = BTreeMap::new();
    for item in source.tree(root)?.iter() {
        work.source_entries = work.source_entries.checked_add(1).ok_or(Error::Limit)?;
        validate_namespace_attributes(2, &item.entry)?;
        match &item.entry.kind {
            EntryKind::File { content, .. } => {
                let predicate = Predicate {
                    object: object(content),
                    value: source.value(&item.entry)?.map(<[u8]>::to_vec),
                };
                relations.entry(predicate).or_default().push(ExpectedRow {
                    key: item.key.clone(),
                    children: None,
                });
            }
            EntryKind::Tree { root: child, props } => {
                if props.as_ref().is_some_and(|properties| {
                    properties
                        .iter()
                        .any(|property| matches!(property.name, "index-roots" | "index-gaps"))
                }) {
                    return Err(Error::Source);
                }
                // Each occurrence owns its relations. Shared digests must still
                // undergo branch, depth and contextual validation on every hop.
                for (predicate, children) in inventory(source, *child, active, work)? {
                    relations.entry(predicate).or_default().push(ExpectedRow {
                        key: item.key.clone(),
                        children: Some(children),
                    });
                }
            }
            EntryKind::Conflict { .. } => return Err(Error::Incomplete),
            _ => {}
        }
    }
    active.pop();
    Ok(relations)
}

struct Reader<'data> {
    data: &'data IndexData,
    context: SemanticContext,
    minimum: u64,
    used: BTreeSet<Digest>,
    work: Work,
    physical_work: PhysicalWork,
}

impl<'data> Reader<'data> {
    fn physical(
        &mut self,
        root: Digest,
        role: Role,
    ) -> Result<(Vec<LeafItem<'data>>, Option<Digest>), Error> {
        let mut entries = Vec::new();
        let mut active = Vec::new();
        self.node(root, role, true, &mut active, &mut entries)?;
        let bytes = self.data.nodes.get(&root).ok_or(Error::MissingNode)?;
        self.record_decode(bytes.len())?;
        let node = decode_node_for(bytes, true, self.minimum, TreeUse::Index)?;
        let gap = validate_node(self.context, role, &node, true)?.map(|binding| binding.node());
        // This constructor emits exactly one empty frame, accounted below.
        // Full insertion and property replacement use the measured editor seam.
        let empty = Tree::build(Vec::new(), None, self.minimum, TreeUse::Index)?;
        let initial = crate::tree_builder::StreamWork {
            node_bytes_encoded: empty.root().encoded().len(),
            node_bytes_hashed: self.preimage_length(empty.root().encoded().len())?,
            ..Default::default()
        };
        let edits: Vec<_> = entries
            .iter()
            .map(|item| (item.key.clone(), Some(item.entry.clone())))
            .collect();
        let inserted = empty.edit_entries(&edits)?;
        let properties = inserted.tree.with_properties(node.props)?;
        let canonical = properties.tree;
        self.physical_work.reconstructions.push(ReconstructionWork {
            root,
            initial,
            entries: inserted.work,
            properties: properties.work,
        });
        if canonical.root_identity() != root {
            return Err(Error::Relationship);
        }
        Ok((entries, gap))
    }

    fn preimage_length(&self, bytes: usize) -> Result<usize, Error> {
        bytes
            .checked_add(
                TERRANE_V1
                    .domain(IdentityKind::Node)
                    .map_err(|_| Error::Relationship)?
                    .len(),
            )
            .and_then(|length| length.checked_add(1))
            .ok_or(Error::Limit)
    }

    fn record_decode(&mut self, bytes: usize) -> Result<(), Error> {
        self.physical_work.node_decodes = self
            .physical_work
            .node_decodes
            .checked_add(1)
            .ok_or(Error::Limit)?;
        self.physical_work.node_bytes_decoded = self
            .physical_work
            .node_bytes_decoded
            .checked_add(bytes)
            .ok_or(Error::Limit)?;
        Ok(())
    }

    fn node(
        &mut self,
        digest: Digest,
        role: Role,
        is_root: bool,
        active: &mut Vec<Digest>,
        entries: &mut Vec<LeafItem<'data>>,
    ) -> Result<u8, Error> {
        if active.len() > usize::from(MAX_TREE_LEVEL) || active.contains(&digest) {
            return Err(Error::Limit);
        }
        let bytes = self.data.nodes.get(&digest).ok_or(Error::MissingNode)?;
        self.physical_work.node_bytes_hashed = self
            .physical_work
            .node_bytes_hashed
            .checked_add(self.preimage_length(bytes.len())?)
            .ok_or(Error::Limit)?;
        let identity = TERRANE_V1
            .calculate(IdentityKind::Node, bytes)
            .map_err(|_| Error::Relationship)?
            .terrane_v1_digest()
            .map_err(|_| Error::Relationship)?;
        if identity != digest {
            return Err(Error::Relationship);
        }
        self.record_decode(bytes.len())?;
        let node = decode_node_for(bytes, is_root, self.minimum, TreeUse::Index)?;
        validate_node(self.context, role, &node, is_root)?;
        self.used.insert(digest);
        self.work.nodes = self.work.nodes.checked_add(1).ok_or(Error::Limit)?;
        active.push(digest);
        match node.items {
            NodeItems::Leaf(items) => {
                self.work.rows = self
                    .work
                    .rows
                    .checked_add(items.len())
                    .ok_or(Error::Limit)?;
                entries.extend(items);
            }
            NodeItems::Internal(references) => {
                for reference in references {
                    let level = self.node(reference.child, role, false, active, entries)?;
                    if level.checked_add(1) != Some(node.level) {
                        return Err(Error::Relationship);
                    }
                }
            }
        }
        active.pop();
        Ok(node.level)
    }

    fn route(
        &mut self,
        predicate: &Predicate,
        root: Digest,
        expected: &[ExpectedRow],
    ) -> Result<(), Error> {
        let role = if predicate.value.is_some() {
            Role::PresentRoute
        } else {
            Role::MissingRoute
        };
        let (rows, gap) = self.physical(root, role)?;
        if expected.is_empty() || rows.len() != expected.len() || gap.is_some() {
            return Err(Error::Relationship);
        }
        for (row, expected) in rows.iter().zip(expected) {
            if row.key != expected.key {
                return Err(Error::Relationship);
            }
            let classified = validate_row(self.context, role, &row.key, &row.entry)?;
            if classified.object() != predicate.object {
                return Err(Error::Relationship);
            }
            match (&expected.children, classified.route()) {
                (None, None) => {}
                (Some(children), Some(child)) => self.route(predicate, child, children)?,
                _ => return Err(Error::Relationship),
            }
        }
        Ok(())
    }
}

/// Exhaustively verifies canonical auxiliary bytes against independently loaded sources.
///
/// Enumerates each namespace occurrence once; source work counts that traversal.
/// Physical work still counts every carrier occurrence and reconstruction.
/// Checks every actual source occurrence, including absent inline values and
/// repeated grafts. A digest cache does not suppress contextual checks. The
/// supplied Node map must be exactly the reachable auxiliary closure; extra
/// storage objects can be retained separately by a caller. Successful checking
/// proves immutable data only, without current policy or producer applicability.
///
/// # Errors
/// Rejects invalid source contexts, unavailable or wrongly hashed Nodes,
/// noncanonical boundaries, role/placement errors, empty forwarding routes,
/// omissions/additions, divergent objects/values/grafts, cycles/depth limits,
/// unsupported conditional coverage and invalid registered value types.
pub fn verify(
    recipe: &IndexEvaluationRecipe<'_>,
    trees: &BTreeMap<Digest, Tree<'_>>,
    minimum: u64,
    context: SemanticContext,
    data: &IndexData,
) -> Result<Verification, Error> {
    let source = Source {
        trees,
        attribute: recipe.attribute(),
        minimum,
    };
    let mut reader = Reader {
        data,
        context,
        minimum,
        used: BTreeSet::new(),
        work: Work::default(),
        physical_work: PhysicalWork::default(),
    };
    let relations = inventory(&source, recipe.owner(), &mut Vec::new(), &mut reader.work)?;
    let (primary, gap) = reader.physical(data.root, Role::Primary)?;
    let missing_objects = relations
        .keys()
        .filter(|predicate| predicate.value.is_none())
        .count();
    let candidates = relations.len() - missing_objects;
    if primary.len() != candidates || gap.is_some() != (missing_objects != 0) {
        return Err(Error::Relationship);
    }
    let gaps = match gap {
        Some(root) => {
            let (rows, nested_gap) = reader.physical(root, Role::Gap)?;
            if rows.len() != missing_objects || nested_gap.is_some() {
                return Err(Error::Relationship);
            }
            rows
        }
        None => Vec::new(),
    };

    for (predicate, expected) in relations {
        let (rows, role, key) = match &predicate.value {
            Some(value) => (
                &primary,
                Role::Primary,
                IndexKey::new(value, predicate.object)?.encode(),
            ),
            None => (&gaps, Role::Gap, predicate.object.to_vec()),
        };
        let position = rows
            .binary_search_by(|row| row.key.cmp(&key))
            .map_err(|_| Error::Relationship)?;
        let row = &rows[position];
        let classified = validate_row(context, role, &row.key, &row.entry)?;
        if classified.object() != predicate.object {
            return Err(Error::Relationship);
        }
        let route = classified.route().ok_or(Error::Relationship)?;
        reader.route(&predicate, route, &expected)?;
    }
    if reader.used.len() != data.nodes.len() {
        return Err(Error::Relationship);
    }
    Ok(Verification {
        candidates,
        missing_objects,
        work: reader.work,
        physical_work: reader.physical_work,
    })
}
