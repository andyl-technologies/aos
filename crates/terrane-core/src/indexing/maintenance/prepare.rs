//! Proves existing relationships once and retains canonical contextual Trees.

use alloc::{collections::BTreeMap, rc::Rc, string::ToString, vec::Vec};

use super::{
    ByteArena, Coordinate, Error, Predicate, PreparationWork, PreparedIndex, closure,
    persistent::Map, selected,
};
use crate::{
    identity::Digest,
    indexing::{
        IndexEvaluationRecipe, IndexKey,
        carrier::{Role, SemanticContext, validate_node, validate_row},
        evaluation::{self, IndexData},
        incremental::PreparedSource,
    },
    tree_builder::Tree,
    tree_format::{LeafItem, NodeItems, Property, TreeUse, decode_node_for},
};

struct Reader<'a> {
    data: &'a IndexData,
    minimum: u64,
    context: SemanticContext,
    cache: BTreeMap<Digest, Rc<Tree<'a>>>,
    work: PreparationWork,
}

impl<'a> Reader<'a> {
    fn rows(
        &mut self,
        root: Digest,
        is_root: bool,
        rows: &mut Vec<LeafItem<'a>>,
    ) -> Result<Option<Vec<Property<'a>>>, Error> {
        let bytes = self
            .data
            .nodes
            .get(&root)
            .ok_or(evaluation::Error::MissingNode)?;
        super::accounting::add(&mut self.work.decoded_nodes, 1)?;
        super::accounting::add(&mut self.work.decoded_bytes, bytes.len())?;
        let node = decode_node_for(bytes, is_root, self.minimum, TreeUse::Index)?;
        match node.items {
            NodeItems::Leaf(items) => rows.extend(items),
            NodeItems::Internal(children) => {
                for child in children {
                    self.rows(child.child, false, rows)?;
                }
            }
        }
        Ok(node.props)
    }

    fn tree(&mut self, root: Digest, role: Role) -> Result<Rc<Tree<'a>>, Error> {
        if let Some(tree) = self.cache.get(&root) {
            return Ok(Rc::clone(tree));
        }
        let mut rows = Vec::new();
        let properties = self.rows(root, true, &mut rows)?;
        let empty = Tree::build(Vec::new(), None, self.minimum, TreeUse::Index)?;
        super::accounting::add(&mut self.work.empty_trees, 1)?;
        super::accounting::add(
            &mut self.work.empty_bytes_encoded,
            empty.root().encoded().len(),
        )?;
        super::accounting::add(
            &mut self.work.empty_bytes_hashed,
            empty.root().encoded().len() + b"terrane-node-v1\0".len(),
        )?;
        let edits: Vec<_> = rows
            .into_iter()
            .map(|row| (row.key, Some(row.entry)))
            .collect();
        let result = empty.edit_entries(&edits)?;
        self.work.reconstruction.push(result.work);
        let result = result.tree.with_properties(properties)?;
        self.work.reconstruction.push(result.work);
        if result.tree.root_identity() != root {
            return Err(evaluation::Error::Relationship.into());
        }
        validate_node(self.context, role, result.tree.root().node(), true)?;
        let tree = Rc::new(result.tree);
        self.cache.insert(root, Rc::clone(&tree));
        Ok(tree)
    }

    fn route(
        &mut self,
        predicate: &Predicate,
        hops: Vec<Vec<u8>>,
        root: Digest,
        routes: &mut Map<Coordinate, Rc<Tree<'a>>>,
    ) -> Result<(), Error> {
        let coordinate = Coordinate::Route {
            predicate: predicate.clone(),
            hops: hops.clone(),
        };
        let tree = self.tree(root, coordinate.role())?;
        routes.insert(coordinate.clone(), Rc::clone(&tree), &mut self.work.maps);
        for item in tree.iter() {
            let row = validate_row(self.context, coordinate.role(), &item.key, &item.entry)?;
            if let Some(child) = row.route() {
                let mut child_hops = hops.clone();
                child_hops.push(item.key.clone());
                self.route(predicate, child_hops, child, routes)?;
            }
        }
        Ok(())
    }
}

/// Independently verifies and retains an existing exact ordinary index closure.
///
/// The report preserves independent-verifier traversal events and physical
/// decoding, hashing and reconstruction phases separately from the later
/// measured retention reconstruction. Update reuses the retained state directly.
/// The supplied byte data and stable arena must outlive every retained snapshot.
///
/// # Errors
/// Rejects mismatched source selection, unsupported semantics/geometry, invalid
/// canonical data, omitted/extra closure objects and any divergent relationship.
pub fn prepare<'graph, 'epoch>(
    recipe: &IndexEvaluationRecipe<'_>,
    source: &PreparedSource<'graph, 'epoch>,
    graph: &'graph BTreeMap<Digest, Tree<'epoch>>,
    data: &'epoch IndexData,
    arena: &'epoch ByteArena,
    minimum: u64,
    context: SemanticContext,
) -> Result<(PreparedIndex<'graph, 'epoch>, PreparationWork), Error> {
    selected(source, recipe.owner(), recipe.attribute())?;
    let verification = evaluation::verify(recipe, graph, minimum, context, data)?;
    let mut reader = Reader {
        data,
        minimum,
        context,
        cache: BTreeMap::new(),
        work: PreparationWork {
            verification: verification.work,
            verification_physical: verification.physical_work,
            ..PreparationWork::default()
        },
    };
    let primary = reader.tree(data.root, Role::Primary)?;
    let gap = validate_node(context, Role::Primary, primary.root().node(), true)?
        .map(|binding| binding.node());
    let gap = gap.map(|root| reader.tree(root, Role::Gap)).transpose()?;
    let mut routes = Map::default();
    for item in primary.iter() {
        let key = IndexKey::decode(&item.key)?;
        let predicate = Predicate {
            object: key.object(),
            value: Some(key.value().to_vec()),
        };
        let row = validate_row(context, Role::Primary, &item.key, &item.entry)?;
        reader.route(
            &predicate,
            Vec::new(),
            row.route().ok_or(Error::Transition)?,
            &mut routes,
        )?;
    }
    if let Some(gap) = &gap {
        for item in gap.iter() {
            let row = validate_row(context, Role::Gap, &item.key, &item.entry)?;
            let predicate = Predicate {
                object: row.object(),
                value: None,
            };
            reader.route(
                &predicate,
                Vec::new(),
                row.route().ok_or(Error::Transition)?,
                &mut routes,
            )?;
        }
    }
    let mut staged = super::temporary::Ordered::new();
    for tree in reader.cache.values() {
        // Retained Tree children expose safe shared handles, so stage from
        // the actual root graph rather than manufacturing StoredNodes.
        fn stage_tree<'a>(
            node: Rc<crate::tree_builder::StoredNode<'a>>,
            context: SemanticContext,
            staged: &mut super::temporary::Ordered<Digest, closure::Record<'a>>,
            work: &mut super::StagingWork,
        ) -> Result<(), Error> {
            if staged.contains_key(&node.identity()) {
                return Ok(());
            }
            for child in node.children() {
                stage_tree(Rc::clone(child), context, staged, work)?;
            }
            work.combine(closure::stage(node, context, staged)?)
        }
        stage_tree(
            tree.root_rc(),
            context,
            &mut staged,
            &mut reader.work.staging,
        )?;
    }
    let mut closure = Map::default();
    let mut work = closure::Work::default();
    closure::add(data.root, &mut closure, &staged, &mut work)?;
    reader.work.maps.combine(work.maps);
    reader.work.edges = work.edges;
    reader.work.temporary.combine(staged.work()?)?;
    reader.work.maps.checked()?;
    let state = PreparedIndex {
        owner: recipe.owner(),
        attribute: recipe.attribute().to_string(),
        minimum,
        context,
        sources: source.lookup().clone(),
        arena,
        primary,
        gap,
        routes,
        closure,
    };
    Ok((state, reader.work))
}

/// Distinguishes full new-population construction from an explicit rebuild.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConstructionKind {
    /// First population of a newly enabled attribute.
    NewlyEnabled,
    /// Full explicit recomputation after divergence or loss.
    Rebuild,
}

/// Reports full population work separately from existing-index maintenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstructionWork {
    /// Explicit full-operation mode selected by the caller.
    pub kind: ConstructionKind,
    /// Complete population, canonical batches and persistent closure work.
    pub work: super::UpdateWork,
}

/// Constructs a newly enabled ordinary population with measured full work.
///
/// Full enumeration is explicitly tagged as initialization. Canonical edits,
/// empty-baseline encoding and closure installation remain visible separately;
/// they do not establish an incremental cost claim. Independent verification
/// and materialization remain explicit separate operations.
///
/// # Errors
/// Rejects mismatched source bindings, unsupported geometry, unavailable
/// affected graph inputs, invalid rows and stable allocation failure.
pub fn initialize<'graph, 'epoch>(
    recipe: &IndexEvaluationRecipe<'_>,
    source: &PreparedSource<'graph, 'epoch>,
    arena: &'epoch ByteArena,
    minimum: u64,
    context: SemanticContext,
) -> Result<(PreparedIndex<'graph, 'epoch>, ConstructionWork), Error> {
    selected(source, recipe.owner(), recipe.attribute())?;
    let discovery = crate::indexing::incremental::discover_with_mode(
        source,
        source,
        crate::indexing::incremental::PopulationMode::NewlyEnabled,
    )?;
    if discovery.sources().minimum() != minimum || discovery.sources().context() != context {
        return Err(Error::Binding);
    }
    let primary = Rc::new(Tree::build(Vec::new(), None, minimum, TreeUse::Index)?);
    let empty_bytes = primary.root().encoded().len();
    let mut staged = super::temporary::Ordered::new();
    let initial_staging = closure::stage(primary.root_rc(), context, &mut staged)?;
    let mut closure = Map::default();
    let mut closure_work = closure::Work::default();
    closure::add(
        primary.root_identity(),
        &mut closure,
        &staged,
        &mut closure_work,
    )?;
    // This baseline is private to the explicit full operation and never
    // escapes as a supposedly checked existing maintained population.
    let baseline = PreparedIndex {
        owner: recipe.owner(),
        attribute: recipe.attribute().to_string(),
        minimum,
        context,
        sources: source.lookup().clone(),
        arena,
        primary,
        gap: None,
        routes: Map::default(),
        closure,
    };
    let (state, mut work) = super::update::apply(
        &baseline,
        &discovery,
        crate::indexing::incremental::PopulationMode::NewlyEnabled,
    )?;
    super::accounting::add(&mut work.empty_trees, 1)?;
    super::accounting::add(&mut work.empty_bytes_encoded, empty_bytes)?;
    super::accounting::add(
        &mut work.empty_bytes_hashed,
        empty_bytes + b"terrane-node-v1\0".len(),
    )?;
    work.temporary.combine(staged.work()?)?;
    work.maps.combine(closure_work.maps);
    super::accounting::add(&mut work.closure_added, closure_work.added)?;
    work.staging.combine(initial_staging)?;
    work.maps.checked()?;
    Ok((
        state,
        ConstructionWork {
            kind: ConstructionKind::NewlyEnabled,
            work,
        },
    ))
}

/// Explicitly recomputes immutable ordinary data after reporting divergence.
///
/// The caller must publish a corrected owner separately. Full work is labeled
/// rebuild and never used as an implicit existing-index update fallback.
///
/// # Errors
/// Rejects the same invalid contexts and allocation failures as initialization.
pub fn rebuild<'graph, 'epoch>(
    recipe: &IndexEvaluationRecipe<'_>,
    source: &PreparedSource<'graph, 'epoch>,
    arena: &'epoch ByteArena,
    minimum: u64,
    context: SemanticContext,
) -> Result<(PreparedIndex<'graph, 'epoch>, ConstructionWork), Error> {
    let (state, mut work) = initialize(recipe, source, arena, minimum, context)?;
    work.kind = ConstructionKind::Rebuild;
    Ok((state, work))
}
