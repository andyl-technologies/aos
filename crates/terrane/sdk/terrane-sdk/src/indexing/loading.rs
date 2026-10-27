//! Fetches exact namespace and contextual auxiliary closures using only get.

mod frontier;
#[cfg(test)]
mod timings;

use super::*;
use crate::store::ContentStore;
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_format::indexing::IndexRoots;
use terrane_format::indexing::carrier::{
    Role, validate_namespace_attributes, validate_node, validate_row,
};
use terrane_format::tree_format::{
    self, EntryKind, MAX_GRAFT_DEPTH, MAX_TREE_LEVEL, NodeItems, TreeUse, decode_node_for,
};

#[cfg(test)]
use super::tests::FixtureValue;

struct Visit {
    node: Digest,
    is_root: bool,
    role: Option<Role>,
    physical: Vec<Digest>,
    roots: Vec<Digest>,
}

impl Visit {
    fn root(node: Digest, role: Option<Role>, roots: Vec<Digest>) -> Self {
        Self {
            node,
            is_root: true,
            role,
            physical: Vec::new(),
            roots,
        }
    }
}

struct Fetcher<'store, S: ?Sized> {
    store: &'store S,
    context: SemanticContext,
    minimum: u64,
    usage: TreeUse,
    bytes: BTreeMap<Digest, Vec<u8>>,
    namespace: BTreeMap<Digest, Vec<u8>>,
    auxiliary: BTreeMap<Digest, Vec<u8>>,
    roots: BTreeSet<Digest>,
    work: Loading,
    #[cfg(test)]
    timings: timings::LoadTimings,
}

/// Acquires the selected namespace independently of any auxiliary index evidence.
///
/// Only reached `get(Node, None)` requests are issued. Valid `index-roots`
/// pointers remain immutable source data and are never followed; an absent
/// binding is accepted. The caller independently selects the owner, semantic
/// revisions and `cdc-1m` minimum. Store permissions apply to every request;
/// this operation supplies no authority or current coverage proof.
///
/// Returned bytes require separate canonical reconstruction and preparation
/// before explicit initialization or rebuilding. This does not repair an index
/// or silently replace the strict owner-bound [`load`] operation.
///
/// # Errors
/// Reports absent/unavailable namespace evidence as incomplete, retaining the
/// requested Node and original store failure. Rejects unsupported revisions or
/// geometry, wrong addresses, malformed physical Nodes and owner-local wrappers,
/// structural metadata misuse, graft overrides, cycles and independent limits.
pub async fn load_source<S: ContentStore + ?Sized>(
    store: &S,
    owner: Digest,
    revisions: SemanticRevisions,
    minimum: u64,
) -> Result<LoadedSource, Error> {
    load_source_for(store, owner, revisions, minimum, TreeUse::Ordinary).await
}

/// Acquires a canonical namespace under an independently selected physical use.
///
/// `usage` must be ordinary namespace or retained overlay-layer context. It
/// applies to every reached namespace root and physical Node, including graft
/// targets. It never comes from decoded bytes or an auxiliary index. A Layer
/// root is actual immutable data; a virtual composite supplies no such root.
/// Callers must independently authenticate the selected context when required.
/// No index bindings are followed and this read grants no current authority.
///
/// # Errors
/// Reports the same namespace failures as [`load_source`], and rejects Index or
/// surface interpretations without attempting an alternative decode.
pub async fn load_source_for<S: ContentStore + ?Sized>(
    store: &S,
    owner: Digest,
    revisions: SemanticRevisions,
    minimum: u64,
    usage: TreeUse,
) -> Result<LoadedSource, Error> {
    let mut fetcher = Fetcher::new_for(store, revisions, minimum, usage)?;
    fetcher.walk(Visit::root(owner, None, Vec::new())).await?;
    let loading = fetcher.work;

    Ok(fetcher.take_source(owner, loading))
}

/// Loads an independently selected owner and its exact bound index closure.
///
/// Only `get(Node, None)` is used. The registered executable profile currently
/// supports `cdc-1m`; `minimum` must be its independently selected minimum.
/// Neither a memo nor an optional derived ref supplies the owner binding.
/// No content bodies are needed for immutable metadata relationship checking.
/// Returned bytes still require reconstruction and exhaustive preparation.
///
/// # Errors
/// Reports missing owner-local bindings and absent/unavailable store evidence as
/// incomplete, preserves original typed store failures and subjects, and rejects
/// unsupported profiles, invalid addresses, physical Nodes or contextual roles.
pub async fn load<S: ContentStore + ?Sized>(
    store: &S,
    owner: Digest,
    attribute: &str,
    revisions: SemanticRevisions,
    minimum: u64,
) -> Result<Loaded, Error> {
    load_for(
        store,
        owner,
        attribute,
        revisions,
        minimum,
        TreeUse::Ordinary,
    )
    .await
}

/// Loads a retained namespace owner and its index under an explicit physical use.
///
/// The independently selected ordinary or overlay-layer context applies to the
/// complete namespace closure. Auxiliary Nodes retain their exact contextual
/// Index roles. The required owner-local binding is followed and checked by
/// subsequent reconstruction and preparation; Layer use does not waive it.
/// Callers must independently authenticate the selected context when required.
///
/// # Errors
/// Reports the same evidence, binding and contextual failures as [`load`], and
/// rejects Index or surface interpretations without alternative decoding.
pub async fn load_for<S: ContentStore + ?Sized>(
    store: &S,
    owner: Digest,
    attribute: &str,
    revisions: SemanticRevisions,
    minimum: u64,
    usage: TreeUse,
) -> Result<Loaded, Error> {
    let mut fetcher = Fetcher::new_for(store, revisions, minimum, usage)?;
    IndexEvaluationRecipe::new(owner, attribute).map_err(|error| invalid(owner, error))?;

    fetcher.walk(Visit::root(owner, None, Vec::new())).await?;
    let namespace_loading = fetcher.work;

    #[cfg(test)]
    let binding_span = fetcher.timings.span("owner-binding");
    let owner_bytes = fetcher
        .namespace
        .get(&owner)
        .ok_or_else(|| invalid(owner, evaluation::Error::MissingSource))?;
    let owner_node = decode_node_for(owner_bytes, true, minimum, usage)
        .map_err(|error| invalid(owner, error))?;
    increment(&mut fetcher.work.node_decodes, 1, owner)?;
    let property = owner_node
        .props
        .as_deref()
        .and_then(|properties| {
            properties
                .iter()
                .find(|property| property.name == "index-roots")
        })
        .ok_or(Error::MissingBinding(owner))?;
    let primary = IndexRoots::decode_binding(property.value)
        .map_err(|error| invalid(owner, error))?
        .get(attribute)
        .ok_or(Error::MissingBinding(owner))?;
    drop(owner_node);
    #[cfg(test)]
    drop(binding_span);
    fetcher
        .walk(Visit::root(primary, Some(Role::Primary), Vec::new()))
        .await?;

    Ok(Loaded {
        source: fetcher.take_source(owner, namespace_loading),
        attribute: attribute.to_owned(),
        index: IndexData {
            root: primary,
            nodes: fetcher.auxiliary,
            work: evaluation::Work::default(),
        },
        loading: fetcher.work,
    })
}

impl<'store, S: ContentStore + ?Sized> Fetcher<'store, S> {
    #[cfg(test)]
    fn new(store: &'store S, revisions: SemanticRevisions, minimum: u64) -> Result<Self, Error> {
        Self::new_for(store, revisions, minimum, TreeUse::Ordinary)
    }

    fn new_for(
        store: &'store S,
        revisions: SemanticRevisions,
        minimum: u64,
        usage: TreeUse,
    ) -> Result<Self, Error> {
        if !matches!(usage, TreeUse::Ordinary | TreeUse::OverlayLayer) {
            return Err(Error::Unsupported);
        }

        let context = SemanticContext::new(revisions.property, revisions.attribute, revisions.tree)
            .map_err(|_| Error::Unsupported)?;
        if minimum != CDC_1M_MIN as u64 {
            return Err(Error::Unsupported);
        }

        Ok(Self {
            store,
            context,
            minimum,
            usage,
            bytes: BTreeMap::new(),
            namespace: BTreeMap::new(),
            auxiliary: BTreeMap::new(),
            roots: BTreeSet::new(),
            work: Loading::default(),
            #[cfg(test)]
            timings: timings::LoadTimings::new(),
        })
    }

    fn take_source(&mut self, owner: Digest, loading: Loading) -> LoadedSource {
        LoadedSource {
            owner,
            context: self.context,
            minimum: self.minimum,
            usage: self.usage,
            namespace: std::mem::take(&mut self.namespace),
            roots: std::mem::take(&mut self.roots),
            loading,
        }
    }

    async fn read(
        &mut self,
        node: Digest,
        pending: &[Visit],
        frontier: &mut frontier::Frontier,
    ) -> Result<Vec<u8>, Error> {
        if let Some(bytes) = self.bytes.get(&node) {
            #[cfg(test)]
            self.timings.count("byte-cache-hits", 1);
            return Ok(bytes.clone());
        }
        if !frontier.contains(&node) {
            // The current subject already passed its DFS branch checks. Only
            // validated parents have placed the other subjects on this stack.
            let mut reads = vec![node];
            // Bound planning as well as retained reads. Shared or cached subjects
            // may fill a large pending stack without filling any read slots;
            // searching past them would repeatedly scan unrelated DFS work.
            // Deferred subjects retain their normal validation and error order.
            for visit in pending.iter().rev().take(frontier::WIDTH - 1) {
                if reads.len() == frontier.remaining() {
                    break;
                }
                if frontier::permitted(visit)
                    && !self.bytes.contains_key(&visit.node)
                    && !frontier.contains(&visit.node)
                    && !reads.contains(&visit.node)
                {
                    reads.push(visit.node);
                }
            }
            #[cfg(test)]
            self.timings.count("planned-get-subjects", reads.len());
            for subject in &reads {
                increment(&mut self.work.gets, 1, *subject)?;
            }
            frontier.fill(self.store, &reads).await?;
        }
        let bytes = frontier
            .take(&node)
            .ok_or_else(|| invalid(node, evaluation::Error::MissingSource))?
            .map_err(|failure| Error::Store { node, failure })?;
        increment(&mut self.work.fetched_bytes, bytes.len(), node)?;
        self.bytes.insert(node, bytes.clone());
        Ok(bytes)
    }

    async fn walk(&mut self, first: Visit) -> Result<(), Error> {
        let mut pending = vec![first];
        let mut frontier = frontier::Frontier::default();
        while let Some(mut visit) = pending.pop() {
            // Physical height and namespace/continuation depth are independent.
            // Cloned active branches preserve valid sharing between siblings.
            if visit.physical.len() > usize::from(MAX_TREE_LEVEL)
                || visit.physical.contains(&visit.node)
            {
                return Err(invalid(visit.node, evaluation::Error::Limit));
            }
            if visit.is_root {
                if visit.roots.len() > MAX_GRAFT_DEPTH || visit.roots.contains(&visit.node) {
                    return Err(invalid(visit.node, evaluation::Error::Limit));
                }
                visit.roots.push(visit.node);
                if visit.role.is_none() {
                    increment(&mut self.work.namespace_roots, 1, visit.node)?;
                    self.roots.insert(visit.node);
                }
            }
            visit.physical.push(visit.node);

            #[cfg(test)]
            let read_span = self.timings.span(if visit.role.is_some() {
                "auxiliary-read-await"
            } else {
                "namespace-read-await"
            });
            let bytes = self.read(visit.node, &pending, &mut frontier).await?;
            #[cfg(test)]
            drop(read_span);
            #[cfg(test)]
            let address_span = self.timings.span("address-hash");
            // A cache hit establishes bytes only, never their contextual use.
            increment(&mut self.work.identity_checks, 1, visit.node)?;
            let digest = TERRANE_V1
                .calculate(IdentityKind::Node, &bytes)
                .and_then(|identity| identity.terrane_v1_digest())
                .map_err(|_| invalid(visit.node, evaluation::Error::Source))?;
            if digest != visit.node {
                return Err(invalid(visit.node, evaluation::Error::Relationship));
            }
            #[cfg(test)]
            drop(address_span);
            let usage = if visit.role.is_some() {
                TreeUse::Index
            } else {
                self.usage
            };
            #[cfg(test)]
            let decode_span = self.timings.span("node-decode");
            increment(&mut self.work.node_decodes, 1, visit.node)?;
            let node = decode_node_for(&bytes, visit.is_root, self.minimum, usage)
                .map_err(|error| invalid(visit.node, error))?;
            #[cfg(test)]
            drop(decode_span);
            #[cfg(test)]
            let context_span = self.timings.span("context-and-traversal");
            if let Some(role) = visit.role {
                increment(&mut self.work.carrier_checks, 1, visit.node)?;
                let gap = validate_node(self.context, role, &node, visit.is_root)
                    .map_err(|error| invalid(visit.node, error))?;
                if let Some(gap) = gap {
                    pending.push(Visit::root(gap.node(), Some(Role::Gap), Vec::new()));
                }
                self.auxiliary.insert(visit.node, bytes.clone());
            } else {
                reject_structural_properties(visit.node, node.props.as_deref(), true)?;
                self.namespace.insert(visit.node, bytes.clone());
            }

            match node.items {
                NodeItems::Internal(children) => {
                    for child in children.into_iter().rev() {
                        pending.push(Visit {
                            node: child.child,
                            is_root: false,
                            role: visit.role,
                            physical: visit.physical.clone(),
                            roots: visit.roots.clone(),
                        });
                    }
                }
                NodeItems::Leaf(items) => {
                    for item in items.into_iter().rev() {
                        if let Some(role) = visit.role {
                            let row = validate_row(self.context, role, &item.key, &item.entry)
                                .map_err(|error| invalid(visit.node, error))?;
                            if let Some(route) = row.route() {
                                let next = match role {
                                    Role::Primary | Role::PresentRoute => Role::PresentRoute,
                                    Role::Gap | Role::MissingRoute => Role::MissingRoute,
                                };
                                // I/G are selectors rather than namespace graft hops.
                                let branch = if matches!(role, Role::Primary | Role::Gap) {
                                    Vec::new()
                                } else {
                                    visit.roots.clone()
                                };
                                pending.push(Visit::root(route, Some(next), branch));
                            }
                        } else {
                            validate_namespace_attributes(2, &item.entry)
                                .map_err(|error| invalid(visit.node, error))?;
                            if let EntryKind::Tree { root, props } = &item.entry.kind {
                                reject_structural_properties(visit.node, props.as_deref(), false)?;
                                pending.push(Visit::root(*root, None, visit.roots.clone()));
                            }
                        }
                    }
                }
            }
            #[cfg(test)]
            drop(context_span);
        }
        Ok(())
    }
}

fn reject_structural_properties(
    node: Digest,
    properties: Option<&[tree_format::Property<'_>]>,
    allow_binding: bool,
) -> Result<(), Error> {
    if properties.is_some_and(|properties| {
        properties.iter().any(|property| {
            property.name == "index-gaps" || (!allow_binding && property.name == "index-roots")
        })
    }) {
        return Err(invalid(node, evaluation::Error::Source));
    }
    if let Some(binding) = properties
        .into_iter()
        .flatten()
        .find(|property| property.name == "index-roots")
    {
        // A source-only read validates the local wrapper without resolving I.
        IndexRoots::decode_binding(binding.value).map_err(|error| invalid(node, error))?;
    }
    Ok(())
}

/// Checks cached namespace placement, depth and cycle refusals without new reads.
///
/// # Panics
/// Panics if the independent valid fixture is rejected or a contextual refusal
/// changes its expected subject, error kind or read accounting.
#[cfg(test)]
pub(super) async fn check_source_cached_context_guards<S: ContentStore>(store: &S, owner: Digest) {
    let mut fetcher = Fetcher::new(
        store,
        SemanticRevisions {
            property: 3,
            attribute: 2,
            tree: 1,
        },
        CDC_1M_MIN as u64,
    )
    .require();
    fetcher
        .walk(Visit::root(owner, None, Vec::new()))
        .await
        .require();
    let before = fetcher.work;

    // Cached bytes retain root properties and cannot become an internal Node.
    let placement = Visit {
        node: owner,
        is_root: false,
        role: None,
        physical: Vec::new(),
        roots: Vec::new(),
    };
    let error = fetcher.walk(placement).await.err().require();
    assert_eq!(error.subject(), Some(owner));
    assert!(matches!(
        error,
        Error::Invalid {
            failure: evaluation::Error::Tree(_),
            ..
        }
    ));
    assert_eq!(fetcher.work.gets, before.gets);
    assert_eq!(fetcher.work.identity_checks, before.identity_checks + 1);
    assert_eq!(fetcher.work.node_decodes, before.node_decodes + 1);

    // A canonical self-addressed cycle would require a hash fixed point. These
    // direct active states isolate branch guards before any address violation.
    for visit in [
        Visit {
            node: owner,
            is_root: false,
            role: None,
            physical: vec![owner],
            roots: Vec::new(),
        },
        Visit::root(owner, None, vec![owner]),
        Visit {
            node: owner,
            is_root: false,
            role: None,
            physical: vec![[9; 32]; 16],
            roots: Vec::new(),
        },
        Visit::root(owner, None, vec![[9; 32]; 65]),
    ] {
        let before = fetcher.work;
        let error = fetcher.walk(visit).await.err().require();
        assert_eq!(error.subject(), Some(owner));
        assert!(matches!(
            error,
            Error::Invalid {
                failure: evaluation::Error::Limit,
                ..
            }
        ));
        assert_eq!(fetcher.work, before);
    }
}

/// Checks cached owner and auxiliary placement, depth and cycle refusals.
///
/// # Panics
/// Panics if the independent valid fixture is rejected or a contextual refusal
/// changes its expected error kind or read accounting.
#[cfg(test)]
pub(super) async fn check_cached_context_guards<S: ContentStore>(
    store: &S,
    owner: Digest,
    primary: Digest,
) {
    let context =
        SemanticContext::new(3, 2, 1).unwrap_or_else(|error| panic!("fixture context: {error:?}"));
    let mut fetcher = Fetcher {
        store,
        context,
        minimum: CDC_1M_MIN as u64,
        usage: TreeUse::Ordinary,
        bytes: BTreeMap::new(),
        namespace: BTreeMap::new(),
        auxiliary: BTreeMap::new(),
        roots: BTreeSet::new(),
        work: Loading::default(),
        timings: timings::LoadTimings::new(),
    };
    fetcher
        .walk(Visit::root(owner, None, Vec::new()))
        .await
        .unwrap_or_else(|error| panic!("valid cached source: {error:?}"));
    let gets = fetcher.work.gets;
    let wrong_placement = Visit {
        node: owner,
        is_root: false,
        role: None,
        physical: Vec::new(),
        roots: Vec::new(),
    };
    let failure = fetcher
        .walk(wrong_placement)
        .await
        .err()
        .unwrap_or_else(|| panic!("cached root props accepted on internal Node"));
    assert!(matches!(
        failure,
        Error::Invalid {
            failure: evaluation::Error::Tree(_),
            ..
        }
    ));
    assert_eq!(fetcher.work.gets, gets);

    fetcher
        .walk(Visit::root(primary, Some(Role::Primary), Vec::new()))
        .await
        .unwrap_or_else(|error| panic!("valid cached primary: {error:?}"));
    let gets = fetcher.work.gets;
    let failure = fetcher
        .walk(Visit::root(primary, Some(Role::PresentRoute), Vec::new()))
        .await
        .err()
        .unwrap_or_else(|| panic!("cached primary props accepted on route"));
    assert!(matches!(
        failure,
        Error::Invalid {
            failure: evaluation::Error::Carrier(_),
            ..
        }
    ));
    assert_eq!(fetcher.work.gets, gets);

    // Exercise active-branch guard states directly. A canonical self-addressed
    // cycle would require a hash fixed point; inventing wrong addresses instead
    // would test identity failure before ever reaching these guards.
    for visit in [
        Visit {
            node: owner,
            is_root: false,
            role: None,
            physical: vec![owner],
            roots: Vec::new(),
        },
        Visit::root(owner, None, vec![owner]),
        Visit {
            node: owner,
            is_root: false,
            role: None,
            physical: vec![[9; 32]; 16],
            roots: Vec::new(),
        },
        Visit::root(owner, Some(Role::PresentRoute), vec![[9; 32]; 65]),
    ] {
        let failure = fetcher
            .walk(visit)
            .await
            .err()
            .unwrap_or_else(|| panic!("active branch accepted"));
        assert!(matches!(
            failure,
            Error::Invalid {
                failure: evaluation::Error::Limit,
                ..
            }
        ));
        assert_eq!(fetcher.work.gets, gets);
    }
}
