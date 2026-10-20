//! Admits materialized overlays from explicit signed layer inputs and current authority.
//!
//! Inputs are authenticated before constructing output nodes. Their order binds
//! both the recipe and signed parent list; introduction receipts refer to the
//! highest visible source instead of reintroducing it under the destination signer.

#[cfg(feature = "std")]
use std::collections::BTreeMap;
#[cfg(all(feature = "std", unix))]
use std::collections::BTreeSet;

#[cfg(feature = "std")]
use terrane_format::algebra::{OperationDomains, Overlay, OverlayPolicy, Roots};
#[cfg(all(feature = "std", unix))]
use terrane_format::auth::Verb;
use terrane_format::identity::Digest;
#[cfg(all(feature = "std", unix))]
use terrane_format::identity::{IdentityKind, TERRANE_V1};
#[cfg(feature = "std")]
use terrane_format::properties::RootLayer;
#[cfg(all(feature = "std", unix))]
use terrane_format::refs::CommitSource;
#[cfg(all(feature = "std", unix))]
use terrane_format::tree_format::TreeUse;

#[cfg(all(feature = "std", unix))]
use super::{AdmissionSources, AdmittedCommit, SourceAuthorization};
#[cfg(all(feature = "std", unix))]
use crate::guard::snapshot::layers::OverlayInput;
#[cfg(all(feature = "std", unix))]
use crate::guard::{CommitRequest, StagedUpload, denied};
#[cfg(feature = "std")]
use crate::guard::{Guard, HistoryObservation};
use crate::guard::{TreeEvidence, invalid};
use crate::store::StoreFailure;
#[cfg(feature = "std")]
use crate::store::{Clock, Store};

#[cfg(feature = "std")]
impl<S: Store, C: Clock> Guard<S, C> {
    /// Admits an ordinary namespace computed from ordered, authenticated layers.
    ///
    /// The destination baseline remains independent of input precedence.
    /// Input-only layers keep separate current policy references.
    ///
    /// # Errors
    /// Preserves signature, Original, current Read/Commit, producer, domain,
    /// canonical metadata and storage failures; refuses changed input order,
    /// omitted destination ancestry and unsupported layer index contracts.
    #[cfg(all(feature = "std", unix))]
    pub(crate) async fn admit_overlay(
        &self,
        reference: &str,
        epoch: u64,
        inputs: &[OverlayInput],
        mut request: CommitRequest,
    ) -> Result<AdmittedCommit, StoreFailure> {
        if inputs.is_empty() {
            return Err(invalid());
        }
        let current = self.store().ref_get(reference).await?;

        let mut sources = Vec::new();
        let mut authorizations = Vec::new();
        for input in inputs {
            let (verified, _) = self
                .verified_overlay_layer_history_observed(
                    input.commit,
                    HistoryObservation::default(),
                )
                .await?;
            // A caller cannot borrow an unrelated broad policy reference to
            // authorize a private signed layer's complete source history.
            let original = self.original_commit(&input.commit)?;
            let authority = self
                .config()
                .policy_authority
                .as_deref()
                .unwrap_or(original.baseline().reference());
            if authority != input.reference {
                return Err(denied(&input.reference, Verb::Read));
            }
            let paths = verified
                .evidence
                .occurrences(self.config().min_chunk_size)?
                .into_iter()
                .map(|occurrence| occurrence.path)
                .collect::<Vec<_>>();
            let mut record = None;
            for path in &paths {
                let authorized = self
                    .authorize_observed(
                        &input.reference,
                        &request.token,
                        Verb::Read,
                        std::slice::from_ref(path),
                        &request.surface,
                        HistoryObservation::default(),
                    )
                    .await?;
                let actual = authorized
                    .record()
                    .ok_or_else(|| denied(&input.reference, Verb::Read))?;
                if record.as_ref().is_some_and(|previous| previous != actual) {
                    return Err(denied(&input.reference, Verb::Read));
                }
                record = Some(actual.clone());
            }
            authorizations.push((
                input.commit,
                SourceAuthorization {
                    reference: input.reference.clone(),
                    verb: Verb::Read,
                    paths,
                    record: record.ok_or_else(invalid)?,
                    cold_route_lifetime: None,
                },
            ));
            sources.push((input.commit, verified.evidence));
        }

        let domains = self.overlay_input_domains(&sources)?;
        let authenticated = sources
            .iter()
            .map(|(commit, evidence)| (*commit, evidence))
            .collect::<Vec<_>>();
        let materialized = self.materialize_overlay_inputs(
            &authenticated,
            Some(&domains),
            HistoryObservation::default(),
        )?;
        if request
            .commit
            .profile_pair
            .recipe
            .as_ref()
            .is_some_and(|recipe| *recipe != materialized.recipe)
        {
            return Err(invalid());
        }
        request.commit.tree = materialized.root;
        request.commit.parents = current
            .iter()
            .map(|record| record.commit)
            .chain(inputs.iter().map(|input| input.commit))
            .collect();
        request.commit.profile_pair.recipe = Some(materialized.recipe);
        request.commit.provenance.source = CommitSource::Derived;
        request.commit.signature = None;
        let nodes = materialized.nodes;
        let mut staged = BTreeSet::new();
        for upload in &request.uploads {
            if let StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes,
            } = upload
            {
                staged.insert(
                    TERRANE_V1
                        .calculate(IdentityKind::Node, bytes)
                        .and_then(|identity| identity.terrane_v1_digest())
                        .map_err(|_| invalid())?,
                );
            }
        }
        for (identity, bytes) in nodes {
            if staged.insert(identity) {
                request.uploads.push(StagedUpload::Meta {
                    kind: IdentityKind::Node,
                    bytes,
                });
            }
        }
        let mut admitted = self
            .admit_inner_observed(
                reference,
                epoch,
                request,
                AdmissionSources {
                    usage: TreeUse::Ordinary,
                    copied: None,
                    base: None,
                    merged_source: None,
                    overlay: sources,
                },
                HistoryObservation::default().requested_target(),
            )
            .await?;
        admitted.overlay_sources = authorizations;
        Ok(admitted)
    }

    /// Materializes only authenticated closures under their retained interpretations.
    ///
    /// Source policies belong to their immutable occurrence. Emitted policies
    /// use the top input's own historical interpretation and defaults, including
    /// the actual new ancestor chain rather than a selected source's old chain.
    /// All Rc-backed trees remain inside this synchronous operation.
    ///
    /// # Errors
    /// Rejects ambiguous input policies, missing roots, invalid contextual grafts
    /// and policy transitions that cannot preserve authenticated boundaries.
    #[cfg(feature = "std")]
    pub(in crate::guard) fn materialize_overlay_inputs(
        &self,
        sources: &[(Digest, &TreeEvidence)],
        domains: Option<&OperationDomains>,
        observation: HistoryObservation<'_>,
    ) -> Result<MaterializedOverlayInputs, StoreFailure> {
        let mut graph = BTreeMap::new();
        let mut policies = BTreeMap::new();
        let mut selected_inputs = Vec::new();
        for (commit, evidence) in sources {
            let selected = self.select_view(*commit, evidence.root, observation)?;
            for occurrence in evidence.occurrences(self.config().min_chunk_size)? {
                let layers = occurrence
                    .layers
                    .iter()
                    .map(|(properties, overrides)| RootLayer {
                        properties,
                        overrides,
                    })
                    .collect::<Vec<_>>();
                let effective = selected.resolve(&layers, self.defaults_for(evidence))?;
                let policy = OverlayPolicy::from_effective(&effective).map_err(|_| invalid())?;
                let boundary = occurrence
                    .path
                    .strip_prefix(b"/")
                    .ok_or_else(invalid)?
                    .to_vec();
                let key = (evidence.root, boundary);
                if policies
                    .get(&key)
                    .is_some_and(|previous| previous != &policy)
                {
                    return Err(invalid());
                }
                policies.insert(key, policy);
            }
            for root in &evidence.roots {
                graph
                    .entry(*root)
                    .or_insert(evidence.tree(*root, self.config().min_chunk_size)?);
            }
            selected_inputs.push((evidence.root, *evidence, selected));
        }
        let roots = OverlayRoots(graph);
        let inputs = sources
            .iter()
            .map(|(_, evidence)| roots.0.get(&evidence.root).ok_or_else(invalid))
            .collect::<Result<Vec<_>, _>>()?;
        let overlay = Overlay::new(&inputs);
        let prepared = overlay
            .prepare_with_roots(
                &roots,
                domains,
                |root, boundary| {
                    policies
                        .get(&(*root, boundary.to_vec()))
                        .cloned()
                        .ok_or(terrane_format::algebra::Error::Boundary)
                },
                |owner, layers| {
                    let (_, evidence, selected) = selected_inputs
                        .iter()
                        .find(|(root, _, _)| root == owner)
                        .ok_or(terrane_format::algebra::Error::Boundary)?;
                    let effective = selected
                        .resolve(layers, self.defaults_for(evidence))
                        .map_err(|_| terrane_format::algebra::Error::Boundary)?;
                    OverlayPolicy::from_effective(&effective)
                },
            )
            .map_err(|_| invalid())?;
        let materialized = prepared.materialize().map_err(|_| invalid())?;
        let mut nodes = BTreeMap::new();
        for tree in core::iter::once(&materialized.tree).chain(materialized.grafts.iter()) {
            for node in tree.nodes() {
                nodes.insert(node.identity(), node.encoded().to_vec());
            }
        }
        Ok(MaterializedOverlayInputs {
            root: materialized.tree.root_identity(),
            recipe: materialized.recipe.clone(),
            nodes: nodes.into_iter().collect(),
        })
    }

    /// Resolves each immutable input under its independently selected original view.
    #[cfg(all(feature = "std", unix))]
    fn overlay_input_domains(
        &self,
        sources: &[(Digest, TreeEvidence)],
    ) -> Result<OperationDomains, StoreFailure> {
        let mut domains = OperationDomains::new();
        for (commit, evidence) in sources {
            let selected =
                self.select_view(*commit, evidence.root, HistoryObservation::default())?;
            for occurrence in evidence.occurrences(self.config().min_chunk_size)? {
                let layers = occurrence
                    .layers
                    .iter()
                    .map(|(properties, overrides)| RootLayer {
                        properties,
                        overrides,
                    })
                    .collect::<Vec<_>>();
                let effective = selected.resolve(&layers, self.defaults_for(evidence))?;
                domains
                    .bind_resolved(occurrence.root, &effective)
                    .map_err(|_| invalid())?;
            }
        }
        Ok(domains)
    }
}

/// Resolves only roots in the previously authenticated complete input closure.
#[cfg(feature = "std")]
struct OverlayRoots<'a>(BTreeMap<Digest, terrane_format::tree_builder::Tree<'a>>);

#[cfg(feature = "std")]
impl<'a> Roots<'a> for OverlayRoots<'a> {
    fn resolve(&self, identity: &Digest) -> Option<&terrane_format::tree_builder::Tree<'a>> {
        self.0.get(identity)
    }
}

/// Owns complete namespace uploads without retaining borrowed composition state.
#[cfg(feature = "std")]
pub(in crate::guard) struct MaterializedOverlayInputs {
    /// Canonical ordinary root after complete contextual composition.
    pub(in crate::guard) root: Digest,
    /// Exact canonical recipe retaining the signed input order.
    pub(in crate::guard) recipe: Vec<u8>,
    /// Deduplicated namespace Node identities and canonical encoded bytes.
    pub(in crate::guard) nodes: Vec<(Digest, Vec<u8>)>,
}

/// Retains a visible entry's exact original signed root-relative placement.
pub(super) struct OverlayEntrySource<'a> {
    /// Exact signed input that supplies this visible entry.
    pub(super) commit: Digest,
    /// Original namespace root at the authenticated source occurrence.
    pub(super) root: Digest,
    /// Canonical root-relative source key before output repartitioning.
    pub(super) path: Vec<u8>,
    /// Unchanged visible entry from that signed source root.
    pub(super) entry: terrane_format::tree_format::Entry<'a>,
}

/// Finds the highest-precedence signed source for one materialized occurrence.
///
/// # Errors
/// Rejects unavailable canonical roots or an unexpected visible whiteout.
pub(super) fn overlay_source_entry<'a>(
    sources: &'a [(Digest, TreeEvidence)],
    occurrence_path: &[u8],
    key: &[u8],
    minimum: u64,
) -> Result<Option<OverlayEntrySource<'a>>, StoreFailure> {
    let mut absolute = occurrence_path.to_vec();
    if absolute != b"/" {
        absolute.push(b'/');
    }
    absolute.extend_from_slice(key);

    for (commit, evidence) in sources {
        let occurrences = evidence.occurrences(minimum)?;
        // Materialization can inline a graft or create a new target boundary.
        // Receipts follow the original absolute source placement, rather than
        // assuming its root-relative partition matches the resulting tree.
        let Some(occurrence) = occurrences
            .iter()
            .filter(|occurrence| {
                occurrence.path == b"/"
                    || (absolute.starts_with(&occurrence.path)
                        && absolute.get(occurrence.path.len()) == Some(&b'/'))
            })
            .max_by_key(|occurrence| occurrence.path.len())
        else {
            continue;
        };
        let relative = &absolute[occurrence.path.len()..];
        let relative = relative.strip_prefix(b"/").unwrap_or(relative);
        let tree = evidence.tree(occurrence.root, minimum)?;
        if let Some(entry) = tree.get(relative) {
            if matches!(entry.kind, terrane_format::tree_format::EntryKind::Whiteout) {
                return Err(invalid());
            }
            return Ok(Some(OverlayEntrySource {
                commit: *commit,
                root: occurrence.root,
                path: relative.to_vec(),
                entry: entry.clone(),
            }));
        }
    }
    Ok(None)
}
