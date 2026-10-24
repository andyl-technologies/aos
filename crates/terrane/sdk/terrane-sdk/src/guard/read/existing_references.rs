//! Qualifies unchanged owner references independently of derived side values.
//!
//! Actual completed signed history, current requests and bound Original controls
//! qualify the owner. The native backend separately verifies live opaque pack
//! integrity. Neither component supplies the other's authority or body evidence.

use std::collections::BTreeMap;

use terrane_format::auth::Verb;
use terrane_format::gc::publication::evidence::ConfiguredRegistryInputs;
use terrane_format::identity::{Identity, IdentityKind, TERRANE_V1};
use terrane_format::properties::RootLayer;
use terrane_format::refs::RefRecord;
use terrane_format::tree_format::{self, ContentRef, Entry, EntryKind, Property};

use super::super::{AdmittedCommit, AuthorizedRef, ConsumedResolver, Guard, HistoryObservation};
use super::super::{StagedUpload, TreeEvidence, domain_label, invalid};
use super::AuthorizedSnapshot;
use crate::bucket::existing_references::ExistingPlacement;
use crate::bucket::held::{HeldBucket, SingleHeld};
use crate::bucket::publication::SelectedObservation;
use crate::bucket::{BucketBinding, FileBucket};
use crate::domain::DomainRecord;
use crate::repository::PreparedTree;
use crate::store::{
    Clock, ContentValidator, CorruptSubject, LocalFs, RefStore, Store, StoreErrorKind, StoreFailure,
};

/// Retains genuinely qualified unchanged owners and their exact storage reads.
///
/// Construction belongs only to the successful native factory below. This does
/// not authorize publication; normal candidate admission, Original retention and
/// final current checks remain mandatory. It is neither serialized nor cloned.
pub(crate) struct ExistingOwnerReferences {
    source: AuthorizedSnapshot,
    maintenance: Option<super::super::index_maintenance::Purpose>,
    root: std::path::PathBuf,
    physical_identity: ((u64, u64), (u64, u64)),
    record: RefRecord,
    profile: ConfiguredRegistryInputs,
    shape: NamespaceShape,
    placements: Vec<ExistingPlacement>,
    records: Vec<DomainRecord>,
    guard: Option<[u8; 32]>,
    loss_generation: u64,
}

#[derive(Eq, PartialEq)]
struct NamespaceShape {
    roots: Vec<RootShape>,
    entries: BTreeMap<Vec<u8>, EntryShape>,
    files: BTreeMap<Vec<u8>, Identity>,
}

#[derive(Eq, PartialEq)]
struct RootShape {
    path: Vec<u8>,
    domain: String,
    layers: Vec<(PropertyBytes, PropertyBytes)>,
}

type PropertyBytes = Vec<(String, Vec<u8>)>;

#[derive(Eq, PartialEq)]
enum EntryShape {
    File(Vec<u8>),
    Graft {
        properties: Option<PropertyBytes>,
        attrs: PropertyBytes,
        attrs_present: bool,
        xattrs: Vec<(Vec<u8>, Vec<u8>)>,
        xattrs_present: bool,
    },
    Other(Vec<u8>),
}

impl ExistingOwnerReferences {
    /// Borrows the private operation purpose, never a serving qualification.
    pub(crate) fn maintenance_purpose(&self) -> Option<&super::super::index_maintenance::Purpose> {
        self.maintenance.as_ref()
    }

    /// Checks the exact immutable source and credentials before ordinary admission.
    ///
    /// # Errors
    /// Refuses stale or rebase templates, injected evidence, changed parent,
    /// credentials or surface. It grants no bypass for any normal Commit check.
    pub(crate) fn check_template(
        &self,
        session: &crate::ref_advance::WriterSession,
        request: &super::super::CommitRequest,
    ) -> Result<(), StoreFailure> {
        if session.reference() != self.source.authority_reference
            || session.record() != Some(&self.record)
            || request.commit.parents != [self.source.commit.identity()]
            || request.token != self.source.token
            || request.surface != self.source.surface
            || !request.reference_records.is_empty()
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Copies only storage-issued records from this successful owning factory.
    pub(crate) fn records(&self) -> Vec<DomainRecord> {
        self.records.clone()
    }

    /// Checks the actual signed candidate after normal admission and index writing.
    ///
    /// # Errors
    /// Refuses changed ownership, source/parent, selected profile, paths or payload.
    /// Normal writer index-root updates do not alter the file-reference proof.
    pub(crate) async fn check_candidate<S: Store, C: Clock>(
        &self,
        guard: &Guard<S, C>,
        admitted: &AdmittedCommit,
    ) -> Result<(), StoreFailure> {
        if admitted.publication_reference != self.source.authority_reference
            || admitted.expected.as_ref() != Some(&self.record)
            || admitted.commit.commit().parents != [self.source.commit.identity()]
            || admitted.token != self.source.token
            || admitted.surface != self.source.surface
            || admitted.publication_verb != Verb::Commit
            || admitted.source_authorization.is_some()
            || admitted.admission_profile != self.profile
        {
            return Err(invalid());
        }
        // Authored candidate selection binds a different signed view/root. Equal
        // complete profiles and unchanged ownership/payload are required here;
        // the original source selection is separately rechecked under the holder.
        let candidate = TreeEvidence::load_tree(
            guard.store(),
            admitted.commit.commit().tree,
            &admitted.uploads,
            guard.config().min_chunk_size,
        )
        .await?;
        if shape(guard, &candidate, &admitted.admission_interpretation)? != self.shape {
            return Err(invalid());
        }
        Ok(())
    }

    /// Rechecks genuine source requests and storage under the final actual holder.
    ///
    /// # Errors
    /// Preserves current Read, Original/history, profile, pack integrity and I/O
    /// errors. Refuses changed Guard/loss state, current source or placement.
    /// Returned requests remain subject to the ordinary final clock checks.
    pub(crate) async fn revalidate<F, B, V, C, const WRITABLE: bool>(
        &self,
        guard: &Guard<HeldBucket<'_, F, B, V, WRITABLE>, C>,
        admitted: &AdmittedCommit,
        observed: &SelectedObservation<'_>,
        observation: HistoryObservation<'_>,
    ) -> Result<Vec<AuthorizedRef>, StoreFailure>
    where
        F: LocalFs + BucketBinding,
        B: Clock + BucketBinding,
        V: ContentValidator + BucketBinding,
        C: Clock,
    {
        let observation = self
            .maintenance
            .as_ref()
            .map_or(observation, |purpose| observation.maintenance(purpose));
        observed.revalidate().await?;
        if guard.store().root() != self.root.as_path()
            || guard.store().physical_identity() != self.physical_identity
            || observed.state().guard != self.guard
            || observed.state().loss_generation != self.loss_generation
            || guard
                .store()
                .ref_get(&self.source.authority_reference)
                .await?
                .as_ref()
                != Some(&self.record)
        {
            return Err(invalid());
        }
        self.check_candidate(guard, admitted).await?;
        let mut requests = Vec::new();
        for path in self.shape.files.keys() {
            requests.extend(
                guard
                    .snapshot_authorizations_observed(&self.source, path, observation)
                    .await?,
            );
        }
        if self.maintenance.is_some() {
            requests.extend(
                guard
                    .check_index_source_producers(
                        &self.source,
                        observation,
                        &mut Default::default(),
                    )
                    .await?,
            );
        }
        for placement in &self.placements {
            placement.revalidate(guard.store(), observed).await?;
        }
        observed.revalidate().await?;
        Ok(requests)
    }

    /// Borrows actual opaque artifact reads for the native effect's whole preimages.
    pub(crate) fn reads(
        &self,
    ) -> impl Iterator<Item = &crate::bucket::publication::receipts::RecordRead> {
        self.placements.iter().flat_map(ExistingPlacement::reads)
    }
}

impl<F, B, V, C> Guard<FileBucket<F, B, V>, C>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding + Sync,
    V: ContentValidator + BucketBinding + Sync,
    C: Clock + Sync,
{
    /// Qualifies actual unchanged references for one metadata-only candidate.
    ///
    /// Physical opaque pack/index reads are required for integrity. No typed
    /// Chunk GET, plaintext decoder or derived-function evaluation runs here.
    /// Initial property installation does not call this producer.
    ///
    /// # Errors
    /// Preserves actual history/current/Original/catalogue/storage errors; refuses
    /// incompatible profiles, changed payload/domain, missing inventory, unknown
    /// retirement state and unavailable or corrupt eligible storage. Conflicted
    /// occurrence graphs and synthetic empty records are explicitly unsupported
    /// by this bounded producer; they do not become invalid historical data.
    pub(crate) async fn existing_owner_references(
        &self,
        source: AuthorizedSnapshot,
        candidate: &mut PreparedTree,
        uploads: &[StagedUpload],
    ) -> Result<ExistingOwnerReferences, StoreFailure> {
        self.existing_owner_references_inner(source, candidate, uploads, None)
            .await
    }

    /// Qualifies unchanged native references for an explicit canonical index correction.
    ///
    /// # Errors
    /// Preserves current source/producer, Original and physical storage failures;
    /// rejects changed namespace shape, profiles, source records or native bindings.
    pub(in crate::guard) async fn existing_owner_references_for_index_rebuild(
        &self,
        source: AuthorizedSnapshot,
        candidate: &mut PreparedTree,
        uploads: &[StagedUpload],
        purpose: super::super::index_maintenance::Purpose,
    ) -> Result<ExistingOwnerReferences, StoreFailure> {
        self.existing_owner_references_inner(source, candidate, uploads, Some(purpose))
            .await
    }

    /// Captures genuine unchanged-owner evidence with a separately bounded purpose.
    ///
    /// # Errors
    /// Rejects incompatible domains/profiles, stale source state, changed payload,
    /// unsafe Original controls or missing native placements; preserves store errors.
    pub(crate) async fn existing_owner_references_inner(
        &self,
        source: AuthorizedSnapshot,
        candidate: &mut PreparedTree,
        uploads: &[StagedUpload],
        maintenance: Option<super::super::index_maintenance::Purpose>,
    ) -> Result<ExistingOwnerReferences, StoreFailure> {
        let authority = self.configured_original_authority()?;
        if authority.root() != self.store().root()
            || authority.domain() != self.config().storage_domain
            || source.storage_domain != self.config().storage_domain
        {
            return Err(invalid());
        }
        let clock = self.clock().retain_native_clock().map_err(|error| {
            let kind = if error.kind() == std::io::ErrorKind::Unsupported {
                StoreErrorKind::Unsupported
            } else {
                StoreErrorKind::Unavailable { retry_after: None }
            };
            StoreFailure::with_source(kind, error)
        })?;
        let holder = SingleHeld::acquire(self.store()).await?;
        let held = holder.source();
        let guard = self.held_guard(holder.source(), clock)?;
        let observed = held.observe_for_read().await?;
        let proof = held.identity_proof();
        let consumed = ConsumedResolver::new(&guard, &authority)?;
        consumed.registration(&authority)?;
        let observation = HistoryObservation::held(&proof).tracked(&consumed);
        let observation = maintenance
            .as_ref()
            .map_or(observation, |purpose| observation.maintenance(purpose));
        let (fresh, _) = guard
            .snapshot_authorizations(
                source.commit.identity(),
                source.authority_reference.clone(),
                &source.token,
                &source.scope,
                &source.surface,
                observation,
            )
            .await?;
        if fresh.authority_reference != source.authority_reference
            || fresh.evidence.root != source.evidence.root
            || fresh.interpretation != source.interpretation
            || fresh.storage_domain != source.storage_domain
            || fresh.scope != b"/"
        {
            return Err(invalid());
        }
        let record = held
            .ref_get(&fresh.authority_reference)
            .await?
            .ok_or_else(invalid)?;
        if record.commit != fresh.commit.identity() {
            return Err(invalid());
        }
        let profile = super::super::history::completion::profile_inputs(
            &guard,
            &fresh.commit,
            &fresh.interpretation,
        )?;
        if profile != guard.configured_authoring_registries()? {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        // The authenticated owner supplies membership, never the side value or
        // inventory. Exact native placement below independently supplies integrity.
        let old = shape(&guard, &fresh.evidence, &fresh.interpretation)?;
        let domain = old
            .roots
            .iter()
            .find(|root| root.path == b"/")
            .ok_or_else(invalid)?
            .domain
            .clone();
        candidate.inherit_domain(&domain).map_err(invalid_cause)?;
        let mut staged = candidate.uploads.clone();
        staged.extend_from_slice(uploads);
        let proposed = TreeEvidence::load_tree(
            guard.store(),
            candidate.root(),
            &staged,
            guard.config().min_chunk_size,
        )
        .await?;
        if shape(&guard, &proposed, &fresh.interpretation)? != old {
            return Err(invalid());
        }
        for path in old.files.keys() {
            guard
                .snapshot_authorizations_observed(&fresh, path, observation)
                .await?;
            let relative = path.strip_prefix(b"/").ok_or_else(invalid)?;
            let (location, _) = fresh
                .history
                .locate(fresh.commit.identity(), relative)
                .map_err(invalid_cause)?;
            fresh
                .history
                .introducing_commit(&location)
                .map_err(invalid_cause)?;
        }
        if maintenance.is_some() {
            guard
                .check_index_source_producers(&fresh, observation, &mut Default::default())
                .await?;
        }
        let _controls = crate::selected_bridge::native_guard::hold_consumed_controls(
            self, &authority, &held, &observed, &consumed,
        )
        .await?;
        let mut placements = Vec::<ExistingPlacement>::new();
        let mut records = Vec::new();
        let mut pending = old.files.values().cloned().collect::<Vec<_>>();
        while let Some(identity) = pending.pop() {
            if placements
                .iter()
                .any(|placement| placement.identity() == &identity)
            {
                continue;
            }
            let placement = held.existing_placement(&observed, &identity).await?;
            pending.extend(dependencies(&placement, &guard.config().chunk_profile)?);
            records.push(DomainRecord::admitted(
                placement.identity().clone(),
                authority.domain().to_owned(),
            )?);
            placements.push(placement);
        }
        observed.revalidate().await?;
        Ok(ExistingOwnerReferences {
            source: fresh,
            maintenance,
            root: observed.identity().root().to_owned(),
            physical_identity: observed.identity().physical_identity(),
            record,
            profile,
            shape: old,
            placements,
            records,
            guard: observed.state().guard,
            loss_generation: observed.state().loss_generation,
        })
    }
}

// The backend supplies only verified opaque bytes; repository ownership interprets
// the references without decompressing plaintext or evaluating derived functions.
fn dependencies(
    placement: &ExistingPlacement,
    profile: &terrane_format::chunking::ChunkProfile,
) -> Result<Vec<Identity>, StoreFailure> {
    let identity = placement.identity();
    let body = placement.encoded_member()?;
    let mut dependencies = Vec::new();

    match identity.kind() {
        IdentityKind::Manifest => {
            let manifest =
                terrane_format::manifest::Manifest::decode_verified(body, profile, identity)
                    .map_err(|error| corrupt_body(identity, error))?;
            for chunk in manifest.chunks {
                dependencies.push(
                    TERRANE_V1
                        .from_digest(IdentityKind::Chunk, &chunk.digest)
                        .map_err(|error| corrupt_body(identity, error))?,
                );
            }
        }
        IdentityKind::Chunk => {
            let envelope = terrane_format::codec::parse_envelope(body)
                .map_err(|error| corrupt_body(identity, error))?;
            if let terrane_format::codec::Codec::ZstdDictionary(dictionary) = envelope.codec {
                dependencies.push(
                    TERRANE_V1
                        .from_digest(IdentityKind::Chunk, &dictionary)
                        .map_err(|error| corrupt_body(identity, error))?,
                );
            }
        }
        _ => return Err(StoreFailure::new(StoreErrorKind::Unsupported)),
    }

    Ok(dependencies)
}

fn corrupt_body(
    identity: &Identity,
    error: impl std::error::Error + Send + Sync + 'static,
) -> StoreFailure {
    StoreFailure::with_source(
        StoreErrorKind::Corrupt(CorruptSubject::Identity(identity.clone())),
        error,
    )
}

// Only native writer auxiliary bindings and the resolved inherited-domain
// spelling may change. Every ordered occurrence still compares its actual domain.
fn properties(properties: &[Property<'_>], normalize_root: bool) -> PropertyBytes {
    properties
        .iter()
        .filter(|property| !normalize_root || !matches!(property.name, "domain" | "index-roots"))
        .map(|property| (property.name.to_owned(), property.value.to_vec()))
        .collect()
}

fn shape<S: Store, C: Clock>(
    guard: &Guard<S, C>,
    evidence: &TreeEvidence,
    selected: &super::super::SelectedReadInterpretation,
) -> Result<NamespaceShape, StoreFailure> {
    let minimum = guard.config().min_chunk_size;
    let mut roots = Vec::new();
    let mut entries = BTreeMap::new();
    let mut files = BTreeMap::new();

    for occurrence in evidence.occurrences(minimum)? {
        if roots
            .iter()
            .any(|root: &RootShape| root.path == occurrence.path)
        {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        let layers = occurrence
            .layers
            .iter()
            .map(|(properties, overrides)| RootLayer {
                properties,
                overrides,
            })
            .collect::<Vec<_>>();
        let effective = selected.resolve(&layers, guard.defaults_for(evidence))?;
        let domain = domain_label(&effective).map_err(invalid_cause)?.to_owned();
        roots.push(RootShape {
            path: occurrence.path.clone(),
            domain,
            layers: occurrence
                .layers
                .iter()
                .map(|(raw, overrides)| (properties(raw, true), properties(overrides, false)))
                .collect(),
        });

        let tree = evidence.tree(occurrence.root, minimum)?;
        for item in tree.iter() {
            let mut path = occurrence.path.clone();
            if path != b"/" {
                path.push(b'/');
            }
            path.extend_from_slice(&item.key);
            let entry = entry_shape(&item.entry, minimum)?;
            if entries.insert(path.clone(), entry).is_some() {
                return Err(StoreFailure::new(StoreErrorKind::Unsupported));
            }
            if let EntryKind::File { content, .. } = &item.entry.kind {
                let (kind, digest) = match *content {
                    ContentRef::Inline(digest) => (IdentityKind::Chunk, digest),
                    ContentRef::Manifest(digest) => (IdentityKind::Manifest, digest),
                };
                files.insert(
                    path,
                    TERRANE_V1
                        .from_digest(kind, &digest)
                        .map_err(invalid_cause)?,
                );
            }
        }
    }

    Ok(NamespaceShape {
        roots,
        entries,
        files,
    })
}

fn entry_shape(entry: &Entry<'_>, minimum: u64) -> Result<EntryShape, StoreFailure> {
    match &entry.kind {
        EntryKind::Tree { props, .. } => Ok(EntryShape::Graft {
            properties: props.as_ref().map(|props| properties(props, false)),
            attrs: entry
                .attrs
                .iter()
                .map(|attribute| (attribute.name.to_owned(), attribute.value.to_vec()))
                .collect(),
            attrs_present: entry.attrs_present,
            xattrs: entry
                .xattrs
                .iter()
                .map(|attribute| (attribute.name.to_vec(), attribute.value.to_vec()))
                .collect(),
            xattrs_present: entry.xattrs_present,
        }),
        EntryKind::Conflict { .. } => Err(StoreFailure::new(StoreErrorKind::Unsupported)),
        EntryKind::File { .. } => {
            let mut payload = entry.clone();
            payload.attrs.clear();
            payload.attrs_present = false;
            payload.provenance = None;
            Ok(EntryShape::File(
                tree_format::encode_entry(&payload, minimum).map_err(invalid_cause)?,
            ))
        }
        _ => {
            let mut payload = entry.clone();
            payload.provenance = None;
            Ok(EntryShape::Other(
                tree_format::encode_entry(&payload, minimum).map_err(invalid_cause)?,
            ))
        }
    }
}

// Preserves native/parser diagnostics without changing the stable malformed outcome.
fn invalid_cause(error: impl std::error::Error + Send + Sync + 'static) -> StoreFailure {
    StoreFailure::with_source(invalid().kind().clone(), error)
}
