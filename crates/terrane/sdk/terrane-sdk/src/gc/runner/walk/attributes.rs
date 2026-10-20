//! Retains actual side-record associations without selecting effective attributes.
//!
//! Catalog inspection is physical input, not a semantic root. Every matching
//! record is classified under genuine producer history and actual occurrence
//! domains. Inactive function versions receive attribution, never activation.
//! Only file objects and declared member/dictionary edges select associations;
//! metadata identities do not invent the entry witness required by DRV-3.

use super::{CollectionError, Expansion, VisitMode, history};
use crate::bucket::BucketBinding;
use crate::bucket::publication::collection_observation::MetadataStore;
use crate::guard::{ConsumedResolver, Guard, HistoryObservation};
use crate::selected_bridge::QualifiedCollectionRoots;
use crate::store::{Clock, ContentValidator, LocalFs, StoreFailure};
use std::collections::{BTreeMap, BTreeSet};
use terrane_format::derived::{self, AttrRecord, AttributeValue};
use terrane_format::gc::ProofContext;
use terrane_format::identity::{Digest, Identity, IdentityKind};
use terrane_format::properties::Domain;
use terrane_format::provenance::{EntryLocation, VerifiedHistory};
use terrane_format::tree_format::{ContentRef, EntryKind};

/// Names an encountered object in its actual consuming domain and proof position.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Target {
    object: Digest,
    context: ProofContext,
    domain: String,
    location: Option<EntryLocation>,
    role: ObjectRole,
}

/// Separates the directly certified object from its independently declared edges.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum ObjectRole {
    EntryObject,
    ManifestMember,
    Dictionary,
    Metadata,
}

impl Target {
    /// Retains the actual occurrence while introducing no invented file path.
    pub(super) fn metadata(object: Digest, occurrence: &history::Occurrence) -> Self {
        Self {
            object,
            context: occurrence.context.clone(),
            domain: occurrence.domain.clone(),
            location: None,
            role: ObjectRole::Metadata,
        }
    }

    /// Retains exactly the object directly named by the canonical file entry.
    pub(super) fn entry(occurrence: &history::Occurrence, file: &history::File) -> Self {
        let object = match file.content {
            ContentRef::Inline(hash) | ContentRef::Manifest(hash) => hash,
        };
        Self::declared(object, occurrence, file, ObjectRole::EntryObject)
    }

    /// Retains a verified manifest member without inheriting the file certificate.
    pub(super) fn manifest_member(
        object: Digest,
        occurrence: &history::Occurrence,
        file: &history::File,
    ) -> Self {
        Self::declared(object, occurrence, file, ObjectRole::ManifestMember)
    }

    /// Retains a registered dictionary edge without inheriting the file certificate.
    pub(super) fn dictionary(
        object: Digest,
        occurrence: &history::Occurrence,
        file: &history::File,
    ) -> Self {
        Self::declared(object, occurrence, file, ObjectRole::Dictionary)
    }

    fn declared(
        object: Digest,
        occurrence: &history::Occurrence,
        file: &history::File,
        role: ObjectRole,
    ) -> Self {
        Self {
            object,
            context: occurrence.context.clone(),
            domain: occurrence.domain.clone(),
            location: Some(file.location.clone()),
            role,
        }
    }

    /// Reports whether this exact ContentRef object may match a file certificate.
    pub(super) fn certificate_eligible(&self) -> bool {
        self.role == ObjectRole::EntryObject
    }
}

/// Borrows the completed consuming view and its held catalog/control observation.
pub(super) struct Inputs<'a> {
    /// Actual consumed original/trust inputs for this held invocation.
    pub(super) consumed: &'a ConsumedResolver,
    /// Held historical observation with no caller-minted authority.
    pub(super) observation: HistoryObservation<'a>,
    /// Completed consuming view used only for exact audit-edge classification.
    pub(super) view: &'a history::View<'a>,
    /// Independently completed selected roots bound to this exact held invocation.
    pub(super) root_histories: &'a QualifiedCollectionRoots<'a>,
    /// Complete structurally checked inspection data, not semantic roots.
    pub(super) records: &'a [(Identity, AttrRecord)],
}

/// Retains every compatible record and all independent producer witnesses.
///
/// # Errors
/// Rejects contradictory or missing attribution and precisely refuses a
/// catalog-only producer claim at an exact certified audit edge before probing
/// that private identity. Physical discovery receipts remain held on failure.
pub(super) async fn expand<F, B, V, C>(
    guard: &Guard<MetadataStore<'_, '_, F, B, V>, C>,
    inputs: Inputs<'_>,
    mut pending: Vec<Target>,
    mode: VisitMode,
    expansion: &mut Expansion,
) -> Result<(), CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let Inputs {
        consumed,
        observation,
        view,
        root_histories,
        records,
    } = inputs;
    let mut by_object: BTreeMap<Digest, Vec<(&Identity, &AttrRecord)>> = BTreeMap::new();
    for (identity, record) in records {
        if identity.kind() != IdentityKind::Attribute {
            return Err(history::invalid(derived::Error::InvalidProvenance).into());
        }
        let computed = record.identity().map_err(history::invalid)?;
        if computed != *identity {
            return Err(history::invalid(derived::Error::InvalidProvenance).into());
        }
        by_object
            .entry(record.object)
            .or_default()
            .push((identity, record));
    }
    let mut targets = BTreeSet::new();
    let mut producer_views = BTreeMap::new();
    while let Some(target) = pending.pop() {
        // A Node, Commit or Attribute identity is not a file Object. Its raw
        // catalog rows remain physical inspection inputs. If the same digest
        // is a genuine ContentRef elsewhere, that actual occurrence supplies
        // its own distinct EntryObject target and independent producer checks.
        if target.role == ObjectRole::Metadata {
            continue;
        }
        if !targets.insert(target.clone()) {
            continue;
        }
        let Some(records) = by_object.get(&target.object) else {
            continue;
        };
        for (identity, record) in records {
            let record_hash: Digest = identity
                .digest()
                .try_into()
                .map_err(|_| history::invalid(derived::Error::InvalidProvenance))?;
            let retained = root_histories.history(&record.producer)?;
            if retained.is_none()
                && ambiguous_audit_producer(view, &target, record)
                && !producer_views.contains_key(&record.producer)
            {
                let source = if target.certificate_eligible() {
                    history::MissingProof::AttributeProducerOccurrence {
                        record: record_hash,
                        producer: record.producer,
                    }
                } else {
                    history::MissingProof::AttributeProducerDeclaredEdge {
                        record: record_hash,
                        object: target.object,
                        producer: record.producer,
                        context: target.context.clone(),
                    }
                };
                return Err(history::missing(source).into());
            }
            if let std::collections::btree_map::Entry::Vacant(entry) =
                producer_views.entry(record.producer)
            {
                let producer = match retained {
                    Some(verified) => history::retained(guard, verified)?,
                    None => {
                        history::acquire(
                            guard,
                            consumed,
                            observation,
                            record.producer,
                            root_histories.contextual_layer(&record.producer)?,
                        )
                        .await?
                    }
                };
                entry.insert(producer);
            }
            let producer = producer_views.get(&record.producer).ok_or_else(|| {
                history::missing(history::MissingProof::AttributeProducerOccurrence {
                    record: record_hash,
                    producer: record.producer,
                })
            })?;
            if !attributed(record, producer, &target.domain)? {
                // The genuine metadata needed to classify an incompatible domain
                // remains a proof read. The inspected record itself is not marked.
                continue;
            }
            expansion.object(7, record_hash, mode.flags(), &target.context);
            let root = producer
                .occurrences
                .iter()
                .find(|occurrence| occurrence.context.absolute_path() == b"/")
                .ok_or_else(|| history::invalid(history::MissingProof::CanonicalOccurrence))?;
            expansion.witness(record.producer, root.context.clone());
            let mut record_target = target.clone();
            record_target.object = record_hash;
            record_target.location = None;
            record_target.role = ObjectRole::Metadata;
            pending.push(record_target);
            if let AttributeValue::ZstdDictionary(dictionary) = &record.value
                && mode == VisitMode::Full
            {
                expansion.object(0, *dictionary, 0, &target.context);
                let mut dictionary_target = target.clone();
                dictionary_target.object = *dictionary;
                dictionary_target.role = ObjectRole::Dictionary;
                pending.push(dictionary_target);
            }
        }
    }
    Ok(())
}

/// Refuses unresolved catalog claims at the exact completed consuming occurrence.
///
/// A declared member or dictionary keeps this proof position for refusal only;
/// the containing entry's certificate does not authenticate or prune its producer.
fn ambiguous_audit_producer(
    view: &history::View<'_>,
    target: &Target,
    record: &AttrRecord,
) -> bool {
    if view
        .verified()
        .completed()
        .history()
        .commit(&record.producer)
        .is_some()
    {
        // This producer completed as an independent dependency in this same
        // held invocation. Catalog membership did not supply that fact.
        return false;
    }
    let (Some(location), Some(batch)) = (&target.location, &view.edges.disclosure) else {
        return false;
    };
    batch.view() == *target.context.destination()
        && batch.boundaries().iter().any(|boundary| {
            boundary.target() == location
                && boundary
                    .root_occurrences()
                    .iter()
                    .any(|path| path == target.context.absolute_path())
                && (boundary.source().commit == record.producer
                    || boundary.original_introducer() == record.producer)
        })
}

/// Separates complete attribution from effective attribute acceptance.
fn attributed(
    record: &AttrRecord,
    producer: &history::View<'_>,
    target_domain: &str,
) -> Result<bool, StoreFailure> {
    let history = producer.verified().completed().history();
    let target_domain = Domain::parse(target_domain).map_err(history::invalid)?;
    if record.signature.is_some() {
        let signed = history
            .commit(&record.producer)
            .ok_or_else(|| history::invalid(derived::Error::InvalidProvenance))?;
        record
            .verify_signature(&signed.signing_public_key())
            .map_err(history::invalid)?;
    }
    let mut valid_occurrence = false;
    let mut first_rejection = None;
    let mut compatible = false;
    for occurrence in &producer.occurrences {
        let producer_domain = Domain::parse(&occurrence.domain).map_err(history::invalid)?;
        for file in &occurrence.files {
            let object = match file.content {
                ContentRef::Inline(hash) | ContentRef::Manifest(hash) => hash,
            };
            if object != record.object {
                continue;
            }
            let attribution = if record.function.supported(record.value.name()) {
                derived::verify_record_producer(record, history, &file.location)
                    .map(|_| ())
                    .map_err(history::invalid)
            } else {
                inactive_attribution(record, history, &file.location)
            };
            match attribution {
                Ok(()) => {
                    valid_occurrence = true;
                    compatible |= target_domain.permits_reference(producer_domain);
                }
                Err(source) => {
                    // The record names a producer commit, not one of its paths.
                    // Another independently checked occurrence can be its actual
                    // witness; a contradictory candidate is never accepted.
                    if first_rejection.is_none() {
                        first_rejection = Some(source);
                    }
                }
            }
        }
    }
    if !valid_occurrence {
        return Err(match first_rejection {
            Some(source) => source,
            None => history::invalid(derived::Error::InvalidProvenance),
        });
    }
    Ok(compatible)
}

/// Validates metadata attribution without activating an unsupported function.
fn inactive_attribution(
    record: &AttrRecord,
    history: &VerifiedHistory,
    location: &EntryLocation,
) -> Result<(), StoreFailure> {
    // The caller owns the Guard's completed producer history; this helper cannot
    // turn caller-built history or an inactive value into reader evidence.
    let entry = history.entry(location).map_err(history::invalid)?;
    let object = match &entry.kind {
        EntryKind::File {
            content: ContentRef::Inline(hash) | ContentRef::Manifest(hash),
            ..
        } => hash,
        _ => return Err(history::invalid(derived::Error::InvalidProvenance)),
    };
    if *object != record.object {
        return Err(history::invalid(derived::Error::InvalidProvenance));
    }
    let inline = entry
        .attrs
        .iter()
        .find(|attribute| attribute.name == record.value.name().as_str());
    if let Some(inline) = inline {
        record
            .agree_inline(inline.value)
            .map_err(history::invalid)?;
    }
    if record.signature.is_some() {
        if location.commit != record.producer {
            return Err(history::invalid(derived::Error::InvalidProvenance));
        }
        let signed = history
            .commit(&record.producer)
            .ok_or_else(|| history::invalid(derived::Error::InvalidProvenance))?;
        record
            .verify_signature(&signed.signing_public_key())
            .map_err(history::invalid)?;
    } else {
        if inline.is_none() {
            return Err(history::invalid(derived::Error::InvalidProvenance));
        }
        let origin = history
            .attribute_producer(location, record.value.name().as_str())
            .map_err(history::invalid)?;
        if origin != record.producer {
            return Err(history::invalid(derived::Error::InvalidProvenance));
        }
    }
    Ok(())
}
