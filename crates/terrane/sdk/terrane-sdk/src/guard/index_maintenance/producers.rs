//! Independently authenticates existing inline values and their current producers.

use std::collections::{BTreeMap, btree_map::Entry};

use terrane_format::derived::{AttrRecord, AttributeName, AttributeValue, verify_record_producer};
use terrane_format::identity::Digest;
use terrane_format::provenance::VerifiedHistory;
use terrane_format::tree_format::{ContentRef, EntryKind};

use crate::guard::{AuthorizedRef, AuthorizedSnapshot, Guard, HistoryObservation, invalid};
use crate::store::{Clock, Store, StoreFailure};

use super::failure;

#[derive(Eq, Ord, PartialEq, PartialOrd)]
enum ContentKind {
    Inline,
    Manifest,
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct CandidateKey {
    content_kind: ContentKind,
    object: Digest,
    size: u64,
    name: AttributeName,
    encoded: Vec<u8>,
}

struct ProducerInputs {
    history: VerifiedHistory,
    originals: Vec<crate::guard::OriginalCommitContext>,
    candidates: BTreeMap<CandidateKey, Vec<Vec<u8>>>,
}

struct ServingInputs {
    verified: crate::guard::history::VerifiedTree,
    history: VerifiedHistory,
    originals: Vec<crate::guard::OriginalCommitContext>,
}

fn candidate_key(
    content: ContentRef,
    size: u64,
    name: AttributeName,
    encoded: &[u8],
) -> CandidateKey {
    let (content_kind, object) = match content {
        ContentRef::Inline(object) => (ContentKind::Inline, object),
        ContentRef::Manifest(object) => (ContentKind::Manifest, object),
    };
    CandidateKey {
        content_kind,
        object,
        size,
        name,
        encoded: encoded.to_vec(),
    }
}

// Inventory only immutable bytes. Provenance checks remain at the original
// matching-row boundary, so unrelated attributes cannot change refusal order.
fn inventory(
    verified: &crate::guard::history::VerifiedTree,
    minimum: u64,
    work: &mut crate::guard::read::indexes::IndexLookupCurrentWork,
) -> Result<BTreeMap<CandidateKey, Vec<Vec<u8>>>, StoreFailure> {
    let mut candidates = BTreeMap::<CandidateKey, Vec<Vec<u8>>>::new();
    for occurrence in verified.evidence.occurrences(minimum)? {
        let tree = verified.evidence.tree(occurrence.root, minimum)?;
        for item in tree.iter() {
            work.producer_entries = work.producer_entries.checked_add(1).ok_or_else(invalid)?;
            let EntryKind::File { content, size, .. } = &item.entry.kind else {
                continue;
            };
            let mut path = occurrence.path.clone();
            if path != b"/" {
                path.push(b'/');
            }
            path.extend_from_slice(&item.key);
            for attribute in &item.entry.attrs {
                if let Ok(name) = AttributeName::parse(attribute.name) {
                    candidates
                        .entry(candidate_key(*content, *size, name, attribute.value))
                        .or_default()
                        .push(path.clone());
                }
            }
        }
    }
    Ok(candidates)
}

impl<S: Store, C: Clock> Guard<S, C> {
    /// Repeats current occurrence and producer checks without reading plaintext.
    ///
    /// # Errors
    /// Refuses unavailable provenance, mismatched values/content, current denial,
    /// unsupported domain evidence and producers failing their own current trust.
    pub(in crate::guard) async fn check_index_source_producers(
        &self,
        snapshot: &AuthorizedSnapshot,
        observation: HistoryObservation<'_>,
        work: &mut crate::guard::read::indexes::IndexLookupCurrentWork,
    ) -> Result<Vec<AuthorizedRef>, StoreFailure> {
        let (_, token, surface) = snapshot.maintenance_credentials();
        let rows = {
            let mut rows = Vec::new();
            for occurrence in snapshot
                .evidence
                .occurrences(self.config().min_chunk_size)?
            {
                let tree = snapshot
                    .evidence
                    .tree(occurrence.root, self.config().min_chunk_size)?;
                for item in tree.iter() {
                    let EntryKind::File { content, size, .. } = &item.entry.kind else {
                        continue;
                    };
                    let mut path = occurrence.path.clone();
                    if path != b"/" {
                        path.push(b'/');
                    }
                    path.extend_from_slice(&item.key);
                    let values = item
                        .entry
                        .attrs
                        .iter()
                        .filter_map(|attribute| {
                            AttributeName::parse(attribute.name)
                                .ok()
                                .map(|name| (name, attribute.value.to_vec()))
                        })
                        .collect::<Vec<_>>();
                    rows.push((path, *content, *size, values));
                }
            }
            rows
        };
        let mut requests = Vec::new();
        // These maps cannot escape this fixed observation, guard or credential
        // invocation. Serving and source qualification have distinct purposes.
        // The signed view fixes each root; refresh checks its retained selection
        // and every captured Original. Domain and live rights are never cached.
        let mut producers = BTreeMap::<Digest, ProducerInputs>::new();
        let mut serving = BTreeMap::<Digest, ServingInputs>::new();
        for (path, content, size, values) in rows {
            work.occurrence_checks = work.occurrence_checks.checked_add(1).ok_or_else(invalid)?;
            requests.extend(
                self.snapshot_authorizations_observed(snapshot, &path, observation)
                    .await?,
            );
            let (location, _) = snapshot
                .history
                .locate(
                    snapshot.commit.identity(),
                    path.strip_prefix(b"/").ok_or_else(invalid)?,
                )
                .map_err(failure)?;
            for (name, encoded) in values {
                work.attribute_origin_checks = work
                    .attribute_origin_checks
                    .checked_add(1)
                    .ok_or_else(invalid)?;
                let producer = snapshot
                    .history
                    .attribute_producer(&location, name.as_str())
                    .map_err(failure)?;
                let prepared: &ProducerInputs = match producers.entry(producer) {
                    Entry::Vacant(entry) => {
                        work.history_boundary_calls = work
                            .history_boundary_calls
                            .checked_add(1)
                            .ok_or_else(invalid)?;
                        let (verified, history) = self
                            .verified_tree_history_observed(producer, observation)
                            .await?;
                        let candidates = inventory(&verified, self.config().min_chunk_size, work)?;
                        let originals = self.producer_originals(&history)?;
                        entry.insert(ProducerInputs {
                            history,
                            originals,
                            candidates,
                        })
                    }
                    Entry::Occupied(entry) => {
                        let prepared = entry.into_mut();
                        self.refresh_producer_history(
                            &prepared.history,
                            &prepared.originals,
                            observation,
                        )
                        .await?;

                        prepared
                    }
                };
                let mut paths = Vec::new();
                for producer_path in prepared
                    .candidates
                    .get(&candidate_key(content, size, name, &encoded))
                    .into_iter()
                    .flatten()
                {
                    let (source, _) = prepared
                        .history
                        .locate(
                            producer,
                            producer_path.strip_prefix(b"/").ok_or_else(invalid)?,
                        )
                        .map_err(failure)?;
                    if prepared
                        .history
                        .attribute_producer(&source, name.as_str())
                        .map_err(failure)?
                        != producer
                    {
                        continue;
                    }
                    let value = AttributeValue::decode(name, &encoded).map_err(failure)?;
                    let object = match content {
                        ContentRef::Inline(object) | ContentRef::Manifest(object) => object,
                    };
                    verify_record_producer(
                        &AttrRecord::new(object, value, producer),
                        &prepared.history,
                        &source,
                    )
                    .map_err(failure)?;
                    paths.push(producer_path.clone());
                }
                if paths.is_empty() {
                    return Err(invalid());
                }
                // At least one actual producer occurrence must pass its own current
                // capability, live ACL and effective immutable trust intersection.
                let mut accepted = false;
                let mut denied = None;
                for producer_path in paths {
                    work.producer_checks =
                        work.producer_checks.checked_add(1).ok_or_else(invalid)?;
                    let prepared: &ServingInputs = match serving.entry(producer) {
                        Entry::Vacant(entry) => {
                            work.history_boundary_calls = work
                                .history_boundary_calls
                                .checked_add(1)
                                .ok_or_else(invalid)?;
                            let (verified, history) = self
                                .verified_tree_history_observed(
                                    producer,
                                    observation.requested_target(),
                                )
                                .await?;
                            let originals = self.producer_originals(&history)?;
                            entry.insert(ServingInputs {
                                verified,
                                history,
                                originals,
                            })
                        }
                        Entry::Occupied(entry) => {
                            let prepared = entry.into_mut();
                            self.refresh_producer_history(
                                &prepared.history,
                                &prepared.originals,
                                observation.requested_target(),
                            )
                            .await?;

                            prepared
                        }
                    };
                    match self
                        .producer_authorizations_from_history(
                            (&prepared.verified, &prepared.history),
                            token,
                            &producer_path,
                            surface,
                            observation,
                        )
                        .await
                    {
                        Ok((domain, current)) => {
                            if domain != snapshot.storage_domain {
                                return Err(invalid());
                            }
                            requests.extend(current);
                            accepted = true;
                            break;
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                crate::store::StoreErrorKind::Denied { .. }
                            ) =>
                        {
                            if denied.is_none() {
                                denied = Some(error);
                            }
                        }
                        Err(error) => return Err(error),
                    }
                }
                if !accepted {
                    return Err(match denied {
                        Some(error) => error,
                        None => invalid(),
                    });
                }
            }
        }
        Ok(requests)
    }
}
