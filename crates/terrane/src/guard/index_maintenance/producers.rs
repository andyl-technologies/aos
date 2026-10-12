//! Independently authenticates existing inline values and their current producers.

use terrane_core::derived::{AttrRecord, AttributeName, AttributeValue, verify_record_producer};
use terrane_core::tree_format::EntryKind;

use crate::guard::{AuthorizedRef, AuthorizedSnapshot, Guard, HistoryObservation, invalid};
use crate::store::{Clock, Store, StoreFailure};

use super::failure;

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
                work.history_boundary_calls = work
                    .history_boundary_calls
                    .checked_add(1)
                    .ok_or_else(invalid)?;
                let producer = snapshot
                    .history
                    .attribute_producer(&location, name.as_str())
                    .map_err(failure)?;
                let (verified, history) = self
                    .verified_tree_history_observed(producer, observation)
                    .await?;
                let paths = {
                    let mut paths = Vec::new();
                    for occurrence in verified
                        .evidence
                        .occurrences(self.config().min_chunk_size)?
                    {
                        let tree = verified
                            .evidence
                            .tree(occurrence.root, self.config().min_chunk_size)?;
                        for item in tree.iter() {
                            work.producer_entries =
                                work.producer_entries.checked_add(1).ok_or_else(invalid)?;
                            let EntryKind::File {
                                content: actual,
                                size: actual_size,
                                ..
                            } = &item.entry.kind
                            else {
                                continue;
                            };
                            if *actual != content
                                || *actual_size != size
                                || !item.entry.attrs.iter().any(|attribute| {
                                    attribute.name == name.as_str() && attribute.value == encoded
                                })
                            {
                                continue;
                            }
                            let mut producer_path = occurrence.path.clone();
                            if producer_path != b"/" {
                                producer_path.push(b'/');
                            }
                            producer_path.extend_from_slice(&item.key);
                            let (source, _) = history
                                .locate(
                                    producer,
                                    producer_path.strip_prefix(b"/").ok_or_else(invalid)?,
                                )
                                .map_err(failure)?;
                            if history
                                .attribute_producer(&source, name.as_str())
                                .map_err(failure)?
                                != producer
                            {
                                continue;
                            }
                            let value = AttributeValue::decode(name, &encoded).map_err(failure)?;
                            let object = match content {
                                terrane_core::tree_format::ContentRef::Inline(object)
                                | terrane_core::tree_format::ContentRef::Manifest(object) => object,
                            };
                            verify_record_producer(
                                &AttrRecord::new(object, value, producer),
                                &history,
                                &source,
                            )
                            .map_err(failure)?;
                            paths.push(producer_path);
                        }
                    }
                    paths
                };
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
                    work.history_boundary_calls = work
                        .history_boundary_calls
                        .checked_add(1)
                        .ok_or_else(invalid)?;
                    match self
                        .read_commit_snapshot_authorizations_observed(
                            producer,
                            token,
                            &producer_path,
                            surface,
                            observation,
                        )
                        .await
                    {
                        Ok((producer_snapshot, current)) => {
                            if producer_snapshot.storage_domain != snapshot.storage_domain {
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
