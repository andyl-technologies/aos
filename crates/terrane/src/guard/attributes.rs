//! Authenticates side records and their current readable producing witnesses.

use terrane_core::derived::{AttrRecord, VerifiedAttributeEvidence, verify_record_producer};
use terrane_core::identity::IdentityKind;
use terrane_core::provenance::EntryLocation;
use terrane_core::tree_format::{ContentRef, EntryKind};

use super::admission::CandidateRequest;
use super::{Guard, StagedUpload, invalid};
use crate::store::{Clock, Store, StoreFailure};

pub(super) struct RequirementEvidence {
    pub(super) attribute: VerifiedAttributeEvidence,
    pub(super) path: Vec<u8>,
}

impl<S: Store, C: Clock> Guard<S, C> {
    pub(super) async fn requirement_evidence(
        &self,
        request: &CandidateRequest<'_>,
    ) -> Result<Vec<RequirementEvidence>, StoreFailure> {
        let mut records = Vec::new();
        for upload in request.uploads {
            if let StagedUpload::Meta {
                kind: IdentityKind::Attribute,
                bytes,
            } = upload
            {
                records.push(AttrRecord::decode(bytes).map_err(|_| invalid())?);
            }
        }
        for record in request.reference_records {
            if record.identity().kind() != IdentityKind::Attribute {
                continue;
            }
            if record.domain() != self.config().storage_domain {
                return Err(invalid());
            }
            let bytes = self.store().get(record.identity(), None).await?;
            let attribute = AttrRecord::decode(&bytes).map_err(|_| invalid())?;
            if attribute.identity().map_err(|_| invalid())? != *record.identity() {
                return Err(invalid());
            }
            records.push(attribute);
        }
        let mut verified = Vec::new();
        for record in records {
            let history = self.verified_history(record.producer).await?;
            let producer = self.verified_tree(record.producer).await?;
            let locations = {
                let mut locations = Vec::new();
                for occurrence in producer
                    .evidence
                    .occurrences(self.config().min_chunk_size)?
                {
                    let tree = producer
                        .evidence
                        .tree(occurrence.root, self.config().min_chunk_size)?;
                    for item in tree.iter() {
                        let EntryKind::File {
                            content: ContentRef::Inline(object) | ContentRef::Manifest(object),
                            ..
                        } = &item.entry.kind
                        else {
                            continue;
                        };
                        if *object != record.object {
                            continue;
                        }
                        let mut path = occurrence.path.clone();
                        if path != b"/" {
                            path.push(b'/');
                        }
                        path.extend_from_slice(&item.key);
                        locations.push((
                            EntryLocation {
                                commit: record.producer,
                                root: occurrence.root,
                                path: item.key.to_vec(),
                            },
                            path,
                        ));
                    }
                }
                locations
            };
            let mut selected = None;
            for (location, path) in locations {
                let Ok(attribute) = verify_record_producer(&record, &history, &location) else {
                    continue;
                };
                let Ok(snapshot) = self
                    .read_commit_snapshot(record.producer, request.token, &path, request.surface)
                    .await
                else {
                    continue;
                };
                if snapshot.storage_domain != self.config().storage_domain {
                    continue;
                }
                selected = Some(RequirementEvidence { attribute, path });
                break;
            }
            verified.push(selected.ok_or_else(invalid)?);
        }
        Ok(verified)
    }

    /// Rechecks required Admin decisions and readable attribute producers while held.
    ///
    /// # Errors
    /// Preserves current authority, historical witness, and storage failures.
    pub(crate) async fn revalidate_admission_observed(
        &self,
        admitted: &super::AdmittedCommit,
        observation: super::HistoryObservation<'_>,
    ) -> Result<(), StoreFailure> {
        self.capture_admission_authorizations_observed(admitted, observation)
            .await
            .map(|_| ())
    }

    /// Captures each successful required Admin and producer Read request after revalidation.
    ///
    /// The result retains genuine request inputs for a final clock/token refresh;
    /// it does not replace current policy or physical-control exclusion.
    ///
    /// # Errors
    /// Preserves current denial, unavailable storage and authenticated witness failures.
    pub(crate) async fn capture_admission_authorizations_observed(
        &self,
        admitted: &super::AdmittedCommit,
        observation: super::HistoryObservation<'_>,
    ) -> Result<Vec<super::AuthorizedRef>, StoreFailure> {
        let mut captured = Vec::new();
        for check in &admitted.admin_checks {
            let mut authorized = false;
            for path in &check.alternatives {
                match self
                    .authorize_observed(
                        &admitted.publication_reference,
                        &admitted.token,
                        terrane_core::auth::Verb::Admin,
                        std::slice::from_ref(path),
                        &admitted.surface,
                        observation,
                    )
                    .await
                {
                    Ok(request) => {
                        captured.push(request);
                        authorized = true;
                        break;
                    }
                    Err(failure)
                        if matches!(
                            failure.kind(),
                            crate::store::StoreErrorKind::Denied { .. }
                        ) => {}
                    Err(failure) => return Err(failure),
                }
            }
            if !authorized {
                return Err(super::denied(
                    &admitted.publication_reference,
                    terrane_core::auth::Verb::Admin,
                ));
            }
        }

        for evidence in &admitted.requirements {
            let (_, requests) = self
                .read_commit_snapshot_authorizations_observed(
                    *evidence.attribute.producer(),
                    &admitted.token,
                    &evidence.path,
                    &admitted.surface,
                    observation,
                )
                .await?;
            captured.extend(requests);
        }
        Ok(captured)
    }
}
