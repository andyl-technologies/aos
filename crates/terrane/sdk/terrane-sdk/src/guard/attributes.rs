//! Authenticates side records and their current readable producing witnesses.

use terrane_format::derived::{AttrRecord, VerifiedAttributeEvidence};
use terrane_format::identity::IdentityKind;
use terrane_format::provenance::EntryLocation;
use terrane_format::tree_format::{ContentRef, EntryKind};

use crate::derived::ProducerEvidence;

use super::admission::CandidateRequest;
use super::{Guard, StagedUpload, invalid};
use crate::store::{Clock, Store, StoreFailure};

/// Retains a qualified attribute value and its actual current-readable producer path.
pub(super) struct RequirementEvidence {
    /// Retains the value authenticated through its genuine producing history.
    pub(super) attribute: VerifiedAttributeEvidence,
    /// Names the producing occurrence requiring fresh Read authorization.
    pub(super) path: Vec<u8>,
}

/// Retains genuine producer evidence and a readable occurrence for one side record.
///
/// This carrier supplies immutable producer evidence, not current Read or Commit
/// authority. Ordinary admission still rechecks the producing path while held.
pub(super) struct CheckedAttributeRecord {
    /// Existing producer evidence constructed by the authentic history verifier.
    pub(super) producer: ProducerEvidence,
    /// Actual producing file path that passed current scoped Read and trust.
    pub(super) path: Vec<u8>,
}

impl<S: Store, C: Clock> Guard<S, C> {
    /// Qualifies actual required attribute records and their current producing paths.
    ///
    /// # Errors
    /// Rejects malformed records, invalid producers, unsupported functions and
    /// current Read/trust denial; preserves originating Original/store failures.
    pub(super) async fn requirement_evidence_observed(
        &self,
        request: &CandidateRequest<'_>,
        observation: super::HistoryObservation<'_>,
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
            let checked = self
                .checked_attribute_record_observed(
                    record,
                    request.token,
                    request.surface,
                    observation,
                )
                .await?;
            verified.push(RequirementEvidence {
                attribute: checked.producer.as_verified().clone(),
                path: checked.path,
            });
        }
        Ok(verified)
    }

    /// Qualifies an exact ordinary record through genuine original producer history.
    ///
    /// The caller must separately verify storage identity and catalog membership.
    /// This extracts the existing admission checks without selecting a value,
    /// changing provenance, or granting publication authority.
    ///
    /// # Errors
    /// Preserves original history and storage failures. Rejects unsupported
    /// functions, contradictory producer/value witnesses and records without a
    /// current readable, trusted producing occurrence in this storage domain.
    pub(super) async fn checked_attribute_record(
        &self,
        record: AttrRecord,
        token: &[u8],
        surface: &str,
    ) -> Result<CheckedAttributeRecord, StoreFailure> {
        self.checked_attribute_record_observed(
            record,
            token,
            surface,
            super::HistoryObservation::default(),
        )
        .await
    }

    /// Authenticates a record's original producer under the exact borrowed observation.
    ///
    /// # Errors
    /// Preserves signed history, Original, current Read/trust and storage failures;
    /// rejects unsupported functions or contradictory value/content witnesses.
    /// Initial failures follow the paired verifier's tree-before-history order.
    pub(super) async fn checked_attribute_record_observed(
        &self,
        record: AttrRecord,
        token: &[u8],
        surface: &str,
        observation: super::HistoryObservation<'_>,
    ) -> Result<CheckedAttributeRecord, StoreFailure> {
        let (producer, history) = self
            .verified_tree_history_observed(record.producer, observation)
            .await?;
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
        for (location, path) in locations {
            let Ok(producer) = ProducerEvidence::from_history(&record, &history, &location) else {
                continue;
            };
            let Ok(snapshot) = self
                .read_commit_snapshot_observed(record.producer, token, &path, surface, observation)
                .await
            else {
                continue;
            };
            if snapshot.storage_domain != self.config().storage_domain {
                continue;
            }
            return Ok(CheckedAttributeRecord { producer, path });
        }
        Err(invalid())
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
        let mut captured = vec![
            self.authorize_observed(
                &admitted.publication_reference,
                &admitted.token,
                admitted.publication_verb,
                admitted.publication_paths(),
                &admitted.surface,
                observation,
            )
            .await?,
        ];
        for check in &admitted.admin_checks {
            let mut authorized = false;
            for path in &check.alternatives {
                match self
                    .authorize_observed(
                        &admitted.publication_reference,
                        &admitted.token,
                        terrane_format::auth::Verb::Admin,
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
                    terrane_format::auth::Verb::Admin,
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
