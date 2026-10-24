//! Adapts actual native producer qualification to the existing side-table owner.

use std::collections::BTreeMap;

use terrane_format::derived::{AttrRecord, AttributeName};
use terrane_format::identity::{Digest, Identity, IdentityKind, TERRANE_V1};

use crate::derived::{self, AttributeCatalog, ProducerEvidence, ProducerVerifier, SideTable};
use crate::guard::Guard;
use crate::store::{ContentStore, StoreErrorKind, StoreFailure};

use super::IndexBackfillGapReason;

/// Retains one side record with genuine producer evidence and its readable occurrence.
pub(super) struct CheckedRecord {
    /// Retains the exact ordinary attribute record qualified by the producer.
    pub(super) record: AttrRecord,
    /// Retains immutable evidence authenticated by the owning history verifier.
    pub(super) producer: ProducerEvidence,
    /// Names the producing occurrence checked under current Read and trust.
    pub(super) path: Vec<u8>,
}

/// Collects qualified side records and explicit reasons for missing evidence.
pub(super) struct Records {
    /// Retains the rebuilt side table whose records passed producer qualification.
    pub(super) table: SideTable,
    checked: BTreeMap<Digest, CheckedRecord>,
    failed: BTreeMap<(Digest, AttributeName), IndexBackfillGapReason>,
}

impl Records {
    /// Borrows the qualified evidence for an exact selected side record.
    ///
    /// # Errors
    /// Rejects malformed record identities or records absent from qualified evidence.
    pub(super) fn selected(&self, record: &AttrRecord) -> Result<&CheckedRecord, StoreFailure> {
        let identity = record.identity().map_err(super::edits::failure)?;
        self.checked
            .get(&record_key(&identity)?)
            .ok_or_else(crate::guard::invalid)
    }

    /// Returns the observed gap reason or MissingEvidence when none was recorded.
    pub(super) fn missing(&self, object: Digest, name: AttributeName) -> IndexBackfillGapReason {
        self.failed
            .get(&(object, name))
            .cloned()
            .unwrap_or(IndexBackfillGapReason::MissingEvidence)
    }
}

// Kind and profile are checked before the digest becomes a private ordering
// key. Public reports retain the complete original identity.
/// Extracts a private ordering key after checking Attribute kind and identity profile.
///
/// # Errors
/// Rejects non-Attribute identities or identities outside the Terrane v1 profile.
pub(super) fn record_key(identity: &Identity) -> Result<Digest, StoreFailure> {
    if identity.kind() != IdentityKind::Attribute {
        return Err(crate::guard::invalid());
    }
    identity.terrane_v1_digest().map_err(super::edits::failure)
}

struct Qualified<'a>(&'a BTreeMap<Digest, CheckedRecord>);

impl ProducerVerifier for Qualified<'_> {
    fn verify(&self, record: &AttrRecord) -> Result<Option<ProducerEvidence>, derived::Error> {
        let identity = record.identity()?;
        let key = record_key(&identity).map_err(derived::Error::Store)?;
        match self.0.get(&key) {
            Some(checked) => Ok(Some(checked.producer.clone())),
            // An unsuccessful producer/current qualification is not an ordinary
            // trusted record. This ephemeral quarantine does not modify storage.
            None => Err(derived::Error::InvalidProducer),
        }
    }
}

/// Qualifies catalog records through actual producer history and current readable paths.
///
/// # Errors
/// Preserves catalog, immutable read and side-table failures. Expected producer
/// refusals become gap reasons; other producer failures propagate unchanged.
#[cfg(unix)]
pub(super) async fn acquire<F, B, V, C>(
    guard: &Guard<crate::bucket::FileBucket<F, B, V>, C>,
    token: &[u8],
    surface: &str,
) -> Result<Records, StoreFailure>
where
    F: crate::store::LocalFs + crate::bucket::BucketBinding + Sync,
    B: crate::store::Clock + crate::bucket::BucketBinding + Sync,
    V: crate::store::ContentValidator + crate::bucket::BucketBinding + Sync,
    C: crate::store::Clock + Sync,
{
    let catalog = guard
        .store()
        .attribute_identities()
        .await
        .map_err(derived_failure)?;
    let mut checked = BTreeMap::new();
    let mut failed = BTreeMap::new();
    for identity in catalog {
        let bytes = guard.store().get(&identity, None).await?;
        if TERRANE_V1.verify(&identity, &bytes).is_err() {
            // The existing SideTable independently quarantines malformed bodies.
            continue;
        }
        let Ok(record) = AttrRecord::decode(&bytes) else {
            continue;
        };
        if !record.function.supported(record.value.name()) {
            failed.insert(
                (record.object, record.value.name()),
                IndexBackfillGapReason::UnsupportedInput,
            );
            continue;
        }
        match guard
            .checked_attribute_record(record.clone(), token, surface)
            .await
        {
            Ok(evidence) => {
                checked.insert(
                    record_key(&identity)?,
                    CheckedRecord {
                        record,
                        producer: evidence.producer,
                        path: evidence.path,
                    },
                );
            }
            Err(error) => {
                let reason = match error.kind() {
                    StoreErrorKind::Denied { .. } => IndexBackfillGapReason::ProducerDenied,
                    StoreErrorKind::Unavailable { .. } | StoreErrorKind::Absent(_) => {
                        IndexBackfillGapReason::UnavailableEvidence
                    }
                    StoreErrorKind::Unsupported => IndexBackfillGapReason::UnsupportedInput,
                    StoreErrorKind::Invalid(_) | StoreErrorKind::Corrupt(_) => {
                        IndexBackfillGapReason::InvalidEvidence
                    }
                    _ => return Err(error),
                };
                failed.insert((record.object, record.value.name()), reason);
            }
        }
    }
    let table = SideTable::rebuild(guard.store(), guard.store(), &Qualified(&checked))
        .await
        .map_err(derived_failure)?;
    Ok(Records {
        table,
        checked,
        failed,
    })
}

fn derived_failure(error: derived::Error) -> StoreFailure {
    match error {
        derived::Error::Store(failure) => failure,
        other => super::edits::failure(other),
    }
}
