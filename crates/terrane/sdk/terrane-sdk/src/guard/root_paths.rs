//! Discovers actual readable root occurrences without a whole-view grant.

use terrane_format::{auth, auth::Verb, refs::RefName};

use super::{Guard, HistoryObservation, denied};
use crate::store::{Clock, Store, StoreErrorKind, StoreFailure};

impl<S: Store, C: Clock> Guard<S, C> {
    /// Returns only actual root paths authorized under one unchanged whole head.
    pub(crate) async fn readable_root_paths(
        &self,
        reference: &str,
        token: &[u8],
        surface: &str,
    ) -> Result<Vec<Vec<u8>>, StoreFailure> {
        RefName::parse(reference).map_err(|_| denied(reference, Verb::Read))?;
        self.check_root_discovery_identity(reference, token)?;
        let (record, evidence) = self
            .current_authorization_evidence(
                reference,
                #[cfg(all(feature = "std", feature = "tokio", unix))]
                token,
                Verb::Read,
                HistoryObservation::default(),
            )
            .await?;

        // A digest can occur at several graft paths with different effective
        // policy. Never deduplicate occurrences by their shared root identity.
        let mut readable = Vec::new();
        if let Some(evidence) = evidence {
            for occurrence in evidence.occurrences(self.config.min_chunk_size)? {
                match self
                    .authorize(
                        reference,
                        token,
                        Verb::Read,
                        std::slice::from_ref(&occurrence.path),
                        surface,
                    )
                    .await
                {
                    Ok(authorized) => {
                        if authorized.record() != record.as_ref() {
                            return Err(changed());
                        }
                        readable.push(occurrence.path);
                    }
                    Err(error) if matches!(error.kind(), StoreErrorKind::Denied { .. }) => {}
                    Err(error) => return Err(error),
                }
            }
        }

        readable.sort();
        self.check_root_discovery_identity(reference, token)?;
        if readable.is_empty() {
            let (closing, _) = self
                .current_authorization_evidence(
                    reference,
                    #[cfg(all(feature = "std", feature = "tokio", unix))]
                    token,
                    Verb::Read,
                    HistoryObservation::default(),
                )
                .await?;
            if closing != record {
                return Err(changed());
            }
        } else {
            // Initial denials filter candidates. A closing denial discards the
            // entire prepared result, including paths authorized earlier.
            for path in &readable {
                let authorized = self
                    .authorize(
                        reference,
                        token,
                        Verb::Read,
                        std::slice::from_ref(path),
                        surface,
                    )
                    .await?;
                if authorized.record() != record.as_ref() {
                    return Err(changed());
                }
            }
        }

        if self.store.ref_get(reference).await? != record {
            return Err(changed());
        }
        self.check_root_discovery_identity(reference, token)?;
        Ok(readable)
    }

    fn check_root_discovery_identity(
        &self,
        reference: &str,
        token: &[u8],
    ) -> Result<(), StoreFailure> {
        auth::verify(token, &self.keys, self.now(reference, Verb::Read)?)
            .map(|_| ())
            .map_err(|_| denied(reference, Verb::Read))
    }
}

fn changed() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Unavailable { retry_after: None })
}
