//! Resolves actual absolute root occurrences from completed collection history.
//!
//! Each occurrence retains its selected immutable interpretation. These values
//! describe checked history; current leases and retirement permission belong to
//! the separate collector producer.

use terrane_format::identity::Digest;
use terrane_format::properties::RootLayer;

use super::{Guard, VerifiedCollectionTree};
use crate::guard::{SelectedReadInterpretation, domain_label, invalid};
use crate::store::{Clock, Store, StoreFailure};

/// Retains one actual root occurrence and its resolved historical domain.
pub(crate) struct CollectionOccurrence {
    root: Digest,
    path: Vec<u8>,
    domain: String,
    interpretation: SelectedReadInterpretation,
}

impl CollectionOccurrence {
    /// Returns the canonical root reached at this occurrence.
    pub(crate) fn root(&self) -> Digest {
        self.root
    }

    /// Borrows the canonical absolute path, including every enclosing graft.
    pub(crate) fn path(&self) -> &[u8] {
        &self.path
    }

    /// Borrows the actual domain resolved from the full occurrence layer stack.
    pub(crate) fn domain(&self) -> &str {
        &self.domain
    }

    /// Borrows the immutable interpretation selected by the completed verifier.
    pub(crate) fn interpretation(&self) -> &SelectedReadInterpretation {
        &self.interpretation
    }
}

impl<S: Store, C: Clock> Guard<S, C> {
    /// Resolves every actual root occurrence under its retained interpretation.
    ///
    /// Repeated root identities retain separate absolute paths. Configuration
    /// cannot downgrade a completed explicit interpretation to legacy semantics.
    ///
    /// # Errors
    /// Rejects changed interpretation, malformed graft layers or invalid domains.
    pub(crate) fn collection_occurrences(
        &self,
        checked: &VerifiedCollectionTree,
    ) -> Result<Vec<CollectionOccurrence>, StoreFailure> {
        let evidence = &checked.tree.evidence;
        if self.select_view(
            checked.tree.commit.identity(),
            evidence.root,
            super::HistoryObservation::default(),
        )? != checked.interpretation
        {
            return Err(invalid());
        }

        evidence
            .occurrences(self.config().min_chunk_size)?
            .into_iter()
            .map(|occurrence| {
                let layers = occurrence
                    .layers
                    .iter()
                    .map(|(properties, overrides)| RootLayer {
                        properties,
                        overrides,
                    })
                    .collect::<Vec<_>>();
                let effective = checked
                    .interpretation
                    .resolve(&layers, self.defaults_for(evidence))?;
                let domain = domain_label(&effective).map_err(|_| invalid())?.to_owned();
                Ok(CollectionOccurrence {
                    root: occurrence.root,
                    path: occurrence.path,
                    domain,
                    interpretation: checked.interpretation.clone(),
                })
            })
            .collect()
    }
}
