//! Retains one original query and consumed initial ACK before any Compute.
//!
//! The same endpoint and four fixed historical frames survive Busy, backpressure
//! and permanent refusal. Durable original records precede each outgoing request.
//! Portable matching remains correlation; only the installed source can consume
//! an ACK, and this driver never issues a common prepared token or native epoch.

// SPDX-License-Identifier: Apache-2.0

use crucible_protocol::node_control::{
    NativeFrame, NativePrefixPreparationAcknowledgement, NativePrefixPreparationFacts,
};

use super::initial_store::InitialEvidenceStore;
use super::{ArchiveError, OriginalOperationEndpoint};

/// Reports original preparation custody while execution remains unrequested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginalPreparationProgress {
    /// Retains the same outgoing request or unanswered original obligation.
    Pending,
    /// Durably retains source facts and the exact offered initial ACK.
    FactsRetained,
    /// Durably retains the source consumed-ACK response, without common readiness.
    AcknowledgementConsumed,
    /// Recovers an equal historical response without renewing an obligation.
    HistoricalRecovered,
}

/// Retains a fixed initial journal on the same original endpoint.
pub struct OriginalPreparationDriver<T: OriginalOperationEndpoint> {
    endpoint: T,
    store: InitialEvidenceStore,
    query: Option<NativeFrame>,
    facts: Option<NativePrefixPreparationFacts>,
    offered: Option<NativePrefixPreparationAcknowledgement>,
    consumed: Option<NativePrefixPreparationAcknowledgement>,
    pending: Option<NativeFrame>,
    sent: bool,
    failure: Option<ArchiveError>,
}

impl<T: OriginalOperationEndpoint> OriginalPreparationDriver<T> {
    /// Retains the original endpoint and fsyncs its query before permitting any send.
    ///
    /// Failure returns an inert owner containing the unchanged endpoint and file.
    /// Restored metadata and an offered ACK never become consumed authority.
    pub fn retain(endpoint: T, mut store: InitialEvidenceStore) -> Self {
        let query = (|| {
            let preparation = store.preparation();
            if endpoint.prefix_preparation() != Some(preparation) {
                return Err(ArchiveError::Conflict);
            }
            let original = &preparation.original_effect.original_root.administration;
            let query = NativeFrame::QueryPrefixPreparation {
                scope: original
                    .phase
                    .initialization
                    .preparation
                    .scope
                    .identity_digest()?,
                prefix_preparation: preparation.identity_digest()?,
            };
            store.retain_original(&query)?;
            Ok(query)
        })();
        let (query, failure) = match query {
            Ok(query) => (Some(query), None),
            Err(error) => (None, Some(error)),
        };
        Self {
            endpoint,
            store,
            query: query.clone(),
            facts: None,
            offered: None,
            consumed: None,
            pending: query,
            sent: false,
            failure,
        }
    }

    /// Borrows the complete original source facts after exact independent matching.
    pub fn facts(&self) -> Option<&NativePrefixPreparationFacts> {
        self.facts.as_ref()
    }

    /// Borrows only the source consumed-ACK reply, never an offered request.
    pub fn consumed_acknowledgement(&self) -> Option<&NativePrefixPreparationAcknowledgement> {
        self.consumed.as_ref()
    }

    /// Borrows the permanent refusal while the original file and endpoint stay owned.
    pub fn failure(&self) -> Option<&ArchiveError> {
        self.failure.as_ref()
    }

    /// Reports a settled durable initial journal without asserting Ready or liveness.
    pub fn settled(&self) -> bool {
        self.failure.is_none()
            && self.pending.is_none()
            && self.consumed.is_some()
            && self.store.complete()
    }

    /// Advances the same original initial protocol obligation without blocking.
    ///
    /// # Errors
    /// Retains a permanent framing, original-correlation or storage failure. No
    /// later call exposes another packet after refusal. Busy preserves the same
    /// unsent frame or unanswered request and does not resend automatically.
    pub fn poll(&mut self) -> Result<OriginalPreparationProgress, ArchiveError> {
        if self.failure.is_some() {
            return Err(ArchiveError::Failed);
        }
        match self.poll_original() {
            Ok(progress) => Ok(progress),
            Err(error) => {
                self.failure = Some(error);
                Err(ArchiveError::Failed)
            }
        }
    }

    /// Requests byte-equal recovery of the same current initial obligation.
    ///
    /// # Errors
    /// Rejects permanent refusal or an absent unanswered original. It neither
    /// reserves a replacement credit nor creates a second initialization epoch.
    pub fn request_original_again(&mut self) -> Result<(), ArchiveError> {
        if self.failure.is_some() || self.pending.is_none() {
            return Err(ArchiveError::Failed);
        }
        self.sent = false;
        Ok(())
    }

    pub(super) fn endpoint(&self) -> &T {
        &self.endpoint
    }

    pub(super) fn into_parts(self) -> (T, OriginalInitialEvidence) {
        (
            self.endpoint,
            OriginalInitialEvidence {
                store: self.store,
                query: self.query,
                facts: self.facts,
                offered: self.offered,
                consumed: self.consumed,
            },
        )
    }

    fn poll_original(&mut self) -> Result<OriginalPreparationProgress, ArchiveError> {
        if !self.sent
            && let Some(frame) = &self.pending
        {
            if !self.endpoint.send_original(frame)? {
                return Ok(OriginalPreparationProgress::Pending);
            }
            self.sent = true;
        }
        let Some(frame) = self.endpoint.receive_original()? else {
            return Ok(OriginalPreparationProgress::Pending);
        };
        match frame {
            NativeFrame::PrefixPreparationFacts(facts) => {
                if let Some(original) = &self.facts {
                    return if original == facts.as_ref() {
                        Ok(OriginalPreparationProgress::HistoricalRecovered)
                    } else {
                        Err(ArchiveError::Conflict)
                    };
                }
                if self.pending != self.query || !self.sent {
                    return Err(ArchiveError::Conflict);
                }
                let observation = facts
                    .observe_original(self.store.preparation(), self.store.initialization())?;
                let offered = NativePrefixPreparationAcknowledgement::from_original(&observation)?;
                self.store
                    .retain_original(&NativeFrame::PrefixPreparationFacts(facts.clone()))?;
                let request = NativeFrame::AcknowledgePrefixPreparation(offered.clone());
                self.store.retain_original(&request)?;
                self.facts = Some(*facts);
                self.offered = Some(offered);
                self.pending = Some(request);
                self.sent = false;
                Ok(OriginalPreparationProgress::FactsRetained)
            }
            NativeFrame::PrefixPreparationAcknowledged(consumed) => {
                if self.offered.as_ref() != Some(&consumed) {
                    return Err(ArchiveError::Conflict);
                }
                if let Some(original) = &self.consumed {
                    return if original == &consumed {
                        Ok(OriginalPreparationProgress::HistoricalRecovered)
                    } else {
                        Err(ArchiveError::Conflict)
                    };
                }
                if self.pending != Some(NativeFrame::AcknowledgePrefixPreparation(consumed.clone()))
                    || !self.sent
                {
                    return Err(ArchiveError::Conflict);
                }
                self.store
                    .retain_original(&NativeFrame::PrefixPreparationAcknowledged(
                        consumed.clone(),
                    ))?;
                self.consumed = Some(consumed);
                self.pending = None;
                self.sent = false;
                Ok(OriginalPreparationProgress::AcknowledgementConsumed)
            }
            _ => Err(ArchiveError::Conflict),
        }
    }
}

/// Retains every original initial body and its durable file after session consumption.
///
/// The records are historical correlation data. This value exposes no native
/// handles, dispatch method, common prepared token or storage restore authority.
pub struct OriginalInitialEvidence {
    store: InitialEvidenceStore,
    query: Option<NativeFrame>,
    facts: Option<NativePrefixPreparationFacts>,
    offered: Option<NativePrefixPreparationAcknowledgement>,
    consumed: Option<NativePrefixPreparationAcknowledgement>,
}

impl OriginalInitialEvidence {
    /// Borrows the unchanged durable initial evidence file and complete companions.
    pub fn store(&self) -> &InitialEvidenceStore {
        &self.store
    }

    /// Borrows the exact original query retained before its first send.
    pub fn query(&self) -> Option<&NativeFrame> {
        self.query.as_ref()
    }

    /// Borrows the complete original source response.
    pub fn facts(&self) -> Option<&NativePrefixPreparationFacts> {
        self.facts.as_ref()
    }

    /// Borrows the offered original ACK without claiming source consumption.
    pub fn offered_acknowledgement(&self) -> Option<&NativePrefixPreparationAcknowledgement> {
        self.offered.as_ref()
    }

    /// Borrows the byte-equal actual consumed-ACK response retained before Compute.
    pub fn consumed_acknowledgement(&self) -> Option<&NativePrefixPreparationAcknowledgement> {
        self.consumed.as_ref()
    }
}
