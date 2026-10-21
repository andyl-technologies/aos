//! Copies fixed actor-owned foundation observations for ordinary controls.
//!
//! Only the owning actor publishes these values. The public handle cannot
//! change them, invoke callbacks or turn a copied observation into authority.

use super::NodeObservationServiceError;
use std::sync::{Arc, Mutex};

/// Reports the actual funded capsule's retained preparation/cleanup disposition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundedTemplatePhase {
    /// No funded capsule is installed in this actor.
    Absent,
    /// The retained capsule has not consumed its preparation entry.
    Unattempted,
    /// The first preparation failed or unwound; its original custody remains.
    AttemptFailed,
    /// The first preparation returned authenticated template success only.
    TemplatesRetained,
    /// All three original worker results and private Births remain retained.
    PrivateBirthsRetained,
    /// An authenticated template later failed its worker or Birth construction.
    DerivationFailed,
    /// Explicit revocation and actual namespace cleanup released its credit.
    Reclaimed,
}

/// Copies foundation disposition and the actor's actual complete-scene debit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FundedTemplateObservation {
    phase: FundedTemplatePhase,
    retained_worlds: usize,
    failure_reason: Option<&'static str>,
}

impl FundedTemplateObservation {
    pub(crate) fn from_actor(
        phase: FundedTemplatePhase,
        retained_worlds: usize,
        failure_reason: Option<&'static str>,
    ) -> Self {
        Self {
            phase,
            retained_worlds,
            failure_reason,
        }
    }

    /// Reads the copied first-attempt/cleanup disposition.
    #[must_use]
    pub fn phase(self) -> FundedTemplatePhase {
        self.phase
    }

    /// Reads the owning actor's actual complete-scene world count.
    #[must_use]
    pub fn retained_worlds(self) -> usize {
        self.retained_worlds
    }

    /// Reads a fixed diagnostic from the actor's retained first failure.
    ///
    /// Dynamic evidence and schema contents are replaced by fixed categories.
    /// This observation carries no input bytes or preparation authority.
    #[must_use]
    pub fn failure_reason(self) -> Option<&'static str> {
        self.failure_reason
    }
}

/// Reads actor-published observations, including the final copied cleanup state.
#[derive(Clone)]
pub struct FundedTemplateObserver {
    snapshot: Arc<Mutex<FundedTemplateObservation>>,
}

impl FundedTemplateObserver {
    /// Copies the latest actor-published fixed snapshot without an actor callback.
    ///
    /// # Errors
    /// Refuses a poisoned observer lock; it never represents that as zero credit.
    pub fn snapshot(&self) -> Result<FundedTemplateObservation, NodeObservationServiceError> {
        self.snapshot
            .lock()
            .map(|value| *value)
            .map_err(|_| super::refused("funded template observer is poisoned"))
    }
}

pub(super) struct Publisher {
    snapshot: Arc<Mutex<FundedTemplateObservation>>,
}

pub(super) fn channel() -> (Publisher, FundedTemplateObserver) {
    let snapshot = Arc::new(Mutex::new(FundedTemplateObservation::from_actor(
        FundedTemplatePhase::Absent,
        0,
        None,
    )));
    (
        Publisher {
            snapshot: Arc::clone(&snapshot),
        },
        FundedTemplateObserver { snapshot },
    )
}

impl Publisher {
    pub(super) fn publish(
        &self,
        value: FundedTemplateObservation,
    ) -> Result<(), NodeObservationServiceError> {
        *self
            .snapshot
            .lock()
            .map_err(|_| super::refused("funded template observer is poisoned"))? = value;
        Ok(())
    }
}
